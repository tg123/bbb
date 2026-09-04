// Package acr provides access to OCI artifacts stored in an Azure Container
// Registry (or any registry implementing the OCI distribution spec).
//
// Paths use the form:
//
//	acr://<registry>/<repository>:<tag>[/<file>]
//	acr://<registry>/<repository>@<digest>[/<file>]
//	acr://<registry>/<repository>            (defaults to the "latest" tag)
//
// Files inside an artifact are its layers; a layer's name is taken from the
// standard "org.opencontainers.image.title" annotation.
//
// The registry protocol itself is handled by go-containerregistry: manifest
// resolution, blob transfer, digest verification, auth challenges and token
// caching all live there rather than being reimplemented here.
package acr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// Scheme is the URI scheme prefix handled by this package.
const Scheme = "acr://"

// TitleAnnotation is the OCI annotation carrying a layer's file name.
const TitleAnnotation = "org.opencontainers.image.title"

// DefaultTag is used when a path does not specify a tag or digest.
const DefaultTag = "latest"

// defaultSuffix is appended to bare registry names (e.g. "myregistry").
const defaultSuffix = ".azurecr.io"

// configMediaType marks the (empty) config blob of a plain file artifact.
const configMediaType = types.MediaType("application/vnd.unknown.config.v1+json")

// layerMediaType is used for each file published as a layer.
const layerMediaType = types.MediaType("application/octet-stream")

var errEmptyToken = errors.New("acr: registry token response was empty")

// ErrArtifactExists indicates that a tag already exists and overwrite was not requested.
var ErrArtifactExists = errors.New("acr: destination artifact already exists")

func policyTokenRequest(scope string) policy.TokenRequestOptions {
	return policy.TokenRequestOptions{Scopes: []string{scope}}
}

// sharedClient holds an optional *http.Client used by the acr package. When
// set via SetHTTPClient it overrides the default transport for all requests,
// ensuring features like DNS pinning/caching configured at program startup
// apply to registry traffic too.
var sharedClient atomic.Pointer[http.Client]

// SetHTTPClient installs a process-wide HTTP client used for all requests
// issued by this package. Passing nil clears the override.
//
// This must be called before any request is issued, e.g. from main's
// Before: hook, so that all callers observe the override.
func SetHTTPClient(c *http.Client) {
	sharedClient.Store(c)
}

func roundTripper() http.RoundTripper {
	if c := sharedClient.Load(); c != nil && c.Transport != nil {
		return c.Transport
	}
	return remote.DefaultTransport
}

// HTTPStatusError is returned when a registry request fails with a non-2xx
// status code.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *HTTPStatusError) Error() string {
	return e.Status
}

// NotFound reports whether the registry answered 404, so callers treating a
// missing artifact as absent rather than as a failure can recognise it.
func (e *HTTPStatusError) NotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// Is lets a 404 match os.ErrNotExist, so a missing artifact behaves like a
// missing file inside one.
func (e *HTTPStatusError) Is(target error) bool {
	return target == os.ErrNotExist && e.NotFound()
}

// asStatusError attaches an HTTPStatusError to a go-containerregistry
// transport failure, so the retry logic in bbbfs can classify it.
func asStatusError(err error) error {
	if err == nil {
		return nil
	}
	var terr *transport.Error
	if errors.As(err, &terr) {
		return fmt.Errorf("%w: %w", err, &HTTPStatusError{
			StatusCode: terr.StatusCode,
			Status:     http.StatusText(terr.StatusCode),
		})
	}
	return err
}

// Path represents an artifact, or a file inside an artifact, in a registry.
type Path struct {
	Registry   string // e.g. myregistry.azurecr.io
	Repository string // e.g. models/llama
	Reference  string // tag (e.g. v1) or digest (e.g. sha256:...)
	File       string // optional file (layer) path within the artifact
}

func (p Path) String() string {
	registry := p.displayRegistry()
	if p.Repository == "" {
		return Scheme + registry
	}
	// A repository with no reference names the repository itself, which is
	// what a registry listing reports: claiming a tag that may not exist would
	// hand back a path that does not resolve.
	if p.Reference == "" {
		return Scheme + registry + "/" + p.Repository
	}
	sep := ":"
	if strings.Contains(p.Reference, ":") {
		sep = "@"
	}
	s := Scheme + registry + "/" + p.Repository + sep + p.Reference
	if p.File != "" {
		s += "/" + p.File
	}
	return s
}

// displayRegistry undoes the Azure shorthand for display, so a path reads the
// way it was written.
//
// Only the suffix Parse adds is removed, and only when the remainder would
// expand back to the same host: a sovereign endpoint or a name that is already
// qualified would otherwise be rewritten into a different registry.
func (p Path) displayRegistry() string {
	host, port, err := net.SplitHostPort(p.Registry)
	if err != nil {
		host, port = p.Registry, ""
	}
	short, found := strings.CutSuffix(host, defaultSuffix)
	if !found || !isAzureShortName(short) {
		return p.Registry
	}
	if port == "" {
		return short
	}
	return net.JoinHostPort(short, port)
}

// IsRegistry reports whether p addresses a whole registry rather than an
// artifact within it.
func (p Path) IsRegistry() bool { return p.Repository == "" }

// IsRepository reports whether p addresses a repository without naming a tag
// or digest, so its children are the repository's tags.
func (p Path) IsRepository() bool { return p.Repository != "" && p.Reference == "" }

const expectedPathErr = "expected acr://registry[/repository[:tag|@digest][/file]]"

// canonicalAuthority normalises a registry authority for comparison. scheme is
// the transport the endpoint is actually reached over, which decides the
// default port; a non-default port is preserved, because it names a different
// service. An empty scheme defers to go-containerregistry's own inference.
//
// Writing a default port explicitly addresses the same endpoint as omitting it,
// so both must yield one key for caches and collision checks. This is
// deliberately not applied to Path.Registry itself: the port is part of the
// authority used for requests, and dropping it would move
// registry.example:80 from port 80 to 443.
func canonicalAuthority(registry string, scheme string) string {
	registry = strings.ToLower(strings.TrimSpace(registry))
	host, port, err := net.SplitHostPort(registry)
	if err != nil {
		host, port = strings.TrimPrefix(strings.TrimSuffix(registry, "]"), "["), ""
	}
	// A trailing dot is the DNS root label and names the same host.
	host = strings.TrimSuffix(host, ".")
	// An IP literal has many spellings; ParseIP().String() picks one, so
	// [::1] and [0:0:0:0:0:0:0:1] cannot address one registry under two keys.
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	}
	// Ports are numeric, so :0443 reaches the same place as :443.
	if port != "" {
		if n, convErr := strconv.Atoi(port); convErr == nil {
			port = strconv.Itoa(n)
		}
	}
	bare := host
	if strings.Contains(host, ":") {
		bare = "[" + host + "]"
	}
	if port == "" {
		return bare
	}
	authority := net.JoinHostPort(host, port)
	if scheme == "" {
		scheme = "https"
		if parsed, perr := name.NewRegistry(authority, name.WeakValidation); perr == nil {
			scheme = parsed.Scheme()
		}
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return bare
	}
	return authority
}

// registryScheme reports the transport bbb will actually use for registry.
func registryScheme(registry string) string {
	if isInsecureAllowed(registry) || isLoopback(registry) {
		return "http"
	}
	if parsed, err := name.NewRegistry(registry, name.WeakValidation); err == nil {
		return parsed.Scheme()
	}
	return "https"
}

// insecureAuthority canonicalises for an endpoint reached over HTTP, matching
// how BBB_ACR_INSECURE entries are normalised so a suggested value is one that
// will actually match.
func insecureAuthority(registry string) string {
	return canonicalAuthority(registry, "http")
}

// registryKey identifies the endpoint a registry authority addresses. The
// scheme is part of the key because the same authority means different things
// under each: http://host is port 80 and https://host is port 443, so a cache
// entry or a credential scope for one must never satisfy the other.
func registryKey(registry string) string {
	scheme := registryScheme(registry)
	return scheme + "://" + canonicalAuthority(registry, scheme)
}

// ArtifactKey identifies the artifact a path addresses, ignoring any file
// within it. Equivalent spellings of one endpoint share a key, so callers can
// detect that two paths target the same artifact.
func (p Path) ArtifactKey() string {
	return registryKey(p.Registry) + "/" + p.Repository + "@" + p.Reference
}

// isAzureShortName reports whether a registry host is the Azure shorthand, so
// "myregistry" means "myregistry.azurecr.io".
//
// "localhost" is excluded because it is a real registry host the backend
// supports, as are address literals, which never take the suffix.
func isAzureShortName(host string) bool {
	if host == "" || host == "localhost" {
		return false
	}
	if strings.Contains(host, ".") || strings.HasPrefix(host, "[") {
		return false
	}
	return net.ParseIP(host) == nil
}

// Parse parses an acr:// path.
func Parse(raw string) (Path, error) {
	if !strings.HasPrefix(raw, Scheme) {
		return Path{}, errors.New(expectedPathErr)
	}
	rest := strings.TrimPrefix(raw, Scheme)
	registry, rest, _ := strings.Cut(rest, "/")
	if registry == "" {
		return Path{}, errors.New(expectedPathErr)
	}
	// Hostnames are case-insensitive, so canonicalising case cannot change the
	// endpoint. The port is left exactly as written, because it can.
	registry = strings.ToLower(registry)
	// Apply the Azure shorthand to the host alone, so an explicit port or an
	// IPv6 authority does not suppress it.
	host, port, splitErr := net.SplitHostPort(registry)
	if splitErr != nil {
		host, port = registry, ""
	}
	if isAzureShortName(host) {
		host += defaultSuffix
	}
	if port == "" {
		registry = host
	} else {
		registry = net.JoinHostPort(host, port)
	}
	p := Path{Registry: registry}
	// A registry on its own addresses the whole registry, whose children are
	// its repositories — the same shape as az:// naming an account without a
	// container.
	if strings.Trim(rest, "/") == "" {
		return Path{Registry: registry}, nil
	}
	idx := strings.IndexAny(rest, ":@")
	if idx < 0 {
		// A repository with no tag addresses the repository, whose children
		// are its tags. Defaulting to :latest here would claim a tag that need
		// not exist, and would leave no way to ask what a repository holds.
		p.Repository = strings.Trim(rest, "/")
		if p.Repository == "" {
			return Path{}, errors.New(expectedPathErr)
		}
		return p, nil
	}
	p.Repository = rest[:idx]
	if p.Repository == "" {
		return Path{}, errors.New(expectedPathErr)
	}
	reference, file, _ := strings.Cut(rest[idx+1:], "/")
	if rest[idx] == '@' && !strings.Contains(reference, ":") {
		// Digests have the form <algorithm>:<hex>.
		return Path{}, errors.New(expectedPathErr)
	}
	if reference == "" {
		return Path{}, errors.New(expectedPathErr)
	}
	p.Reference = reference
	if file != "" {
		cleaned, err := cleanFile(file)
		if err != nil {
			return Path{}, err
		}
		p.File = cleaned
	}
	return p, nil
}

// DefaultFilename returns the filename to use when writing this path to a directory.
func (p Path) DefaultFilename() string {
	if p.File != "" {
		return path.Base(p.File)
	}
	if p.Repository == "" {
		return registryHost(p.Registry)
	}
	repo := p.Repository
	if idx := strings.LastIndex(repo, "/"); idx >= 0 {
		repo = repo[idx+1:]
	}
	return repo
}

// windowsReservedNames are DOS device names. On Windows these do not name
// ordinary files: writing to NUL discards the content entirely, and the
// reservation applies with any extension, so CON.txt is reserved too.
// Superscript digit forms are reserved as well.
var windowsReservedNames = map[string]struct{}{
	"con": {}, "prn": {}, "aux": {}, "nul": {},
	"com1": {}, "com2": {}, "com3": {}, "com4": {}, "com5": {},
	"com6": {}, "com7": {}, "com8": {}, "com9": {},
	"com\u00b9": {}, "com\u00b2": {}, "com\u00b3": {},
	"lpt1": {}, "lpt2": {}, "lpt3": {}, "lpt4": {}, "lpt5": {},
	"lpt6": {}, "lpt7": {}, "lpt8": {}, "lpt9": {},
	"lpt\u00b9": {}, "lpt\u00b2": {}, "lpt\u00b3": {},
}

// windowsForbidden are characters Windows does not allow in a filename.
// Backslash, colon and slash are handled separately: the first two are
// rejected for the whole path, and the third is the separator.
const windowsForbidden = `<>"|?*`

// checkPortableSegment rejects a path element that does not name a distinct,
// ordinary file on Windows. Layer titles are registry-controlled, so a name
// that silently discards content (NUL), aliases another name (a. and a) or
// cannot be created at all would let an extraction report success while
// losing or overwriting data, or fail only once bytes are already on disk.
func checkPortableSegment(segment string) error {
	if strings.ContainsAny(segment, windowsForbidden) {
		return fmt.Errorf("invalid file path: %q contains a character that is not allowed in a filename", segment)
	}
	for _, r := range segment {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid file path: %q contains a control character", segment)
		}
	}
	// Windows strips trailing dots and spaces, so "a." and "a" are one file.
	if trimmed := strings.TrimRight(segment, ". "); trimmed != segment {
		return fmt.Errorf("invalid file path: %q ends with a dot or space", segment)
	}
	base := segment
	if idx := strings.Index(base, "."); idx >= 0 {
		base = base[:idx]
	}
	if _, reserved := windowsReservedNames[strings.ToLower(base)]; reserved {
		return fmt.Errorf("invalid file path: %q is a reserved device name", segment)
	}
	return nil
}

// ancestors returns each directory prefix of a cleaned artifact file name,
// so "a/b/c" yields "a" and "a/b".
func ancestors(name string) []string {
	var out []string
	for idx := strings.IndexByte(name, '/'); idx >= 0; {
		out = append(out, name[:idx])
		next := strings.IndexByte(name[idx+1:], '/')
		if next < 0 {
			break
		}
		idx += next + 1
	}
	return out
}

// nameSet tracks accepted artifact file names and rejects any name that cannot
// coexist with them on a filesystem.
//
// Comparing whole names is not enough on two counts: layers "a" and "a/b" are
// distinct strings, but no filesystem can hold a file and a directory at one
// path; and "A.txt" and "a.txt" are distinct on Linux yet alias on the
// case-insensitive filesystems Windows and macOS use by default. Names are
// therefore keyed case-folded, with the original spelling kept for diagnostics.
type nameSet struct {
	files map[string]nameEntry
	dirs  map[string]string
}

type nameEntry struct {
	name   string
	digest string
}

func newNameSet(size int) *nameSet {
	return &nameSet{
		files: make(map[string]nameEntry, size),
		dirs:  make(map[string]string, size),
	}
}

// foldKey returns the key under which a name is tracked.
//
// Case folding alone is not enough: macOS stores names in a normalised form,
// so NFC "é.txt" and NFD "e\u0301.txt" are the same file there despite being
// different strings. Normalising first, then folding, makes both aliases and
// case variants collide here the way they would on disk.
func foldKey(name string) string {
	return cases.Fold().String(norm.NFC.String(name))
}

// checkCoexists reports whether name can be added alongside everything already
// accepted, ignoring any entry for the name itself.
func (s *nameSet) checkCoexists(name string) error {
	if original, isDir := s.dirs[foldKey(name)]; isDir {
		return fmt.Errorf("%q is also used as a directory by another file (%q)", name, original)
	}
	for _, ancestor := range ancestors(name) {
		if existing, isFile := s.files[foldKey(ancestor)]; isFile {
			return fmt.Errorf("%q is nested under %q, which is a file", name, existing.name)
		}
	}
	return nil
}

func (s *nameSet) record(name, digest string) {
	s.files[foldKey(name)] = nameEntry{name: name, digest: digest}
	for _, ancestor := range ancestors(name) {
		s.dirs[foldKey(ancestor)] = ancestor
	}
}

// addLayer registers a layer name read from a manifest. It reports whether the
// identical descriptor was already accepted, which happens when manifests in
// an index share a layer and is safe to skip.
func (s *nameSet) addLayer(name, digest string) (bool, error) {
	if existing, ok := s.files[foldKey(name)]; ok {
		switch {
		case existing.name == name && existing.digest == digest:
			return true, nil
		case existing.name == name:
			return false, fmt.Errorf(
				"conflicting layers named %q (%s and %s); address the artifact by digest to read a specific manifest",
				name, existing.digest, digest)
		default:
			return false, fmt.Errorf(
				"layers %q and %q differ only in case and collide on a case-insensitive filesystem",
				existing.name, name)
		}
	}
	if err := s.checkCoexists(name); err != nil {
		return false, err
	}
	s.record(name, digest)
	return false, nil
}

// addUpload registers a name being published, where any repeat is an error.
func (s *nameSet) addUpload(name string) error {
	if existing, ok := s.files[foldKey(name)]; ok {
		if existing.name == name {
			return fmt.Errorf("duplicate upload file name %q", name)
		}
		return fmt.Errorf(
			"%q and %q differ only in case and collide on a case-insensitive filesystem",
			existing.name, name)
	}
	if err := s.checkCoexists(name); err != nil {
		return err
	}
	s.record(name, "")
	return nil
}

// cleanFile validates a name used as a path relative to a local destination.
//
// Layer titles come from the registry and are untrusted, so reject anything
// that denotes a location outside the destination, or that resolves to a
// different file than it appears to. This is lexical only: it stops a name
// from itself escaping, not the local write from following a pre-existing
// symlink.
func cleanFile(file string) (string, error) {
	if file == "" {
		return "", errors.New("missing file path")
	}
	// path.Clean treats a backslash as an ordinary character, but it separates
	// path elements on Windows, so `..\..\outside` would otherwise survive.
	if strings.Contains(file, `\`) {
		return "", errors.New("invalid file path: backslash is not allowed")
	}
	// A colon opens a Windows alternate data stream: `a.txt::$DATA` writes to
	// the same default stream as `a.txt`, so two layers could quietly race for
	// one destination file.
	if strings.Contains(file, ":") {
		return "", errors.New("invalid file path: colon is not allowed")
	}
	// OCI annotations are JSON strings, so a name that is not valid UTF-8
	// would be published with replacement characters: a different title from
	// the file pushed, and one that can collide with another mangled name.
	if !utf8.ValidString(file) {
		return "", errors.New("invalid file path: name is not valid UTF-8")
	}
	if strings.HasPrefix(file, "/") {
		return "", errors.New("invalid file path")
	}
	// Reject traversal before cleaning. path.Clean would resolve
	// "sub/../secret.txt" to "secret.txt", silently renaming a
	// registry-controlled title into a different file.
	for _, segment := range strings.Split(file, "/") {
		if segment == ".." {
			return "", errors.New("invalid file path: .. is not allowed")
		}
	}
	cleaned := path.Clean(file)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("invalid file path")
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if err := checkPortableSegment(segment); err != nil {
			return "", err
		}
	}
	return cleaned, nil
}

// ValidateUploadNames checks the names of an artifact's files without
// contacting the registry, so a dry run rejects exactly what a real push would.
func ValidateUploadNames(files []UploadFile) error {
	seen := newNameSet(len(files))
	for _, file := range files {
		cleaned, err := cleanFile(file.Name)
		if err != nil {
			return fmt.Errorf("acr: invalid upload file name %q: %w", file.Name, err)
		}
		if file.Open == nil {
			return fmt.Errorf("acr: upload file %q has no reader", cleaned)
		}
		if err := seen.addUpload(cleaned); err != nil {
			return fmt.Errorf("acr: %w", err)
		}
	}
	return nil
}

// File describes a single file inside an artifact.
//
// A plain artifact stores one file per layer, so Digest identifies the blob to
// read. For a container image the file lives inside a tar layer instead, and
// TarPath names it within that layer's archive.
type File struct {
	Name   string
	Size   int64
	Digest string
	// TarPath, when set, is the entry's path inside the tar layer identified
	// by Digest. Empty means the layer is the file.
	TarPath string
}

// insecureRegistries returns the registry hosts explicitly allowed to be
// contacted over plain HTTP, from BBB_ACR_INSECURE.
func insecureRegistries() []string {
	// Normalised with HTTP semantics, because that is how these will be
	// reached: an entry for :443 must not collapse to a bare host, which
	// name.Insecure would then contact on port 80 — a different service from
	// the one that was allowed.
	return authorityList(os.Getenv("BBB_ACR_INSECURE"), insecureAuthority)
}

// isLoopback reports whether registry genuinely addresses the local machine,
// where plain HTTP carries no network exposure.
func isLoopback(registry string) bool {
	host := registryHost(registry)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isInsecureAllowed reports whether the operator explicitly allowed plain HTTP
// for registry via BBB_ACR_INSECURE.
func isInsecureAllowed(registry string) bool {
	return slices.Contains(insecureRegistries(), canonicalAuthority(registry, "http"))
}

// checkTransportSecurity refuses to contact a registry that
// go-containerregistry would silently downgrade to plain HTTP.
//
// The decision is taken from name.Registry.Scheme() rather than by
// re-implementing its heuristics, which are looser than they appear and have
// changed between releases: v0.21.5 matched "::1" unanchored and treated every
// .local name as link-local, both of which v0.21.7 narrowed. Asking the
// library keeps this correct across upgrades, so anything it will not contact
// over TLS needs an explicit opt-in, except genuine loopback.
func checkTransportSecurity(registry string) error {
	parsed, err := name.NewRegistry(registry, name.WeakValidation)
	if err != nil {
		return err
	}
	if parsed.Scheme() == "https" || isLoopback(registry) || isInsecureAllowed(registry) {
		return nil
	}
	return fmt.Errorf(
		"acr: refusing to contact %s over plain HTTP; set BBB_ACR_INSECURE=%s to allow it, or address the registry by a name that resolves over HTTPS",
		registry, insecureAuthority(registry))
}

// blobReference builds a digest reference for a blob in the same repository,
// going through reference() so the transport-security decision (including an
// explicit BBB_ACR_INSECURE opt-in) applies to blob requests too.
func (p Path) blobReference(digest string) (name.Digest, error) {
	blob := p
	blob.File = ""
	blob.Reference = digest
	ref, err := blob.reference()
	if err != nil {
		return name.Digest{}, err
	}
	digestRef, ok := ref.(name.Digest)
	if !ok {
		return name.Digest{}, fmt.Errorf("acr: %q is not a digest reference", digest)
	}
	return digestRef, nil
}

// reference builds the go-containerregistry reference for p.
func (p Path) reference() (name.Reference, error) {
	if err := checkTransportSecurity(p.Registry); err != nil {
		return nil, err
	}
	options := []name.Option{name.WeakValidation}
	if isInsecureAllowed(p.Registry) || isLoopback(p.Registry) {
		// Both cases must actually be contacted over HTTP. Without this,
		// go-containerregistry still chooses HTTPS for an ordinary hostname,
		// so the documented opt-in would have no effect, and it does not
		// recognise every loopback spelling as local either.
		options = append(options, name.Insecure)
	}
	repo := p.Registry + "/" + p.Repository
	if strings.Contains(p.Reference, ":") {
		return name.NewDigest(repo+"@"+p.Reference, options...)
	}
	return name.NewTag(repo+":"+p.Reference, options...)
}

// httpsOnlyTransport refuses a plaintext request to a registry that was not
// explicitly allowed one.
//
// checkTransportSecurity governs the endpoint bbb chooses, but a registry can
// also redirect a blob upload elsewhere: go-containerregistry follows the
// Location it returns, and forces HTTPS only while that URL stays on the
// registry host. Without this, a secure registry could have local file
// contents PATCHed to http://other-host/.
type httpsOnlyTransport struct {
	base http.RoundTripper
	// registry is the endpoint the caller addressed, canonicalised, and
	// permitted says whether plaintext was allowed for it.
	registry  string
	permitted bool
}

func (t *httpsOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.plaintextAllowed(req.URL) {
		return nil, fmt.Errorf(
			"acr: refusing to send a request to %s over plain HTTP; set BBB_ACR_INSECURE=%s to allow it",
			req.URL.Host, insecureAuthority(req.URL.Host))
	}
	return t.base.RoundTrip(req)
}

// plaintextAllowed decides per request, because the host can change mid-flight.
//
// A redirect off the registry needs its own entry in BBB_ACR_INSECURE:
// loopback is deliberately not trusted here, since a remote registry pointing
// an upload at the caller's own machine is exactly what this guards against,
// and the caller's opt-in for the registry says nothing about wherever it
// chose to redirect to.
func (t *httpsOnlyTransport) plaintextAllowed(u *url.URL) bool {
	if strings.EqualFold(u.Scheme, "https") {
		return true
	}
	if t.permitted && insecureAuthority(u.Host) == t.registry {
		return true
	}
	return isInsecureAllowed(u.Host)
}

// transport returns the HTTP transport for requests about p, enforcing the
// same plaintext policy on every request the library makes, including ones
// aimed at a host the registry chose.
func (p Path) transport() http.RoundTripper {
	return &httpsOnlyTransport{
		base:      roundTripper(),
		registry:  insecureAuthority(p.Registry),
		permitted: isInsecureAllowed(p.Registry) || isLoopback(p.Registry),
	}
}

func (p Path) remoteOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(p.transport()),
		authOption(ctx, p.Registry),
	}
}

// pullerOptions omits the context, so a cached puller is not bound to whichever
// caller happened to create it; each read passes its own.
func (p Path) pullerOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithTransport(p.transport()),
		authOption(ctx, p.Registry),
	}
}

type pullerEntry struct {
	once   sync.Once
	puller *remote.Puller
	err    error
}

// pullerCache keeps one authenticated puller per registry, so a whole-artifact
// copy does not repeat the registry ping and token exchange before every blob.
var pullerCache sync.Map

func (p Path) blobPuller(ctx context.Context) (*remote.Puller, error) {
	key := registryKey(p.Registry)
	value, _ := pullerCache.LoadOrStore(key, &pullerEntry{})
	entry := value.(*pullerEntry)
	entry.once.Do(func() {
		entry.puller, entry.err = remote.NewPuller(p.pullerOptions(ctx)...)
		if entry.err != nil {
			pullerCache.Delete(key)
		}
	})
	return entry.puller, entry.err
}

// maxIndexDepth bounds how many nested image indexes are followed.
const maxIndexDepth = 4

// artifact is one resolved snapshot of an acr:// reference.
//
// Only immutable metadata is retained. Layer objects are deliberately not
// cached: a go-containerregistry remote layer captures the context and
// authenticated fetcher it was created with, so reusing one would make a later
// download ignore its own cancellation, or fail because the resolving context
// had already expired. Blobs are content-addressed, so refetching by digest
// with the caller's context returns exactly the pinned content.
type artifact struct {
	files  []File
	byName map[string]File
	seen   *nameSet
	// groups holds the tar layers of each manifest, expanded only when a path
	// reaches inside one. Listing a multi-platform image's root is answered
	// from the index alone rather than by transferring every layer.
	groups []*imageGroup
	mu     sync.Mutex
}

// layerCacheEntry memoises one resolved artifact.
type layerCacheEntry struct {
	once sync.Once
	art  *artifact
	err  error
}

// layerCache keys resolved artifacts by registry|repository|reference.
var layerCache sync.Map

func layerCacheKey(p Path) string {
	return registryKey(p.Registry) + "|" + p.Repository + "|" + p.Reference
}

// invalidateLayers drops any cached artifact for p, so a tag republished by
// this process is not later read back from a stale snapshot.
func invalidateLayers(p Path) {
	layerCache.Delete(layerCacheKey(p))
}

// resolve fetches and caches the artifact referenced by p.
//
// A reference is resolved at most once per process. Besides collapsing the
// manifest fetch that each subsequent Stat would otherwise repeat, this pins a
// whole-artifact copy to a single snapshot: a tag republished mid-transfer
// cannot leave the destination holding a mix of two revisions.
func resolve(ctx context.Context, p Path) (*artifact, error) {
	key := layerCacheKey(p)
	value, _ := layerCache.LoadOrStore(key, &layerCacheEntry{})
	entry := value.(*layerCacheEntry)
	entry.once.Do(func() {
		entry.art, entry.err = fetchArtifact(ctx, p)
		if entry.err != nil {
			// Never memoise a failure: it would defeat --retry-count and let a
			// cancelled context poison every later read.
			layerCache.Delete(key)
		}
	})
	if entry.err != nil {
		return nil, entry.err
	}
	return entry.art, nil
}

func fetchArtifact(ctx context.Context, p Path) (*artifact, error) {
	if p.Repository == "" {
		return nil, errors.New("acr: a registry has no artifact; name a repository")
	}
	if p.Reference == "" {
		return nil, fmt.Errorf("acr: %s names a repository; add :tag to address an artifact", p.String())
	}
	ref, err := p.reference()
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(ref, p.remoteOptions(ctx)...)
	if err != nil {
		return nil, asStatusError(err)
	}
	art := &artifact{byName: map[string]File{}, seen: newNameSet(0)}
	switch desc.MediaType {
	case types.OCIImageIndex, types.DockerManifestList:
		// Descriptor.Image() would resolve an index to the single child
		// matching the current platform, and fail outright when an artifact
		// index carries no platform metadata. Artifacts are not
		// platform-specific, so merge every child instead.
		index, err := desc.ImageIndex()
		if err != nil {
			return nil, asStatusError(err)
		}
		if err := art.addIndex(index, 0); err != nil {
			return nil, err
		}
	default:
		image, err := desc.Image()
		if err != nil {
			return nil, asStatusError(err)
		}
		if err := art.addImage(image); err != nil {
			return nil, err
		}
	}
	return art, nil
}

// addIndex merges the layers of every manifest an index references.
func (a *artifact) addIndex(index v1.ImageIndex, depth int) error {
	if depth > maxIndexDepth {
		return errors.New("acr: too many nested image indexes")
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return err
	}
	for _, child := range manifest.Manifests {
		switch child.MediaType {
		case types.OCIImageIndex, types.DockerManifestList:
			nested, err := index.ImageIndex(child.Digest)
			if err != nil {
				return asStatusError(err)
			}
			if err := a.addIndex(nested, depth+1); err != nil {
				return err
			}
		default:
			image, err := index.Image(child.Digest)
			if err != nil {
				return asStatusError(err)
			}
			// A multi-platform image repeats the same file names once per
			// platform, so each manifest's contents are kept apart under its
			// own os/arch rather than colliding at the root.
			if err := a.addImageAt(image, platformPrefix(child.Platform)); err != nil {
				return err
			}
		}
	}
	return nil
}

// addImage merges one manifest's layers into the artifact.
func (a *artifact) addImage(image v1.Image) error {
	return a.addImageAt(image, "")
}

func (a *artifact) addImageAt(image v1.Image, prefix string) error {
	manifest, err := image.Manifest()
	if err != nil {
		return err
	}
	group := &imageGroup{prefix: prefix}
	for _, descriptor := range manifest.Layers {
		digest := descriptor.Digest.String()
		// A filesystem layer holds files rather than being one, so it is
		// recorded for expansion instead of being named here.
		if isTarLayer(descriptor.MediaType) {
			group.layers = append(group.layers, layerRef{digest: digest, size: descriptor.Size})
			continue
		}
		title := descriptor.Annotations[TitleAnnotation]
		if title == "" {
			title = strings.ReplaceAll(digest, ":", "-")
		}
		cleaned, err := cleanFile(title)
		if err != nil {
			return fmt.Errorf("acr: invalid layer name %q: %w", title, err)
		}
		if prefix != "" {
			cleaned = prefix + "/" + cleaned
		}
		dup, err := a.seen.addLayer(cleaned, digest)
		if err != nil {
			return fmt.Errorf("acr: %w", err)
		}
		if dup {
			continue
		}
		// Record by name rather than by digest: two files with identical
		// contents share a blob but are still two distinct files, and dropping
		// the second would silently lose it.
		file := File{Name: cleaned, Size: descriptor.Size, Digest: digest}
		a.files = append(a.files, file)
		a.byName[cleaned] = file
	}
	if len(group.layers) > 0 {
		a.groups = append(a.groups, group)
	}
	return nil
}

// materialise expands the tar layers needed to answer a question about file,
// and returns every file known once they have been.
//
// Expanding transfers a layer, so a group is only read when the requested path
// reaches into it, or it reaches into the requested directory.
func (a *artifact) materialise(ctx context.Context, p Path, file string) ([]File, error) {
	files := a.files
	for _, group := range a.groups {
		if !group.covers(file) {
			continue
		}
		entries, err := group.expand(ctx, p)
		if err != nil {
			return nil, err
		}
		files = append(files, entries...)
	}
	return files, nil
}

// lookup finds a single file, expanding only the layer that could hold it.
func (a *artifact) lookup(ctx context.Context, p Path, name string) (File, bool, error) {
	if file, ok := a.byName[name]; ok {
		return file, true, nil
	}
	for _, group := range a.groups {
		if !group.covers(name) {
			continue
		}
		entries, err := group.expand(ctx, p)
		if err != nil {
			return File{}, false, err
		}
		for _, entry := range entries {
			if entry.Name == name {
				return entry, true, nil
			}
		}
	}
	return File{}, false, nil
}

// unexpandedDirs returns the directories that exist because a tar layer will be
// expanded under them, so a listing can show them without transferring
// anything.
func (a *artifact) unexpandedDirs() []string {
	dirs := make([]string, 0, len(a.groups))
	for _, group := range a.groups {
		if group.prefix != "" {
			dirs = append(dirs, group.prefix)
		}
	}
	return dirs
}

// ListTags returns the tags a repository holds.
func ListTags(ctx context.Context, p Path) ([]string, error) {
	if p.Repository == "" {
		return nil, errors.New("acr: a registry has no tags; name a repository")
	}
	if err := checkTransportSecurity(p.Registry); err != nil {
		return nil, err
	}
	options := []name.Option{name.WeakValidation}
	if isInsecureAllowed(p.Registry) || isLoopback(p.Registry) {
		options = append(options, name.Insecure)
	}
	repository, err := name.NewRepository(p.Registry+"/"+p.Repository, options...)
	if err != nil {
		return nil, err
	}
	tags, err := remote.List(repository, p.remoteOptions(ctx)...)
	if err != nil {
		return nil, asStatusError(err)
	}
	slices.Sort(tags)
	return tags, nil
}

// ListRepositories returns the repositories a registry holds, from the
// distribution catalog endpoint.
//
// The result is what the registry reports, including any slashes: ACR namespaces
// repositories, so "models/llama" is one repository rather than a directory
// holding another. Each name can be addressed directly as acr://registry/<name>.
func ListRepositories(ctx context.Context, p Path) ([]string, error) {
	if err := checkTransportSecurity(p.Registry); err != nil {
		return nil, err
	}
	options := []name.Option{name.WeakValidation}
	if isInsecureAllowed(p.Registry) || isLoopback(p.Registry) {
		options = append(options, name.Insecure)
	}
	registry, err := name.NewRegistry(p.Registry, options...)
	if err != nil {
		return nil, err
	}
	// Catalog paginates internally and can be large, so the caller's context
	// governs how long that is allowed to take.
	repositories, err := remote.Catalog(ctx, registry, p.remoteOptions(ctx)...)
	if err != nil {
		return nil, asStatusError(err)
	}
	slices.Sort(repositories)
	return repositories, nil
}

// ListFiles returns the files contained in the artifact referenced by p,
// including everything inside p.File when it names a directory.
//
// Files inside a container image's tar layers require transferring those
// layers, so only the ones covering p.File are expanded: listing a single
// platform of a multi-platform image reads that platform alone.
func ListFiles(ctx context.Context, p Path) ([]File, error) {
	art, err := resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	art.mu.Lock()
	defer art.mu.Unlock()
	files, err := art.materialise(ctx, p, p.File)
	if err != nil {
		return nil, err
	}
	return slices.Clone(files), nil
}

// ListDir returns the immediate children of p.File without expanding layers it
// does not have to.
//
// The root of a multi-platform image is answered from the index alone, so
// listing it costs one manifest fetch rather than a copy of every layer.
func ListDir(ctx context.Context, p Path) ([]Entry, error) {
	art, err := resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	art.mu.Lock()
	defer art.mu.Unlock()

	// Only groups reaching into p.File are expanded; one sitting below it
	// contributes just the directory that leads to it.
	var files []File
	for _, group := range art.groups {
		if group.prefix != "" && strings.HasPrefix(group.prefix+"/", childPrefix(p.File)) &&
			group.prefix != p.File {
			continue
		}
		if !group.covers(p.File) {
			continue
		}
		entries, expandErr := group.expand(ctx, p)
		if expandErr != nil {
			return nil, expandErr
		}
		files = append(files, entries...)
	}
	files = append(files, art.files...)

	seen := map[string]Entry{}
	var order []string
	add := func(entry Entry) {
		if _, ok := seen[entry.Name]; !ok {
			order = append(order, entry.Name)
		}
		seen[entry.Name] = entry
	}
	for _, file := range files {
		if child, dir, ok := immediateChild(p.File, file.Name); ok {
			if dir {
				add(Entry{Name: child, IsDir: true})
			} else {
				add(Entry{Name: child, Size: file.Size})
			}
		}
	}
	// A platform that has not been expanded still exists as a directory.
	for _, prefix := range art.unexpandedDirs() {
		if child, _, ok := immediateChild(p.File, prefix); ok {
			add(Entry{Name: child, IsDir: true})
		}
	}

	out := make([]Entry, 0, len(order))
	for _, name := range order {
		out = append(out, seen[name])
	}
	return out, nil
}

// Entry is one child in a directory listing.
type Entry struct {
	Name  string
	Size  int64
	IsDir bool
}

// childPrefix renders dir as the prefix its children share.
func childPrefix(dir string) string {
	if dir == "" {
		return ""
	}
	return dir + "/"
}

// immediateChild reports name's first path segment below dir, and whether that
// segment is a directory rather than the file itself.
func immediateChild(dir, name string) (child string, isDir bool, ok bool) {
	prefix := childPrefix(dir)
	if !strings.HasPrefix(name, prefix) {
		return "", false, false
	}
	rest := name[len(prefix):]
	if rest == "" {
		return "", false, false
	}
	if head, _, found := strings.Cut(rest, "/"); found {
		return head, true, true
	}
	return rest, false, true
}

// Stat returns metadata for the file referenced by p.File.
func Stat(ctx context.Context, p Path) (File, error) {
	if p.File == "" {
		return File{}, errors.New("acr: missing file path")
	}
	art, err := resolve(ctx, p)
	if err != nil {
		return File{}, err
	}
	art.mu.Lock()
	defer art.mu.Unlock()
	file, ok, err := art.lookup(ctx, p, p.File)
	if err != nil {
		return File{}, err
	}
	if !ok {
		return File{}, &notFoundError{path: p.String()}
	}
	return file, nil
}

// IsDir reports whether p.File addresses a directory within the artifact:
// either the artifact root, one of the virtual directories synthesised from
// file names, or a platform of a multi-platform image.
//
// A name that matches a file exactly is decided by an O(1) map lookup, and only
// an unmatched name falls back to scanning. Downloading an N-file artifact
// stats every file through here, so a linear scan per file would make the whole
// transfer quadratic.
func IsDir(ctx context.Context, p Path) (bool, error) {
	if p.File == "" {
		return true, nil
	}
	art, err := resolve(ctx, p)
	if err != nil {
		return false, err
	}
	art.mu.Lock()
	defer art.mu.Unlock()
	if _, ok := art.byName[p.File]; ok {
		return false, nil
	}
	// A platform directory is known from the index, so this answers without
	// expanding the layers underneath it.
	prefix := p.File + "/"
	for _, dir := range art.unexpandedDirs() {
		if dir == p.File || strings.HasPrefix(dir, prefix) {
			return true, nil
		}
	}
	files, err := art.materialise(ctx, p, p.File)
	if err != nil {
		return false, err
	}
	for _, f := range files {
		if f.Name == p.File {
			return false, nil
		}
		if strings.HasPrefix(f.Name, prefix) {
			return true, nil
		}
	}
	return false, nil
}

type notFoundError struct {
	path string
}

func (e *notFoundError) Error() string { return "acr: file not found: " + e.path }

// NotFound reports that the referenced file does not exist.
func (e *notFoundError) NotFound() bool { return true }

func (e *notFoundError) Is(target error) bool { return target == os.ErrNotExist }

// DownloadStream streams the contents of the file referenced by p.
//
// go-containerregistry verifies the blob against its descriptor digest as the
// stream is read, so a corrupt registry or proxy cannot silently yield
// different bytes.
func DownloadStream(ctx context.Context, p Path) (io.ReadCloser, error) {
	if p.File == "" {
		return nil, errors.New("acr: missing file path")
	}
	art, err := resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	art.mu.Lock()
	target, ok, err := art.lookup(ctx, p, p.File)
	art.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, &notFoundError{path: p.String()}
	}
	// A file inside a container image is one entry of a tar layer rather than
	// the layer itself.
	if target.TarPath != "" {
		return openTarEntry(ctx, p, target)
	}
	body, err := openBlob(ctx, p, target.Digest)
	if err != nil {
		return nil, err
	}
	return downloadReadCloser{ReadCloser: body, size: target.Size}, nil
}

// openBlob streams a layer blob by digest.
//
// The blob is fetched with the caller's context rather than the one that
// resolved the manifest. The digest pins the content, so this still reads
// exactly the snapshot that was listed, and a shared puller keeps the
// authentication rather than repeating it per layer.
func openBlob(ctx context.Context, p Path, digest string) (io.ReadCloser, error) {
	digestRef, err := p.blobReference(digest)
	if err != nil {
		return nil, err
	}
	puller, err := p.blobPuller(ctx)
	if err != nil {
		return nil, asStatusError(err)
	}
	layer, err := puller.Layer(ctx, digestRef)
	if err != nil {
		// NewPuller does not authenticate: the fetcher is built on first use
		// behind a sync.Once, so a failed initialisation would be replayed for
		// the rest of the run and defeat --retry-count.
		pullerCache.Delete(registryKey(p.Registry))
		return nil, asStatusError(err)
	}
	// Compressed() returns the blob exactly as stored, which is what an
	// artifact layer is; Uncompressed() would try to gunzip it.
	body, err := layer.Compressed()
	if err != nil {
		pullerCache.Delete(registryKey(p.Registry))
		return nil, asStatusError(err)
	}
	return body, nil
}

type downloadReadCloser struct {
	io.ReadCloser
	size int64
}

// Size reports the blob size or -1 if unknown.
func (d downloadReadCloser) Size() int64 {
	return d.size
}

// UploadFile describes one layer to publish in an OCI artifact. Open must
// return a fresh reader on every call, because the layer is read more than
// once (digest calculation, then upload) and to allow retries.
type UploadFile struct {
	Name string
	Size int64
	Open func() (io.ReadCloser, error)
}

// PushOptions controls publishing an OCI artifact.
type PushOptions struct {
	Concurrency int
	Overwrite   bool
	// OnProgress receives a layer's file name and how many of its bytes have
	// been uploaded so far in the current attempt. The value is cumulative per
	// layer and can restart at zero, so callers must keep a high-water mark
	// per name rather than summing what they are given.
	OnProgress func(name string, uploaded int64)
}

// ValidatePushTarget reports whether p names something that can be published
// to. Exported so callers such as a dry run can reject an impossible
// destination without performing the push.
func ValidatePushTarget(p Path) error {
	if p.Repository == "" {
		return errors.New("acr: push destination must name a repository, not just a registry")
	}
	if p.Reference == "" {
		// Publishing replaces a tag, so which one cannot be left implicit.
		return fmt.Errorf("acr: push destination %s must name a tag, as %s:<tag>", p.String(), p.String())
	}
	if p.File != "" {
		return errors.New("acr: push destination must be an artifact, not a file")
	}
	if strings.Contains(p.Reference, ":") {
		return errors.New("acr: push destination must use a tag, not a digest")
	}
	// Resolving the reference also checks repository/tag syntax and refuses a
	// registry that would be contacted over plain HTTP, so a dry run rejects
	// everything the real push would.
	if _, err := p.reference(); err != nil {
		return err
	}
	return nil
}

// Push publishes files as the layers of a single OCI artifact at p.Reference.
//
// go-containerregistry uploads every blob and only then writes the manifest,
// so the tag is never left pointing at a partial artifact.
//
// An empty file set publishes an artifact with no layers. That keeps mirror
// semantics honest: syncing an empty directory, or one whose files are all
// excluded, must replace the tag rather than leave the previous contents.
func Push(ctx context.Context, p Path, files []UploadFile, opts PushOptions) error {
	if err := ValidatePushTarget(p); err != nil {
		return err
	}
	if err := ValidateUploadNames(files); err != nil {
		return err
	}
	ref, err := p.reference()
	if err != nil {
		return err
	}

	adds := make([]mutate.Addendum, 0, len(files))
	for _, file := range files {
		cleaned, err := cleanFile(file.Name)
		if err != nil {
			return fmt.Errorf("acr: invalid upload file name %q: %w", file.Name, err)
		}
		adds = append(adds, mutate.Addendum{
			Layer:       &fileLayer{ctx: ctx, name: cleaned, open: file.Open, size: file.Size, onRead: opts.OnProgress},
			MediaType:   layerMediaType,
			Annotations: map[string]string{TitleAnnotation: cleaned},
		})
	}

	image := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	image = mutate.ConfigMediaType(image, configMediaType)
	image, err = mutate.Append(image, adds...)
	if err != nil {
		return err
	}

	if !opts.Overwrite {
		// Compare against the manifest we are about to publish rather than
		// merely testing for existence. An outer retry re-enters Push after a
		// committed PUT whose response was lost, and reporting failure for an
		// artifact we ourselves just published would be wrong.
		intended, err := image.Digest()
		if err != nil {
			return err
		}
		existing, err := manifestDigest(ctx, p)
		switch {
		case err != nil:
			return err
		case existing == intended.String():
			slog.Debug("acr: destination already holds this exact artifact, treating the push as complete",
				"artifact", p.String(), "digest", existing)
			invalidateLayers(p)
			return nil
		case existing != "":
			return fmt.Errorf("%w: %s", ErrArtifactExists, p.String())
		}
	}

	options := p.remoteOptions(ctx)
	if opts.Concurrency > 0 {
		// go-containerregistry defaults to four jobs, so a requested limit of
		// one has to be passed through rather than omitted.
		options = append(options, remote.WithJobs(opts.Concurrency))
	}
	if !opts.Overwrite {
		// The existence check above and this write are separate requests, so
		// two publishers could both observe an absent tag. Ask the registry to
		// make the manifest PUT create-only; go-containerregistry has no option
		// for this, so the header is added in the transport.
		options = append(options, remote.WithTransport(&createOnlyTransport{base: p.transport()}))
	}
	if err := remote.Write(ref, image, options...); err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusPreconditionFailed {
			// A registry honouring If-None-Match rejected the write because the
			// tag exists. That may be this process's own earlier attempt whose
			// response was lost, so let the published digest decide.
			return confirmPublished(ctx, p, image)
		}
		return asStatusError(err)
	}
	if !opts.Overwrite {
		// Registries are not required to honour If-None-Match, so confirm the
		// tag holds exactly what we published.
		if err := confirmPublished(ctx, p, image); err != nil {
			return err
		}
	}
	// The tag now points somewhere new, so drop any snapshot this process
	// cached for it.
	invalidateLayers(p)
	return nil
}

// confirmPublished reports whether p holds the artifact that was just written.
//
// An exact digest match is success, including when a retry re-published its own
// earlier work. A different digest means another writer won the tag. A missing
// tag is a plain error so it stays retryable, since it may have been removed
// between the write and the check.
func confirmPublished(ctx context.Context, p Path, image v1.Image) error {
	published, err := manifestDigest(ctx, p)
	if err != nil {
		return err
	}
	intended, err := image.Digest()
	if err != nil {
		return err
	}
	switch {
	case published == intended.String():
		invalidateLayers(p)
		return nil
	case published == "":
		return fmt.Errorf("acr: %s is missing after publication; it may have been removed concurrently", p.String())
	default:
		return fmt.Errorf("%w: %s was published concurrently by another writer", ErrArtifactExists, p.String())
	}
}

// createOnlyTransport marks manifest writes as create-only, so a registry that
// supports conditional requests rejects a tag that appeared after the caller's
// existence check. Registries that ignore the header are unaffected.
type createOnlyTransport struct {
	base http.RoundTripper
}

// isManifestWrite reports whether a request path addresses a manifest rather
// than a blob.
//
// A substring test is not enough: a repository may itself contain a
// "manifests" segment, so a blob upload for team/manifests/model would look
// like a manifest request and be given a precondition the registry could
// reject. Only the rightmost distribution endpoint decides, and a manifest
// reference is a single trailing segment.
func isManifestWrite(path string) bool {
	const marker = "/manifests/"
	idx := strings.LastIndex(path, marker)
	if idx < 0 {
		return false
	}
	reference := path[idx+len(marker):]
	return reference != "" && !strings.Contains(reference, "/")
}

func (t *createOnlyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPut && isManifestWrite(req.URL.Path) {
		req = req.Clone(req.Context())
		req.Header.Set("If-None-Match", "*")
	}
	return t.base.RoundTrip(req)
}

// manifestDigest returns the digest currently published at p.Reference, or an
// empty string when the reference does not exist.
func manifestDigest(ctx context.Context, p Path) (string, error) {
	ref, err := p.reference()
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(ref, p.remoteOptions(ctx)...)
	if err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return "", nil
		}
		return "", asStatusError(err)
	}
	return desc.Digest.String(), nil
}

// ManifestExists reports whether p.Reference currently resolves to a manifest.
func ManifestExists(ctx context.Context, p Path) (bool, error) {
	digest, err := manifestDigest(ctx, p)
	if err != nil {
		return false, err
	}
	return digest != "", nil
}
