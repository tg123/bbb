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
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
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
	sep := ":"
	if strings.Contains(p.Reference, ":") {
		sep = "@"
	}
	s := Scheme + p.Registry + "/" + p.Repository + sep + p.Reference
	if p.File != "" {
		s += "/" + p.File
	}
	return s
}

const expectedPathErr = "expected acr://registry/repository[:tag|@digest][/file]"

// Parse parses an acr:// path.
func Parse(raw string) (Path, error) {
	if !strings.HasPrefix(raw, Scheme) {
		return Path{}, errors.New(expectedPathErr)
	}
	rest := strings.TrimPrefix(raw, Scheme)
	registry, rest, ok := strings.Cut(rest, "/")
	if !ok || registry == "" || rest == "" {
		return Path{}, errors.New(expectedPathErr)
	}
	if !strings.ContainsAny(registry, ".:") {
		registry += defaultSuffix
	}
	p := Path{Registry: registry, Reference: DefaultTag}
	idx := strings.IndexAny(rest, ":@")
	if idx < 0 {
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
	repo := p.Repository
	if idx := strings.LastIndex(repo, "/"); idx >= 0 {
		repo = repo[idx+1:]
	}
	return repo
}

// cleanFile validates a name used as a path relative to a local destination.
//
// Layer titles come from the registry and are untrusted, so reject anything
// that denotes a location outside the destination. This is lexical only: it
// stops a name from itself escaping, not the local write from following a
// pre-existing symlink.
func cleanFile(file string) (string, error) {
	if file == "" {
		return "", errors.New("missing file path")
	}
	// path.Clean treats a backslash as an ordinary character, but it separates
	// path elements on Windows, so `..\..\outside` would otherwise survive.
	if strings.Contains(file, `\`) {
		return "", errors.New("invalid file path: backslash is not allowed")
	}
	if strings.HasPrefix(file, "/") {
		return "", errors.New("invalid file path")
	}
	cleaned := path.Clean(file)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("invalid file path")
	}
	return cleaned, nil
}

// File describes a single file (layer) inside an artifact.
type File struct {
	Name   string
	Size   int64
	Digest string
}

// reference builds the go-containerregistry reference for p. Plain-HTTP
// registries (localhost, loopback and RFC1918 addresses) are detected by
// go-containerregistry itself.
func (p Path) reference() (name.Reference, error) {
	repo := p.Registry + "/" + p.Repository
	if strings.Contains(p.Reference, ":") {
		return name.NewDigest(repo+"@"+p.Reference, name.WeakValidation)
	}
	return name.NewTag(repo+":"+p.Reference, name.WeakValidation)
}

func (p Path) remoteOptions(ctx context.Context) []remote.Option {
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithTransport(roundTripper()),
		authOption(ctx, p.Registry),
	}
}

// layerCacheEntry memoises one artifact's resolved layer set.
type layerCacheEntry struct {
	once  sync.Once
	files []File
	image v1.Image
	err   error
}

// layerCache keys resolved artifacts by registry|repository|reference.
var layerCache sync.Map

func layerCacheKey(p Path) string {
	return p.Registry + "|" + p.Repository + "|" + p.Reference
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
func resolve(ctx context.Context, p Path) ([]File, v1.Image, error) {
	key := layerCacheKey(p)
	value, _ := layerCache.LoadOrStore(key, &layerCacheEntry{})
	entry := value.(*layerCacheEntry)
	entry.once.Do(func() {
		entry.files, entry.image, entry.err = fetchArtifact(ctx, p)
		if entry.err != nil {
			// Never memoise a failure: it would defeat --retry-count and let a
			// cancelled context poison every later read.
			layerCache.Delete(key)
		}
	})
	if entry.err != nil {
		return nil, nil, entry.err
	}
	return entry.files, entry.image, nil
}

func fetchArtifact(ctx context.Context, p Path) ([]File, v1.Image, error) {
	ref, err := p.reference()
	if err != nil {
		return nil, nil, err
	}
	desc, err := remote.Get(ref, p.remoteOptions(ctx)...)
	if err != nil {
		return nil, nil, asStatusError(err)
	}
	// For an image index, Image() resolves a child manifest, matching the
	// single flat file set an acr:// path presents.
	image, err := desc.Image()
	if err != nil {
		return nil, nil, asStatusError(err)
	}
	manifest, err := image.Manifest()
	if err != nil {
		return nil, nil, err
	}
	files := make([]File, 0, len(manifest.Layers))
	seen := make(map[string]string, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		digest := layer.Digest.String()
		title := layer.Annotations[TitleAnnotation]
		if title == "" {
			title = strings.ReplaceAll(digest, ":", "-")
		}
		cleaned, err := cleanFile(title)
		if err != nil {
			return nil, nil, fmt.Errorf("acr: invalid layer name %q: %w", title, err)
		}
		if previous, dup := seen[cleaned]; dup {
			// One blob listed twice is redundant and safe to collapse. Two
			// different blobs claiming the same name are not: silently keeping
			// the first would hide part of the artifact, so surface it.
			if previous == digest {
				slog.Debug("acr: skipping duplicate layer", "name", cleaned, "digest", digest)
				continue
			}
			return nil, nil, fmt.Errorf(
				"acr: conflicting layers named %q (%s and %s); address the artifact by digest to read a specific manifest",
				cleaned, previous, digest)
		}
		seen[cleaned] = digest
		files = append(files, File{Name: cleaned, Size: layer.Size, Digest: digest})
	}
	return files, image, nil
}

// ListFiles returns the files (layers) contained in the artifact referenced by p.
func ListFiles(ctx context.Context, p Path) ([]File, error) {
	files, _, err := resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	return slices.Clone(files), nil
}

// Stat returns metadata for the file referenced by p.File.
func Stat(ctx context.Context, p Path) (File, error) {
	if p.File == "" {
		return File{}, errors.New("acr: missing file path")
	}
	files, _, err := resolve(ctx, p)
	if err != nil {
		return File{}, err
	}
	for _, f := range files {
		if f.Name == p.File {
			return f, nil
		}
	}
	return File{}, &notFoundError{path: p.String()}
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
	files, image, err := resolve(ctx, p)
	if err != nil {
		return nil, err
	}
	var target File
	for _, f := range files {
		if f.Name == p.File {
			target = f
			break
		}
	}
	if target.Name == "" {
		return nil, &notFoundError{path: p.String()}
	}
	digest, err := v1.NewHash(target.Digest)
	if err != nil {
		return nil, err
	}
	layer, err := image.LayerByDigest(digest)
	if err != nil {
		return nil, asStatusError(err)
	}
	// Compressed() returns the blob exactly as stored, which is what an
	// artifact layer is; Uncompressed() would try to gunzip it.
	body, err := layer.Compressed()
	if err != nil {
		return nil, asStatusError(err)
	}
	return downloadReadCloser{ReadCloser: body, size: target.Size}, nil
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
	OnProgress  func(int64)
}

// ValidatePushTarget reports whether p names something that can be published
// to. Exported so callers such as a dry run can reject an impossible
// destination without performing the push.
func ValidatePushTarget(p Path) error {
	if p.File != "" {
		return errors.New("acr: push destination must be an artifact, not a file")
	}
	if strings.Contains(p.Reference, ":") {
		return errors.New("acr: push destination must use a tag, not a digest")
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
	ref, err := p.reference()
	if err != nil {
		return err
	}
	if !opts.Overwrite {
		exists, err := ManifestExists(ctx, p)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w: %s", ErrArtifactExists, p.String())
		}
	}

	names := make(map[string]struct{}, len(files))
	adds := make([]mutate.Addendum, 0, len(files))
	for _, file := range files {
		cleaned, err := cleanFile(file.Name)
		if err != nil {
			return fmt.Errorf("acr: invalid upload file name %q: %w", file.Name, err)
		}
		if _, exists := names[cleaned]; exists {
			return fmt.Errorf("acr: duplicate upload file name %q", cleaned)
		}
		if file.Open == nil {
			return fmt.Errorf("acr: upload file %q has no reader", cleaned)
		}
		names[cleaned] = struct{}{}
		adds = append(adds, mutate.Addendum{
			Layer:       &fileLayer{open: file.Open, size: file.Size, onRead: opts.OnProgress},
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

	options := p.remoteOptions(ctx)
	if opts.Concurrency > 1 {
		options = append(options, remote.WithJobs(opts.Concurrency))
	}
	if err := remote.Write(ref, image, options...); err != nil {
		return asStatusError(err)
	}
	// The tag now points somewhere new, so drop any snapshot this process
	// cached for it.
	invalidateLayers(p)
	return nil
}

// ManifestExists reports whether p.Reference currently resolves to a manifest.
func ManifestExists(ctx context.Context, p Path) (bool, error) {
	ref, err := p.reference()
	if err != nil {
		return false, err
	}
	if _, err := remote.Head(ref, p.remoteOptions(ctx)...); err != nil {
		var terr *transport.Error
		if errors.As(err, &terr) && terr.StatusCode == http.StatusNotFound {
			return false, nil
		}
		return false, asStatusError(err)
	}
	return true, nil
}
