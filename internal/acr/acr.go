// Package acr provides read-only access to OCI artifacts stored in an Azure
// Container Registry (or any registry implementing the OCI distribution spec).
//
// Paths use the form:
//
//	acr://<registry>/<repository>:<tag>[/<file>]
//	acr://<registry>/<repository>@<digest>[/<file>]
//	acr://<registry>/<repository>            (defaults to the "latest" tag)
//
// Files inside an artifact are its layers; a layer's name is taken from the
// standard "org.opencontainers.image.title" annotation.
package acr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// Scheme is the URI scheme prefix handled by this package.
const Scheme = "acr://"

// TitleAnnotation is the OCI annotation carrying a layer's file name.
const TitleAnnotation = "org.opencontainers.image.title"

// DefaultTag is used when a path does not specify a tag or digest.
const DefaultTag = "latest"

// defaultSuffix is appended to bare registry names (e.g. "myregistry").
const defaultSuffix = ".azurecr.io"

// aadScope is the Entra ID scope used to obtain a token that is then
// exchanged for an ACR refresh token.
const aadScope = "https://management.azure.com/.default"

var manifestAcceptTypes = []string{
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
}

// sharedClient holds an optional *http.Client used by the acr package. When
// set via SetHTTPClient it overrides http.DefaultClient for all requests,
// ensuring features like DNS pinning/caching configured at program startup
// apply to registry traffic too.
var sharedClient atomic.Pointer[http.Client]

// SetHTTPClient installs a process-wide HTTP client used for all requests
// issued by this package. Passing nil clears the override and restores
// http.DefaultClient behavior.
//
// This must be called before any request is issued, e.g. from main's
// Before: hook, so that all callers observe the override.
func SetHTTPClient(c *http.Client) {
	sharedClient.Store(c)
}

func httpClient() *http.Client {
	if c := sharedClient.Load(); c != nil {
		return c
	}
	return http.DefaultClient
}

var doRequest = func(req *http.Request) (*http.Response, error) {
	return httpClient().Do(req)
}

// HTTPStatusError is returned when an HTTP request returns a non-2xx status code.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *HTTPStatusError) Error() string {
	return e.Status
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

func cleanFile(file string) (string, error) {
	if file == "" {
		return "", errors.New("missing file path")
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

type descriptor struct {
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

type manifest struct {
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

// maxIndexDepth bounds how many nested image indexes are followed.
const maxIndexDepth = 4

// ListFiles returns the files (layers) contained in the artifact referenced by p.
func ListFiles(ctx context.Context, p Path) ([]File, error) {
	m, err := fetchManifest(ctx, p, p.Reference, 0)
	if err != nil {
		return nil, err
	}
	files := make([]File, 0, len(m.Layers))
	seen := make(map[string]struct{}, len(m.Layers))
	for _, layer := range m.Layers {
		name := layer.Annotations[TitleAnnotation]
		if name == "" {
			name = strings.ReplaceAll(layer.Digest, ":", "-")
		}
		cleaned, err := cleanFile(name)
		if err != nil {
			return nil, fmt.Errorf("acr: invalid layer name %q: %w", name, err)
		}
		if _, dup := seen[cleaned]; dup {
			slog.Debug("acr: skipping duplicate layer name", "name", cleaned, "digest", layer.Digest)
			continue
		}
		seen[cleaned] = struct{}{}
		files = append(files, File{Name: cleaned, Size: layer.Size, Digest: layer.Digest})
	}
	return files, nil
}

// Stat returns metadata for the file referenced by p.File.
func Stat(ctx context.Context, p Path) (File, error) {
	if p.File == "" {
		return File{}, errors.New("acr: missing file path")
	}
	files, err := ListFiles(ctx, p)
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
func DownloadStream(ctx context.Context, p Path) (io.ReadCloser, error) {
	f, err := Stat(ctx, p)
	if err != nil {
		return nil, err
	}
	blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", p.Registry, p.Repository, url.PathEscape(f.Digest))
	resp, err := authorizedGet(ctx, p, blobURL, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("acr download failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	size := f.Size
	if size <= 0 {
		size = resp.ContentLength
	}
	return downloadReadCloser{ReadCloser: resp.Body, size: size}, nil
}

type downloadReadCloser struct {
	io.ReadCloser
	size int64
}

// Size reports the blob size or -1 if unknown.
func (d downloadReadCloser) Size() int64 {
	return d.size
}

func fetchManifest(ctx context.Context, p Path, reference string, depth int) (*manifest, error) {
	if depth > maxIndexDepth {
		return nil, errors.New("acr: too many nested image indexes")
	}
	if p.Repository == "" {
		return nil, errors.New("acr: missing repository")
	}
	manifestURL := fmt.Sprintf("https://%s/v2/%s/manifests/%s", p.Registry, p.Repository, url.PathEscape(reference))
	resp, err := authorizedGet(ctx, p, manifestURL, http.Header{
		"Accept": []string{strings.Join(manifestAcceptTypes, ", ")},
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("acr manifest fetch failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	var m manifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, err
	}
	if len(m.Layers) == 0 && len(m.Manifests) > 0 {
		// Image index: follow the first referenced manifest.
		return fetchManifest(ctx, p, m.Manifests[0].Digest, depth+1)
	}
	return &m, nil
}

func authorizedGet(ctx context.Context, p Path, target string, header http.Header) (*http.Response, error) {
	newRequest := func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		for k, values := range header {
			for _, v := range values {
				req.Header.Add(k, v)
			}
		}
		return req, nil
	}
	scope := fmt.Sprintf("repository:%s:pull", p.Repository)
	req, err := newRequest()
	if err != nil {
		return nil, err
	}
	if token := cachedToken(p.Registry, scope); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := resp.Header.Get("Www-Authenticate")
	_ = resp.Body.Close()
	token, err := acquireToken(ctx, p.Registry, scope, challenge)
	if err != nil {
		return nil, err
	}
	req, err = newRequest()
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return doRequest(req)
}

var (
	tokenCacheMu sync.Mutex
	tokenCache   = map[string]string{}
)

func cachedToken(registry, scope string) string {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	return tokenCache[registry+"|"+scope]
}

func storeToken(registry, scope, token string) {
	tokenCacheMu.Lock()
	defer tokenCacheMu.Unlock()
	tokenCache[registry+"|"+scope] = token
}

// parseChallenge extracts realm, service and scope from a token challenge
// carried in a WWW-Authenticate response header.
func parseChallenge(header string) (realm, service, scope string) {
	const prefix = "bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", ""
	}
	for _, part := range splitChallengeParams(header[len(prefix):]) {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "realm":
			realm = value
		case "service":
			service = value
		case "scope":
			scope = value
		}
	}
	return realm, service, scope
}

// splitChallengeParams splits comma-separated challenge parameters, ignoring
// commas inside quoted values.
func splitChallengeParams(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func acquireToken(ctx context.Context, registry, scope, challenge string) (string, error) {
	realm, service, challengeScope := parseChallenge(challenge)
	if realm == "" {
		realm = fmt.Sprintf("https://%s/oauth2/token", registry)
	}
	if service == "" {
		service = registry
	}
	if challengeScope != "" {
		scope = challengeScope
	}

	if user, pass, ok := basicCredentials(); ok {
		token, err := requestToken(ctx, realm, service, scope, func(req *http.Request) {
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
		})
		if err != nil {
			return "", err
		}
		storeToken(registry, scope, token)
		return token, nil
	}

	token, err := entraToken(ctx, registry, realm, service, scope)
	if err != nil {
		slog.Debug("acr: Entra ID authentication unavailable, falling back to anonymous access",
			"registry", registry, "error", err)
		token, err = requestToken(ctx, realm, service, scope, nil)
		if err != nil {
			return "", err
		}
	}
	storeToken(registry, scope, token)
	return token, nil
}

func basicCredentials() (string, string, bool) {
	user := os.Getenv("BBB_ACR_USERNAME")
	pass := os.Getenv("BBB_ACR_PASSWORD")
	if user == "" || pass == "" {
		return "", "", false
	}
	return user, pass, true
}

// entraToken exchanges an Entra ID (Azure AD) access token for a registry
// refresh token and then for a scoped registry access token.
func entraToken(ctx context.Context, registry, realm, service, scope string) (string, error) {
	cred, err := getCredential()
	if err != nil {
		return "", err
	}
	aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{aadScope}})
	if err != nil {
		return "", err
	}
	refreshToken, err := postForm(ctx, fmt.Sprintf("https://%s/oauth2/exchange", registry), url.Values{
		"grant_type":   {"access_token"},
		"service":      {service},
		"access_token": {aadToken.Token},
	}, "refresh_token")
	if err != nil {
		return "", err
	}
	return postForm(ctx, realm, url.Values{
		"grant_type":    {"refresh_token"},
		"service":       {service},
		"scope":         {scope},
		"refresh_token": {refreshToken},
	}, "access_token")
}

var (
	credOnce sync.Once
	cred     azcore.TokenCredential
	credErr  error
)

func getCredential() (azcore.TokenCredential, error) {
	credOnce.Do(func() {
		opts := &azidentity.DefaultAzureCredentialOptions{}
		if c := sharedClient.Load(); c != nil {
			opts.ClientOptions.Transport = c
		}
		cred, credErr = azidentity.NewDefaultAzureCredential(opts)
	})
	return cred, credErr
}

// requestToken performs a registry token request against the realm endpoint.
func requestToken(ctx context.Context, realm, service, scope string, decorate func(*http.Request)) (string, error) {
	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := tokenURL.Query()
	q.Set("service", service)
	if scope != "" {
		q.Set("scope", scope)
	}
	tokenURL.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	if decorate != nil {
		decorate(req)
	}
	resp, err := doRequest(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return decodeToken(resp, "access_token")
}

func postForm(ctx context.Context, target string, form url.Values, field string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := doRequest(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	return decodeToken(resp, field)
}

func decodeToken(resp *http.Response, field string) (string, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("acr auth failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	var payload map[string]json.RawMessage
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return "", err
	}
	for _, key := range []string{field, "token"} {
		raw, ok := payload[key]
		if !ok {
			continue
		}
		var token string
		if err := json.Unmarshal(raw, &token); err != nil {
			continue
		}
		if token != "" {
			return token, nil
		}
	}
	return "", errors.New("acr auth failed: no token in response")
}
