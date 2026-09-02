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
package acr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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

const (
	manifestMediaType = "application/vnd.oci.image.manifest.v1+json"
	configMediaType   = "application/vnd.unknown.config.v1+json"
	layerMediaType    = "application/octet-stream"
)

// defaultSuffix is appended to bare registry names (e.g. "myregistry").
const defaultSuffix = ".azurecr.io"

// aadScopes are the Entra ID scopes tried, in order, to obtain a token that is
// then exchanged for a registry refresh token. Registries accept a token with
// the container registry audience; the ARM audience is kept as a fallback for
// clouds/credentials where the former cannot be issued.
var aadScopes = []string{
	"https://containerregistry.azure.net/.default",
	"https://management.azure.com/.default",
}

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

func registryURL(registry, suffix string) string {
	base := "https://" + registry
	if endpoint := strings.TrimSpace(os.Getenv("BBB_ACR_ENDPOINT")); endpoint != "" {
		if strings.Contains(endpoint, "%s") {
			base = fmt.Sprintf(endpoint, registry)
		} else {
			base = endpoint
		}
	}
	return strings.TrimRight(base, "/") + suffix
}

var doRequest = func(req *http.Request) (*http.Response, error) {
	return httpClient().Do(req)
}

// HTTPStatusError is returned when an HTTP request returns a non-2xx status code.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

// ErrArtifactExists indicates that a tag already exists and overwrite was not requested.
var ErrArtifactExists = errors.New("acr: destination artifact already exists")

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
	// Layer titles come from the registry and are untrusted. path.Clean treats
	// a backslash as an ordinary character, but it separates path elements on
	// Windows, so a name such as `..\..\outside` would survive the checks below
	// and then escape the destination once joined with filepath.Join.
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

type descriptor struct {
	MediaType   string            `json:"mediaType,omitempty"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int          `json:"schemaVersion,omitempty"`
	MediaType     string       `json:"mediaType,omitempty"`
	Config        descriptor   `json:"config,omitempty"`
	Layers        []descriptor `json:"layers"`
	Manifests     []descriptor `json:"manifests,omitempty"`
}

// maxIndexDepth bounds how many nested image indexes are followed.
const maxIndexDepth = 4

// ListFiles returns the files (layers) contained in the artifact referenced by
// p. For a multi-platform artifact (image index) the layers of every
// referenced manifest are merged.
func ListFiles(ctx context.Context, p Path) ([]File, error) {
	layers, err := fetchLayers(ctx, p, p.Reference, 0)
	if err != nil {
		return nil, err
	}
	files := make([]File, 0, len(layers))
	seen := make(map[string]struct{}, len(layers))
	for _, layer := range layers {
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
	blobURL := registryURL(p.Registry, fmt.Sprintf("/v2/%s/blobs/%s", p.Repository, url.PathEscape(f.Digest)))
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

// UploadFile describes one layer to publish in an OCI artifact. Open must
// return a fresh reader on every call so an interrupted request can be retried.
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

// Push uploads files as OCI layers and publishes one manifest at p.Reference.
// Blob uploads may run concurrently, but the manifest is published only after
// every layer succeeds.
func Push(ctx context.Context, p Path, files []UploadFile, opts PushOptions) error {
	if p.File != "" {
		return errors.New("acr: push destination must be an artifact, not a file")
	}
	if strings.Contains(p.Reference, ":") {
		return errors.New("acr: push destination must use a tag, not a digest")
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
	if len(files) == 0 {
		return errors.New("acr: no files to push")
	}

	names := make(map[string]struct{}, len(files))
	for i := range files {
		cleaned, err := cleanFile(files[i].Name)
		if err != nil {
			return fmt.Errorf("acr: invalid upload file name %q: %w", files[i].Name, err)
		}
		if _, exists := names[cleaned]; exists {
			return fmt.Errorf("acr: duplicate upload file name %q", cleaned)
		}
		if files[i].Open == nil {
			return fmt.Errorf("acr: upload file %q has no reader", cleaned)
		}
		names[cleaned] = struct{}{}
		files[i].Name = cleaned
	}

	configData := []byte("{}")
	config, err := uploadBlob(ctx, p, UploadFile{
		Name: "config.json",
		Size: int64(len(configData)),
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(configData)), nil
		},
	}, configMediaType, nil)
	if err != nil {
		return fmt.Errorf("acr config upload failed: %w", err)
	}

	layers := make([]descriptor, len(files))
	concurrency := opts.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > len(files) && len(files) > 0 {
		concurrency = len(files)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				layer, err := uploadBlob(workerCtx, p, files[i], layerMediaType, opts.OnProgress)
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("acr layer upload %q failed: %w", files[i].Name, err)
						cancel()
					}
					errMu.Unlock()
					continue
				}
				layer.Annotations = map[string]string{TitleAnnotation: files[i].Name}
				layers[i] = layer
			}
		}()
	}
sendFiles:
	for i := range files {
		select {
		case jobs <- i:
		case <-workerCtx.Done():
			break sendFiles
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	payload, err := json.Marshal(manifest{
		SchemaVersion: 2,
		MediaType:     manifestMediaType,
		Config:        config,
		Layers:        layers,
	})
	if err != nil {
		return err
	}
	manifestURL := registryURL(p.Registry, fmt.Sprintf("/v2/%s/manifests/%s", p.Repository, url.PathEscape(p.Reference)))
	headers := http.Header{"Content-Type": []string{manifestMediaType}}
	if !opts.Overwrite {
		headers.Set("If-None-Match", "*")
	}
	resp, err := authorizedRequest(ctx, p, http.MethodPut, manifestURL, headers,
		fmt.Sprintf("repository:%s:pull,push", p.Repository),
		func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(payload)), nil
		}, int64(len(payload)))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("acr manifest push failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	return nil
}

// ManifestExists reports whether p.Reference currently resolves to a manifest.
func ManifestExists(ctx context.Context, p Path) (bool, error) {
	manifestURL := registryURL(p.Registry, fmt.Sprintf("/v2/%s/manifests/%s", p.Repository, url.PathEscape(p.Reference)))
	resp, err := authorizedRequest(ctx, p, http.MethodHead, manifestURL, http.Header{
		"Accept": []string{strings.Join(manifestAcceptTypes, ", ")},
	}, fmt.Sprintf("repository:%s:pull", p.Repository), nil, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return false, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	default:
		return false, fmt.Errorf("acr manifest check failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
}

type uploadReadCloser struct {
	source     io.ReadCloser
	hasher     hash.Hash
	size       int64
	onProgress func(int64)
}

func (r *uploadReadCloser) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if n > 0 {
		_, _ = r.hasher.Write(p[:n])
		r.size += int64(n)
		if r.onProgress != nil {
			r.onProgress(int64(n))
		}
	}
	return n, err
}

func (r *uploadReadCloser) Close() error {
	return r.source.Close()
}

func uploadBlob(ctx context.Context, p Path, file UploadFile, mediaType string, onProgress func(int64)) (descriptor, error) {
	scope := fmt.Sprintf("repository:%s:pull,push", p.Repository)
	startURL := registryURL(p.Registry, fmt.Sprintf("/v2/%s/blobs/uploads/", p.Repository))
	resp, err := authorizedRequest(ctx, p, http.MethodPost, startURL, nil, scope, nil, 0)
	if err != nil {
		return descriptor{}, err
	}
	location := resp.Header.Get("Location")
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return descriptor{}, fmt.Errorf("acr blob upload start failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	if location == "" {
		return descriptor{}, errors.New("acr blob upload start failed: missing Location header")
	}
	location, err = resolveLocation(startURL, location)
	if err != nil {
		return descriptor{}, err
	}

	var uploaded *uploadReadCloser
	resp, err = authorizedRequest(ctx, p, http.MethodPatch, location, http.Header{
		"Content-Type": []string{"application/octet-stream"},
	}, scope, func() (io.ReadCloser, error) {
		source, err := file.Open()
		if err != nil {
			return nil, err
		}
		uploaded = &uploadReadCloser{
			source:     source,
			hasher:     sha256.New(),
			onProgress: onProgress,
		}
		return uploaded, nil
	}, file.Size)
	if err != nil {
		return descriptor{}, err
	}
	nextLocation := resp.Header.Get("Location")
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return descriptor{}, fmt.Errorf("acr blob upload failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	if uploaded == nil {
		return descriptor{}, errors.New("acr blob upload failed: request body was not read")
	}
	if file.Size >= 0 && uploaded.size != file.Size {
		return descriptor{}, fmt.Errorf("acr blob upload failed: read %d bytes, expected %d", uploaded.size, file.Size)
	}
	if nextLocation != "" {
		location, err = resolveLocation(location, nextLocation)
		if err != nil {
			return descriptor{}, err
		}
	}
	digest := "sha256:" + hex.EncodeToString(uploaded.hasher.Sum(nil))
	completeURL, err := url.Parse(location)
	if err != nil {
		return descriptor{}, err
	}
	query := completeURL.Query()
	query.Set("digest", digest)
	completeURL.RawQuery = query.Encode()
	resp, err = authorizedRequest(ctx, p, http.MethodPut, completeURL.String(), nil, scope, nil, 0)
	if err != nil {
		return descriptor{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return descriptor{}, fmt.Errorf("acr blob upload completion failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	return descriptor{MediaType: mediaType, Digest: digest, Size: uploaded.size}, nil
}

func resolveLocation(base, location string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return baseURL.ResolveReference(locationURL).String(), nil
}

type downloadReadCloser struct {
	io.ReadCloser
	size int64
}

// Size reports the blob size or -1 if unknown.
func (d downloadReadCloser) Size() int64 {
	return d.size
}

// fetchLayers returns the layers of the manifest referenced by reference,
// recursively merging the layers of every manifest referenced by an image
// index. Layers with a digest that was already collected are skipped.
func fetchLayers(ctx context.Context, p Path, reference string, depth int) ([]descriptor, error) {
	m, err := fetchManifest(ctx, p, reference, depth)
	if err != nil {
		return nil, err
	}
	if len(m.Layers) > 0 || len(m.Manifests) == 0 {
		return m.Layers, nil
	}
	var layers []descriptor
	seen := map[string]struct{}{}
	for _, child := range m.Manifests {
		if child.Digest == "" {
			continue
		}
		childLayers, err := fetchLayers(ctx, p, child.Digest, depth+1)
		if err != nil {
			return nil, err
		}
		for _, layer := range childLayers {
			if _, dup := seen[layer.Digest]; dup {
				continue
			}
			seen[layer.Digest] = struct{}{}
			layers = append(layers, layer)
		}
	}
	return layers, nil
}

func fetchManifest(ctx context.Context, p Path, reference string, depth int) (*manifest, error) {
	if depth > maxIndexDepth {
		return nil, errors.New("acr: too many nested image indexes")
	}
	if p.Repository == "" {
		return nil, errors.New("acr: missing repository")
	}
	manifestURL := registryURL(p.Registry, fmt.Sprintf("/v2/%s/manifests/%s", p.Repository, url.PathEscape(reference)))
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
	return &m, nil
}

func authorizedGet(ctx context.Context, p Path, target string, header http.Header) (*http.Response, error) {
	return authorizedRequest(ctx, p, http.MethodGet, target, header,
		fmt.Sprintf("repository:%s:pull", p.Repository), nil, 0)
}

func authorizedRequest(
	ctx context.Context,
	p Path,
	method string,
	target string,
	header http.Header,
	scope string,
	bodyFactory func() (io.ReadCloser, error),
	contentLength int64,
) (*http.Response, error) {
	newRequest := func() (*http.Request, error) {
		var body io.ReadCloser
		var err error
		if bodyFactory != nil {
			body, err = bodyFactory()
			if err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			if body != nil {
				_ = body.Close()
			}
			return nil, err
		}
		if body != nil && contentLength >= 0 {
			req.ContentLength = contentLength
		}
		for k, values := range header {
			for _, v := range values {
				req.Header.Add(k, v)
			}
		}
		return req, nil
	}
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
	storeToken(p.Registry, scope, token)
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
		realm = registryURL(registry, "/oauth2/token")
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
	var lastErr error
	for _, audience := range aadScopes {
		aadToken, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{audience}})
		if err != nil {
			lastErr = err
			slog.Debug("acr: Entra ID token request failed", "audience", audience, "error", err)
			continue
		}
		refreshToken, err := postForm(ctx, registryURL(registry, "/oauth2/exchange"), url.Values{
			"grant_type":   {"access_token"},
			"service":      {service},
			"access_token": {aadToken.Token},
		}, "refresh_token")
		if err != nil {
			lastErr = err
			slog.Debug("acr: registry token exchange failed", "audience", audience, "error", err)
			continue
		}
		return postForm(ctx, realm, url.Values{
			"grant_type":    {"refresh_token"},
			"service":       {service},
			"scope":         {scope},
			"refresh_token": {refreshToken},
		}, "access_token")
	}
	if lastErr == nil {
		lastErr = errors.New("acr: no Entra ID audience configured")
	}
	return "", lastErr
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
			opts.Transport = c
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
