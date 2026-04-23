package hf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
)

// sharedClient holds an optional *http.Client used by the hf package.
// When set via SetHTTPClient it overrides http.DefaultClient for all
// requests, ensuring features like DNS pinning/caching configured at
// program startup apply to Hugging Face traffic too.
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

var doRequest = func(req *http.Request) (*http.Response, error) {
	if c := sharedClient.Load(); c != nil {
		return c.Do(req)
	}
	return http.DefaultClient.Do(req)
}

// HTTPStatusError is returned when an HTTP request returns a non-2xx status code.
type HTTPStatusError struct {
	StatusCode int
	Status     string
}

func (e *HTTPStatusError) Error() string {
	return e.Status
}

// Path represents a Hugging Face repository or file.
type Path struct {
	Repo string // owner/name
	File string // optional file path within repo
}

func (p Path) String() string {
	if p.File == "" {
		return "hf://" + p.Repo
	}
	return "hf://" + p.Repo + "/" + p.File
}

// Parse parses hf://owner/repo[/file] and hf://datasets/owner/repo[/file] paths.
func Parse(raw string) (Path, error) {
	const expectedPathErr = "expected hf://owner/repo[/file] or hf://datasets/owner/repo[/file]"
	if !strings.HasPrefix(raw, "hf://") {
		return Path{}, errors.New(expectedPathErr)
	}
	rest := strings.TrimPrefix(raw, "hf://")
	if rest == "" {
		return Path{}, errors.New(expectedPathErr)
	}
	parts := strings.Split(rest, "/")
	repoParts := 2
	if parts[0] == "datasets" {
		repoParts = 3
	}
	if len(parts) < repoParts {
		return Path{}, errors.New(expectedPathErr)
	}
	for _, part := range parts[:repoParts] {
		if part == "" {
			return Path{}, errors.New(expectedPathErr)
		}
	}
	p := Path{Repo: strings.Join(parts[:repoParts], "/")}
	if len(parts) > repoParts {
		p.File = strings.Join(parts[repoParts:], "/")
	}
	return p, nil
}

// DefaultFilename returns the filename to use when writing this path to a directory.
func (p Path) DefaultFilename() string {
	if p.File != "" {
		return path.Base(p.File)
	}
	repo := p.Repo
	if idx := strings.LastIndex(repo, "/"); idx >= 0 {
		repo = repo[idx+1:]
	}
	return repo
}

// URL returns the download URL for the path.
func (p Path) URL() (string, error) {
	if p.Repo == "" {
		return "", errors.New("missing repo")
	}
	if p.File == "" {
		return "", errors.New("missing file path")
	}
	escaped, err := escapeFilePath(p.File)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://huggingface.co/%s/resolve/main/%s", p.Repo, escaped), nil
}

// Download retrieves the contents of a file in a Hugging Face repository.
func Download(ctx context.Context, p Path) ([]byte, error) {
	rc, err := DownloadStream(ctx, p)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = rc.Close()
	}()
	return io.ReadAll(rc)
}

func DownloadStream(ctx context.Context, p Path) (io.ReadCloser, error) {
	downloadURL, err := p.URL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("hf download failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	return downloadReadCloser{
		ReadCloser: resp.Body,
		size:       resp.ContentLength,
	}, nil
}

type downloadReadCloser struct {
	io.ReadCloser
	size int64
}

// Size reports the HTTP Content-Length or -1 if unknown.
func (d downloadReadCloser) Size() int64 {
	return d.size
}

// ListFiles retrieves repo files for directory-like paths.
func ListFiles(ctx context.Context, p Path) ([]string, error) {
	if p.Repo == "" {
		return nil, errors.New("missing repo")
	}
	if p.File != "" {
		return nil, errors.New("path is not directory-like")
	}
	apiURL := fmt.Sprintf("https://huggingface.co/api/models/%s?blobs=true", p.Repo)
	if strings.HasPrefix(p.Repo, "datasets/") {
		apiURL = fmt.Sprintf("https://huggingface.co/api/datasets/%s?blobs=true", strings.TrimPrefix(p.Repo, "datasets/"))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := doRequest(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hf list failed: %w", &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status})
	}
	var payload struct {
		Siblings []struct {
			Name string `json:"rfilename"`
		} `json:"siblings"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	files := make([]string, 0, len(payload.Siblings))
	for _, entry := range payload.Siblings {
		if entry.Name == "" {
			continue
		}
		cleaned, err := cleanFile(entry.Name)
		if err != nil {
			return nil, err
		}
		files = append(files, cleaned)
	}
	return files, nil
}

func escapeFilePath(file string) (string, error) {
	cleaned, err := cleanFile(file)
	if err != nil {
		return "", err
	}
	parts := strings.Split(cleaned, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/"), nil
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
