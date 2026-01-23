package hf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
)

// Path represents a Hugging Face repository or file.
type Path struct {
	Repo string // owner/name
	File string // optional file path within repo
}

// Parse parses hf://owner/repo[/file] paths.
func Parse(raw string) (Path, error) {
	if !strings.HasPrefix(raw, "hf://") {
		return Path{}, errors.New("expected hf://owner/repo[/file]")
	}
	rest := strings.TrimPrefix(raw, "hf://")
	if rest == "" {
		return Path{}, errors.New("expected hf://owner/repo[/file]")
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return Path{}, errors.New("expected hf://owner/repo[/file]")
	}
	p := Path{Repo: parts[0] + "/" + parts[1]}
	if len(parts) == 3 {
		p.File = strings.TrimPrefix(parts[2], "/")
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
	return repo + ".zip"
}

// URL returns the download URL for the path.
func (p Path) URL() (string, error) {
	if p.Repo == "" {
		return "", errors.New("missing repo")
	}
	if p.File == "" {
		return fmt.Sprintf("https://huggingface.co/%s/archive/main.zip", p.Repo), nil
	}
	return fmt.Sprintf("https://huggingface.co/%s/resolve/main/%s", p.Repo, path.Clean(p.File)), nil
}

// Download retrieves the Hugging Face repo archive or file.
func Download(ctx context.Context, p Path) ([]byte, error) {
	url, err := p.URL()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("hf download failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
