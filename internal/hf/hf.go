package hf

import (
	"context"
	"encoding/json"
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

func (p Path) String() string {
	if p.File == "" {
		return "hf://" + p.Repo
	}
	return "hf://" + p.Repo + "/" + p.File
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
		p.File = parts[2]
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
	cleaned, err := cleanFile(p.File)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://huggingface.co/%s/resolve/main/%s", p.Repo, cleaned), nil
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hf download failed: %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ListFiles retrieves repo files for directory-like paths.
func ListFiles(ctx context.Context, p Path) ([]string, error) {
	if p.Repo == "" {
		return nil, errors.New("missing repo")
	}
	if p.File != "" {
		return nil, errors.New("path is not directory-like")
	}
	url := fmt.Sprintf("https://huggingface.co/api/models/%s?blobs=true", p.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("hf list failed: %s", resp.Status)
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
