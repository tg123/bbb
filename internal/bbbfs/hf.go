package bbbfs

import (
	"context"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/tg123/bbb/internal/hf"
)

type hfFS struct{}

const hfUnknownSize = int64(0)

func (hfFS) Match(path string) bool {
	return IsHF(path)
}

func (hfFS) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	hp, err := hf.Parse(path)
	if err != nil {
		return nil, err
	}
	return hf.DownloadStream(ctx, hp)
}

func (hfFS) Write(ctx context.Context, path string, r io.Reader) error {
	return ErrWriteUnsupported
}

func (hfFS) List(ctx context.Context, target string) ([]Entry, error) {
	hp, err := hf.Parse(target)
	if err != nil {
		return nil, err
	}
	hp.File = hfListPrefix(hp.File)
	files, err := hf.ListFiles(ctx, hf.Path{Repo: hp.Repo})
	if err != nil {
		return nil, err
	}
	entries := hfListEntries(files, hp.File)
	out := make([]Entry, 0, len(entries))
	for _, name := range entries {
		trimmed := strings.TrimSuffix(name, "/")
		if trimmed == "" {
			continue
		}
		fullFile := path.Join(hp.File, trimmed)
		fullpath := hf.Path{Repo: hp.Repo, File: fullFile}.String()
		out = append(out, Entry{
			Name:    name,
			Path:    fullpath,
			Size:    hfUnknownSize, // HF API list doesn't expose size/modtime.
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	}
	return out, nil
}

func (hfFS) ListRecursive(ctx context.Context, target string) ([]Entry, error) {
	hp, err := hf.Parse(target)
	if err != nil {
		return nil, err
	}
	hp.File = hfListPrefix(hp.File)
	files, err := hf.ListFiles(ctx, hf.Path{Repo: hp.Repo})
	if err != nil {
		return nil, err
	}
	list := hfFilterFiles(files, hp.File)
	sort.Strings(list)
	out := make([]Entry, 0, len(list))
	for _, name := range list {
		if name == "" {
			continue
		}
		fullFile := path.Join(hp.File, name)
		fullpath := hf.Path{Repo: hp.Repo, File: fullFile}.String()
		out = append(out, Entry{
			Name:    name,
			Path:    fullpath,
			Size:    hfUnknownSize, // HF API list doesn't expose size/modtime.
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	}
	return out, nil
}

func (hfFS) Stat(ctx context.Context, target string) (Entry, error) {
	hp, err := hf.Parse(target)
	if err != nil {
		return Entry{}, err
	}
	if hp.File == "" || strings.HasSuffix(hp.File, "/") {
		name := pathBase(hp.File)
		return Entry{
			Name:    name,
			Path:    hp.String(),
			IsDir:   true,
			ModTime: time.Time{},
		}, nil
	}
	return Entry{
		Name:    path.Base(hp.File),
		Path:    hp.String(),
		Size:    hfUnknownSize, // HF API doesn't expose size/modtime for single file metadata.
		IsDir:   false,
		ModTime: time.Time{},
	}, nil
}

// HFFilterFiles exposes HF filtering for tests/shared logic.
func HFFilterFiles(files []string, prefix string) []string {
	return hfFilterFiles(files, prefix)
}

// HFListEntries exposes HF entry listing for tests/shared logic.
func HFListEntries(files []string, prefix string) []string {
	return hfListEntries(files, prefix)
}

func normalizeHFPrefix(prefix string) string {
	for strings.HasPrefix(prefix, "/") {
		prefix = strings.TrimPrefix(prefix, "/")
	}
	if prefix == "" {
		return ""
	}
	prefix = path.Clean(prefix)
	if prefix == "." {
		return ""
	}
	return prefix
}

func hfListPrefix(prefix string) string {
	prefix = normalizeHFPrefix(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix
}

func hfFilterFiles(files []string, prefix string) []string {
	prefix = normalizeHFPrefix(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	out := make([]string, 0, len(files))
	for _, file := range files {
		if file == "" {
			continue
		}
		if prefix != "" {
			if !strings.HasPrefix(file, prefix) {
				continue
			}
			file = strings.TrimPrefix(file, prefix)
			if file == "" {
				continue
			}
		}
		out = append(out, file)
	}
	return out
}

func hfListEntries(files []string, prefix string) []string {
	seen := map[string]struct{}{}
	for _, file := range hfFilterFiles(files, prefix) {
		parts := strings.SplitN(file, "/", 2)
		name := parts[0]
		if name == "" {
			continue
		}
		if len(parts) > 1 {
			name += "/"
		}
		seen[name] = struct{}{}
	}
	entries := make([]string, 0, len(seen))
	for name := range seen {
		entries = append(entries, name)
	}
	sort.Strings(entries)
	return entries
}

// NormalizeHFPrefix exposes HF prefix normalization for tests/shared logic.
func NormalizeHFPrefix(prefix string) string {
	return normalizeHFPrefix(prefix)
}
