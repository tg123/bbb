package bbbfs

import (
	"context"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tg123/bbb/internal/acr"
)

type acrFS struct{}

func (acrFS) Match(p string) bool {
	return strings.HasPrefix(p, ACRScheme)
}

func (acrFS) Read(ctx context.Context, p string) (io.ReadCloser, error) {
	ap, err := acr.Parse(p)
	if err != nil {
		return nil, err
	}
	return acr.DownloadStream(ctx, ap)
}

func (acrFS) Write(_ context.Context, _ string, _ io.Reader) error {
	return ErrWriteUnsupported
}

func (acrFS) List(ctx context.Context, target string) ([]Entry, error) {
	ap, err := acr.Parse(target)
	if err != nil {
		return nil, err
	}
	prefix := ap.File
	ap.File = ""
	files, err := acr.ListFiles(ctx, ap)
	if err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
		sizes[f.Name] = f.Size
	}
	entries := hfListEntries(names, prefix)
	out := make([]Entry, 0, len(entries))
	for _, name := range entries {
		trimmed := strings.TrimSuffix(name, "/")
		if trimmed == "" {
			continue
		}
		fullFile := path.Join(prefix, trimmed)
		isDir := strings.HasSuffix(name, "/")
		child := ap
		child.File = fullFile
		out = append(out, Entry{
			Name:  name,
			Path:  child.String(),
			Size:  sizes[fullFile],
			IsDir: isDir,
		})
	}
	return out, nil
}

func (acrFS) Stat(ctx context.Context, target string) (Entry, error) {
	ap, err := acr.Parse(target)
	if err != nil {
		return Entry{}, err
	}
	if ap.File == "" {
		return Entry{
			Name:  ap.DefaultFilename(),
			Path:  ap.String(),
			IsDir: true,
		}, nil
	}
	file, err := acr.Stat(ctx, ap)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    path.Base(file.Name),
		Path:    ap.String(),
		Size:    file.Size,
		IsDir:   false,
		ModTime: time.Time{},
	}, nil
}

func (acrFS) ListRecursive(ctx context.Context, target string, emit func(Entry) error) error {
	ap, err := acr.Parse(target)
	if err != nil {
		return err
	}
	prefix := ap.File
	ap.File = ""
	files, err := acr.ListFiles(ctx, ap)
	if err != nil {
		return err
	}
	sizes := map[string]int64{}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
		sizes[f.Name] = f.Size
	}
	filtered := hfFilterFiles(names, prefix)
	sort.Strings(filtered)
	for _, name := range filtered {
		if name == "" {
			continue
		}
		fullFile := path.Join(prefix, name)
		child := ap
		child.File = fullFile
		if err := emit(Entry{
			Name:  name,
			Path:  child.String(),
			Size:  sizes[fullFile],
			IsDir: false,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (acrFS) IsDirLike(_ context.Context, p string) (bool, error) {
	ap, err := acr.Parse(p)
	if err != nil {
		return false, err
	}
	return ap.File == "", nil
}

func (acrFS) IsDirLikeFromPath(p string) bool {
	ap, err := acr.Parse(p)
	if err != nil {
		return false
	}
	return ap.File == ""
}

func (acrFS) ChildPath(parent, child string) string {
	ap, err := acr.Parse(parent)
	if err != nil {
		return parent + "/" + child
	}
	child = filepath.ToSlash(child) // normalize Windows backslash separators
	if ap.File == "" {
		ap.File = child
	} else {
		ap.File = path.Join(ap.File, child)
	}
	return ap.String()
}

func (acrFS) BaseName(p string) string {
	ap, err := acr.Parse(p)
	if err != nil {
		return path.Base(p)
	}
	return ap.DefaultFilename()
}

func (acrFS) ListFilesFlat(ctx context.Context, p string) ([]string, error) {
	ap, err := acr.Parse(p)
	if err != nil {
		return nil, err
	}
	if ap.File != "" {
		return nil, fmt.Errorf("acr:// path must target an artifact, not individual files")
	}
	files, err := acr.ListFiles(ctx, ap)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	return names, nil
}
