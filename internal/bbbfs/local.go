package bbbfs

import (
	"context"
	"io"
	"os"
	"path/filepath"
)

type localFS struct{}

func (localFS) Match(path string) bool {
	return true
}

func (localFS) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (localFS) Write(ctx context.Context, path string, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeLocal(path, r)
}

func (localFS) List(ctx context.Context, path string) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		path = "."
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{
			Name:    name,
			Path:    name,
			Size:    info.Size(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime(),
		})
	}
	return out, nil
}

func (localFS) ListRecursive(ctx context.Context, path string) ([]Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if path == "" {
		path = "."
	}
	out := []Entry{}
	err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(path, p)
		if err != nil {
			return err
		}
		out = append(out, Entry{
			Name:    rel,
			Path:    p,
			Size:    info.Size(),
			IsDir:   info.IsDir(),
			ModTime: info.ModTime(),
		})
		return nil
	})
	return out, err
}

func (localFS) Stat(ctx context.Context, path string) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    filepath.Base(path),
		Path:    path,
		Size:    info.Size(),
		IsDir:   info.IsDir(),
		ModTime: info.ModTime(),
	}, nil
}

func writeLocal(path string, r io.Reader) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	dstFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dstFile.Close(); err == nil {
			err = closeErr
		}
	}()
	_, err = io.Copy(dstFile, r)
	return err
}
