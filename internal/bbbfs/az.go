package bbbfs

import (
	"context"
	"io"
	"path"
	"strings"
	"time"

	"github.com/tg123/bbb/internal/azblob"
)

type azFS struct{}

func (azFS) Match(path string) bool {
	return IsAz(path)
}

func (azFS) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	ap, err := azblob.Parse(path)
	if err != nil {
		return nil, err
	}
	return azblob.DownloadStream(ctx, ap)
}

func (azFS) Write(ctx context.Context, path string, r io.Reader) error {
	ap, err := azblob.Parse(path)
	if err != nil {
		return err
	}
	return azblob.UploadStream(ctx, ap, r)
}

func (azFS) List(ctx context.Context, path string) ([]Entry, error) {
	ap, err := azblob.Parse(path)
	if err != nil {
		return nil, err
	}
	list, err := azblob.List(ctx, ap)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(list))
	for _, bm := range list {
		name := bm.Name
		if name == "" {
			continue
		}
		entries = append(entries, Entry{
			Name:    name,
			Path:    azChildPath(ap, name),
			Size:    bm.Size,
			IsDir:   strings.HasSuffix(name, "/") || (bm.Size == 0 && strings.HasSuffix(ap.Blob, "/")) || ap.Container == "",
			ModTime: time.Time{},
		})
	}
	return entries, nil
}

func (azFS) ListRecursive(ctx context.Context, path string) ([]Entry, error) {
	ap, err := azblob.Parse(path)
	if err != nil {
		return nil, err
	}
	list, err := azblob.ListRecursive(ctx, ap)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(list))
	for _, bm := range list {
		name := bm.Name
		if name == "" || strings.HasSuffix(name, "/") {
			continue
		}
		full := ap.Child(name).String()
		entries = append(entries, Entry{
			Name:    name,
			Path:    full,
			Size:    bm.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	}
	return entries, nil
}

func (azFS) Stat(ctx context.Context, target string) (Entry, error) {
	ap, err := azblob.Parse(target)
	if err != nil {
		return Entry{}, err
	}
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return Entry{
			Name:    pathBase(ap.Blob),
			Path:    ap.String(),
			IsDir:   true,
			ModTime: time.Time{},
		}, nil
	}
	size, err := azblob.HeadBlob(ctx, ap)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    path.Base(ap.Blob),
		Path:    ap.String(),
		Size:    size,
		IsDir:   false,
		ModTime: time.Time{},
	}, nil
}

func azChildPath(ap azblob.AzurePath, name string) string {
	trimmed := strings.TrimSuffix(name, "/")
	if ap.Container == "" || ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return ap.Child(trimmed).String()
	}
	return ap.Child(path.Join(ap.Blob, trimmed)).String()
}

func pathBase(name string) string {
	if name == "" {
		return ""
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" {
		return ""
	}
	return path.Base(trimmed)
}
