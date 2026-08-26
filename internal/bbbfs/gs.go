package bbbfs

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gspkg "github.com/tg123/bbb/internal/gs"
)

type gsFS struct{}

func (gsFS) Match(p string) bool {
	return strings.HasPrefix(p, gspkg.Scheme)
}

func (gsFS) Read(ctx context.Context, p string) (io.ReadCloser, error) {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return nil, err
	}
	return gspkg.DownloadStream(ctx, gp)
}

func (gsFS) Write(ctx context.Context, p string, r io.Reader) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	return gspkg.UploadStream(ctx, gp, r, UploadConcurrency(ctx))
}

// DownloadToFile downloads the object at src into localPath using parallel
// ranged reads.
func (gsFS) DownloadToFile(ctx context.Context, src, localPath string, concurrency int, onProgress func(int64)) (int64, error) {
	gp, err := gspkg.Parse(src)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		return 0, err
	}
	f, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, err
	}
	n, downloadErr := gspkg.DownloadFile(ctx, gp, f, concurrency, onProgress)
	closeErr := f.Close()
	if downloadErr != nil {
		return n, downloadErr
	}
	return n, closeErr
}

// UploadFromFile uploads localPath to the object at dst.
func (gsFS) UploadFromFile(ctx context.Context, localPath, dst string, concurrency int, onProgress func(int64)) (int64, error) {
	gp, err := gspkg.Parse(dst)
	if err != nil {
		return 0, err
	}
	f, err := os.Open(localPath)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()
	var uploaded atomic.Int64
	tracker := func(n int64) {
		for {
			cur := uploaded.Load()
			if n <= cur || uploaded.CompareAndSwap(cur, n) {
				break
			}
		}
		if onProgress != nil {
			onProgress(n)
		}
	}
	if err := gspkg.UploadFile(ctx, gp, f, concurrency, tracker); err != nil {
		return uploaded.Load(), err
	}
	return uploaded.Load(), nil
}

func (gsFS) List(ctx context.Context, p string) ([]Entry, error) {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return nil, err
	}
	list, err := gspkg.List(ctx, gp)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(list))
	for _, om := range list {
		name := om.Name
		if name == "" {
			continue
		}
		entries = append(entries, Entry{
			Name:    name,
			Path:    gsChildPath(gp, name),
			Size:    om.Size,
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	}
	return entries, nil
}

func (gsFS) Stat(ctx context.Context, target string) (Entry, error) {
	gp, err := gspkg.Parse(target)
	if err != nil {
		return Entry{}, err
	}
	if gp.Object == "" || strings.HasSuffix(gp.Object, "/") {
		return Entry{
			Name:    pathBase(gp.Object),
			Path:    gp.String(),
			IsDir:   true,
			ModTime: time.Time{},
		}, nil
	}
	size, err := gspkg.HeadObject(ctx, gp)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    path.Base(gp.Object),
		Path:    gp.String(),
		Size:    size,
		IsDir:   false,
		ModTime: time.Time{},
	}, nil
}

func gsChildPath(gp gspkg.GSPath, name string) string {
	trimmed := strings.TrimSuffix(name, "/")
	return gp.Child(trimmed).String()
}

func (gsFS) IsDirLike(_ context.Context, p string) (bool, error) {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return false, err
	}
	return gp.IsDirLike(), nil
}

func (gsFS) IsDirLikeFromPath(p string) bool {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return false
	}
	return gp.IsDirLike()
}

func (gsFS) ChildPath(parent, child string) string {
	gp, err := gspkg.Parse(parent)
	if err != nil {
		return parent + "/" + child
	}
	return gp.Child(filepath.ToSlash(child)).String()
}

func (gsFS) BaseName(p string) string {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return path.Base(p)
	}
	if gp.Object != "" {
		return path.Base(gp.Object)
	}
	return gp.Bucket
}

func (gsFS) Delete(ctx context.Context, p string) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	return gspkg.Delete(ctx, gp)
}

func (gsFS) Touch(ctx context.Context, p string) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	return gspkg.Touch(ctx, gp)
}

func (gsFS) MkDir(ctx context.Context, p string) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	if gp.Bucket == "" {
		return fmt.Errorf("bucket name is required")
	}
	return gspkg.MkBucket(ctx, gp.Bucket)
}

func (gsFS) ListStream(ctx context.Context, p string, fn func(Entry) error) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	return gspkg.ListStream(ctx, gp, func(om gspkg.ObjectMeta) error {
		name := om.Name
		if name == "" {
			return nil
		}
		return fn(Entry{
			Name:    name,
			Path:    gsChildPath(gp, name),
			Size:    om.Size,
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	})
}

func (gsFS) ListRecursive(ctx context.Context, target string, emit func(Entry) error) error {
	gp, err := gspkg.Parse(target)
	if err != nil {
		return err
	}
	return gspkg.ListRecursiveStream(ctx, gp, func(om gspkg.ObjectMeta) error {
		return emit(Entry{
			Name:    om.Name,
			Path:    gsChildPath(gp, om.Name),
			Size:    om.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	})
}

func (gsFS) ListRecursiveWithSizeStream(ctx context.Context, p string, emit func(Entry) error) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	return gspkg.ListRecursiveStream(ctx, gp, func(om gspkg.ObjectMeta) error {
		return emit(Entry{
			Name:    om.Name,
			Path:    gsChildPath(gp, om.Name),
			Size:    om.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	})
}

func (f gsFS) ListRecursiveWithSize(ctx context.Context, p string) ([]Entry, error) {
	var mu sync.Mutex
	var entries []Entry
	if err := f.ListRecursiveWithSizeStream(ctx, p, func(e Entry) error {
		mu.Lock()
		entries = append(entries, e)
		mu.Unlock()
		return nil
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

func (gsFS) ListFilesFlat(ctx context.Context, p string) ([]string, error) {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return nil, err
	}
	var names []string
	if err := gspkg.ListRecursiveStream(ctx, gp, func(om gspkg.ObjectMeta) error {
		names = append(names, om.Name)
		return nil
	}); err != nil {
		return nil, err
	}
	return names, nil
}

func (gsFS) ResolveDstPath(dst, base string, mustBeDir bool) (string, error) {
	dp, err := gspkg.Parse(dst)
	if err != nil {
		return "", err
	}
	if mustBeDir && dp.Object != "" && !strings.HasSuffix(dp.Object, "/") {
		dp.Object += "/"
	}
	if dp.Object == "" || strings.HasSuffix(dp.Object, "/") {
		if dp.Object == "" {
			dp.Object = base
		} else {
			dp.Object = strings.TrimSuffix(dp.Object, "/") + "/" + base
		}
		return dp.String(), nil
	}
	if mustBeDir {
		return "", fmt.Errorf("destination must be a directory")
	}
	return dst, nil
}

func (gsFS) CopyServerSide(ctx context.Context, src, dst string, concurrency int, sizeHint int64, onProgress CopyProgress) error {
	srcGP, err := gspkg.Parse(src)
	if err != nil {
		return err
	}
	dstGP, err := gspkg.Parse(dst)
	if err != nil {
		return err
	}
	return gspkg.CopyServerSide(ctx, srcGP, dstGP, concurrency, sizeHint, onProgress)
}

func (gsFS) DeletePrefix(ctx context.Context, p string) error {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return err
	}
	return gspkg.DeletePrefix(ctx, gp)
}

func (gsFS) ShareInfo(p string) (portal, direct string, err error) {
	gp, err := gspkg.Parse(p)
	if err != nil {
		return "", "", err
	}
	// Object names are opaque and may contain spaces, '#', '?', '%', etc.
	// Escape each path segment (preserving '/' separators) for URL paths, and
	// query-escape the console prefix parameter, so links are always valid.
	escapedPath := escapeS3KeyPath(gp.Object)
	if ep := gspkg.Endpoint(); ep != "" {
		base := strings.TrimRight(ep, "/")
		direct = joinURLPath(base+"/"+gp.Bucket, escapedPath)
		// Emulators have no web console, so surface the object URL for both.
		return direct, direct, nil
	}
	portal = "https://console.cloud.google.com/storage/browser/" + gp.Bucket
	if gp.Object != "" {
		portal += "?prefix=" + url.QueryEscape(gp.Object)
	}
	direct = joinURLPath("https://storage.googleapis.com/"+gp.Bucket, escapedPath)
	return portal, direct, nil
}
