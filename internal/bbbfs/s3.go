package bbbfs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	s3pkg "github.com/tg123/bbb/internal/s3"
)

type s3FS struct{}

func (s3FS) Match(p string) bool {
	return strings.HasPrefix(p, s3pkg.Scheme)
}

func (s3FS) Read(ctx context.Context, p string) (io.ReadCloser, error) {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return nil, err
	}
	return s3pkg.DownloadStream(ctx, sp)
}

func (s3FS) Write(ctx context.Context, p string, r io.Reader) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	return s3pkg.UploadStream(ctx, sp, r, UploadConcurrency(ctx))
}

// DownloadToFile downloads the object at src into localPath using the S3
// transfer manager's parallel ranged GETs.
func (s3FS) DownloadToFile(ctx context.Context, src, localPath string, concurrency int, onProgress func(int64)) (int64, error) {
	sp, err := s3pkg.Parse(src)
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
	n, downloadErr := s3pkg.DownloadFile(ctx, sp, f, concurrency, onProgress)
	closeErr := f.Close()
	if downloadErr != nil {
		return n, downloadErr
	}
	return n, closeErr
}

// UploadFromFile uploads localPath to the object at dst using the S3 transfer
// manager's parallel multipart upload.
func (s3FS) UploadFromFile(ctx context.Context, localPath, dst string, concurrency int, onProgress func(int64)) (int64, error) {
	sp, err := s3pkg.Parse(dst)
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
	if err := s3pkg.UploadFile(ctx, sp, f, concurrency, tracker); err != nil {
		return uploaded.Load(), err
	}
	return uploaded.Load(), nil
}

func (s3FS) List(ctx context.Context, p string) ([]Entry, error) {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return nil, err
	}
	list, err := s3pkg.List(ctx, sp)
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
			Path:    s3ChildPath(sp, name),
			Size:    om.Size,
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	}
	return entries, nil
}

func (s3FS) Stat(ctx context.Context, target string) (Entry, error) {
	sp, err := s3pkg.Parse(target)
	if err != nil {
		return Entry{}, err
	}
	if sp.Key == "" || strings.HasSuffix(sp.Key, "/") {
		return Entry{
			Name:    pathBase(sp.Key),
			Path:    sp.String(),
			IsDir:   true,
			ModTime: time.Time{},
		}, nil
	}
	size, err := s3pkg.HeadObject(ctx, sp)
	if err != nil {
		return Entry{}, err
	}
	return Entry{
		Name:    path.Base(sp.Key),
		Path:    sp.String(),
		Size:    size,
		IsDir:   false,
		ModTime: time.Time{},
	}, nil
}

func s3ChildPath(sp s3pkg.S3Path, name string) string {
	trimmed := strings.TrimSuffix(name, "/")
	return sp.Child(trimmed).String()
}

func (s3FS) IsDirLike(_ context.Context, p string) (bool, error) {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return false, err
	}
	return sp.IsDirLike(), nil
}

func (s3FS) IsDirLikeFromPath(p string) bool {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return false
	}
	return sp.IsDirLike()
}

func (s3FS) ChildPath(parent, child string) string {
	sp, err := s3pkg.Parse(parent)
	if err != nil {
		return parent + "/" + child
	}
	return sp.Child(filepath.ToSlash(child)).String()
}

func (s3FS) BaseName(p string) string {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return path.Base(p)
	}
	if sp.Key != "" {
		return path.Base(sp.Key)
	}
	return sp.Bucket
}

func (s3FS) Delete(ctx context.Context, p string) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	return s3pkg.Delete(ctx, sp)
}

func (s3FS) Touch(ctx context.Context, p string) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	return s3pkg.Touch(ctx, sp)
}

func (s3FS) MkDir(ctx context.Context, p string) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	if sp.Bucket == "" {
		return fmt.Errorf("bucket name is required")
	}
	return s3pkg.MkBucket(ctx, sp.Bucket)
}

func (s3FS) ListStream(ctx context.Context, p string, fn func(Entry) error) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	return s3pkg.ListStream(ctx, sp, func(om s3pkg.ObjectMeta) error {
		name := om.Name
		if name == "" {
			return nil
		}
		return fn(Entry{
			Name:    name,
			Path:    s3ChildPath(sp, name),
			Size:    om.Size,
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	})
}

func (s3FS) ListRecursive(ctx context.Context, target string, emit func(Entry) error) error {
	sp, err := s3pkg.Parse(target)
	if err != nil {
		return err
	}
	return s3pkg.ListRecursiveStream(ctx, sp, func(om s3pkg.ObjectMeta) error {
		name := om.Name
		if name == "" || strings.HasSuffix(name, "/") {
			return nil
		}
		return emit(Entry{
			Name:    name,
			Path:    s3ChildPath(sp, name),
			Size:    om.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	})
}

func (s3FS) ListRecursiveWithSizeStream(ctx context.Context, p string, emit func(Entry) error) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	return s3pkg.ListRecursiveStream(ctx, sp, func(om s3pkg.ObjectMeta) error {
		name := om.Name
		if name == "" || strings.HasSuffix(name, "/") {
			return nil
		}
		return emit(Entry{
			Name:    name,
			Path:    s3ChildPath(sp, name),
			Size:    om.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	})
}

func (f s3FS) ListRecursiveWithSize(ctx context.Context, p string) ([]Entry, error) {
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

func (s3FS) ListFilesFlat(ctx context.Context, p string) ([]string, error) {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return nil, err
	}
	var names []string
	if err := s3pkg.ListRecursiveStream(ctx, sp, func(om s3pkg.ObjectMeta) error {
		if om.Name == "" || strings.HasSuffix(om.Name, "/") {
			return nil
		}
		names = append(names, om.Name)
		return nil
	}); err != nil {
		return nil, err
	}
	return names, nil
}

func (s3FS) ResolveDstPath(dst, base string, mustBeDir bool) (string, error) {
	dp, err := s3pkg.Parse(dst)
	if err != nil {
		return "", err
	}
	if mustBeDir && dp.Key != "" && !strings.HasSuffix(dp.Key, "/") {
		dp.Key += "/"
	}
	if dp.Key == "" || strings.HasSuffix(dp.Key, "/") {
		if dp.Key == "" {
			dp.Key = base
		} else {
			dp.Key = strings.TrimSuffix(dp.Key, "/") + "/" + base
		}
		return dp.String(), nil
	}
	if mustBeDir {
		return "", fmt.Errorf("destination must be a directory")
	}
	return dst, nil
}

func (s3FS) CopyServerSide(ctx context.Context, src, dst string, concurrency int, sizeHint int64, onProgress CopyProgress) error {
	srcSP, err := s3pkg.Parse(src)
	if err != nil {
		return err
	}
	dstSP, err := s3pkg.Parse(dst)
	if err != nil {
		return err
	}
	return s3pkg.CopyServerSide(ctx, srcSP, dstSP, concurrency, sizeHint, onProgress)
}

func (s3FS) DeletePrefix(ctx context.Context, p string) error {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return err
	}
	return s3pkg.DeletePrefix(ctx, sp)
}

func (s3FS) ShareInfo(p string) (portal, direct string, err error) {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return "", "", err
	}
	portal = fmt.Sprintf("https://s3.console.aws.amazon.com/s3/object/%s?prefix=%s", sp.Bucket, sp.Key)
	direct = fmt.Sprintf("https://%s.s3.amazonaws.com/%s", sp.Bucket, sp.Key)
	return portal, direct, nil
}

// S3Bucket returns the bucket name from an s3:// path.
func S3Bucket(p string) (string, error) {
	sp, err := s3pkg.Parse(p)
	if err != nil {
		return "", err
	}
	return sp.Bucket, nil
}
