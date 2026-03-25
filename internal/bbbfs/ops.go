package bbbfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"

	"github.com/tg123/bbb/internal/hf"
)

type scanConcurrencyKey struct{}

// WithScanConcurrency returns a context that carries the scan (listing)
// concurrency hint.  Backends that support parallel prefix walking
// (e.g. Azure) use this to bound the number of concurrent listing
// goroutines.
func WithScanConcurrency(ctx context.Context, n int) context.Context {
	return context.WithValue(ctx, scanConcurrencyKey{}, n)
}

// ScanConcurrency returns the scan concurrency stored in ctx, or 1 if unset.
func ScanConcurrency(ctx context.Context) int {
	if v, ok := ctx.Value(scanConcurrencyKey{}).(int); ok && v > 0 {
		return v
	}
	return 1
}

// IsAz returns true if the path targets an Azure Blob Storage backend.
func IsAz(path string) bool {
	return azProvider.Match(path)
}

// IsHF returns true if the path targets a Hugging Face backend.
func IsHF(path string) bool {
	return hfProvider.Match(path)
}

// IsRemote returns true if the path targets a remote (non-local) backend.
func IsRemote(path string) bool {
	return IsAz(path) || IsHF(path)
}

// dirChecker is an optional FS extension for checking whether a path is directory-like.
type dirChecker interface {
	IsDirLike(ctx context.Context, path string) (bool, error)
}

// IsDirLike checks whether the path is directory-like. For remote paths this
// is determined from the path structure; for local paths os.Stat is used.
func IsDirLike(ctx context.Context, p string) (bool, error) {
	fs := Resolve(p)
	if dc, ok := fs.(dirChecker); ok {
		return dc.IsDirLike(ctx, p)
	}
	// fallback: use Stat
	entry, err := fs.Stat(ctx, p)
	if err != nil {
		return false, err
	}
	return entry.IsDir, nil
}

// childPather is an optional FS extension for joining a child to a parent path.
type childPather interface {
	ChildPath(parent, child string) string
}

// ChildPath joins child to parent using the backend-specific separator.
func ChildPath(parent, child string) string {
	fs := Resolve(parent)
	if cp, ok := fs.(childPather); ok {
		return cp.ChildPath(parent, child)
	}
	return filepath.Join(parent, child)
}

// baseNamer is an optional FS extension for extracting the base filename.
type baseNamer interface {
	BaseName(path string) string
}

// BaseName returns the base filename from any path.
func BaseName(p string) string {
	fs := Resolve(p)
	if bn, ok := fs.(baseNamer); ok {
		return bn.BaseName(p)
	}
	return filepath.Base(p)
}

// Exists checks whether a file exists at the given path.
func Exists(ctx context.Context, p string) (bool, error) {
	_, err := Resolve(p).Stat(ctx, p)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// deleter is an optional FS extension for deleting a file.
type deleter interface {
	Delete(ctx context.Context, path string) error
}

// Delete removes a file at the given path.
func Delete(ctx context.Context, p string) error {
	fs := Resolve(p)
	if d, ok := fs.(deleter); ok {
		return d.Delete(ctx, p)
	}
	return os.Remove(p)
}

// toucher is an optional FS extension for creating an empty file / touching.
type toucher interface {
	Touch(ctx context.Context, path string) error
}

// Touch creates an empty file or updates the modification time.
func Touch(ctx context.Context, p string) error {
	fs := Resolve(p)
	if t, ok := fs.(toucher); ok {
		return t.Touch(ctx, p)
	}
	// local fallback
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o666)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chtimes(p, time.Now(), time.Now())
}

// dirMaker is an optional FS extension for creating a directory/container.
type dirMaker interface {
	MkDir(ctx context.Context, path string) error
}

// MkDir creates a directory or container at the given path.
func MkDir(ctx context.Context, p string) error {
	fs := Resolve(p)
	if m, ok := fs.(dirMaker); ok {
		return m.MkDir(ctx, p)
	}
	return os.MkdirAll(p, 0o755)
}

// CopyProgress is the callback type for copy progress reporting.
type CopyProgress = func(copied, total int64)

// serverSideCopier is an optional FS extension for server-side copy.
type serverSideCopier interface {
	CopyServerSide(ctx context.Context, src, dst string, concurrency int, onProgress CopyProgress) error
}

// CanCopyServerSide returns true when both src and dst can use server-side copy.
func CanCopyServerSide(src, dst string) bool {
	srcFS := Resolve(src)
	dstFS := Resolve(dst)
	_, srcOK := srcFS.(serverSideCopier)
	_, dstOK := dstFS.(serverSideCopier)
	return srcOK && dstOK && IsAz(src) && IsAz(dst)
}

// CopyServerSide performs an optimised server-side copy (e.g. Azure→Azure).
// Returns an error if the backends do not support server-side copy.
func CopyServerSide(ctx context.Context, src, dst string, concurrency int, onProgress CopyProgress) error {
	srcFS := Resolve(src)
	if sc, ok := srcFS.(serverSideCopier); ok {
		return sc.CopyServerSide(ctx, src, dst, concurrency, onProgress)
	}
	return errors.New("server-side copy not supported")
}

// streamLister is an optional FS extension for streaming list.
type streamLister interface {
	ListStream(ctx context.Context, path string, fn func(Entry) error) error
}

// ListStream lists entries via a streaming callback. Falls back to List
// when the backend does not provide a streaming implementation.
func ListStream(ctx context.Context, p string, fn func(Entry) error) error {
	fs := Resolve(p)
	if sl, ok := fs.(streamLister); ok {
		return sl.ListStream(ctx, p, fn)
	}
	entries, err := fs.List(ctx, p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// flatLister is an optional FS extension returning just file names.
type flatLister interface {
	ListFilesFlat(ctx context.Context, path string) ([]string, error)
}

// ListFilesFlat returns a flat list of relative file names under the path.
func ListFilesFlat(ctx context.Context, p string) ([]string, error) {
	fs := Resolve(p)
	if fl, ok := fs.(flatLister); ok {
		return fl.ListFilesFlat(ctx, p)
	}
	// generic fallback via ListRecursive
	var names []string
	for res := range ListRecursive(ctx, p) {
		if res.Err != nil {
			return nil, res.Err
		}
		if !res.Entry.IsDir {
			names = append(names, res.Entry.Name)
		}
	}
	return names, nil
}

// dstPathResolver is an optional FS extension for computing destination paths.
type dstPathResolver interface {
	ResolveDstPath(dst, base string, mustBeDir bool) (string, error)
}

// ResolveDstPath computes the final destination file path for a copy operation.
// If the destination is directory-like, base is appended.
func ResolveDstPath(dst, base string, mustBeDir bool) (string, error) {
	fs := Resolve(dst)
	if rp, ok := fs.(dstPathResolver); ok {
		return rp.ResolveDstPath(dst, base, mustBeDir)
	}
	// local fallback
	info, err := os.Stat(dst)
	if err == nil && info.IsDir() {
		return filepath.Join(dst, base), nil
	}
	if strings.HasSuffix(dst, string(os.PathSeparator)) || strings.HasSuffix(dst, "/") {
		return filepath.Join(dst, base), nil
	}
	if mustBeDir {
		return "", errors.New("destination must be a directory")
	}
	return dst, nil
}

// ExistsAsBlob checks whether the path points to an existing non-directory file.
// Returns false if the path is directory-like or does not exist.
func ExistsAsBlob(ctx context.Context, p string) (bool, error) {
	entry, err := Resolve(p).Stat(ctx, p)
	if err != nil {
		return false, nil
	}
	return !entry.IsDir, nil
}

// IsNonRetryableHTTPErr returns true when err is an HTTP 401, 403, or 404
// from any supported backend, indicating a non-retryable failure.
func IsNonRetryableHTTPErr(err error) bool {
	var hfErr *hf.HTTPStatusError
	if errors.As(err, &hfErr) && (hfErr.StatusCode == 401 || hfErr.StatusCode == 403 || hfErr.StatusCode == 404) {
		return true
	}
	var azErr *azcore.ResponseError
	if errors.As(err, &azErr) && (azErr.StatusCode == 401 || azErr.StatusCode == 403 || azErr.StatusCode == 404) {
		return true
	}
	return false
}

// ParseShareInfo returns shareable links for the path.
func ParseShareInfo(p string) (portal, direct string, err error) {
	fs := Resolve(p)
	type shareInfoProvider interface {
		ShareInfo(path string) (portal, direct string, err error)
	}
	if sp, ok := fs.(shareInfoProvider); ok {
		return sp.ShareInfo(p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", "", fmt.Errorf("share: %s: %w", p, err)
	}
	return "", "file://" + abs, nil
}

// IsDirLikeFromPath checks if a path is directory-like without making any
// network calls. Uses path structure only.
func IsDirLikeFromPath(p string) bool {
	fs := Resolve(p)
	type pathOnlyDirChecker interface {
		IsDirLikeFromPath(path string) bool
	}
	if dc, ok := fs.(pathOnlyDirChecker); ok {
		return dc.IsDirLikeFromPath(p)
	}
	// local fallback
	info, err := os.Stat(p)
	if err != nil {
		return strings.HasSuffix(p, string(os.PathSeparator)) || strings.HasSuffix(p, "/")
	}
	return info.IsDir()
}
