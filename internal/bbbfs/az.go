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

	"github.com/tg123/bbb/internal/azblob"
)

type azFS struct{}

func (azFS) Match(path string) bool {
	return strings.HasPrefix(path, "az://") || azblob.IsBlobURL(path)
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
	return azblob.UploadStream(ctx, ap, r, UploadConcurrency(ctx))
}

// DownloadToFile downloads the blob at src into localPath using parallel ranged
// GETs, mirroring azcopy's chunked download for higher single-file throughput.
func (azFS) DownloadToFile(ctx context.Context, src, localPath string, concurrency int, onProgress func(int64)) (int64, error) {
	ap, err := azblob.Parse(src)
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
	n, downloadErr := azblob.DownloadFile(ctx, ap, f, concurrency, onProgress)
	closeErr := f.Close()
	if downloadErr != nil {
		return n, downloadErr
	}
	return n, closeErr
}

// UploadFromFile uploads localPath to the blob at dst using parallel ranged
// reads + StageBlock, mirroring azcopy's chunked upload for higher single-file
// throughput.
func (azFS) UploadFromFile(ctx context.Context, localPath, dst string, concurrency int, onProgress func(int64)) (int64, error) {
	ap, err := azblob.Parse(dst)
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
	if err := azblob.UploadFile(ctx, ap, f, concurrency, tracker); err != nil {
		return uploaded.Load(), err
	}
	return uploaded.Load(), nil
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

func (azFS) ListRecursive(ctx context.Context, target string, emit func(Entry) error) error {
	ap, err := azblob.Parse(target)
	if err != nil {
		return err
	}
	return azblob.ListRecursiveStream(ctx, ap, ScanConcurrency(ctx), func(bm azblob.BlobMeta) error {
		name := bm.Name
		if name == "" || strings.HasSuffix(name, "/") {
			return nil
		}
		return emit(Entry{
			Name:    name,
			Path:    azChildPath(ap, name),
			Size:    bm.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	})
}

func azChildPath(ap azblob.AzurePath, name string) string {
	trimmed := strings.TrimSuffix(name, "/")
	return ap.Child(trimmed).String()
}

func (azFS) IsDirLike(_ context.Context, p string) (bool, error) {
	ap, err := azblob.Parse(p)
	if err != nil {
		return false, err
	}
	return ap.IsDirLike(), nil
}

func (azFS) IsDirLikeFromPath(p string) bool {
	ap, err := azblob.Parse(p)
	if err != nil {
		return false
	}
	return ap.IsDirLike()
}

func (azFS) ChildPath(parent, child string) string {
	ap, err := azblob.Parse(parent)
	if err != nil {
		return parent + "/" + child
	}
	return ap.Child(filepath.ToSlash(child)).String() // normalize Windows backslash separators
}

func (azFS) BaseName(p string) string {
	ap, err := azblob.Parse(p)
	if err != nil {
		return path.Base(p)
	}
	if ap.Blob != "" {
		return path.Base(ap.Blob)
	}
	if ap.Container != "" {
		return ap.Container
	}
	return ap.Account
}

func (azFS) Delete(ctx context.Context, p string) error {
	ap, err := azblob.Parse(p)
	if err != nil {
		return err
	}
	return azblob.Delete(ctx, ap)
}

func (azFS) Touch(ctx context.Context, p string) error {
	ap, err := azblob.Parse(p)
	if err != nil {
		return err
	}
	return azblob.Touch(ctx, ap)
}

func (azFS) MkDir(ctx context.Context, p string) error {
	ap, err := azblob.Parse(p)
	if err != nil {
		return err
	}
	if ap.Container == "" {
		return fmt.Errorf("container name is required")
	}
	return azblob.MkContainer(ctx, ap.Account, ap.Container)
}

func (azFS) CopyServerSide(ctx context.Context, src, dst string, concurrency int, sizeHint int64, onProgress CopyProgress) error {
	srcAP, err := azblob.Parse(src)
	if err != nil {
		return err
	}
	dstAP, err := azblob.Parse(dst)
	if err != nil {
		return err
	}
	return azblob.CopyBlobServerSide(ctx, srcAP, dstAP, concurrency, sizeHint, onProgress)
}

// CopyFromURLServerSide copies a public source URL directly into an Azure blob
// server-side, without streaming bytes through this process.
func (azFS) CopyFromURLServerSide(ctx context.Context, sourceURL, dst string, size int64, concurrency int, onProgress CopyProgress) error {
	dstAP, err := azblob.Parse(dst)
	if err != nil {
		return err
	}
	return azblob.CopyBlobFromURLServerSide(ctx, dstAP, sourceURL, size, concurrency, onProgress)
}

// UploadReader ingests an arbitrary reader into an Azure blob by first spooling
// it to a temporary file and then using the size-aware parallel block-staging
// upload path (16 MiB blocks), which is more robust on real Azure than the
// SDK's streaming uploader (whose 256 MiB block floor can trigger
// InvalidBlobOrBlock on some accounts). onProgress, when non-nil, receives the
// cumulative number of bytes uploaded.
func (azFS) UploadReader(ctx context.Context, dst string, r io.Reader, concurrency int, onProgress func(copied int64)) error {
	ap, err := azblob.Parse(dst)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "bbb-upload-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if _, err := io.Copy(tmp, r); err != nil {
		return err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return err
	}
	// UploadFile reports cumulative bytes uploaded, matching onProgress's
	// contract, so it is forwarded directly.
	return azblob.UploadFile(ctx, ap, tmp, concurrency, onProgress)
}

func (azFS) ListStream(ctx context.Context, p string, fn func(Entry) error) error {
	ap, err := azblob.Parse(p)
	if err != nil {
		return err
	}
	return azblob.ListStream(ctx, ap, func(bm azblob.BlobMeta) error {
		name := bm.Name
		if name == "" {
			return nil
		}
		fullpath := azChildPath(ap, name)
		return fn(Entry{
			Name:    name,
			Path:    fullpath,
			Size:    bm.Size,
			IsDir:   strings.HasSuffix(name, "/"),
			ModTime: time.Time{},
		})
	})
}

func (azFS) ListFilesFlat(ctx context.Context, p string) ([]string, error) {
	ap, err := azblob.Parse(p)
	if err != nil {
		return nil, err
	}
	concurrency := ScanConcurrency(ctx)
	var mu sync.Mutex
	var names []string
	if err := azblob.ListRecursiveStream(ctx, ap, concurrency, func(bm azblob.BlobMeta) error {
		if bm.Name == "" || strings.HasSuffix(bm.Name, "/") {
			return nil
		}
		if concurrency > 1 {
			mu.Lock()
			names = append(names, bm.Name)
			mu.Unlock()
		} else {
			names = append(names, bm.Name)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return names, nil
}

func (azFS) ResolveDstPath(dst, base string, mustBeDir bool) (string, error) {
	dap, err := azblob.Parse(dst)
	if err != nil {
		return "", err
	}
	if mustBeDir && dap.Blob != "" && !strings.HasSuffix(dap.Blob, "/") {
		dap.Blob += "/"
	}
	if dap.Blob == "" || strings.HasSuffix(dap.Blob, "/") {
		if dap.Blob == "" {
			dap.Blob = base
		} else {
			dap.Blob = strings.TrimSuffix(dap.Blob, "/") + "/" + base
		}
		return dap.String(), nil
	}
	if mustBeDir {
		return "", fmt.Errorf("destination must be a directory")
	}
	return dst, nil
}

func (azFS) ShareInfo(p string) (portal, direct string, err error) {
	ap, err := azblob.Parse(p)
	if err != nil {
		return "", "", err
	}
	portal = fmt.Sprintf("https://portal.azure.com/#blade/Microsoft_Azure_Storage/ContainerMenuBlade/overview/storageaccount/%s/container/%s/path/%s", ap.Account, ap.Container, ap.Blob)
	direct = fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", ap.Account, ap.Container, ap.Blob)
	return portal, direct, nil
}

// AzAccountContainer returns the account and container from an Azure path.
// Returns empty strings for non-Azure paths.
func AzAccountContainer(p string) (account, container string, err error) {
	ap, err := azblob.Parse(p)
	if err != nil {
		return "", "", err
	}
	return ap.Account, ap.Container, nil
}

// RegisterAzAccountRoles tags source and destination storage accounts with
// their roles so that SRC_AZURE_* / DST_AZURE_* environment variables are
// used for authentication in multi-tenant environments.
//
// If the same account appears in both srcPaths and dstPaths it is not tagged
// with any role, so the normal (non-role-scoped) credential flow is used.
func RegisterAzAccountRoles(srcPaths, dstPaths []string) {
	srcAccounts := make(map[string]struct{})
	for _, p := range srcPaths {
		if !IsAz(p) {
			continue
		}
		ap, err := azblob.Parse(p)
		if err != nil || ap.Account == "" {
			continue
		}
		srcAccounts[ap.Account] = struct{}{}
	}

	dstAccounts := make(map[string]struct{})
	for _, p := range dstPaths {
		if !IsAz(p) {
			continue
		}
		ap, err := azblob.Parse(p)
		if err != nil || ap.Account == "" {
			continue
		}
		dstAccounts[ap.Account] = struct{}{}
	}

	for acct := range srcAccounts {
		if _, both := dstAccounts[acct]; both {
			continue // account is both src and dst — skip role tagging
		}
		azblob.RegisterAccountRole(acct, "SRC")
	}
	for acct := range dstAccounts {
		if _, both := srcAccounts[acct]; both {
			continue
		}
		azblob.RegisterAccountRole(acct, "DST")
	}
}

// PreAuthenticateAz eagerly authenticates to the storage accounts referenced
// by the given az:// paths. Call this before spawning parallel workers so
// that any interactive login popups happen sequentially.
func PreAuthenticateAz(ctx context.Context, paths ...string) error {
	seen := make(map[string]struct{})
	var accounts []string
	for _, p := range paths {
		if !IsAz(p) {
			continue
		}
		ap, err := azblob.Parse(p)
		if err != nil {
			continue
		}
		if _, ok := seen[ap.Account]; ok {
			continue
		}
		seen[ap.Account] = struct{}{}
		accounts = append(accounts, ap.Account)
	}
	if len(accounts) == 0 {
		return nil
	}
	return azblob.PreAuthenticate(ctx, accounts...)
}

// ListRecursiveWithSize lists all entries recursively with their sizes.
func ListRecursiveWithSize(ctx context.Context, p string) ([]Entry, error) {
	fs := Resolve(p)
	type sizedRecursiveLister interface {
		ListRecursiveWithSize(ctx context.Context, path string) ([]Entry, error)
	}
	if srl, ok := fs.(sizedRecursiveLister); ok {
		return srl.ListRecursiveWithSize(ctx, p)
	}
	// fallback
	var entries []Entry
	for result := range ListRecursive(ctx, p) {
		if result.Err != nil {
			return nil, result.Err
		}
		entries = append(entries, result.Entry)
	}
	return entries, nil
}

// sizedRecursiveStreamLister is an optional FS extension for streaming
// recursive listing with sizes.
type sizedRecursiveStreamLister interface {
	ListRecursiveWithSizeStream(ctx context.Context, path string, emit func(Entry) error) error
}

// ListRecursiveWithSizeStream streams all entries recursively with their sizes
// via a callback. If the backend does not implement streaming, it falls back
// to collecting all entries and emitting them one by one.
func ListRecursiveWithSizeStream(ctx context.Context, p string, emit func(Entry) error) error {
	fs := Resolve(p)
	if srl, ok := fs.(sizedRecursiveStreamLister); ok {
		return srl.ListRecursiveWithSizeStream(ctx, p, emit)
	}
	// fallback: collect and emit
	entries, err := ListRecursiveWithSize(ctx, p)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := emit(e); err != nil {
			return err
		}
	}
	return nil
}

func (azFS) ListRecursiveWithSizeStream(ctx context.Context, p string, emit func(Entry) error) error {
	ap, err := azblob.Parse(p)
	if err != nil {
		return err
	}
	return azblob.ListRecursiveStream(ctx, ap, ScanConcurrency(ctx), func(bm azblob.BlobMeta) error {
		name := bm.Name
		if name == "" || strings.HasSuffix(name, "/") {
			return nil
		}
		return emit(Entry{
			Name:    name,
			Path:    azChildPath(ap, name),
			Size:    bm.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
	})
}

func (f azFS) ListRecursiveWithSize(ctx context.Context, p string) ([]Entry, error) {
	concurrency := ScanConcurrency(ctx)
	var mu sync.Mutex
	var entries []Entry
	if err := f.ListRecursiveWithSizeStream(ctx, p, func(e Entry) error {
		if concurrency > 1 {
			mu.Lock()
			entries = append(entries, e)
			mu.Unlock()
		} else {
			entries = append(entries, e)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return entries, nil
}

// DeletePrefix deletes all files under the prefix. Only Azure supports this natively.
func DeletePrefix(ctx context.Context, p string) error {
	fs := Resolve(p)
	type prefixDeleter interface {
		DeletePrefix(ctx context.Context, path string) error
	}
	if pd, ok := fs.(prefixDeleter); ok {
		return pd.DeletePrefix(ctx, p)
	}
	return fmt.Errorf("delete prefix not supported for %s", p)
}

func (azFS) DeletePrefix(ctx context.Context, p string) error {
	ap, err := azblob.Parse(p)
	if err != nil {
		return err
	}
	return azblob.DeletePrefix(ctx, ap)
}
