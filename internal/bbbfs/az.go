package bbbfs

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/tg123/bbb/internal/azblob"
	"github.com/tg123/bbb/internal/hf"
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
	list, err := azblob.ListRecursive(ctx, ap)
	if err != nil {
		return err
	}
	for _, bm := range list {
		name := strings.TrimSuffix(bm.Name, "/")
		if name == "" {
			continue
		}
		if err := emit(Entry{
			Name:    name,
			Path:    azChildPath(ap, name),
			Size:    bm.Size,
			IsDir:   false,
			ModTime: time.Time{},
		}); err != nil {
			return err
		}
	}
	return nil
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

func (azFS) ChildPath(parent, child string) string {
	ap, err := azblob.Parse(parent)
	if err != nil {
		return parent + "/" + child
	}
	return ap.Child(child).String()
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
		return fmt.Errorf("mkcontainer: need az://account/container")
	}
	return azblob.MkContainer(ctx, ap.Account, ap.Container)
}

func (azFS) CopyServerSide(ctx context.Context, src, dst string, concurrency int, onProgress CopyProgress) error {
	srcAP, err := azblob.Parse(src)
	if err != nil {
		return err
	}
	dstAP, err := azblob.Parse(dst)
	if err != nil {
		return err
	}
	return azblob.CopyBlobServerSide(ctx, srcAP, dstAP, concurrency, onProgress)
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
		if ap.Container == "" {
			fullpath = fmt.Sprintf("az://%s/%s", ap.Account, name)
		}
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
	list, err := azblob.ListRecursive(ctx, ap)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for _, bm := range list {
		if bm.Name == "" || strings.HasSuffix(bm.Name, "/") {
			continue
		}
		names = append(names, bm.Name)
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
func AzAccountContainer(p string) (account, container string) {
	ap, err := azblob.Parse(p)
	if err != nil {
		return "", ""
	}
	return ap.Account, ap.Container
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

func (azFS) ListRecursiveWithSize(ctx context.Context, p string) ([]Entry, error) {
	ap, err := azblob.Parse(p)
	if err != nil {
		return nil, err
	}
	list, err := azblob.ListRecursive(ctx, ap)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(list))
	for _, bm := range list {
		name := strings.TrimSuffix(bm.Name, "/")
		if name == "" {
			continue
		}
		entries = append(entries, Entry{
			Name:    name,
			Path:    azChildPath(ap, name),
			Size:    bm.Size,
			IsDir:   false,
			ModTime: time.Time{},
		})
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

// HeadSize returns the file size without downloading. For backends that
// do not support HEAD-like queries, it falls back to Stat.
func HeadSize(ctx context.Context, p string) (int64, error) {
	entry, err := Resolve(p).Stat(ctx, p)
	if err != nil {
		return 0, err
	}
	return entry.Size, nil
}

// IsDirLikeFromPath checks if a path is directory-like without making any
// network calls. Uses path structure only.
func IsDirLikeFromPath(p string) bool {
	if IsAz(p) {
		ap, err := azblob.Parse(p)
		if err != nil {
			return false
		}
		return ap.IsDirLike()
	}
	if IsHF(p) {
		hp, err := hfParse(p)
		if err != nil {
			return false
		}
		return hp.file == ""
	}
	info, err := os.Stat(p)
	if err != nil {
		return strings.HasSuffix(p, string(os.PathSeparator)) || strings.HasSuffix(p, "/")
	}
	return info.IsDir()
}

// hfParsed is a minimal internal struct to avoid exposing hf.Path.
type hfParsed struct {
	file string
}

func hfParse(p string) (hfParsed, error) {
	hp, err := hf.Parse(p)
	if err != nil {
		return hfParsed{}, err
	}
	return hfParsed{file: hp.File}, nil
}
