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
	// OCI manifests must be published once for the complete file set; callers
	// use UploadArtifact rather than racing per-file Write calls.
	return ErrWriteUnsupported
}

func (acrFS) UploadArtifact(ctx context.Context, target string, files []ArtifactFile, concurrency int, overwrite bool, onProgress func(name string, uploaded int64)) error {
	ap, err := acr.Parse(target)
	if err != nil {
		return err
	}
	uploadFiles := make([]acr.UploadFile, len(files))
	for i, file := range files {
		uploadFiles[i] = acr.UploadFile{
			Name: file.Name,
			Size: file.Size,
			Open: file.Open,
		}
	}
	return acr.Push(ctx, ap, uploadFiles, acr.PushOptions{
		Concurrency: concurrency,
		Overwrite:   overwrite,
		OnProgress:  onProgress,
	})
}

// confirmPrefix turns an empty listing for a nested path into a not-found
// error. The artifact itself resolved, so an empty result means the prefix
// matched neither a layer nor a virtual directory; without this, listing a
// path that does not exist would exit successfully with no output, unlike
// every other backend.
//
// An exact layer name legitimately has no children, so the prefix is checked
// against the artifact rather than assumed missing: that case still returns an
// empty list for the caller to resolve through Stat. A directory that is
// genuinely empty — a scratch image's platform is one — has no file to stat
// either, so the directory question is asked before the miss is believed.
func confirmPrefix(ctx context.Context, ap acr.Path, prefix string) error {
	if prefix == "" {
		return nil
	}
	probe := ap
	probe.File = prefix
	_, err := acr.Stat(ctx, probe)
	if err == nil {
		return nil
	}
	if isDir, dirErr := acr.IsDir(ctx, probe); dirErr == nil && isDir {
		return nil
	}
	return err
}

func (acrFS) List(ctx context.Context, target string) ([]Entry, error) {
	ap, err := acr.Parse(target)
	if err != nil {
		return nil, err
	}
	if ap.IsRegistry() {
		return listRepositories(ctx, ap)
	}
	if ap.IsRepository() {
		return listTags(ctx, ap)
	}
	prefix := ap.File
	// ListDir answers from the manifest where it can, so listing the root of a
	// container image costs one fetch rather than a copy of every layer.
	children, err := acr.ListDir(ctx, ap)
	if err != nil {
		return nil, err
	}
	if len(children) == 0 {
		root := ap
		root.File = ""
		if err := confirmPrefix(ctx, root, prefix); err != nil {
			return nil, err
		}
	}
	out := make([]Entry, 0, len(children))
	for _, entry := range children {
		child := ap
		child.File = path.Join(prefix, entry.Name)
		name := entry.Name
		if entry.IsDir {
			name += "/"
		}
		out = append(out, Entry{
			Name:  name,
			Path:  child.String(),
			Size:  entry.Size,
			IsDir: entry.IsDir,
		})
	}
	return out, nil
}

// listTags presents a repository's tags as its children. Each is a directory:
// a tag names an artifact, whose own children are its files.
func listTags(ctx context.Context, ap acr.Path) ([]Entry, error) {
	tags, err := acr.ListTags(ctx, ap)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(tags))
	for _, tag := range tags {
		child := ap
		child.Reference = tag
		entries = append(entries, Entry{
			Name:  tag + "/",
			Path:  child.String(),
			IsDir: true,
		})
	}
	return entries, nil
}

// listRepositories presents a registry's repositories as its children. Each is
// a directory: a repository holds tagged artifacts rather than bytes.
func listRepositories(ctx context.Context, ap acr.Path) ([]Entry, error) {
	repositories, err := acr.ListRepositories(ctx, ap)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(repositories))
	for _, repository := range repositories {
		child := ap
		child.Repository = repository
		entries = append(entries, Entry{
			Name:  repository + "/",
			Path:  child.String(),
			IsDir: true,
		})
	}
	return entries, nil
}

func (acrFS) Stat(ctx context.Context, target string) (Entry, error) {
	ap, err := acr.Parse(target)
	if err != nil {
		return Entry{}, err
	}
	if ap.IsRegistry() {
		// A registry exists as a directory of repositories; confirm it answers
		// rather than trusting the path shape.
		if _, err := acr.ListRepositories(ctx, ap); err != nil {
			return Entry{}, err
		}
		return Entry{
			Name:  ap.DefaultFilename(),
			Path:  ap.String(),
			IsDir: true,
		}, nil
	}
	if ap.IsRepository() {
		// Likewise a repository, whose children are its tags.
		if _, err := acr.ListTags(ctx, ap); err != nil {
			return Entry{}, err
		}
		return Entry{
			Name:  ap.DefaultFilename(),
			Path:  ap.String(),
			IsDir: true,
		}, nil
	}
	if ap.File == "" {
		// Resolve the artifact rather than trusting the path shape, so a
		// missing tag reports not-found instead of an existing directory.
		// An artifact with no layers is still a valid, existing artifact.
		if _, err := acr.ListFiles(ctx, ap); err != nil {
			return Entry{}, err
		}
		return Entry{
			Name:  ap.DefaultFilename(),
			Path:  ap.String(),
			IsDir: true,
		}, nil
	}
	file, err := acr.Stat(ctx, ap)
	if err != nil {
		// The path may name one of the virtual directories List synthesises
		// from layer names, which has no layer of its own.
		if dir, dirErr := acr.IsDir(ctx, ap); dirErr == nil && dir {
			return Entry{
				Name:  path.Base(ap.File),
				Path:  ap.String(),
				IsDir: true,
			}, nil
		}
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
	if ap.IsRegistry() {
		// Walking a whole registry means resolving every tag of every
		// repository, which is a different and far larger operation than the
		// caller is likely to have intended.
		return fmt.Errorf("acr: %s is a registry; name a repository to list recursively", target)
	}
	if ap.IsRepository() {
		return fmt.Errorf("acr: %s names a repository; add :tag to address an artifact", target)
	}
	prefix := ap.File
	// The prefix is kept on the path so only the layers beneath it are
	// expanded; the names returned are still full artifact paths.
	files, err := acr.ListFiles(ctx, ap)
	if err != nil {
		return err
	}
	root := ap
	root.File = ""
	sizes := map[string]int64{}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
		sizes[f.Name] = f.Size
	}
	filtered := filterFilesByPrefix(names, prefix)
	if len(filtered) == 0 {
		if err := confirmPrefix(ctx, root, prefix); err != nil {
			return err
		}
	}
	sort.Strings(filtered)
	for _, name := range filtered {
		if name == "" {
			continue
		}
		fullFile := path.Join(prefix, name)
		child := root
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

func (acrFS) IsDirLike(ctx context.Context, p string) (bool, error) {
	ap, err := acr.Parse(p)
	if err != nil {
		return false, err
	}
	if ap.IsRegistry() {
		return true, nil
	}
	if ap.IsRepository() {
		return true, nil
	}
	return acr.IsDir(ctx, ap)
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
	if ap.IsRegistry() {
		// A registry's children are repositories, not files.
		ap.Repository = strings.TrimSuffix(child, "/")
		return ap.String()
	}
	if ap.IsRepository() {
		// A repository's children are its tags.
		ap.Reference = strings.TrimSuffix(child, "/")
		return ap.String()
	}
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
