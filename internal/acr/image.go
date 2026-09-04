package acr

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// A container image stores its files inside its layers rather than as layers.
// Each layer is a tarball of filesystem changes, so the names bbb reports for a
// plain artifact — one file per layer, from the org.opencontainers.image.title
// annotation — describe nothing useful for an image: image layers carry no
// title, leaving only digests, and the files people actually want are one level
// further in.
//
// Two things bridge that gap. A manifest reached through an index is prefixed
// with its platform, so the members of a multi-platform image are told apart by
// os/arch instead of by digest. And a tar layer is presented as a directory of
// its entries.
//
// Expanding a layer means transferring it, so it happens only when a path
// reaches inside one. Listing the root of a multi-platform image is answered
// from the index alone.

// maxTarEntries bounds how many entries are held for one image, so a crafted
// layer cannot exhaust memory through the listing path alone.
const maxTarEntries = 500_000

// whiteoutPrefix marks a file deleted by a later layer, and whiteoutOpaque
// marks a directory whose earlier contents are dropped entirely.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// isTarLayer reports whether a layer is a filesystem tarball whose entries can
// be listed. zstd layers are excluded deliberately: without a decompressor they
// stay opaque blobs, which is the existing behaviour rather than an error.
func isTarLayer(mediaType types.MediaType) bool {
	switch mediaType {
	case types.OCILayer, types.OCIUncompressedLayer,
		types.DockerLayer, types.DockerUncompressedLayer:
		return true
	}
	return false
}

// platformPrefix names the directory a manifest's contents live under, so the
// members of a multi-platform image are distinguishable. It returns "" when the
// index gives no platform, leaving the layers at the artifact root.
func platformPrefix(platform *v1.Platform) string {
	if platform == nil || platform.OS == "" || platform.Architecture == "" {
		return ""
	}
	parts := []string{platform.OS, platform.Architecture}
	if platform.Variant != "" {
		parts = append(parts, platform.Variant)
	}
	prefix := strings.Join(parts, "/")
	// A platform is registry-controlled, so it is validated like any other
	// name rather than trusted into a path.
	if cleaned, err := cleanFile(prefix); err == nil {
		return cleaned
	}
	return ""
}

// layerRef identifies one tar layer to expand.
type layerRef struct {
	digest string
	size   int64
}

// imageGroup is the tar layers of a single manifest, in order.
//
// Expansion is per manifest rather than per layer because layers overlay: a
// later one replaces a file an earlier one wrote, and removes it with a
// whiteout. Only the result of applying all of them describes the image.
type imageGroup struct {
	prefix string
	layers []layerRef

	mu      sync.Mutex
	done    bool
	entries []File
}

// covers reports whether expanding this group is needed to answer a question
// about file, either because file lives inside the group or because the group
// lives inside the directory being listed.
func (g *imageGroup) covers(file string) bool {
	switch {
	case file == "":
		return true
	case g.prefix == "":
		return true
	case g.prefix == file:
		return true
	}
	return strings.HasPrefix(file, g.prefix+"/") || strings.HasPrefix(g.prefix, file+"/")
}

// expand lists the group's entries, transferring each layer once.
//
// A failure is deliberately not memoised, so --retry-count still works and a
// cancelled context does not poison the group for the rest of the run.
func (g *imageGroup) expand(ctx context.Context, p Path) ([]File, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.done {
		return g.entries, nil
	}
	entries, err := g.read(ctx, p)
	if err != nil {
		return nil, err
	}
	g.entries = entries
	g.done = true
	return g.entries, nil
}

func (g *imageGroup) read(ctx context.Context, p Path) ([]File, error) {
	// Applied in layer order so a later layer replaces what an earlier one
	// wrote; names is kept alongside to preserve that order in the listing.
	merged := map[string]File{}
	var names []string
	for _, layer := range g.layers {
		if err := g.readLayer(ctx, p, layer, merged, &names); err != nil {
			return nil, err
		}
	}
	entries := make([]File, 0, len(merged))
	for _, name := range names {
		if file, ok := merged[name]; ok {
			entries = append(entries, file)
		}
	}
	return entries, nil
}

func (g *imageGroup) readLayer(ctx context.Context, p Path, layer layerRef, merged map[string]File, names *[]string) error {
	blob, err := openBlob(ctx, p, layer.digest)
	if err != nil {
		return err
	}
	defer func() { _ = blob.Close() }()

	reader, err := tarReader(blob)
	if err != nil {
		return fmt.Errorf("acr: reading layer %s: %w", layer.digest, err)
	}
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("acr: reading layer %s: %w", layer.digest, err)
		}
		name, whiteout, ok := tarEntryName(header)
		if !ok {
			continue
		}
		full := name
		if g.prefix != "" {
			full = g.prefix + "/" + name
		}
		switch {
		case whiteout == whiteoutOpaque:
			removeTree(merged, full)
		case whiteout != "":
			delete(merged, full)
		default:
			if _, seen := merged[full]; !seen {
				if len(merged) >= maxTarEntries {
					return fmt.Errorf("acr: layer %s holds more than %d files", layer.digest, maxTarEntries)
				}
				*names = append(*names, full)
			}
			merged[full] = File{
				Name:    full,
				Size:    header.Size,
				Digest:  layer.digest,
				TarPath: header.Name,
			}
		}
	}
}

// removeTree drops everything under an opaque whiteout directory.
func removeTree(merged map[string]File, dir string) {
	prefix := dir + "/"
	for name := range merged {
		if strings.HasPrefix(name, prefix) {
			delete(merged, name)
		}
	}
}

// tarEntryName validates a tar entry and classifies it.
//
// Only regular files become entries: a directory has no contents of its own,
// and a symlink, hardlink or device cannot be served as a stream of bytes.
// Entry names come from the registry, so they are validated exactly like a
// layer title rather than trusted into a path.
func tarEntryName(header *tar.Header) (name, whiteout string, ok bool) {
	clean := path.Clean("/" + strings.ReplaceAll(header.Name, `\`, "/"))
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		return "", "", false
	}

	base := path.Base(clean)
	if base == whiteoutOpaque {
		parent := path.Dir(clean)
		if parent == "." {
			return "", "", false
		}
		if _, err := cleanFile(parent); err != nil {
			return "", "", false
		}
		return parent, whiteoutOpaque, true
	}
	if after, found := strings.CutPrefix(base, whiteoutPrefix); found {
		removed := path.Join(path.Dir(clean), after)
		if _, err := cleanFile(removed); err != nil {
			return "", "", false
		}
		return removed, whiteoutPrefix, true
	}

	if header.Typeflag != tar.TypeReg {
		return "", "", false
	}
	cleaned, err := cleanFile(clean)
	if err != nil {
		return "", "", false
	}
	return cleaned, "", true
}

// tarReader gunzips a layer when it is compressed. The media type is not
// trusted for this: registries and builders disagree about which type a
// compressed layer carries, and the magic bytes are unambiguous.
func tarReader(blob io.Reader) (io.Reader, error) {
	buffered := bufio.NewReader(blob)
	magic, err := buffered.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		return gzip.NewReader(buffered)
	}
	return buffered, nil
}

// openTarEntry streams one file out of a tar layer.
//
// A tar is sequential, so the entry is found by scanning headers and the
// reader is handed back positioned at its contents; the layer before it is
// skipped rather than buffered, and nothing after it is read.
func openTarEntry(ctx context.Context, p Path, file File) (io.ReadCloser, error) {
	blob, err := openBlob(ctx, p, file.Digest)
	if err != nil {
		return nil, err
	}
	reader, err := tarReader(blob)
	if err != nil {
		_ = blob.Close()
		return nil, fmt.Errorf("acr: reading layer %s: %w", file.Digest, err)
	}
	archive := tar.NewReader(reader)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			_ = blob.Close()
			return nil, &notFoundError{path: p.String()}
		}
		if err != nil {
			_ = blob.Close()
			return nil, fmt.Errorf("acr: reading layer %s: %w", file.Digest, err)
		}
		if header.Name != file.TarPath || header.Typeflag != tar.TypeReg {
			continue
		}
		return &tarEntryReader{Reader: archive, closer: blob, size: header.Size}, nil
	}
}

// tarEntryReader reads one entry and closes the layer beneath it.
type tarEntryReader struct {
	io.Reader
	closer io.Closer
	size   int64
}

func (r *tarEntryReader) Close() error { return r.closer.Close() }

// Size reports the entry size, so a download can show progress against it
// rather than against the whole layer.
func (r *tarEntryReader) Size() int64 { return r.size }
