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
	// merged is the filesystem built up by the layers applied so far, and
	// names preserves the order entries were first seen in.
	merged := map[string]File{}
	var names []string
	// listed guards the order slice: a name removed by a whiteout and written
	// again by the same layer is still one entry, and appending on every
	// reappearance would list it twice.
	listed := map[string]bool{}
	// seen counts every name a layer offered, including ones later removed:
	// bounding only the live map would let a layer add and delete in turn
	// forever while names grew without limit.
	seen := 0
	for _, layer := range g.layers {
		added, addedNames, whiteouts, count, err := g.readLayer(ctx, p, layer, seen)
		if err != nil {
			return nil, err
		}
		seen = count
		// Whiteouts hide what is underneath, so they are applied to the lower
		// layers only. Applying them to this layer's own entries would let a
		// tar hide files it legitimately contains, since a whiteout can
		// appear before the entry it does not refer to.
		for _, w := range whiteouts {
			removeTree(merged, w)
			delete(merged, w)
		}
		for _, name := range addedNames {
			if !listed[name] {
				listed[name] = true
				names = append(names, name)
			}
			merged[name] = added[name]
		}
	}

	entries := make([]File, 0, len(merged))
	for _, name := range names {
		if file, ok := merged[name]; ok {
			entries = append(entries, file)
		}
	}
	// The names come from the registry, so they are held to the same
	// coexistence rules as layer titles: a pair that differs only by case or
	// Unicode normalisation, or a file that is also a directory, cannot be
	// written to one local tree.
	if err := validateNames(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// validateNames rejects a set of names that cannot coexist on a local
// filesystem, matching what is enforced for a published artifact.
func validateNames(entries []File) error {
	set := newNameSet(len(entries))
	for _, entry := range entries {
		if _, err := set.addLayer(entry.Name, entry.Digest+entry.TarPath); err != nil {
			return fmt.Errorf("acr: %w", err)
		}
	}
	return nil
}

// readLayer indexes one tar layer, returning its entries, the order they
// appeared in, the paths it whites out, and the running name count.
func (g *imageGroup) readLayer(ctx context.Context, p Path, layer layerRef, seen int) (map[string]File, []string, []string, int, error) {
	blob, err := openBlob(ctx, p, layer.digest)
	if err != nil {
		return nil, nil, nil, seen, err
	}
	defer func() { _ = blob.Close() }()

	reader, err := tarReader(blob)
	if err != nil {
		return nil, nil, nil, seen, fmt.Errorf("acr: reading layer %s: %w", layer.digest, err)
	}
	archive := tar.NewReader(reader)
	added := map[string]File{}
	var order []string
	var whiteouts []string
	// occurrences counts headers per path so a duplicated entry can be found
	// again: a tar is a log, and the last write of a path is the live one.
	occurrences := map[string]int{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return added, order, whiteouts, seen, nil
		}
		if err != nil {
			return nil, nil, nil, seen, fmt.Errorf("acr: reading layer %s: %w", layer.digest, err)
		}
		index := occurrences[header.Name]
		occurrences[header.Name]++

		name, kind, ok := tarEntryName(header)
		if !ok {
			continue
		}
		full := name
		if g.prefix != "" && name != "" {
			full = g.prefix + "/" + name
		} else if g.prefix != "" {
			full = g.prefix
		}
		if kind != entryFile {
			whiteouts = append(whiteouts, full)
			continue
		}
		seen++
		if seen > maxTarEntries {
			return nil, nil, nil, seen, fmt.Errorf("acr: image holds more than %d files", maxTarEntries)
		}
		if _, exists := added[full]; !exists {
			order = append(order, full)
		}
		added[full] = File{
			Name:     full,
			Size:     header.Size,
			Digest:   layer.digest,
			TarPath:  header.Name,
			TarIndex: index,
		}
	}
}

// removeTree drops everything beneath a whited-out path. A whiteout can name a
// directory, and its descendants go with it.
func removeTree(merged map[string]File, dir string) {
	prefix := dir + "/"
	for name := range merged {
		if strings.HasPrefix(name, prefix) {
			delete(merged, name)
		}
	}
	if dir == "" {
		// An opaque whiteout at the root hides everything below it.
		for name := range merged {
			delete(merged, name)
		}
	}
}

// entryKind distinguishes a file from the two whiteout markers.
type entryKind int

const (
	entryFile entryKind = iota
	entryWhiteout
	entryOpaque
)

// tarEntryName validates a tar entry and classifies it.
//
// Only regular files become entries: a directory has no contents of its own,
// and a symlink, hardlink or device cannot be served as a stream of bytes.
//
// The name is validated as written rather than repaired. Cleaning first would
// turn "../escape" into "escape" and "/etc/passwd" into "etc/passwd", quietly
// admitting a hostile entry under a name that looks ordinary and can alias a
// legitimate one. A leading "./" is the one exception, because it is how tools
// routinely write layer paths and means nothing.
func tarEntryName(header *tar.Header) (name string, kind entryKind, ok bool) {
	raw := strings.TrimPrefix(header.Name, "./")
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" || raw == "." {
		// The root itself, which only matters as an opaque whiteout's parent.
		return "", entryFile, false
	}
	if strings.Contains(raw, `\`) || strings.HasPrefix(raw, "/") {
		return "", entryFile, false
	}

	base := path.Base(raw)
	if base == whiteoutOpaque {
		parent := strings.TrimSuffix(raw, whiteoutOpaque)
		parent = strings.TrimSuffix(parent, "/")
		if parent == "" {
			// A root opaque whiteout is valid and hides every lower entry.
			return "", entryOpaque, true
		}
		if !isSafeEntryName(parent) {
			return "", entryFile, false
		}
		return parent, entryOpaque, true
	}
	if after, found := strings.CutPrefix(base, whiteoutPrefix); found {
		removed := path.Join(path.Dir(raw), after)
		if !isSafeEntryName(removed) {
			return "", entryFile, false
		}
		return removed, entryWhiteout, true
	}

	if header.Typeflag != tar.TypeReg {
		return "", entryFile, false
	}
	if !isSafeEntryName(raw) {
		return "", entryFile, false
	}
	return raw, entryFile, true
}

// isSafeEntryName reports whether a name is already canonical and safe, so an
// entry is accepted as written or not at all.
func isSafeEntryName(name string) bool {
	cleaned, err := cleanFile(name)
	return err == nil && cleaned == name
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
// A tar is a log rather than a directory, so a path can appear more than once
// and the last header is the live one. The occurrence recorded when the layer
// was indexed is matched here, or a listing would describe one entry while a
// download served another.
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
	seen := 0
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
		if header.Name != file.TarPath {
			continue
		}
		if seen != file.TarIndex {
			seen++
			continue
		}
		if header.Typeflag != tar.TypeReg {
			_ = blob.Close()
			return nil, &notFoundError{path: p.String()}
		}
		return &tarEntryReader{
			Reader: io.LimitReader(archive, header.Size),
			blob:   blob,
			rest:   reader,
			size:   header.Size,
		}, nil
	}
}

// tarEntryReader reads one entry and closes the layer beneath it.
//
// go-containerregistry verifies a blob against its digest as it is read, and
// only completes that check at EOF. Stopping at the entry would leave the
// layer unverified, so the remainder is drained before the read is reported as
// successful: without it a registry could serve altered bytes for everything
// after the entry, and for the entry itself on a later read.
type tarEntryReader struct {
	io.Reader
	blob io.ReadCloser
	rest io.Reader
	size int64

	drained bool
	err     error
}

func (r *tarEntryReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) && !r.drained {
		r.drained = true
		if _, drainErr := io.Copy(io.Discard, r.rest); drainErr != nil {
			// The digest did not match, or the layer was truncated. Either way
			// the bytes just read cannot be trusted.
			r.err = fmt.Errorf("acr: layer verification failed: %w", drainErr)
			return n, r.err
		}
	}
	return n, err
}

func (r *tarEntryReader) Close() error {
	closeErr := r.blob.Close()
	if r.err != nil {
		return r.err
	}
	return closeErr
}

// Size reports the entry size, so a download can show progress against it
// rather than against the whole layer.
func (r *tarEntryReader) Size() int64 { return r.size }
