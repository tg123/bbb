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

// maxEntryNameBytes rejects an individual path longer than any filesystem will
// accept, and maxTotalNameBytes bounds what all the retained names cost
// together. The entry count does not do this on its own: PAX and GNU long
// names are registry-controlled and effectively unbounded, so a handful of
// entries could hold far more than half a million ordinary ones.
const (
	maxEntryNameBytes = 4096
	maxTotalNameBytes = 64 << 20
)

// imageBudget bounds what all of an artifact's image groups retain together.
//
// A per-group limit is not a limit: an index is registry-controlled and can
// declare any number of platforms, so N manifests would each be allowed the
// full allowance. Groups charge against one shared budget instead, and a group
// re-read after a failure replaces its own contribution rather than adding to
// it.
type imageBudget struct {
	mu   sync.Mutex
	used map[*imageGroup]budgetUse
	// entries and names are the running sums of used, so a charge costs the
	// same whatever an index declares. Rescanning every group per header would
	// make an image's own size multiply the number of platforms it has.
	entries int
	names   int
}

type budgetUse struct {
	entries int
	names   int
}

func newImageBudget() *imageBudget {
	return &imageBudget{used: map[*imageGroup]budgetUse{}}
}

// charge reports whether group may retain the given totals, counting what
// every other group has already committed. use is a running total for the
// group, so this replaces its previous contribution rather than adding to it.
func (b *imageBudget) charge(group *imageGroup, use budgetUse) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	previous := b.used[group]
	entries := b.entries - previous.entries + use.entries
	names := b.names - previous.names + use.names
	if entries > maxTarEntries {
		return fmt.Errorf("acr: image holds more than %d entries", maxTarEntries)
	}
	if names > maxTotalNameBytes {
		return fmt.Errorf("acr: image entry names exceed %d bytes", maxTotalNameBytes)
	}
	b.used[group] = use
	b.entries, b.names = entries, names
	return nil
}

// release drops a group's contribution, for an expansion that retained nothing.
func (b *imageBudget) release(group *imageGroup) {
	b.mu.Lock()
	defer b.mu.Unlock()
	previous := b.used[group]
	b.entries -= previous.entries
	b.names -= previous.names
	delete(b.used, group)
}

// whiteoutPrefix marks a file deleted by a later layer, and whiteoutOpaque
// marks a directory whose earlier contents are dropped entirely.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)

// isImageConfig reports whether a manifest's config marks it as a container
// image, whose layers are a filesystem, rather than a generic artifact whose
// layers are files.
func isImageConfig(mediaType types.MediaType) bool {
	switch mediaType {
	case types.DockerConfigJSON, types.OCIConfigJSON:
		return true
	}
	return false
}

// isTarLayer reports whether a layer is a filesystem tarball whose entries can
// be listed.
//
// Non-distributable layers are included: they are ordinary tars, and Windows
// base images use them, so treating them as opaque would hide those files.
// zstd layers are excluded deliberately — without a decompressor they stay
// opaque blobs, which is the existing behaviour rather than an error.
func isTarLayer(mediaType types.MediaType) bool {
	switch mediaType {
	case types.OCILayer, types.OCIUncompressedLayer,
		types.DockerLayer, types.DockerUncompressedLayer,
		types.OCIRestrictedLayer, types.OCIUncompressedRestrictedLayer,
		types.DockerForeignLayer:
		return true
	}
	return false
}

// platformPrefix names the directory a manifest's contents live under, so the
// members of a multi-platform image are distinguishable.
//
// An absent platform yields "", putting that manifest's layers at the artifact
// root. Anything else is an error rather than the same "": silently rehoming a
// manifest would merge it into the root namespace, and a platform is
// registry-controlled, so it is validated like any other name.
func platformPrefix(platform *v1.Platform) (string, error) {
	if platform == nil {
		return "", nil
	}
	if platform.OS == "" || platform.Architecture == "" {
		// Partial metadata is not absent metadata: putting it at the root
		// would merge this manifest with unrelated content there, which is
		// exactly the collision the prefix exists to prevent.
		return "", fmt.Errorf("acr: manifest declares an incomplete platform (os %q, architecture %q)",
			platform.OS, platform.Architecture)
	}
	parts := []string{platform.OS, platform.Architecture}
	if platform.Variant != "" {
		parts = append(parts, platform.Variant)
	}
	prefix := strings.Join(parts, "/")
	cleaned, err := cleanFile(prefix)
	if err != nil || cleaned != prefix {
		return "", fmt.Errorf("acr: manifest declares an unusable platform %q", prefix)
	}
	return cleaned, nil
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
	// budget is shared with every other group of the same artifact.
	budget *imageBudget

	mu      sync.Mutex
	done    bool
	entries []File
	// byName indexes entries once expansion has settled. Downloading an
	// N-file image looks up every one of them, so a scan per lookup would
	// make the metadata work quadratic on top of the layer reads.
	byName map[string]File
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
		// Nothing is retained, so this group's charge is released: leaving it
		// committed would make another platform fail against a limit that
		// counts entries no longer held anywhere.
		g.budget.release(g)
		return nil, err
	}
	g.entries = entries
	g.byName = make(map[string]File, len(entries))
	for _, entry := range entries {
		g.byName[entry.Name] = entry
	}
	g.done = true
	return g.entries, nil
}

// find returns an expanded entry by name in constant time. It reports false
// when the group has not been expanded, so callers expand first.
func (g *imageGroup) find(name string) (File, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	file, ok := g.byName[name]
	return file, ok
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
	nameBytes := 0
	for _, layer := range g.layers {
		added, addedNames, shadows, count, bytes, err := g.readLayer(ctx, p, layer, seen, nameBytes, merged)
		if err != nil {
			return nil, err
		}
		seen, nameBytes = count, bytes

		// Everything an upper layer places at a path displaces what the lower
		// layers had beneath it: a whiteout, a symlink, and a regular file
		// over a directory all remove the subtree. Collecting the roots and
		// making one pass keeps that linear — removing per entry rescans the
		// whole merged set and is quadratic on two ordinary layers.
		roots := make(map[string]bool, len(added)+len(shadows))
		rootOpaque := false
		for _, s := range shadows {
			delete(merged, s.path)
			if !s.subtree {
				continue
			}
			if s.path == "" {
				rootOpaque = true
			} else {
				roots[s.path] = true
			}
		}
		for name := range added {
			roots[name] = true
		}
		if rootOpaque {
			clear(merged)
		}
		removeUnder(merged, roots)
		// A tar need not carry an explicit directory header, so an upper
		// layer's "app/config" can arrive with nothing announcing "app". If a
		// lower layer had a regular file there it has become a directory, and
		// leaving it would report a file and a directory at one path. Only the
		// exact ancestors go: the lower layer's other children and siblings
		// are still part of the image.
		for name := range added {
			for cut := strings.LastIndexByte(name, '/'); cut > 0; cut = strings.LastIndexByte(name[:cut], '/') {
				delete(merged, name[:cut])
			}
		}

		for _, name := range addedNames {
			file, ok := added[name]
			if !ok {
				// Replaced later in the same layer by a directory or symlink.
				continue
			}
			if !listed[name] {
				listed[name] = true
				names = append(names, name)
			}
			merged[name] = file
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
func (g *imageGroup) readLayer(ctx context.Context, p Path, layer layerRef, seen, nameBytes int, merged map[string]File) (map[string]File, []string, []shadow, int, int, error) {
	blob, err := openBlob(ctx, p, layer.digest)
	if err != nil {
		return nil, nil, nil, seen, nameBytes, err
	}
	defer func() { _ = blob.Close() }()

	reader, err := tarReader(blob)
	if err != nil {
		return nil, nil, nil, seen, nameBytes, fmt.Errorf("acr: reading layer %s: %w", layer.digest, err)
	}
	archive := tar.NewReader(reader)
	added := map[string]File{}
	var order []string
	var shadows []shadow
	var links []hardLink
	// writtenAt records the header ordinal that last decided each path, so a
	// hard link resolved afterwards cannot undo a later header.
	writtenAt := map[string]int{}
	ordinal := 0
	// occurrences counts headers per path so a duplicated entry can be found
	// again: a tar is a log, and the last write of a path is the live one.
	occurrences := map[string]int{}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			// archive.Next stops at the tar end marker, which can come before
			// the blob does. go-containerregistry only checks the digest when
			// its reader reaches EOF, so the rest is drained rather than
			// caching names and sizes taken from an unverified layer.
			if _, drainErr := io.Copy(io.Discard, reader); drainErr != nil {
				return nil, nil, nil, seen, nameBytes, fmt.Errorf("acr: verifying layer %s: %w", layer.digest, drainErr)
			}
			g.resolveLinks(links, added, &order, writtenAt, merged)
			return added, order, shadows, seen, nameBytes, nil
		}
		if err != nil {
			return nil, nil, nil, seen, nameBytes, fmt.Errorf("acr: reading layer %s: %w", layer.digest, err)
		}
		// Every header costs memory somewhere — the occurrence map, the
		// whiteout list, or the entry map — so the bound is applied before
		// any of them grows. Counting only the files that survive validation
		// would let a layer of directories or unsafe names exhaust it freely.
		seen++
		if err := g.budget.charge(g, budgetUse{entries: seen, names: nameBytes}); err != nil {
			return nil, nil, nil, seen, nameBytes, err
		}
		// The entry count alone does not bound memory: a name is
		// registry-controlled and PAX or GNU long names can be enormous, so a
		// few entries could exhaust the budget the count is meant to protect.
		// A link target is retained just as a name is, so it is charged too.
		if len(header.Name) > maxEntryNameBytes || len(header.Linkname) > maxEntryNameBytes {
			continue
		}
		nameBytes += len(header.Name) + len(header.Linkname)
		if err := g.budget.charge(g, budgetUse{entries: seen, names: nameBytes}); err != nil {
			return nil, nil, nil, seen, nameBytes, err
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
		if kind == entryLink {
			// Resolved once the layer's own entries are known, since a link
			// may name one of them.
			ordinal++
			links = append(links, hardLink{name: full, target: header.Linkname, at: ordinal})
			continue
		}
		ordinal++
		if kind != entryFile {
			// A tar is a log: this also replaces what the same layer wrote
			// earlier at that path, and for anything but a directory the
			// entries beneath it go too — a symlink has no children.
			delete(added, full)
			if kind != entryDir {
				removeUnderOne(added, full)
			}
			writtenAt[full] = ordinal
			shadows = append(shadows, shadow{path: full, subtree: kind != entryDir})
			continue
		}
		if _, exists := added[full]; !exists {
			order = append(order, full)
		}
		writtenAt[full] = ordinal
		added[full] = File{
			Name:     full,
			Size:     header.Size,
			Digest:   layer.digest,
			TarPath:  header.Name,
			TarIndex: index,
		}
	}
}

// hardLink is a second name for a file the archive already carries.
type hardLink struct {
	name   string
	target string
	// at is the header ordinal, so a link cannot resurrect a path that a later
	// header replaced: a tar is a log and the last write wins.
	at int
}

// resolveLinks turns hard links into entries of their own, taking the target's
// content. A link resolves against the layer that declared it first, then the
// layers below, and one whose target cannot be found is dropped rather than
// listed as something unreadable.
func (g *imageGroup) resolveLinks(links []hardLink, added map[string]File, order *[]string, writtenAt map[string]int, merged map[string]File) {
	for _, link := range links {
		if at, ok := writtenAt[link.name]; ok && at > link.at {
			// A later header already decided this path.
			continue
		}
		target := strings.TrimPrefix(link.target, "./")
		target = strings.TrimSuffix(target, "/")
		if target == "" || strings.HasPrefix(target, "/") || !isSafeEntryName(target) {
			continue
		}
		if g.prefix != "" {
			target = g.prefix + "/" + target
		}
		source, ok := added[target]
		if !ok {
			source, ok = merged[target]
		}
		if !ok {
			continue
		}
		if _, exists := added[link.name]; !exists {
			*order = append(*order, link.name)
		}
		added[link.name] = File{
			Name:     link.name,
			Size:     source.Size,
			Digest:   source.Digest,
			TarPath:  source.TarPath,
			TarIndex: source.TarIndex,
		}
		writtenAt[link.name] = link.at
	}
}

// removeUnderOne deletes every entry beneath a single path.
func removeUnderOne(entries map[string]File, dir string) {
	prefix := dir + "/"
	for name := range entries {
		if strings.HasPrefix(name, prefix) {
			delete(entries, name)
		}
	}
}

// removeUnder deletes every entry that lies beneath one of roots.
//
// It walks each surviving name's ancestors rather than testing every root
// against every name, so applying a layer costs the size of the merged set
// times path depth instead of the product of the two sets. Ancestors are found
// by slash position: path.Dir re-cleans and rescans the shrinking prefix each
// time, which makes a deeply segmented registry-controlled name quadratic in
// its own length.
func removeUnder(merged map[string]File, roots map[string]bool) {
	if len(roots) == 0 {
		return
	}
	for name := range merged {
		for cut := strings.LastIndexByte(name, '/'); cut > 0; cut = strings.LastIndexByte(name[:cut], '/') {
			if roots[name[:cut]] {
				delete(merged, name)
				break
			}
		}
	}
}

// entryKind distinguishes a streamable file from the entries that only shadow
// what lies beneath them.
type entryKind int

const (
	entryFile entryKind = iota
	// entryLink is a hard link: a second name for a file already in the
	// archive, so it is a regular file in the resulting image.
	entryLink
	// entryDir is a directory: it replaces a lower file at the same path, but
	// its contents merge rather than being hidden.
	entryDir
	// entryOther is a symlink, hardlink or device. It cannot be served as
	// bytes, and it replaces whatever the lower layers had at that path.
	entryOther
	entryWhiteout
	entryOpaque
)

// shadow is a path a layer hides from the layers below it.
type shadow struct {
	path string
	// subtree is set when everything beneath path goes too. A directory only
	// displaces a file of the same name; a whiteout or a symlink takes the
	// whole subtree.
	subtree bool
}

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
		if after == "" {
			// A bare ".wh." names nothing. Treating it as a whiteout would
			// delete the parent directory and everything under it.
			return "", entryFile, false
		}
		removed := path.Join(path.Dir(raw), after)
		if !isSafeEntryName(removed) {
			return "", entryFile, false
		}
		return removed, entryWhiteout, true
	}

	if header.Typeflag == tar.TypeDir {
		if !isSafeEntryName(raw) {
			return "", entryFile, false
		}
		return raw, entryDir, true
	}
	if header.Typeflag == tar.TypeLink {
		// A hard link is another name for a file already in the archive, so it
		// is a regular file in the image rather than something to drop.
		if !isSafeEntryName(raw) {
			return "", entryFile, false
		}
		return raw, entryLink, true
	}
	if header.Typeflag != tar.TypeReg {
		// Not streamable, but still a replacement: OCI applies it over
		// whatever the lower layers put at this path, so reporting the file
		// underneath would describe a filesystem the image does not have.
		if !isSafeEntryName(raw) {
			return "", entryFile, false
		}
		return raw, entryOther, true
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
	// notFound reports a missing entry only once the layer has been verified:
	// a registry that altered the blob so the indexed entry disappeared would
	// otherwise look like an ordinary missing file rather than tampering.
	notFound := func() (io.ReadCloser, error) {
		if _, drainErr := io.Copy(io.Discard, reader); drainErr != nil {
			_ = blob.Close()
			return nil, fmt.Errorf("acr: verifying layer %s: %w", file.Digest, drainErr)
		}
		_ = blob.Close()
		return nil, &notFoundError{path: p.String()}
	}
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return notFound()
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
			return notFound()
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
