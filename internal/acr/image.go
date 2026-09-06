package acr

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
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

// maxImageLayers bounds the filesystem layers of a single manifest. Applying
// each one costs a pass over the entries below it, so the work is the layer
// count times the entry count; bounding only the entries leaves that product
// to the registry. Docker itself stops at 127, so this is well clear of any
// real image.
const maxImageLayers = 1024

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
	// urls is what a non-distributable descriptor says about where the blob
	// lives. They are never fetched — following a registry-supplied URL is the
	// redirect this package refuses everywhere — but naming them turns "not
	// found" into something the user can act on.
	urls []string
}

// explainMissing turns a bare "not found" for a non-distributable layer into
// something actionable.
//
// A registry is not obliged to hold a foreign blob: the descriptor names where
// it really lives, and bbb will not fetch that URL, so the user has to mirror
// the blob into the registry themselves. A plain 404 against a digest gives
// them nothing to go on.
func (l layerRef) explainMissing(err error) error {
	if len(l.urls) == 0 || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fmt.Errorf(
		"acr: layer %s is non-distributable and this registry does not hold it; "+
			"the manifest says it lives at %s, which bbb will not fetch — mirror it into the registry first: %w",
		l.digest, strings.Join(l.urls, ", "), err)
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

// settled returns the group's entries once expansion has completed.
func (g *imageGroup) settled() ([]File, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.entries, g.done
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
	// listed guards the order slice: a name a layer writes more than once is
	// still one entry, and appending on every reappearance would list it twice.
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
		return nil, nil, nil, seen, nameBytes, layer.explainMissing(err)
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
	// replacements is the *final* non-whiteout state of each path in this
	// layer, since a tar is a log: a symlink followed by a directory header
	// leaves a directory, whose children merge, so the symlink's subtree
	// removal must not survive. Whiteouts are kept separately because they
	// remove from the layers below whatever this layer later puts there.
	replacements := map[string]bool{}
	var replaced []string
	var links []hardLink
	// writtenAt records the header ordinal that last decided each path, so a
	// hard link resolved afterwards cannot undo a later header. nonDirAt is
	// the subset of those that left something other than a directory, which is
	// what displaces the entries beneath a path.
	writtenAt := map[string]int{}
	nonDirAt := map[string]int{}
	ordinal := 0
	// occurrences counts headers per path so a duplicated entry can be found
	// again: a tar is a log, and the last write of a path is the live one.
	occurrences := map[string]int{}
	// whitedOut is the paths this layer has removed from the layers below so
	// far, so a hard link written afterwards cannot reach through one.
	whitedOut := map[string]bool{}
	// claimed is the paths a hard link has taken but not filled, so another
	// link naming one of them does not fall through to the layers below.
	claimed := map[string]bool{}
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
			g.resolveLinks(links, added, &order, writtenAt, nonDirAt, merged, whitedOut, claimed)
			reconcileLayerTree(added, writtenAt, nonDirAt)
			for _, name := range replaced {
				if subtree, still := replacements[name]; still {
					shadows = append(shadows, shadow{path: name, subtree: subtree})
				}
			}
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
		if len(header.Name) > maxEntryNameBytes {
			continue
		}
		nameBytes += len(header.Name)
		// Only a hard link's target is retained, and an oversized one costs
		// the link its identity rather than the whole header: a symlink or
		// link still replaces what the lower layers had at that path, and
		// dropping the header outright would leave that file visible.
		oversizedTarget := header.Typeflag == tar.TypeLink && len(header.Linkname) > maxEntryNameBytes
		if header.Typeflag == tar.TypeLink && !oversizedTarget {
			nameBytes += len(header.Linkname)
		}
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
			ordinal++
			// A link header is the last word on its path whether or not it
			// can be resolved, so what stood there — in this layer or below —
			// is replaced before the target is even looked for. An oversized
			// target leaves nothing to resolve; anything else is attempted.
			delete(added, full)
			writtenAt[full] = ordinal
			nonDirAt[full] = ordinal
			if _, seenBefore := replacements[full]; !seenBefore {
				replaced = append(replaced, full)
			}
			replacements[full] = true
			if oversizedTarget {
				continue
			}
			link := hardLink{name: full, target: header.Linkname, at: ordinal}
			// A link takes the content its target has when the link is
			// written, not what a later header puts there: an extractor calls
			// link() at this point in the log, so a subsequent header at the
			// target replaces that file and leaves this one alone. Resolving
			// here is also what POSIX expects, since a link's target precedes
			// it. Only a forward reference has to wait for the layer to end.
			if target, usable := g.linkTarget(link, writtenAt); usable &&
				g.installLink(link, target, added, &order, writtenAt, nonDirAt, merged, whitedOut, claimed) {
				continue
			}
			// Still claimed, and now empty: another link naming this path must
			// not resolve against what the layers below had there.
			claimed[full] = true
			links = append(links, link)
			continue
		}
		if kind == entryWhiteout || kind == entryOpaque {
			// A whiteout removes from the layers below and nothing else. Its
			// own layer's entries stand whichever side of it they appear on,
			// so an opaque marker written after the directory it covers still
			// hides only what was underneath — the spec's "applies to lower
			// layers" does not depend on position in the tar. Nothing here
			// decides a path for this layer, so no ordinal is recorded either:
			// a hard link declared earlier is still the live entry.
			shadows = append(shadows, shadow{path: full, subtree: true})
			// A link written after this one cannot reach through it to the
			// layers below: by then the extractor has removed that path.
			whitedOut[full] = true
			continue
		}
		ordinal++
		if kind != entryFile {
			// A tar is a log, so this replaces what the same layer wrote
			// earlier at that path. What it does to the entries beneath is
			// settled once the layer ends, from the ordinals recorded here.
			delete(added, full)
			writtenAt[full] = ordinal
			if kind == entryDir {
				delete(nonDirAt, full)
			} else {
				nonDirAt[full] = ordinal
			}
			if _, seenBefore := replacements[full]; !seenBefore {
				replaced = append(replaced, full)
			}
			replacements[full] = kind != entryDir
			continue
		}
		if _, exists := added[full]; !exists {
			order = append(order, full)
		}
		// A regular file supersedes any earlier replacement of this path; the
		// subtree it displaces is handled with the other added names.
		delete(replacements, full)
		writtenAt[full] = ordinal
		nonDirAt[full] = ordinal
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

// resolveLinks settles the hard links that could not resolve where they were
// written, because they name something the layer only defines later.
//
// A link may name another link, so this is a graph walk rather than a sweep: a
// chain written back to front — each link naming the one after it — would let
// a pass-per-link resolver settle a single link per pass, and the entry
// allowance is half a million, so a crafted layer could cost the square of it.
// Each link is instead visited once, following its target through the links
// that have not settled yet. A cycle is left unresolved, so it is dropped like
// any other target that cannot be found.
func (g *imageGroup) resolveLinks(links []hardLink, added map[string]File, order *[]string, writtenAt, nonDirAt map[string]int, merged map[string]File, whitedOut, claimed map[string]bool) {
	if len(links) == 0 {
		return
	}
	// A tar is a log, so the live link at a name is the last to claim it, and
	// that is the one another link naming it depends on.
	byName := make(map[string]int, len(links))
	for i, link := range links {
		byName[link.name] = i
	}
	const (
		unvisited = iota
		visiting
		settled
	)
	state := make([]uint8, len(links))
	// The stack is explicit rather than the call stack: a chain can be as long
	// as the layer has entries.
	stack := make([]int, 0, 16)
	for i := range links {
		if state[i] != unvisited {
			continue
		}
		state[i] = visiting
		stack = append(stack[:0], i)
		for len(stack) > 0 {
			top := stack[len(stack)-1]
			target, ok := g.linkTarget(links[top], writtenAt)
			if ok {
				if _, found := added[target]; !found {
					// The target may be a link that has not been installed
					// yet, in which case it has to settle first.
					if next, isLink := byName[target]; isLink && state[next] == unvisited {
						state[next] = visiting
						stack = append(stack, next)
						continue
					}
				}
				g.installLink(links[top], target, added, order, writtenAt, nonDirAt, merged, whitedOut, claimed)
			}
			// Installed, spent, dangling, or part of a cycle: either way this
			// link is finished with.
			state[top] = settled
			stack = stack[:len(stack)-1]
		}
	}
}

// linkTarget renders a hard link's target as the name it would carry in the
// listing, reporting false when the link can install nothing.
func (g *imageGroup) linkTarget(link hardLink, writtenAt map[string]int) (string, bool) {
	if at, ok := writtenAt[link.name]; ok && at > link.at {
		// A later header already decided this path, so the link is spent.
		return "", false
	}
	target := strings.TrimPrefix(link.target, "./")
	target = strings.TrimSuffix(target, "/")
	if target == "" || strings.HasPrefix(target, "/") || !isSafeEntryName(target) {
		return "", false
	}
	if g.prefix != "" {
		target = g.prefix + "/" + target
	}
	return target, true
}

// installLink gives a link the content of the entry it names, reporting
// whether the target was there to take.
func (g *imageGroup) installLink(link hardLink, target string, added map[string]File, order *[]string, writtenAt, nonDirAt map[string]int, merged map[string]File, whitedOut, claimed map[string]bool) bool {
	source, ok := added[target]
	if !ok {
		// The target may belong to a lower layer, which an extractor links
		// against because it links against the merged tree. Not, however, if
		// this layer has already removed it, or if a link of its own has
		// taken that path without filling it: either way there is nothing
		// left at the target to link to.
		if claimed[target] || coveredByWhiteout(whitedOut, target) {
			return false
		}
		source, ok = merged[target]
	}
	if !ok {
		return false
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
	// A link is a file, so it displaces whatever the same layer wrote beneath
	// its path, exactly as a regular file does.
	nonDirAt[link.name] = link.at
	// The path now holds something, so a link naming it can resolve.
	delete(claimed, link.name)
	return true
}

// coveredByWhiteout reports whether a path, or a directory holding it, has
// been removed from the layers below.
func coveredByWhiteout(whitedOut map[string]bool, name string) bool {
	if len(whitedOut) == 0 {
		return false
	}
	if whitedOut[name] {
		return true
	}
	for cut := strings.LastIndexByte(name, '/'); cut > 0; cut = strings.LastIndexByte(name[:cut], '/') {
		if whitedOut[name[:cut]] {
			return true
		}
	}
	return false
}

// reconcileLayerTree applies one layer's file-over-directory replacements to
// that layer's own entries.
//
// A tar is a log: a regular file, symlink or hard link at a path replaces
// whatever the same layer wrote beneath it, and an entry written deeper
// afterwards makes that path a directory again. Without this a layer holding
// "app/config" and then a regular "app" keeps both, and the artifact is
// rejected as a file that is also a directory instead of honouring the last
// header.
//
// It runs once, from the ordinals already recorded, so each entry costs its
// own depth. Removing a subtree as each header arrives instead scans the whole
// layer per header, which a layer of nothing but symlinks makes quadratic.
func reconcileLayerTree(added map[string]File, writtenAt, nonDirAt map[string]int) {
	for name := range added {
		at := writtenAt[name]
		for cut := strings.LastIndexByte(name, '/'); cut > 0; cut = strings.LastIndexByte(name[:cut], '/') {
			ancestor := name[:cut]
			ancestorAt, ok := nonDirAt[ancestor]
			if !ok {
				continue
			}
			if ancestorAt > at {
				// A later header put a file where this entry's parent was.
				delete(added, name)
				break
			}
			// This entry is deeper and later, so its parent is a directory
			// again and whatever stood there is gone.
			delete(added, ancestor)
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
	// The whole path is checked before any of it is interpreted. Deriving a
	// whiteout target first would let path.Join clean a traversal away, so
	// "tmp/../.wh.keep" would be accepted as a whiteout for "keep" — removing
	// a file the entry never legitimately named.
	if !isSafeEntryName(raw) {
		return "", entryFile, false
	}

	base := path.Base(raw)
	// raw is canonical, so this is the parent with its trailing slash, or
	// empty at the root.
	parent := raw[:len(raw)-len(base)]
	if base == whiteoutOpaque {
		if parent == "" {
			// A root opaque whiteout is valid and hides every lower entry.
			return "", entryOpaque, true
		}
		return strings.TrimSuffix(parent, "/"), entryOpaque, true
	}
	if after, found := strings.CutPrefix(base, whiteoutPrefix); found {
		if after == "" {
			// A bare ".wh." names nothing. Treating it as a whiteout would
			// delete the parent directory and everything under it.
			return "", entryFile, false
		}
		removed := parent + after
		if !isSafeEntryName(removed) {
			return "", entryFile, false
		}
		return removed, entryWhiteout, true
	}

	if header.Typeflag == tar.TypeDir {
		return raw, entryDir, true
	}
	if header.Typeflag == tar.TypeLink {
		// A hard link is another name for a file already in the archive, so it
		// is a regular file in the image rather than something to drop.
		return raw, entryLink, true
	}
	if header.Typeflag != tar.TypeReg {
		// Not streamable, but still a replacement: OCI applies it over
		// whatever the lower layers put at this path, so reporting the file
		// underneath would describe a filesystem the image does not have.
		return raw, entryOther, true
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
