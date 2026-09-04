package acr

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// tarGz builds a gzipped tar layer, the form a container image layer takes.
// Entries are written in order so a later one can shadow an earlier one.
func tarGz(t *testing.T, entries ...[2]string) v1.Layer {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	for _, entry := range entries {
		name, content := entry[0], entry[1]
		header := &tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg}
		if strings.HasSuffix(name, "/") {
			header = &tar.Header{Name: name, Mode: 0o755, Typeflag: tar.TypeDir}
		}
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := archive.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return static.NewLayer(raw.Bytes(), types.DockerLayer)
}

func imageWithLayers(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	image, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		t.Fatal(err)
	}
	return image
}

// pushIndex publishes a multi-platform index, the shape a container image built
// for several os/arch pairs takes.
func pushIndex(t *testing.T, p Path, images map[string]v1.Image) {
	t.Helper()
	index := v1.ImageIndex(empty.Index)
	for platform, image := range images {
		os, arch, _ := strings.Cut(platform, "/")
		index = mutate.AppendManifests(index, mutate.IndexAddendum{
			Add: image,
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{OS: os, Architecture: arch},
			},
		})
	}
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex failed: %v", err)
	}
	invalidateLayers(p)
}

func entryNames(entries []Entry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name
		if entry.IsDir {
			name += "/"
		}
		names = append(names, name)
	}
	return names
}

// A multi-platform image repeats the same file name once per platform, so the
// platform is what tells its members apart. Without it every member is an
// indistinguishable digest.
func TestImageIndexListsPlatformsThenContents(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "orng", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64":   imageWithLayers(t, tarGz(t, [2]string{"orng", "linux-amd64-binary"})),
		"windows/amd64": imageWithLayers(t, tarGz(t, [2]string{"orng.exe", "windows-binary"})),
	})

	root, err := ListDir(t.Context(), p)
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	got := entryNames(root)
	want := map[string]bool{"linux/": true, "windows/": true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] {
		t.Fatalf("root listing = %v, want the platform directories", got)
	}

	arch := p
	arch.File = "linux/amd64"
	contents, err := ListDir(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListDir(linux/amd64) failed: %v", err)
	}
	if names := entryNames(contents); len(names) != 1 || names[0] != "orng" {
		t.Fatalf("linux/amd64 listing = %v, want [orng]", names)
	}

	// The binary is addressable, and reads as the file inside the layer rather
	// than as the layer's tarball.
	binary := p
	binary.File = "linux/amd64/orng"
	file, err := Stat(t.Context(), binary)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if file.Size != int64(len("linux-amd64-binary")) {
		t.Errorf("size = %d, want the entry size not the layer size", file.Size)
	}
	reader, err := DownloadStream(t.Context(), binary)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != "linux-amd64-binary" {
		t.Fatalf("content = %q (%v), want the linux/amd64 binary", content, err)
	}
}

// Expanding a layer means transferring it, so listing the root of an image must
// be answered from the index alone. A layer that cannot be read at all proves
// it was never opened.
func TestImageRootListingDoesNotExpandLayers(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "broken", Reference: "latest"}
	corrupt := static.NewLayer([]byte{0x1f, 0x8b, 0x00, 0x00}, types.DockerLayer)
	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, corrupt),
	})

	root, err := ListDir(t.Context(), p)
	if err != nil {
		t.Fatalf("listing the root must not read layers: %v", err)
	}
	if names := entryNames(root); len(names) != 1 || names[0] != "linux/" {
		t.Fatalf("root listing = %v, want [linux/]", names)
	}

	// Descending is what reads it, and that failure must surface.
	arch := p
	arch.File = "linux/amd64"
	if _, err := ListDir(t.Context(), arch); err == nil {
		t.Fatal("expected the unreadable layer to fail when expanded")
	}
}

// Layers overlay: a later one replaces what an earlier one wrote and removes it
// with a whiteout, so only the result of applying all of them describes the
// image.
func TestImageLayersOverlay(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "overlay", Reference: "latest"}
	base := tarGz(t,
		[2]string{"keep.txt", "original"},
		[2]string{"replaced.txt", "old"},
		[2]string{"removed.txt", "doomed"},
	)
	top := tarGz(t,
		[2]string{"replaced.txt", "new"},
		[2]string{".wh.removed.txt", ""},
	)
	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, base, top),
	})

	arch := p
	arch.File = "linux/amd64"
	entries, err := ListDir(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	names := entryNames(entries)
	if len(names) != 2 {
		t.Fatalf("listing = %v, want the whiteout applied", names)
	}
	for _, name := range names {
		if name == "removed.txt" {
			t.Errorf("a whiteout must remove %q", name)
		}
	}

	replaced := p
	replaced.File = "linux/amd64/replaced.txt"
	reader, err := DownloadStream(t.Context(), replaced)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != "new" {
		t.Fatalf("content = %q (%v), want the upper layer to win", content, err)
	}
}

// Tar entry names come from the registry and are validated as written rather
// than repaired: cleaning first would turn a traversal into an ordinary-looking
// name that can alias a legitimate entry.
func TestImageLayerRejectsUnsafeEntries(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "unsafe", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, tarGz(t,
			[2]string{"../escape", "nope"},
			[2]string{"/absolute", "nope"},
			[2]string{`..\windows`, "nope"},
			[2]string{"dir/", ""},
			[2]string{"./safe.txt", "fine"},
		)),
	})

	arch := p
	arch.File = "linux/amd64"
	entries, err := ListDir(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListDir failed: %v", err)
	}
	names := entryNames(entries)
	// A traversal must be dropped, not admitted under a repaired name: neither
	// "escape" nor "absolute" may appear.
	for _, name := range names {
		switch name {
		case "escape", "absolute", "windows", "dir/":
			t.Errorf("unsafe or non-file entry survived as %q", name)
		}
		if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
			t.Errorf("unsafe entry survived: %q", name)
		}
	}
	// A leading "./" is how tools routinely write layer paths and means
	// nothing, so that entry is kept.
	if !slicesContains(names, "safe.txt") {
		t.Errorf("listing = %v, want the safe entry kept", names)
	}
}

// A whiteout hides what lower layers put there, including a whole directory,
// and an opaque whiteout at the root hides everything.
func TestImageWhiteoutRemovesSubtrees(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "whiteout", Reference: "latest"}
	base := tarGz(t,
		[2]string{"dir/keep.txt", "a"},
		[2]string{"dir/nested/deep.txt", "b"},
		[2]string{"top.txt", "c"},
	)
	// Removing "dir" must take its descendants with it.
	top := tarGz(t, [2]string{"dir/.wh.nested", ""}, [2]string{"new.txt", "d"})
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t, base, top)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	for _, file := range files {
		if strings.Contains(file.Name, "nested") {
			t.Errorf("a whiteout on a directory must remove its contents, kept %q", file.Name)
		}
	}

	// A whiteout must not hide a file its own layer provides, whatever order
	// the entries appear in: it removes from the layers below only.
	q := Path{Registry: host, Repository: "samelayer", Reference: "latest"}
	pushIndex(t, q, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"a.txt", "old"}, [2]string{"b.txt", "old"}),
		tarGz(t, [2]string{".wh.a.txt", ""}, [2]string{"a.txt", "new"}),
		tarGz(t, [2]string{"b.txt", "new"}, [2]string{".wh.b.txt", ""}),
	)})
	q.File = "linux/amd64"
	kept, err := ListFiles(t.Context(), q)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(kept))
	for _, file := range kept {
		names = append(names, file.Name)
	}
	slices.Sort(names)
	want := []string{"linux/amd64/a.txt", "linux/amd64/b.txt"}
	if !slices.Equal(names, want) {
		t.Fatalf("listing = %v, want each layer's own file kept: %v", names, want)
	}
}

// A root opaque whiteout is valid and hides every entry from lower layers.
func TestImageRootOpaqueWhiteout(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "opaque", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"old.txt", "gone"}, [2]string{"sub/old.txt", "gone"}),
		tarGz(t, [2]string{".wh..wh..opq", ""}, [2]string{"new.txt", "kept"}),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "linux/amd64/new.txt" {
		t.Fatalf("listing = %#v, want only the upper layer's file", files)
	}

	// An opaque marker hides the lower layers whichever side of its own
	// layer's entries it is written on.
	q := Path{Registry: host, Repository: "opaquelate", Reference: "latest"}
	pushIndex(t, q, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"sub/old.txt", "gone"}),
		tarGz(t, [2]string{"sub/new.txt", "kept"}, [2]string{"sub/.wh..wh..opq", ""}),
	)})
	q.File = "linux/amd64"
	late, err := ListFiles(t.Context(), q)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(late) != 1 || late[0].Name != "linux/amd64/sub/new.txt" {
		t.Fatalf("listing = %#v, want the marker's own layer kept and the lower one hidden", late)
	}
}

// A tar is a log, so the same path can appear twice and the last header is the
// live one. The listing and the download must agree on which that is.
func TestImageDuplicateTarEntries(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "dupes", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"app", "first-version"}, [2]string{"app", "second"}),
	)})

	file := p
	file.File = "linux/amd64/app"
	stat, err := Stat(t.Context(), file)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	reader, err := DownloadStream(t.Context(), file)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(content) != "second" {
		t.Fatalf("content = %q, want the last entry", content)
	}
	if stat.Size != int64(len(content)) {
		t.Fatalf("stat size %d does not describe the served entry (%d bytes)", stat.Size, len(content))
	}
}

// Image entries are held to the same coexistence rules as layer titles, so a
// registry cannot hand back a pair that maps to one local path.
func TestImageRejectsCollidingNames(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "collide", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"A.txt", "upper"}, [2]string{"a.txt", "lower"}),
	)})

	arch := p
	arch.File = "linux/amd64"
	if _, err := ListFiles(t.Context(), arch); err == nil ||
		!strings.Contains(err.Error(), "differ only by case or Unicode normalisation") {
		t.Fatalf("expected colliding image names to be rejected, got %v", err)
	}
}

func slicesContains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

// An upper layer's directory, symlink or device replaces whatever the lower
// layers had at that path. Reporting the file underneath would describe a
// filesystem the image does not have.
func TestImageNonRegularEntriesReplaceLowerFiles(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "replace", Reference: "latest"}

	base := tarGz(t,
		[2]string{"becomes-dir", "file"},
		[2]string{"becomes-link", "file"},
		[2]string{"becomes-link/child", "under"},
		[2]string{"survives.txt", "kept"},
	)
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	for _, header := range []*tar.Header{
		{Name: "becomes-dir", Mode: 0o755, Typeflag: tar.TypeDir},
		{Name: "becomes-link", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "elsewhere"},
	} {
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	top := static.NewLayer(raw.Bytes(), types.DockerLayer)

	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t, base, top)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	for _, gone := range []string{
		"linux/amd64/becomes-dir",        // now a directory
		"linux/amd64/becomes-link",       // now a symlink
		"linux/amd64/becomes-link/child", // and its subtree went with it
	} {
		if slicesContains(names, gone) {
			t.Errorf("%q was replaced by a non-regular entry and must not be listed", gone)
		}
	}
	if !slicesContains(names, "linux/amd64/survives.txt") {
		t.Errorf("listing = %v, want the untouched file kept", names)
	}
}

// Two manifests can carry the same platform, or none at all. Merging them
// would overlay unrelated filesystems, so the ambiguity is reported.
func TestImageRejectsAmbiguousPlatforms(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "ambiguous", Reference: "latest"}

	index := v1.ImageIndex(empty.Index)
	for _, content := range []string{"first", "second"} {
		index = mutate.AppendManifests(index, mutate.IndexAddendum{
			Add: imageWithLayers(t, tarGz(t, [2]string{"app", content})),
			Descriptor: v1.Descriptor{
				Platform: &v1.Platform{OS: "linux", Architecture: "amd64"},
			},
		})
	}
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex failed: %v", err)
	}
	invalidateLayers(p)

	if _, err := ListDir(t.Context(), p); err == nil ||
		!strings.Contains(err.Error(), "cannot be told apart") {
		t.Fatalf("expected duplicate platforms to be rejected, got %v", err)
	}
}

// A regular file in an upper layer replaces a lower directory, so nothing
// beneath that path survives — otherwise a file and a directory are reported
// at one path, which no filesystem can hold.
func TestImageFileReplacesLowerDirectory(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "shadowdir", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"app/config", "old"}, [2]string{"keep.txt", "kept"}),
		tarGz(t, [2]string{"app", "now-a-file"}),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	if slicesContains(names, "linux/amd64/app/config") {
		t.Errorf("listing = %v, want the lower directory replaced by the file", names)
	}
	if !slicesContains(names, "linux/amd64/app") || !slicesContains(names, "linux/amd64/keep.txt") {
		t.Errorf("listing = %v, want the file and the untouched entry", names)
	}
}

// A bare ".wh." names nothing. Treating it as a whiteout would delete the
// directory holding it, along with everything beneath.
func TestImageIgnoresEmptyWhiteout(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "emptywh", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"dir/keep.txt", "kept"}),
		tarGz(t, [2]string{"dir/.wh.", ""}),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "linux/amd64/dir/keep.txt" {
		t.Fatalf("listing = %#v, want the malformed whiteout ignored", files)
	}
}

// An unusable platform must be reported, not quietly rehomed: sharing the
// empty prefix with genuinely absent metadata would merge an unrelated
// manifest into the artifact root.
func TestImageRejectsUnusablePlatform(t *testing.T) {
	if _, err := platformPrefix(&v1.Platform{OS: "../bad", Architecture: "amd64"}); err == nil {
		t.Error("expected a traversal in a platform to be rejected")
	}
	if _, err := platformPrefix(&v1.Platform{OS: "linux", Architecture: "a:b"}); err == nil {
		t.Error("expected a colon in a platform to be rejected")
	}
	// Partial metadata is not absent metadata.
	if _, err := platformPrefix(&v1.Platform{OS: "linux"}); err == nil {
		t.Error("expected a platform with no architecture to be rejected")
	}
	if _, err := platformPrefix(&v1.Platform{Architecture: "amd64"}); err == nil {
		t.Error("expected a platform with no OS to be rejected")
	}
	// Genuinely absent metadata still means the artifact root.
	if prefix, err := platformPrefix(nil); err != nil || prefix != "" {
		t.Errorf("platformPrefix(nil) = %q (%v), want the root", prefix, err)
	}
	if prefix, err := platformPrefix(&v1.Platform{OS: "linux", Architecture: "amd64", Variant: "v8"}); err != nil || prefix != "linux/amd64/v8" {
		t.Errorf("platformPrefix = %q (%v), want linux/amd64/v8", prefix, err)
	}
}

// A tar need not announce a directory before the files in it, so an upper
// layer can turn a lower regular file into a directory implicitly. The lower
// file has to go, while its siblings stay.
func TestImageImplicitDirectoryReplacesLowerFile(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "implicitdir", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"app", "was-a-file"}, [2]string{"sibling.txt", "kept"}),
		// No "app/" header, which is valid.
		tarGz(t, [2]string{"app/config", "now-a-directory"}),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	if slicesContains(names, "linux/amd64/app") {
		t.Errorf("listing = %v, want the lower file replaced by the directory", names)
	}
	if !slicesContains(names, "linux/amd64/app/config") {
		t.Errorf("listing = %v, want the upper file", names)
	}
	if !slicesContains(names, "linux/amd64/sibling.txt") {
		t.Errorf("listing = %v, want unrelated lower entries kept", names)
	}
}

// The budget bounds the whole artifact, not each manifest: an index is
// registry-controlled and can declare any number of platforms, so a per-group
// limit would be no limit at all.
func TestImageBudgetIsSharedAcrossGroups(t *testing.T) {
	budget := newImageBudget()
	first := &imageGroup{prefix: "linux/amd64", budget: budget}
	second := &imageGroup{prefix: "linux/arm64", budget: budget}

	if err := budget.charge(first, budgetUse{entries: maxTarEntries - 1}); err != nil {
		t.Fatalf("the first group should fit: %v", err)
	}
	if err := budget.charge(second, budgetUse{entries: 2}); err == nil {
		t.Fatal("a second group must not be granted its own full allowance")
	}
	if err := budget.charge(second, budgetUse{names: maxTotalNameBytes + 1}); err == nil {
		t.Fatal("the name budget must be shared too")
	}

	// A group re-read after a failure replaces its own contribution rather
	// than adding to it, or a retry would exhaust the budget by itself.
	if err := budget.charge(first, budgetUse{entries: 1}); err != nil {
		t.Fatalf("re-charging one group must replace its earlier use: %v", err)
	}
	if err := budget.charge(second, budgetUse{entries: maxTarEntries - 2}); err != nil {
		t.Fatalf("the released allowance should be available: %v", err)
	}

	// The running sums must agree with what the groups actually hold, since
	// they are what every charge is decided against.
	budget.mu.Lock()
	total := 0
	for _, use := range budget.used {
		total += use.entries
	}
	aggregate := budget.entries
	budget.mu.Unlock()
	if aggregate != total {
		t.Fatalf("aggregate = %d, want %d: the running sum has drifted", aggregate, total)
	}
}

// A symlink replaces a path and everything beneath it, including entries the
// same layer wrote earlier — a symlink has no children.
func TestImageSymlinkRemovesSameLayerDescendants(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "samelayerlink", Reference: "latest"}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	body := "under"
	if err := archive.WriteHeader(&tar.Header{
		Name: "foo/bar", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := archive.WriteHeader(&tar.Header{
		Name: "foo", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "elsewhere",
	}); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, static.NewLayer(raw.Bytes(), types.DockerLayer)),
	})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	for _, file := range files {
		if strings.HasPrefix(file.Name, "linux/amd64/foo") {
			t.Errorf("a symlink has no children, but %q is listed", file.Name)
		}
	}
}

// Non-distributable layers are ordinary tars and Windows base images use them,
// so their files must participate.
func TestImageExpandsNonDistributableLayers(t *testing.T) {
	for _, mediaType := range []types.MediaType{
		types.OCIRestrictedLayer,
		types.OCIUncompressedRestrictedLayer,
		types.DockerForeignLayer,
	} {
		if !isTarLayer(mediaType) {
			t.Errorf("%s is a tar layer and must be expanded", mediaType)
		}
	}
	// zstd stays opaque rather than becoming an error.
	if isTarLayer(types.MediaType("application/vnd.oci.image.layer.v1.tar+zstd")) {
		t.Error("zstd layers cannot be expanded without a decompressor")
	}
}

// An expansion that retained nothing must not keep its charge, or another
// platform fails against a limit counting entries no longer held.
func TestImageBudgetReleasedOnFailure(t *testing.T) {
	budget := newImageBudget()
	failed := &imageGroup{prefix: "linux/amd64", budget: budget}
	other := &imageGroup{prefix: "linux/arm64", budget: budget}

	if err := budget.charge(failed, budgetUse{entries: maxTarEntries - 1}); err != nil {
		t.Fatalf("charge failed: %v", err)
	}
	budget.release(failed)
	if err := budget.charge(other, budgetUse{entries: maxTarEntries - 1}); err != nil {
		t.Fatalf("the released allowance should be available: %v", err)
	}
}

// A title is the documented name of a file, so a layer carrying one is that
// file whatever its media type. Expanding a published tarball would scatter
// its contents and lose the name it was given.
func TestImageDoesNotExpandTitledTarLayer(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "titledtar", Reference: "latest"}

	layer := tarGz(t, [2]string{"inside.txt", "content"})
	image, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		MediaType:   types.DockerLayer,
		Annotations: map[string]string{TitleAnnotation: "bundle.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, image); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	invalidateLayers(p)

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "bundle.tar.gz" {
		t.Fatalf("listing = %#v, want the titled tarball kept whole", files)
	}
	if files[0].TarPath != "" {
		t.Error("a titled layer must be served as itself, not expanded")
	}
}

// Go's archive/tar normalises the legacy NUL type flag before a header is
// returned, so image code never observes tar.TypeRegA. This pins that, since
// the classification here depends on it.
func TestLegacyRegularTypeFlagIsNormalised(t *testing.T) {
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	// The legacy flag is a NUL byte, written literally rather than through the
	// deprecated tar.TypeRegA constant — which staticcheck rejects, and which
	// production code therefore could not compare against either.
	if err := writer.WriteHeader(&tar.Header{
		Name: "legacy", Mode: 0o644, Size: 3, Typeflag: 0, Format: tar.FormatGNU,
	}); err != nil {
		t.Skipf("this Go version refuses to write the legacy flag: %v", err)
	}
	if _, err := writer.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	reader := tar.NewReader(bytes.NewReader(raw.Bytes()))
	header, err := reader.Next()
	if err != nil {
		t.Fatalf("reading the legacy entry failed: %v", err)
	}
	if header.Typeflag != tar.TypeReg {
		t.Fatalf("typeflag = %q, want TypeReg: archive/tar no longer normalises TypeRegA", header.Typeflag)
	}
	name, kind, ok := tarEntryName(header)
	if !ok || kind != entryFile || name != "legacy" {
		t.Fatalf("tarEntryName = (%q, %v, %v), want the entry treated as a regular file", name, kind, ok)
	}
}

// A generic artifact may carry an untitled tar payload under its own config
// type. Its layers are files, not a filesystem, so expanding them would
// replace what was published with whatever is inside it.
func TestImageOnlyExpandsContainerImageConfigs(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "genericartifact", Reference: "latest"}

	image, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:     tarGz(t, [2]string{"inside.txt", "content"}),
		MediaType: types.DockerLayer,
	})
	if err != nil {
		t.Fatal(err)
	}
	image = mutate.ConfigMediaType(image, types.MediaType("application/vnd.example.config.v1+json"))
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, image); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	invalidateLayers(p)

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].TarPath != "" {
		t.Fatalf("listing = %#v, want the untitled layer left opaque under a non-image config", files)
	}
	if !strings.HasPrefix(files[0].Name, "sha256-") {
		t.Errorf("name = %q, want the digest fallback the README documents", files[0].Name)
	}
}

// A titled layer and a platform directory share one namespace, so an artifact
// where a name is both cannot be served — and that must be decided the same
// way however the path is reached.
func TestImageRejectsTitleCollidingWithPlatform(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "prefixclash", Reference: "latest"}

	titled, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       tarGz(t, [2]string{"unused", "x"}),
		MediaType:   types.MediaType("application/octet-stream"),
		Annotations: map[string]string{TitleAnnotation: "linux"},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{Add: titled},
		mutate.IndexAddendum{
			Add:        imageWithLayers(t, tarGz(t, [2]string{"orng", "binary"})),
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		},
	)
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex failed: %v", err)
	}
	invalidateLayers(p)

	// Every entry point must agree, including the ones that never expand a
	// layer.
	if _, err := ListDir(t.Context(), p); err == nil {
		t.Error("ListDir must reject a title colliding with a platform directory")
	}
	direct := p
	direct.File = "linux"
	if _, err := Stat(t.Context(), direct); err == nil {
		t.Error("Stat must reject it too, rather than serving the titled blob")
	}
}

// A hard link is a second name for a file the archive already carries, so it
// is a regular file in the image and must be listed and readable.
func TestImageResolvesHardLinks(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "hardlink", Reference: "latest"}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	body := "shared-content"
	if err := archive.WriteHeader(&tar.Header{
		Name: "bin/real", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, link := range []*tar.Header{
		{Name: "bin/alias", Mode: 0o755, Typeflag: tar.TypeLink, Linkname: "bin/real"},
		// A link whose target is not in the image is dropped rather than
		// listed as something unreadable.
		{Name: "bin/dangling", Mode: 0o755, Typeflag: tar.TypeLink, Linkname: "bin/missing"},
	} {
		if err := archive.WriteHeader(link); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, static.NewLayer(raw.Bytes(), types.DockerLayer)),
	})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	if !slicesContains(names, "linux/amd64/bin/alias") {
		t.Errorf("listing = %v, want the hard link listed", names)
	}
	if slicesContains(names, "linux/amd64/bin/dangling") {
		t.Errorf("listing = %v, want a dangling link dropped", names)
	}

	// The link serves the target's bytes.
	alias := p
	alias.File = "linux/amd64/bin/alias"
	reader, err := DownloadStream(t.Context(), alias)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != body {
		t.Fatalf("content = %q (%v), want the target's content", content, err)
	}
}

// A title beneath a platform directory is an ordinary child: a manifest may
// carry both an untitled filesystem layer and a titled metadata file.
func TestImageAllowsTitleUnderPlatformDirectory(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "mixedmanifest", Reference: "latest"}

	image, err := mutate.Append(empty.Image,
		mutate.Addendum{Layer: tarGz(t, [2]string{"orng", "binary"}), MediaType: types.DockerLayer},
		mutate.Addendum{
			Layer:       tarGz(t, [2]string{"ignored", "x"}),
			MediaType:   types.MediaType("application/octet-stream"),
			Annotations: map[string]string{TitleAnnotation: "metadata.json"},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(empty.Index, mutate.IndexAddendum{
		Add:        image,
		Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
	})
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex failed: %v", err)
	}
	invalidateLayers(p)

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	if !slicesContains(names, "linux/amd64/metadata.json") || !slicesContains(names, "linux/amd64/orng") {
		t.Fatalf("listing = %v, want the titled file alongside the expanded layer", names)
	}
}

// A tar is a log, so a regular header after a hard link must win: resolving
// links at the end must not resurrect a path a later header replaced.
func TestImageHardLinkDoesNotOverrideLaterHeader(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "linkorder", Reference: "latest"}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	write := func(name, content string) {
		if err := archive.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	write("real", "target-content")
	if err := archive.WriteHeader(&tar.Header{
		Name: "alias", Mode: 0o644, Typeflag: tar.TypeLink, Linkname: "real",
	}); err != nil {
		t.Fatal(err)
	}
	write("alias", "later-wins")
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, static.NewLayer(raw.Bytes(), types.DockerLayer)),
	})

	alias := p
	alias.File = "linux/amd64/alias"
	reader, err := DownloadStream(t.Context(), alias)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != "later-wins" {
		t.Fatalf("content = %q (%v), want the header written after the link", content, err)
	}
}

// A chain of hard links resolves whichever order it appears in, and a cycle
// stops rather than spinning.
func TestImageResolvesChainedHardLinks(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "linkchain", Reference: "latest"}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	body := "target-content"
	if err := archive.WriteHeader(&tar.Header{
		Name: "real", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	for _, link := range []*tar.Header{
		// alias1 names alias2, which is only defined afterwards.
		{Name: "alias1", Typeflag: tar.TypeLink, Linkname: "alias2"},
		{Name: "alias2", Typeflag: tar.TypeLink, Linkname: "real"},
		// A cycle resolves to nothing and must not spin.
		{Name: "loopA", Typeflag: tar.TypeLink, Linkname: "loopB"},
		{Name: "loopB", Typeflag: tar.TypeLink, Linkname: "loopA"},
	} {
		link.Mode = 0o644
		if err := archive.WriteHeader(link); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	pushIndex(t, p, map[string]v1.Image{
		"linux/amd64": imageWithLayers(t, static.NewLayer(raw.Bytes(), types.DockerLayer)),
	})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	for _, want := range []string{"linux/amd64/alias1", "linux/amd64/alias2"} {
		if !slicesContains(names, want) {
			t.Errorf("listing = %v, want the chain resolved to %s", names, want)
		}
	}
	for _, gone := range []string{"linux/amd64/loopA", "linux/amd64/loopB"} {
		if slicesContains(names, gone) {
			t.Errorf("listing = %v, want the cycle dropped", names)
		}
	}

	first := p
	first.File = "linux/amd64/alias1"
	reader, err := DownloadStream(t.Context(), first)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != body {
		t.Fatalf("content = %q (%v), want the end of the chain", content, err)
	}
}

// A hard-link chain written back to front used to settle one link per sweep,
// so a layer could make resolution cost the square of the entry allowance.
// Resolution has to be linear in the number of links.
func TestImageResolvesLongHardLinkChainLinearly(t *testing.T) {
	const chain = 50_000

	group := &imageGroup{budget: newImageBudget()}
	added := map[string]File{"real": {Name: "real", Size: 7, Digest: "sha256:abc", TarPath: "real"}}
	order := []string{"real"}
	writtenAt := map[string]int{"real": 0}

	// Each link names the one after it, and the last names the file. Written
	// in this order, no link can settle until every link below it has.
	links := make([]hardLink, 0, chain)
	for i := range chain {
		target := "real"
		if i+1 < chain {
			target = fmt.Sprintf("link%d", i+1)
		}
		links = append(links, hardLink{name: fmt.Sprintf("link%d", i), target: target, at: i + 1})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		group.resolveLinks(links, added, &order, writtenAt, map[string]File{})
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("resolving a chain of hard links did not finish; it is no longer linear")
	}

	if len(added) != chain+1 {
		t.Fatalf("resolved %d entries, want %d", len(added), chain+1)
	}
	for _, name := range []string{"link0", fmt.Sprintf("link%d", chain-1)} {
		file, ok := added[name]
		if !ok || file.TarPath != "real" {
			t.Fatalf("%s = %#v (%v), want the end of the chain", name, file, ok)
		}
	}
}

// Two groups can produce the same full name — an unprefixed manifest holding
// linux/amd64/app alongside a linux/amd64 manifest holding app — so every path
// must agree that the artifact is ambiguous, not just the recursive one.
func TestImageRejectsOverlappingGroups(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "overlapgroups", Reference: "latest"}

	index := mutate.AppendManifests(empty.Index,
		// No platform, so its entries land at the artifact root.
		mutate.IndexAddendum{Add: imageWithLayers(t, tarGz(t, [2]string{"linux/amd64/app", "root"}))},
		mutate.IndexAddendum{
			Add:        imageWithLayers(t, tarGz(t, [2]string{"app", "platform"})),
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		},
	)
	ref, err := name.NewTag(p.Registry+"/"+p.Repository+":"+p.Reference, name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex failed: %v", err)
	}
	invalidateLayers(p)

	target := p
	target.File = "linux/amd64/app"
	if _, err := Stat(t.Context(), target); err == nil {
		t.Error("Stat must not serve one version of an ambiguous path")
	}
	if _, err := ListFiles(t.Context(), p); err == nil {
		t.Error("ListFiles must reject the artifact")
	}
	if _, err := ListDir(t.Context(), p); err == nil {
		t.Error("ListDir must reject it too")
	}
}

// A whiteout path is validated as written. Cleaning it first would let a
// traversal name a file the entry never legitimately referred to.
func TestImageRejectsNonCanonicalWhiteout(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "whiteouttraversal", Reference: "latest"}
	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"keep", "still-here"}),
		// Cleaning this yields ".wh.keep" at the root, which would delete
		// "keep"; as written it is not a canonical path and must be ignored.
		tarGz(t, [2]string{"tmp/../.wh.keep", ""}),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "linux/amd64/keep" {
		t.Fatalf("listing = %#v, want the non-canonical whiteout ignored", files)
	}
}

// An oversized link target costs the link its identity, not its overlay
// effect: the lower file it replaces must still disappear.
func TestImageOversizedLinkTargetStillShadows(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "hugelink", Reference: "latest"}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{
		Name:     "foo",
		Mode:     0o644,
		Typeflag: tar.TypeLink,
		Linkname: strings.Repeat("a", maxEntryNameBytes+1),
		Format:   tar.FormatPAX,
	}); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"foo", "lower"}, [2]string{"other", "kept"}),
		static.NewLayer(raw.Bytes(), types.DockerLayer),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, file := range files {
		names = append(names, file.Name)
	}
	if slicesContains(names, "linux/amd64/foo") {
		t.Errorf("listing = %v, want the lower file replaced despite the unusable target", names)
	}
	if !slicesContains(names, "linux/amd64/other") {
		t.Errorf("listing = %v, want unrelated entries kept", names)
	}
}

// A tar is a log, so a directory header after a symlink at the same path
// leaves a directory — whose children merge rather than being removed.
func TestImageLaterDirectoryCancelsSubtreeShadow(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "shadowcancel", Reference: "latest"}

	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	archive := tar.NewWriter(gz)
	for _, header := range []*tar.Header{
		{Name: "dir", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "elsewhere"},
		{Name: "dir/", Mode: 0o755, Typeflag: tar.TypeDir},
	} {
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	pushIndex(t, p, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"dir/keep.txt", "kept"}),
		static.NewLayer(raw.Bytes(), types.DockerLayer),
	)})

	arch := p
	arch.File = "linux/amd64"
	files, err := ListFiles(t.Context(), arch)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "linux/amd64/dir/keep.txt" {
		t.Fatalf("listing = %#v, want the lower child kept under the final directory", files)
	}
}

// A published artifact stores one file per layer with a title, which must keep
// working exactly as before: its layers are not tarballs and must not be
// expanded.
func TestPublishedArtifactIsNotTreatedAsAnImage(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "v1"}
	pushTestArtifact(t, p, map[string]string{"a.txt": "alpha", "sub/b.txt": "bravo"})

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("expected two files, got %#v", files)
	}
	for _, file := range files {
		if file.TarPath != "" {
			t.Errorf("%q was expanded as an image layer", file.Name)
		}
	}
}
