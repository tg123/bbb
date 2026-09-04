package acr

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"strings"
	"testing"

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
	// the entries appear in.
	q := Path{Registry: host, Repository: "sameLayer", Reference: "latest"}
	q.Repository = "samelayer"
	pushIndex(t, q, map[string]v1.Image{"linux/amd64": imageWithLayers(t,
		tarGz(t, [2]string{"a.txt", "old"}),
		tarGz(t, [2]string{".wh.a.txt", ""}, [2]string{"a.txt", "new"}),
	)})
	q.File = "linux/amd64"
	kept, err := ListFiles(t.Context(), q)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(kept) != 1 || kept[0].Name != "linux/amd64/a.txt" {
		t.Fatalf("listing = %#v, want the layer's own file kept", kept)
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
