package bbbfs

import (
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/tg123/bbb/internal/acr"
)

// newArtifact publishes an artifact to an in-memory registry and returns its
// acr:// path, so the provider's listing contract runs in CI rather than only
// in the Compose round-trip.
func newArtifact(t *testing.T, files map[string]string) string {
	t.Helper()
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry url: %v", err)
	}

	uploads := make([]acr.UploadFile, 0, len(files))
	for name, content := range files {
		uploads = append(uploads, acr.UploadFile{
			Name: name,
			Size: int64(len(content)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(content)), nil
			},
		})
	}
	target := acr.Path{Registry: parsed.Host, Repository: "models/llama", Reference: "v1"}
	if err := acr.Push(t.Context(), target, uploads, acr.PushOptions{Overwrite: true}); err != nil {
		t.Fatalf("push artifact: %v", err)
	}
	return target.String()
}

func entryNames(entries []Entry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	return names
}

func TestACRListRootAndNested(t *testing.T) {
	artifact := newArtifact(t, map[string]string{
		"a.txt":          "alpha",
		"sub/b.txt":      "bravo",
		"sub/deep/c.txt": "charlie",
	})
	fs := acrFS{}

	root, err := fs.List(t.Context(), artifact)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	// A directory is synthesised from the layer names, with a trailing slash.
	if got := entryNames(root); !slices.Equal(got, []string{"a.txt", "sub/"}) {
		t.Fatalf("root listing = %v, want [a.txt sub/]", got)
	}
	for _, entry := range root {
		if entry.Name == "a.txt" {
			if entry.IsDir || entry.Size != 5 {
				t.Fatalf("unexpected file entry: %#v", entry)
			}
		}
		if entry.Name == "sub/" && !entry.IsDir {
			t.Fatalf("expected sub/ to be a directory: %#v", entry)
		}
	}

	nested, err := fs.List(t.Context(), artifact+"/sub")
	if err != nil {
		t.Fatalf("nested List failed: %v", err)
	}
	if got := entryNames(nested); !slices.Equal(got, []string{"b.txt", "deep/"}) {
		t.Fatalf("nested listing = %v, want [b.txt deep/]", got)
	}
}

func TestACRListRecursiveNamesAndSizes(t *testing.T) {
	artifact := newArtifact(t, map[string]string{
		"a.txt":     "alpha",
		"sub/b.txt": "bravo!",
	})

	sizes := map[string]int64{}
	if err := (acrFS{}).ListRecursive(t.Context(), artifact, func(entry Entry) error {
		if entry.IsDir {
			t.Errorf("recursive listing should only emit files, got %#v", entry)
		}
		sizes[entry.Name] = entry.Size
		return nil
	}); err != nil {
		t.Fatalf("ListRecursive failed: %v", err)
	}
	if len(sizes) != 2 || sizes["a.txt"] != 5 || sizes["sub/b.txt"] != 6 {
		t.Fatalf("unexpected recursive listing: %#v", sizes)
	}
}

func TestACRStatFileAndVirtualDirectory(t *testing.T) {
	artifact := newArtifact(t, map[string]string{"sub/b.txt": "bravo"})
	fs := acrFS{}

	file, err := fs.Stat(t.Context(), artifact+"/sub/b.txt")
	if err != nil {
		t.Fatalf("Stat file failed: %v", err)
	}
	if file.IsDir || file.Size != 5 || file.Name != "b.txt" {
		t.Fatalf("unexpected file stat: %#v", file)
	}

	// "sub" has no layer of its own; it exists only as a name prefix.
	dir, err := fs.Stat(t.Context(), artifact+"/sub")
	if err != nil {
		t.Fatalf("Stat virtual directory failed: %v", err)
	}
	if !dir.IsDir || dir.Name != "sub" {
		t.Fatalf("unexpected directory stat: %#v", dir)
	}
	if dirLike, err := fs.IsDirLike(t.Context(), artifact+"/sub"); err != nil || !dirLike {
		t.Fatalf("IsDirLike(sub) = %v (%v), want true", dirLike, err)
	}
	if dirLike, err := fs.IsDirLike(t.Context(), artifact+"/sub/b.txt"); err != nil || dirLike {
		t.Fatalf("IsDirLike(sub/b.txt) = %v (%v), want false", dirLike, err)
	}

	if _, err := fs.Stat(t.Context(), artifact+"/missing.txt"); err == nil {
		t.Fatal("expected a missing file to be reported")
	}
}

func TestACREmptyArtifact(t *testing.T) {
	artifact := newArtifact(t, nil)
	fs := acrFS{}

	entries, err := fs.List(t.Context(), artifact)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no entries, got %#v", entries)
	}
	// An artifact with no layers still exists.
	root, err := fs.Stat(t.Context(), artifact)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if !root.IsDir {
		t.Fatalf("expected the artifact root to be a directory: %#v", root)
	}
	exists, err := Exists(t.Context(), artifact)
	if err != nil || !exists {
		t.Fatalf("Exists = %v (%v), want true", exists, err)
	}
}
