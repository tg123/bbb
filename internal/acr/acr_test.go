package acr

import (
	"fmt"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    Path
		wantErr bool
	}{
		{
			name: "tag and file",
			raw:  "acr://myreg.azurecr.io/models/llama:v1/weights.bin",
			want: Path{Registry: "myreg.azurecr.io", Repository: "models/llama", Reference: "v1", File: "weights.bin"},
		},
		{
			name: "bare registry name defaults to azurecr.io",
			raw:  "acr://myreg/models:v1",
			want: Path{Registry: "myreg.azurecr.io", Repository: "models", Reference: "v1"},
		},
		{
			name: "no reference defaults to latest",
			raw:  "acr://myreg.azurecr.io/models/llama",
			want: Path{Registry: "myreg.azurecr.io", Repository: "models/llama", Reference: DefaultTag},
		},
		{
			name: "digest reference",
			raw:  "acr://myreg.azurecr.io/models@sha256:abc/sub/file.txt",
			want: Path{Registry: "myreg.azurecr.io", Repository: "models", Reference: "sha256:abc", File: "sub/file.txt"},
		},
		{name: "wrong scheme", raw: "hf://foo/bar", wantErr: true},
		{name: "missing repository", raw: "acr://myreg.azurecr.io/", wantErr: true},
		{name: "empty tag", raw: "acr://myreg.azurecr.io/models:", wantErr: true},
		{name: "digest without algorithm", raw: "acr://myreg.azurecr.io/models@abc", wantErr: true},
		{name: "escaping file path", raw: "acr://myreg.azurecr.io/models:v1/../../etc/passwd", wantErr: true},
		{name: "backslash escaping file path", raw: `acr://myreg.azurecr.io/models:v1/..\..\outside`, wantErr: true},
		{name: "backslash in file path", raw: `acr://myreg.azurecr.io/models:v1/sub\file.bin`, wantErr: true},
		{name: "alternate data stream", raw: "acr://myreg.azurecr.io/models:v1/a.txt::$DATA", wantErr: true},
		{name: "reserved device name", raw: "acr://myreg.azurecr.io/models:v1/NUL", wantErr: true},
		{name: "reserved device name with extension", raw: "acr://myreg.azurecr.io/models:v1/CON.txt", wantErr: true},
		{name: "reserved device name in a subdirectory", raw: "acr://myreg.azurecr.io/models:v1/sub/lpt1.bin", wantErr: true},
		{name: "trailing dot", raw: "acr://myreg.azurecr.io/models:v1/a.", wantErr: true},
		{name: "trailing space", raw: "acr://myreg.azurecr.io/models:v1/a.txt ", wantErr: true},
		{
			name: "name merely containing a device name is fine",
			raw:  "acr://myreg.azurecr.io/models:v1/console.log",
			want: Path{Registry: "myreg.azurecr.io", Repository: "models", Reference: "v1", File: "console.log"},
		},
		{
			name: "registry case is canonicalised",
			raw:  "acr://MyReg.AzureCR.io/models:v1",
			want: Path{Registry: "myreg.azurecr.io", Repository: "models", Reference: "v1"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %#v", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Fatalf("Parse(%q) = %#v, want %#v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestPathString(t *testing.T) {
	p := Path{Registry: "myreg.azurecr.io", Repository: "models", Reference: "v1", File: "a/b.bin"}
	if got := p.String(); got != "acr://myreg.azurecr.io/models:v1/a/b.bin" {
		t.Fatalf("unexpected path: %s", got)
	}
	p.Reference = "sha256:abc"
	if got := p.String(); got != "acr://myreg.azurecr.io/models@sha256:abc/a/b.bin" {
		t.Fatalf("unexpected path: %s", got)
	}
	roundTrip, err := Parse(p.String())
	if err != nil || roundTrip != p {
		t.Fatalf("round trip failed: %#v, %v", roundTrip, err)
	}
}

func TestDefaultFilename(t *testing.T) {
	if got := (Path{Repository: "models/llama", Reference: "v1"}).DefaultFilename(); got != "llama" {
		t.Fatalf("unexpected default filename: %s", got)
	}
	if got := (Path{Repository: "models/llama", Reference: "v1", File: "sub/w.bin"}).DefaultFilename(); got != "w.bin" {
		t.Fatalf("unexpected default filename: %s", got)
	}
}

// newTestRegistry starts an in-memory OCI registry and returns its host.
// Because go-containerregistry serves plain HTTP on localhost and treats
// localhost as insecure, paths can address it directly.
func newTestRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(registry.New(registry.Logger(nopLogger(t))))
	t.Cleanup(server.Close)
	layerCache.Clear()
	t.Cleanup(func() { layerCache.Clear() })
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse registry url: %v", err)
	}
	return parsed.Host
}

func nopLogger(t *testing.T) *log.Logger {
	t.Helper()
	return log.New(io.Discard, "", 0)
}

// pushTestArtifact publishes an artifact with the given named layers.
func pushTestArtifact(t *testing.T, p Path, files map[string]string) {
	t.Helper()
	uploads := make([]UploadFile, 0, len(files))
	for name, content := range files {
		uploads = append(uploads, UploadFile{
			Name: name,
			Size: int64(len(content)),
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(content)), nil
			},
		})
	}
	if err := Push(t.Context(), p, uploads, PushOptions{Overwrite: true}); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
}

func TestPushAndReadRoundTrip(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models/llama", Reference: "v1"}

	var uploaded atomic.Int64
	uploads := []UploadFile{
		{Name: "a.txt", Size: 5, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("alpha")), nil
		}},
		{Name: "sub/b.txt", Size: 5, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("bravo")), nil
		}},
	}
	if err := Push(t.Context(), p, uploads, PushOptions{
		Overwrite:  true,
		OnProgress: func(n int64) { uploaded.Add(n) },
	}); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if uploaded.Load() < 10 {
		t.Fatalf("expected progress for both layers, got %d bytes", uploaded.Load())
	}

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	byName := map[string]File{}
	for _, f := range files {
		byName[f.Name] = f
	}
	if len(byName) != 2 {
		t.Fatalf("unexpected files: %#v", files)
	}
	if byName["a.txt"].Size != 5 || byName["sub/b.txt"].Size != 5 {
		t.Fatalf("unexpected sizes: %#v", files)
	}

	for name, want := range map[string]string{"a.txt": "alpha", "sub/b.txt": "bravo"} {
		child := p
		child.File = name
		rc, err := DownloadStream(t.Context(), child)
		if err != nil {
			t.Fatalf("DownloadStream(%s) failed: %v", name, err)
		}
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}

	missing := p
	missing.File = "nope.txt"
	if _, err := Stat(t.Context(), missing); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

// The tag must replace the previous artifact wholesale, so a mirroring sync
// cannot leave stale files behind.
func TestPushReplacesTag(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "v1"}

	pushTestArtifact(t, p, map[string]string{"old.txt": "old", "keep.txt": "keep"})
	invalidateLayers(p)
	pushTestArtifact(t, p, map[string]string{"keep.txt": "keep"})

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 1 || files[0].Name != "keep.txt" {
		t.Fatalf("expected only keep.txt after republish, got %#v", files)
	}
}

func TestPushPublishesEmptyArtifact(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "empty"}

	// An empty source must still replace the tag, otherwise a mirroring sync
	// would silently leave the previous artifact in place.
	if err := Push(t.Context(), p, nil, PushOptions{Overwrite: true}); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected no files, got %#v", files)
	}
}

func TestPushRefusesExistingTagWithoutOverwrite(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "v1"}
	pushTestArtifact(t, p, map[string]string{"a.txt": "alpha"})

	err := Push(t.Context(), p, nil, PushOptions{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected existing artifact error, got %v", err)
	}
}

func TestPushRejectsBackslashFileName(t *testing.T) {
	host := newTestRegistry(t)
	err := Push(t.Context(), Path{Registry: host, Repository: "models", Reference: "v1"}, []UploadFile{{
		Name: `..\..\outside.txt`,
		Size: 1,
		Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("x")), nil
		},
	}}, PushOptions{Overwrite: true})
	if err == nil || !strings.Contains(err.Error(), "invalid upload file name") {
		t.Fatalf("expected invalid upload file name error, got %v", err)
	}
}

// A registry controls layer titles, so a malicious title must not survive
// into a name that is later joined with a local destination path.
func TestListFilesRejectsBackslashLayerTitle(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "evil"}
	pushRawArtifact(t, p, []layerSpec{{title: `..\..\outside.txt`, content: "x"}})

	if _, err := ListFiles(t.Context(), p); err == nil || !strings.Contains(err.Error(), "invalid layer name") {
		t.Fatalf("expected invalid layer name error, got %v", err)
	}
}

func TestListFilesRejectsConflictingLayerNames(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "conflict"}
	pushRawArtifact(t, p, []layerSpec{
		{title: "a.txt", content: "first"},
		{title: "a.txt", content: "second"},
	})

	if _, err := ListFiles(t.Context(), p); err == nil || !strings.Contains(err.Error(), "conflicting layers") {
		t.Fatalf("expected conflicting layers error, got %v", err)
	}
}

type layerSpec struct {
	title   string
	content string
}

// pushRawArtifact publishes an artifact directly through go-containerregistry,
// bypassing Push's own validation so malformed manifests can be tested.
func pushRawArtifact(t *testing.T, p Path, layers []layerSpec) {
	t.Helper()
	image := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	image = mutate.ConfigMediaType(image, configMediaType)
	adds := make([]mutate.Addendum, 0, len(layers))
	for _, spec := range layers {
		adds = append(adds, mutate.Addendum{
			Layer:       static.NewLayer([]byte(spec.content), layerMediaType),
			MediaType:   layerMediaType,
			Annotations: map[string]string{TitleAnnotation: spec.title},
		})
	}
	image, err := mutate.Append(image, adds...)
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	ref, err := p.reference()
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	if err := remote.Write(ref, image, remote.WithContext(t.Context())); err != nil {
		t.Fatalf("write image: %v", err)
	}
}

// A whole-artifact copy lists once and then stats every file; the reference
// must be resolved a single time so the copy sees one consistent snapshot.
func TestResolveReferenceOnce(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "v1"}
	pushTestArtifact(t, p, map[string]string{"a.txt": "alpha", "b.txt": "bravo"})
	invalidateLayers(p)

	for range 3 {
		if _, err := ListFiles(t.Context(), p); err != nil {
			t.Fatalf("ListFiles failed: %v", err)
		}
	}
	value, ok := layerCache.Load(layerCacheKey(p))
	if !ok {
		t.Fatal("expected the resolved artifact to be cached")
	}
	if entry := value.(*layerCacheEntry); len(entry.art.files) != 2 {
		t.Fatalf("unexpected cached files: %#v", entry.art.files)
	}
}

// An artifact index aggregates several manifests. go-containerregistry's
// Descriptor.Image() would resolve only the platform-matching child (and fail
// when there is no platform metadata at all), so every child must be merged.
func TestListFilesMergesIndexManifests(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "index"}

	first := buildTestImage(t, []layerSpec{
		{title: "a.txt", content: "alpha"},
		{title: "shared.txt", content: "shared"},
	})
	second := buildTestImage(t, []layerSpec{
		// The shared layer is the same blob, so it must collapse rather than
		// be reported as a conflict.
		{title: "shared.txt", content: "shared"},
		{title: "b.txt", content: "bravo"},
	})
	index := mutate.AppendManifests(
		mutate.IndexMediaType(empty.Index, types.OCIImageIndex),
		mutate.IndexAddendum{Add: first},
		mutate.IndexAddendum{Add: second},
	)
	ref, err := p.reference()
	if err != nil {
		t.Fatalf("reference: %v", err)
	}
	if err := remote.WriteIndex(ref, index, remote.WithContext(t.Context())); err != nil {
		t.Fatalf("write index: %v", err)
	}
	invalidateLayers(p)

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	want := []string{"a.txt", "b.txt", "shared.txt"}
	if !slices.Equal(names, want) {
		t.Fatalf("index files = %v, want %v", names, want)
	}

	// Every merged child's blobs must be readable, not just the first.
	for name, content := range map[string]string{"a.txt": "alpha", "b.txt": "bravo", "shared.txt": "shared"} {
		child := p
		child.File = name
		rc, err := DownloadStream(t.Context(), child)
		if err != nil {
			t.Fatalf("DownloadStream(%s) failed: %v", name, err)
		}
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || string(got) != content {
			t.Fatalf("%s = %q (%v), want %q", name, got, err, content)
		}
	}
}

func buildTestImage(t *testing.T, layers []layerSpec) v1.Image {
	t.Helper()
	image := mutate.MediaType(empty.Image, types.OCIManifestSchema1)
	image = mutate.ConfigMediaType(image, configMediaType)
	adds := make([]mutate.Addendum, 0, len(layers))
	for _, spec := range layers {
		adds = append(adds, mutate.Addendum{
			Layer:       static.NewLayer([]byte(spec.content), layerMediaType),
			MediaType:   layerMediaType,
			Annotations: map[string]string{TitleAnnotation: spec.title},
		})
	}
	image, err := mutate.Append(image, adds...)
	if err != nil {
		t.Fatalf("build image: %v", err)
	}
	return image
}

// A failed lookup must not be memoised, or --retry-count would be useless.
func TestResolveDoesNotCacheFailure(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "missing"}

	if _, err := ListFiles(t.Context(), p); err == nil {
		t.Fatal("expected the first lookup to fail")
	}
	if _, cached := layerCache.Load(layerCacheKey(p)); cached {
		t.Fatal("a failed lookup must not be cached")
	}

	pushTestArtifact(t, p, map[string]string{"a.txt": "alpha"})
	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("retry after a failed lookup should succeed, got %v", err)
	}
	if len(files) != 1 || files[0].Name != "a.txt" {
		t.Fatalf("unexpected files after retry: %#v", files)
	}
}

func TestManifestExists(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "v1"}

	exists, err := ManifestExists(t.Context(), p)
	if err != nil {
		t.Fatalf("ManifestExists failed: %v", err)
	}
	if exists {
		t.Fatal("expected the tag to be absent")
	}

	pushTestArtifact(t, p, map[string]string{"a.txt": "alpha"})
	exists, err = ManifestExists(t.Context(), p)
	if err != nil {
		t.Fatalf("ManifestExists failed: %v", err)
	}
	if !exists {
		t.Fatal("expected the tag to exist after push")
	}
}

// Two files with identical contents share one blob but are still two files;
// deduplicating by digest would silently drop the second.
func TestSameContentDifferentNamesRoundTrip(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "dup"}

	same := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("identical")), nil }
	if err := Push(t.Context(), p, []UploadFile{
		{Name: "a.txt", Size: 9, Open: same},
		{Name: "b.txt", Size: 9, Open: same},
	}, PushOptions{Overwrite: true}); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	invalidateLayers(p)

	files, err := ListFiles(t.Context(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	if !slices.Equal(names, []string{"a.txt", "b.txt"}) {
		t.Fatalf("expected both names to survive, got %v", names)
	}
	if files[0].Digest != files[1].Digest {
		t.Fatalf("expected both files to share one blob, got %s and %s", files[0].Digest, files[1].Digest)
	}
	for _, name := range names {
		child := p
		child.File = name
		rc, err := DownloadStream(t.Context(), child)
		if err != nil {
			t.Fatalf("DownloadStream(%s) failed: %v", name, err)
		}
		got, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil || string(got) != "identical" {
			t.Fatalf("%s = %q (%v)", name, got, err)
		}
	}
}

func TestValidatePushTarget(t *testing.T) {
	if err := ValidatePushTarget(Path{Repository: "models", Reference: "v1"}); err != nil {
		t.Fatalf("expected tag target to be valid: %v", err)
	}
	if err := ValidatePushTarget(Path{Repository: "models", Reference: "sha256:abc"}); err == nil {
		t.Fatal("expected a digest target to be rejected")
	}
	if err := ValidatePushTarget(Path{Repository: "models", Reference: "v1", File: "a.txt"}); err == nil {
		t.Fatal("expected a file target to be rejected")
	}
}

func TestValidateUploadNames(t *testing.T) {
	reader := func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("x")), nil }
	if err := ValidateUploadNames([]UploadFile{{Name: "a.txt", Open: reader}}); err != nil {
		t.Fatalf("expected a plain name to be valid: %v", err)
	}
	if err := ValidateUploadNames([]UploadFile{{Name: `a\b.txt`, Open: reader}}); err == nil {
		t.Fatal("expected a backslash name to be rejected")
	}
	if err := ValidateUploadNames([]UploadFile{
		{Name: "a.txt", Open: reader},
		{Name: "a.txt", Open: reader},
	}); err == nil {
		t.Fatal("expected duplicate names to be rejected")
	}
	if err := ValidateUploadNames([]UploadFile{{Name: "a.txt"}}); err == nil {
		t.Fatal("expected a missing reader to be rejected")
	}
}

// A lost response after a committed manifest PUT must not make the retry
// report failure for an artifact this process just published.
func TestPushRetryIsIdempotent(t *testing.T) {
	host := newTestRegistry(t)
	p := Path{Registry: host, Repository: "models", Reference: "v1"}
	files := []UploadFile{{Name: "a.txt", Size: 5, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("alpha")), nil
	}}}

	if err := Push(t.Context(), p, files, PushOptions{}); err != nil {
		t.Fatalf("first push failed: %v", err)
	}
	// Re-running the identical push is what an outer retry does.
	if err := Push(t.Context(), p, files, PushOptions{}); err != nil {
		t.Fatalf("identical retry should succeed, got %v", err)
	}
	// A different artifact on the same tag is still a genuine conflict.
	other := []UploadFile{{Name: "b.txt", Size: 5, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("bravo")), nil
	}}}
	if err := Push(t.Context(), p, other, PushOptions{}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected a conflicting artifact to be rejected, got %v", err)
	}
}

// go-containerregistry silently uses plain HTTP for RFC1918 literals, which
// would put registry credentials on the wire unencrypted.
func TestPrivateAddressRequiresOptIn(t *testing.T) {
	p := Path{Registry: "10.1.2.3:5000", Repository: "models", Reference: "v1"}
	if _, err := p.reference(); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Fatalf("expected a private address to be refused, got %v", err)
	}

	t.Setenv("BBB_ACR_INSECURE", "10.1.2.3")
	if _, err := p.reference(); err != nil {
		t.Fatalf("expected the opt-in to allow the registry, got %v", err)
	}

	// Loopback stays automatic: it never leaves the machine.
	local := Path{Registry: "127.0.0.1:5000", Repository: "models", Reference: "v1"}
	if _, err := local.reference(); err != nil {
		t.Fatalf("expected loopback to be allowed, got %v", err)
	}
}

// .local is mDNS, so it resolves to a real host on the LAN even though
// go-containerregistry downgrades it to plain HTTP like loopback.
func TestMDNSRequiresOptIn(t *testing.T) {
	p := Path{Registry: "registry.local:5000", Repository: "models", Reference: "v1"}
	if _, err := p.reference(); err == nil || !strings.Contains(err.Error(), "plain HTTP") {
		t.Fatalf("expected an mDNS host to be refused, got %v", err)
	}
	t.Setenv("BBB_ACR_INSECURE", "registry.local")
	if _, err := p.reference(); err != nil {
		t.Fatalf("expected the opt-in to allow the registry, got %v", err)
	}
	// .localhost remains automatic.
	loopback := Path{Registry: "reg.localhost:5000", Repository: "models", Reference: "v1"}
	if _, err := loopback.reference(); err != nil {
		t.Fatalf("expected .localhost to be allowed, got %v", err)
	}
}

// An Entra access token is a live Azure credential and must never be offered
// to a registry that merely answers with a bearer challenge.
func TestIsACR(t *testing.T) {
	for _, tc := range []struct {
		registry string
		want     bool
	}{
		{"myreg.azurecr.io", true},
		{"myreg.azurecr.cn", true},
		{"myreg.azurecr.us", true},
		{"myreg.azurecr.io:443", true},
		{"ghcr.io", false},
		{"evil.example.com", false},
		{"notazurecr.io", false},
		{"localhost:5000", false},
	} {
		if got := isACR(tc.registry); got != tc.want {
			t.Errorf("isACR(%q) = %v, want %v", tc.registry, got, tc.want)
		}
	}

	t.Setenv("BBB_ACR_ENTRA_HOSTS", "registry.corp.example")
	if !isACR("registry.corp.example") {
		t.Error("expected an explicitly trusted host to be allowed")
	}
	if isACR("other.corp.example") {
		t.Error("opt-in must not extend to unlisted hosts")
	}
}

// A file layer must stream from disk rather than buffer, and report a digest
// that matches its contents.
func TestFileLayerDigestAndStream(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(local, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	var opened atomic.Int64
	layer := &fileLayer{
		open: func() (io.ReadCloser, error) {
			opened.Add(1)
			return os.Open(local)
		},
		size: 11,
	}
	digest, err := layer.Digest()
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	want := "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if digest.String() != want {
		t.Fatalf("digest = %s, want %s", digest, want)
	}
	diffID, err := layer.DiffID()
	if err != nil || diffID != digest {
		t.Fatalf("DiffID = %v (%v), want %v", diffID, err, digest)
	}
	if _, err := layer.Digest(); err != nil || opened.Load() != 1 {
		t.Fatalf("expected the digest to be computed once, opened %d times", opened.Load())
	}
	size, err := layer.Size()
	if err != nil || size != 11 {
		t.Fatalf("Size = %d (%v), want 11", size, err)
	}
	rc, err := layer.Compressed()
	if err != nil {
		t.Fatalf("Compressed failed: %v", err)
	}
	content, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || string(content) != "hello world" {
		t.Fatalf("content = %q (%v)", content, err)
	}
}

func TestAsStatusError(t *testing.T) {
	if err := asStatusError(nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
	plain := fmt.Errorf("boom")
	if got := asStatusError(plain); got != plain {
		t.Fatalf("expected the original error, got %v", got)
	}
}
