package bbbfs

import (
	"errors"
	"io"
	"log"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/tg123/bbb/internal/acr"
)

// A scratch image's platform is a real directory with nothing in it. Neither
// listing path may mistake "no children" for "no such path".
func TestACRListsAnEmptyPlatform(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := random.Image(64, 1)
	if err != nil {
		t.Fatal(err)
	}
	index := mutate.AppendManifests(empty.Index,
		mutate.IndexAddendum{
			Add:        loaded,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "amd64"}},
		},
		mutate.IndexAddendum{
			Add:        empty.Image,
			Descriptor: v1.Descriptor{Platform: &v1.Platform{OS: "linux", Architecture: "arm64"}},
		},
	)
	ref, err := name.NewTag(parsed.Host+"/scratch:latest", name.WeakValidation)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.WriteIndex(ref, index); err != nil {
		t.Fatalf("WriteIndex failed: %v", err)
	}

	target := "acr://" + parsed.Host + "/scratch:latest/linux/arm64"
	entries, err := (acrFS{}).List(t.Context(), target)
	if err != nil {
		t.Fatalf("List failed for an empty platform: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("List = %v, want nothing inside an empty platform", entries)
	}
	var seen []Entry
	if err := (acrFS{}).ListRecursive(t.Context(), target, func(e Entry) error {
		seen = append(seen, e)
		return nil
	}); err != nil {
		t.Fatalf("ListRecursive failed for an empty platform: %v", err)
	}
	if len(seen) != 0 {
		t.Fatalf("ListRecursive = %v, want nothing inside an empty platform", seen)
	}

	// A path that really is absent must still be reported as missing.
	if _, err := (acrFS{}).List(t.Context(), "acr://"+parsed.Host+"/scratch:latest/linux/riscv64"); err == nil {
		t.Fatal("expected a missing platform to be an error")
	}
}

func TestACRMatchAndResolve(t *testing.T) {
	const p = "acr://myreg.azurecr.io/models/llama:v1/weights.bin"
	if !IsACR(p) {
		t.Fatalf("expected %s to be an acr path", p)
	}
	if !IsRemote(p) {
		t.Fatalf("expected %s to be remote", p)
	}
	if _, ok := Resolve(p).(acrFS); !ok {
		t.Fatalf("expected acrFS provider for %s", p)
	}
	if IsACR("/local/path") || IsACR("az://acct/cont/blob") {
		t.Fatal("non-acr paths must not match")
	}
}

func TestACRPathHelpers(t *testing.T) {
	fs := acrFS{}
	if got := fs.ChildPath("acr://myreg.azurecr.io/models:v1", "sub/file.bin"); got != "acr://myreg/models:v1/sub/file.bin" {
		t.Fatalf("unexpected child path: %s", got)
	}
	if got := fs.ChildPath("acr://myreg.azurecr.io/models:v1/sub", "file.bin"); got != "acr://myreg/models:v1/sub/file.bin" {
		t.Fatalf("unexpected nested child path: %s", got)
	}
	// A registry's children are repositories and a repository's are tags, so
	// descending builds a reference rather than a file path.
	if got := fs.ChildPath("acr://myreg.azurecr.io", "models/llama/"); got != "acr://myreg/models/llama" {
		t.Fatalf("unexpected repository child path: %s", got)
	}
	if got := fs.ChildPath("acr://myreg.azurecr.io/models/llama", "v1/"); got != "acr://myreg/models/llama:v1" {
		t.Fatalf("unexpected tag child path: %s", got)
	}
	if got := fs.BaseName("acr://myreg.azurecr.io/models/llama:v1/sub/file.bin"); got != "file.bin" {
		t.Fatalf("unexpected base name: %s", got)
	}
	if got := fs.BaseName("acr://myreg.azurecr.io/models/llama:v1"); got != "llama" {
		t.Fatalf("unexpected artifact base name: %s", got)
	}
	if !fs.IsDirLikeFromPath("acr://myreg.azurecr.io/models:v1") {
		t.Fatal("artifact root should be directory-like")
	}
	if fs.IsDirLikeFromPath("acr://myreg.azurecr.io/models:v1/file.bin") {
		t.Fatal("file path should not be directory-like")
	}
}

func TestACRWriteUnsupported(t *testing.T) {
	if err := (acrFS{}).Write(t.Context(), "acr://myreg.azurecr.io/models:v1/f", nil); err != ErrWriteUnsupported {
		t.Fatalf("expected ErrWriteUnsupported, got %v", err)
	}
}

// A conflict is only final when it is a create-only manifest write whose tag
// holds something else, which is reported as ErrArtifactExists. A bare 409 or
// 412 can come from a blob upload or an overwrite push, where a retry is
// exactly the right response.
func TestConflictStatusStaysRetryable(t *testing.T) {
	for _, status := range []int{409, 412} {
		if IsNonRetryableHTTPErr(&acr.HTTPStatusError{StatusCode: status}) {
			t.Errorf("a bare %d must stay retryable", status)
		}
	}
	for _, status := range []int{401, 403, 404} {
		if !IsNonRetryableHTTPErr(&acr.HTTPStatusError{StatusCode: status}) {
			t.Errorf("%d cannot be fixed by retrying", status)
		}
	}
	if !IsNonRetryableHTTPErr(acr.ErrArtifactExists) {
		t.Error("an existing artifact is final without -f")
	}
}

// A 404 says the destination is missing, except when it says the registry has
// forgotten an upload session — which starting the upload again fixes.
func TestLostUploadSessionStaysRetryable(t *testing.T) {
	for _, code := range []string{"BLOB_UPLOAD_UNKNOWN", "BLOB_UPLOAD_INVALID"} {
		err := &acr.HTTPStatusError{StatusCode: 404, Codes: []string{code}}
		if IsNonRetryableHTTPErr(err) {
			t.Errorf("a %s upload must be retried, not abandoned", code)
		}
		if err.NotFound() {
			t.Errorf("%s does not mean the destination is missing", code)
		}
		if errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s must not read as a missing file", code)
		}
	}
	// Everything else at 404 stays final.
	for _, code := range []string{"MANIFEST_UNKNOWN", "NAME_UNKNOWN", "BLOB_UNKNOWN"} {
		err := &acr.HTTPStatusError{StatusCode: 404, Codes: []string{code}}
		if !IsNonRetryableHTTPErr(err) {
			t.Errorf("%d %s cannot be fixed by retrying", 404, code)
		}
		if !err.NotFound() {
			t.Errorf("%s means the destination is missing", code)
		}
	}
}
