package bbbfs

import "testing"

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
	if got := fs.ChildPath("acr://myreg.azurecr.io/models:v1", "sub/file.bin"); got != "acr://myreg.azurecr.io/models:v1/sub/file.bin" {
		t.Fatalf("unexpected child path: %s", got)
	}
	if got := fs.ChildPath("acr://myreg.azurecr.io/models:v1/sub", "file.bin"); got != "acr://myreg.azurecr.io/models:v1/sub/file.bin" {
		t.Fatalf("unexpected nested child path: %s", got)
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
