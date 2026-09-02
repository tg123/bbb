package acr

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
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

func TestParseChallenge(t *testing.T) {
	realm, service, scope := parseChallenge(`bearer realm="https://reg.azurecr.io/oauth2/token",service="reg.azurecr.io",scope="repository:a/b:pull,push",error="invalid_token"`)
	if realm != "https://reg.azurecr.io/oauth2/token" {
		t.Fatalf("unexpected realm: %s", realm)
	}
	if service != "reg.azurecr.io" {
		t.Fatalf("unexpected service: %s", service)
	}
	if scope != "repository:a/b:pull,push" {
		t.Fatalf("unexpected scope: %s", scope)
	}
	if r, _, _ := parseChallenge("Basic realm=\"x\""); r != "" {
		t.Fatalf("expected empty realm for non-bearer challenge, got %s", r)
	}
}

// newTestRegistry starts a registry stub and routes all package requests to it.
func newTestRegistry(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	original := doRequest
	doRequest = func(req *http.Request) (*http.Response, error) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		return http.DefaultClient.Do(req)
	}
	t.Cleanup(func() { doRequest = original })
}

func TestListFilesAndDownload(t *testing.T) {
	t.Setenv("BBB_ACR_USERNAME", "user")
	t.Setenv("BBB_ACR_PASSWORD", "pass")
	tokenCacheMu.Lock()
	tokenCache = map[string]string{}
	tokenCacheMu.Unlock()

	const blobDigest = "sha256:deadbeef"
	const blobBody = "hello world"
	newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if user, pass, ok := r.BasicAuth(); !ok || user != "user" || pass != "pass" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("Www-Authenticate", `bearer realm="https://reg.azurecr.io/oauth2/token",service="reg.azurecr.io"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v2/models/llama/manifests/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mediaType": "application/vnd.oci.image.manifest.v1+json",
				"layers": []map[string]any{
					{
						"digest":      blobDigest,
						"size":        len(blobBody),
						"annotations": map[string]string{TitleAnnotation: "weights.bin"},
					},
					{"digest": "sha256:0011", "size": 3},
				},
			})
		case "/v2/models/llama/blobs/" + url.PathEscape(blobDigest):
			_, _ = io.WriteString(w, blobBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	p, err := Parse("acr://reg.azurecr.io/models/llama:v1")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	files, err := ListFiles(context.Background(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("unexpected files: %#v", files)
	}
	if files[0].Name != "weights.bin" || files[0].Size != int64(len(blobBody)) {
		t.Fatalf("unexpected first file: %#v", files[0])
	}
	if files[1].Name != "sha256-0011" {
		t.Fatalf("unexpected fallback name: %#v", files[1])
	}

	p.File = "weights.bin"
	rc, err := DownloadStream(context.Background(), p)
	if err != nil {
		t.Fatalf("DownloadStream failed: %v", err)
	}
	defer func() {
		_ = rc.Close()
	}()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(data) != blobBody {
		t.Fatalf("unexpected body: %q", string(data))
	}

	p.File = "missing.bin"
	if _, err := Stat(context.Background(), p); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestListFilesMergesIndexManifests(t *testing.T) {
	tokenCacheMu.Lock()
	tokenCache = map[string]string{}
	tokenCacheMu.Unlock()

	newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/models/manifests/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mediaType": "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{
					{"digest": "sha256:child1"},
					{"digest": "sha256:child2"},
				},
			})
		case "/v2/models/manifests/" + url.PathEscape("sha256:child1"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"layers": []map[string]any{
					{"digest": "sha256:abc", "size": 5, "annotations": map[string]string{TitleAnnotation: "a.txt"}},
					{"digest": "sha256:shared", "size": 1, "annotations": map[string]string{TitleAnnotation: "shared.txt"}},
				},
			})
		case "/v2/models/manifests/" + url.PathEscape("sha256:child2"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"layers": []map[string]any{
					{"digest": "sha256:shared", "size": 1, "annotations": map[string]string{TitleAnnotation: "shared.txt"}},
					{"digest": "sha256:def", "size": 7, "annotations": map[string]string{TitleAnnotation: "b.txt"}},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}

	})

	p, err := Parse("acr://reg.azurecr.io/models:v1")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	files, err := ListFiles(context.Background(), p)
	if err != nil {
		t.Fatalf("ListFiles failed: %v", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	want := []string{"a.txt", "shared.txt", "b.txt"}
	if len(names) != len(want) {
		t.Fatalf("unexpected files: %#v", names)
	}
	for i, name := range want {
		if names[i] != name {
			t.Fatalf("unexpected file at %d: %#v", i, names)
		}
	}
	if files[2].Size != 7 {
		t.Fatalf("unexpected size: %#v", files[2])
	}
}

func TestPushPublishesManifestAfterUploadingLayers(t *testing.T) {
	t.Setenv("BBB_ACR_USERNAME", "user")
	t.Setenv("BBB_ACR_PASSWORD", "pass")
	tokenCacheMu.Lock()
	tokenCache = map[string]string{}
	tokenCacheMu.Unlock()

	var nextUpload atomic.Int64
	var progress atomic.Int64
	var mu sync.Mutex
	staged := map[string][]byte{}
	blobs := map[string][]byte{}
	var pushed manifest
	newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if got := r.URL.Query().Get("scope"); got != "repository:models:pull,push" {
				t.Errorf("unexpected token scope: %s", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "push-token"})
			return
		}
		if r.Header.Get("Authorization") != "Bearer push-token" {
			w.Header().Set("Www-Authenticate", `Bearer realm="https://reg.azurecr.io/oauth2/token",service="reg.azurecr.io",scope="repository:models:pull,push"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v2/models/blobs/uploads/":
			id := fmt.Sprintf("%d", nextUpload.Add(1))
			w.Header().Set("Location", "/uploads/"+id)
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/uploads/"):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read upload: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			mu.Lock()
			staged[r.URL.Path] = body
			mu.Unlock()
			w.Header().Set("Location", r.URL.Path)
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/uploads/"):
			digest := r.URL.Query().Get("digest")
			mu.Lock()
			body := staged[r.URL.Path]
			sum := sha256.Sum256(body)
			if digest != fmt.Sprintf("sha256:%x", sum) {
				t.Errorf("digest %q does not match uploaded body", digest)
			}
			blobs[digest] = body
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && r.URL.Path == "/v2/models/manifests/v1":
			if err := json.NewDecoder(r.Body).Decode(&pushed); err != nil {
				t.Errorf("decode manifest: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	files := []UploadFile{
		{Name: "a.txt", Size: 3, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("aaa")), nil
		}},
		{Name: "sub/b.txt", Size: 3, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("bbb")), nil
		}},
	}
	p := Path{Registry: "reg.azurecr.io", Repository: "models", Reference: "v1"}
	if err := Push(t.Context(), p, files, PushOptions{
		Concurrency: 2,
		Overwrite:   true,
		OnProgress:  func(n int64) { progress.Add(n) },
	}); err != nil {
		t.Fatalf("Push failed: %v", err)
	}
	if progress.Load() != 6 {
		t.Fatalf("unexpected progress: %d", progress.Load())
	}
	if pushed.SchemaVersion != 2 || pushed.MediaType != manifestMediaType {
		t.Fatalf("unexpected manifest header: %#v", pushed)
	}
	if len(pushed.Layers) != 2 {
		t.Fatalf("unexpected layers: %#v", pushed.Layers)
	}
	if pushed.Layers[0].Annotations[TitleAnnotation] != "a.txt" ||
		pushed.Layers[1].Annotations[TitleAnnotation] != "sub/b.txt" {
		t.Fatalf("unexpected layer names: %#v", pushed.Layers)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(blobs[pushed.Layers[0].Digest]) != "aaa" ||
		string(blobs[pushed.Layers[1].Digest]) != "bbb" {
		t.Fatalf("manifest does not reference uploaded blobs")
	}
	if string(blobs[pushed.Config.Digest]) != "{}" {
		t.Fatalf("unexpected config blob: %q", blobs[pushed.Config.Digest])
	}
}

func TestPushRefusesExistingTagWithoutOverwrite(t *testing.T) {
	tokenCacheMu.Lock()
	tokenCache = map[string]string{}
	tokenCacheMu.Unlock()
	newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && r.URL.Path == "/v2/models/manifests/v1" {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := Push(t.Context(), Path{
		Registry: "reg.azurecr.io", Repository: "models", Reference: "v1",
	}, nil, PushOptions{})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected existing artifact error, got %v", err)
	}
}

func TestPushRejectsEmptyArtifact(t *testing.T) {
	err := Push(t.Context(), Path{
		Registry: "reg.azurecr.io", Repository: "models", Reference: "v1",
	}, nil, PushOptions{Overwrite: true})
	if err == nil || !strings.Contains(err.Error(), "no files") {
		t.Fatalf("expected no-files error, got %v", err)
	}
}

// A registry controls layer titles, so a malicious title must not be able to
// escape the destination directory once joined with a local path.
func TestListFilesRejectsBackslashLayerTitle(t *testing.T) {
	tokenCacheMu.Lock()
	tokenCache = map[string]string{}
	tokenCacheMu.Unlock()

	newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/models/manifests/v1" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"layers": []map[string]any{
					{
						"digest":      "sha256:abc",
						"size":        3,
						"annotations": map[string]string{TitleAnnotation: `..\..\outside.txt`},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	p := Path{Registry: "reg.azurecr.io", Repository: "models", Reference: "v1"}
	if _, err := ListFiles(t.Context(), p); err == nil || !strings.Contains(err.Error(), "invalid layer name") {
		t.Fatalf("expected invalid layer name error, got %v", err)
	}
}

func TestPushRejectsBackslashFileName(t *testing.T) {
	err := Push(t.Context(), Path{
		Registry: "reg.azurecr.io", Repository: "models", Reference: "v1",
	}, []UploadFile{{
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

func TestRegistryURLOverride(t *testing.T) {
	t.Setenv("BBB_ACR_ENDPOINT", "http://%s")
	if got := registryURL("localhost:5000", "/v2/"); got != "http://localhost:5000/v2/" {
		t.Fatalf("unexpected registry URL: %s", got)
	}
}
