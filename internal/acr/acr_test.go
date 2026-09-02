package acr

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestListFilesFollowsIndex(t *testing.T) {
	tokenCacheMu.Lock()
	tokenCache = map[string]string{}
	tokenCacheMu.Unlock()

	newTestRegistry(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/models/manifests/v1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mediaType": "application/vnd.oci.image.index.v1+json",
				"manifests": []map[string]any{{"digest": "sha256:child"}},
			})
		case "/v2/models/manifests/" + url.PathEscape("sha256:child"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"layers": []map[string]any{
					{"digest": "sha256:abc", "size": 5, "annotations": map[string]string{TitleAnnotation: "a.txt"}},
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
	if len(files) != 1 || files[0].Name != "a.txt" || files[0].Size != 5 {
		t.Fatalf("unexpected files: %#v", files)
	}
}
