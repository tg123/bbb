package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tg123/bbb/internal/hf"
)

type hfAuthTransport func(*http.Request) (*http.Response, error)

func (f hfAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHFAuthenticatedCopy(t *testing.T) {
	for _, credentials := range []string{"environment", "saved login"} {
		for _, repo := range []string{"owner/repo", "datasets/owner/repo"} {
			for _, directory := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/directory=%t", credentials, repo, directory), func(t *testing.T) {
					t.Setenv("HF_TOKEN", "")
					t.Setenv("HUGGING_FACE_HUB_TOKEN", "")
					t.Setenv("HF_HUB_DISABLE_IMPLICIT_TOKEN", "")
					tokenFile := filepath.Join(t.TempDir(), "token")
					t.Setenv("HF_TOKEN_PATH", tokenFile)
					if credentials == "environment" {
						t.Setenv("HF_TOKEN", "test-token")
					} else if err := os.WriteFile(tokenFile, []byte("test-token\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					var lists, downloads atomic.Int32
					hf.SetHTTPClient(&http.Client{Transport: hfAuthTransport(func(req *http.Request) (*http.Response, error) {
						if req.Method != http.MethodGet || req.Header.Get("Authorization") != "Bearer test-token" {
							return nil, fmt.Errorf("expected authenticated GET for %s", req.URL)
						}
						listPath := "/api/models/" + repo
						if strings.HasPrefix(repo, "datasets/") {
							listPath = "/api/" + repo
						}
						var body string
						switch req.URL.Path {
						case listPath:
							lists.Add(1)
							body = `{"siblings":[{"rfilename":"file.txt"},{"rfilename":"nested/data.bin"}]}`
						case "/" + repo + "/resolve/main/file.txt":
							downloads.Add(1)
							body = "text contents"
						case "/" + repo + "/resolve/main/nested/data.bin":
							downloads.Add(1)
							body = "binary contents"
						default:
							return nil, fmt.Errorf("unexpected Hugging Face URL: %s", req.URL)
						}
						return &http.Response{
							StatusCode: http.StatusOK, Header: make(http.Header),
							Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
							Request: req,
						}, nil
					})})
					t.Cleanup(func() { hf.SetHTTPClient(nil) })
					src := "hf://" + repo
					wantFiles := map[string]string{"file.txt": "text contents"}
					if directory {
						wantFiles["nested/data.bin"] = "binary contents"
					} else {
						src += "/file.txt"
					}
					dst := t.TempDir()
					if err := cmdCPPaths(t.Context(), false, true, 2, 0, []string{src}, dst, 0, false, nil); err != nil {
						t.Fatal(err)
					}
					for name, want := range wantFiles {
						data, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(name)))
						if err != nil || string(data) != want {
							t.Fatalf("copied %s = %q, %v; want %q", name, data, err, want)
						}
					}
					if (directory && lists.Load() == 0) || downloads.Load() != int32(len(wantFiles)) {
						t.Fatalf("got %d listings and %d downloads; want listings for directories and %d downloads",
							lists.Load(), downloads.Load(), len(wantFiles))
					}
				})
			}
		}
	}
}
