package hf

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isolateAuthEnv(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, name := range []string{
		"HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HF_TOKEN_PATH",
		"HF_HOME", "XDG_CACHE_HOME", "HF_HUB_DISABLE_IMPLICIT_TOKEN",
	} {
		t.Setenv(name, "")
	}
	return home
}

func writeTokenFile(t *testing.T, name, token string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAuthToken(t *testing.T) {
	home := isolateAuthEnv(t)
	writeTokenFile(t, filepath.Join(home, ".cache", "huggingface", "token"), " default-token\r\n")
	writeTokenFile(t, filepath.Join(home, "xdg", "huggingface", "token"), "xdg-token")
	writeTokenFile(t, filepath.Join(home, "hf-home", "token"), "home-token")
	writeTokenFile(t, filepath.Join(home, "custom-token"), "custom-token")
	writeTokenFile(t, filepath.Join(home, "empty-token"), " \r\n\t")
	tests := []struct {
		name    string
		env     map[string]string
		want    string
		wantErr bool
	}{
		{name: "default cache", want: "default-token"},
		{
			name: "environment takes precedence",
			env: map[string]string{
				"HF_TOKEN": " env-token\r\n", "HUGGING_FACE_HUB_TOKEN": "legacy-token",
				"HF_TOKEN_PATH": home,
			},
			want: "env-token",
		},
		{
			name: "legacy environment",
			env:  map[string]string{"HUGGING_FACE_HUB_TOKEN": " legacy-token\n"},
			want: "legacy-token",
		},
		{
			name: "blank environment falls back",
			env:  map[string]string{"HF_TOKEN": " \n", "HUGGING_FACE_HUB_TOKEN": "legacy-token"},
			want: "legacy-token",
		},
		{
			name: "blank environment uses cache",
			env:  map[string]string{"HF_TOKEN": " \n", "HUGGING_FACE_HUB_TOKEN": "\t"},
			want: "default-token",
		},
		{
			name: "explicit token path",
			env: map[string]string{
				"HF_TOKEN_PATH":  filepath.Join(home, "custom-token"),
				"HF_HOME":        filepath.Join(home, "hf-home"),
				"XDG_CACHE_HOME": filepath.Join(home, "xdg"),
			},
			want: "custom-token",
		},
		{
			name: "HF home precedes XDG",
			env: map[string]string{
				"HF_HOME": filepath.Join(home, "hf-home"), "XDG_CACHE_HOME": filepath.Join(home, "xdg"),
			},
			want: "home-token",
		},
		{
			name: "XDG cache",
			env:  map[string]string{"XDG_CACHE_HOME": filepath.Join(home, "xdg")},
			want: "xdg-token",
		},
		{
			name: "tilde token path",
			env:  map[string]string{"HF_TOKEN_PATH": "~/custom-token"},
			want: "custom-token",
		},
		{
			name: "tilde home",
			env:  map[string]string{"HF_HOME": "~/hf-home"},
			want: "home-token",
		},
		{
			name: "missing token is anonymous",
			env:  map[string]string{"HF_TOKEN_PATH": filepath.Join(home, "missing")},
		},
		{
			name: "missing default cache is anonymous",
			env:  map[string]string{"HOME": filepath.Join(home, "missing"), "USERPROFILE": filepath.Join(home, "missing")},
		},
		{
			name: "empty token is anonymous",
			env:  map[string]string{"HF_TOKEN_PATH": filepath.Join(home, "empty-token")},
		},
		{
			name:    "unreadable token",
			env:     map[string]string{"HF_TOKEN_PATH": home},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			got, err := authToken()
			if tc.wantErr {
				var pathErr *os.PathError
				if !errors.As(err, &pathErr) {
					t.Fatalf("expected token read error, got %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("authToken() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestDisableImplicitToken(t *testing.T) {
	home := isolateAuthEnv(t)
	t.Setenv("HF_TOKEN", "env-token")
	t.Setenv("HF_TOKEN_PATH", home)
	for _, value := range []string{"1", "t", "T", "true", "TRUE", "True"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("HF_HUB_DISABLE_IMPLICIT_TOKEN", value)
			token, err := authToken()
			if err != nil || token != "" {
				t.Fatalf("authToken() = %q, %v; want anonymous", token, err)
			}
		})
	}
	for _, value := range []string{"", "0", "f", "F", "false", "FALSE", "False", "ON", "YES", "yes", "TrUe", "invalid"} {
		t.Run("enabled="+value, func(t *testing.T) {
			t.Setenv("HF_HUB_DISABLE_IMPLICIT_TOKEN", value)
			token, err := authToken()
			if err != nil || token != "env-token" {
				t.Fatalf("authToken() = %q, %v; want env-token", token, err)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func useHTTPClient(t *testing.T, client *http.Client) {
	t.Helper()
	old := sharedClient.Load()
	SetHTTPClient(client)
	t.Cleanup(func() { SetHTTPClient(old) })
}

func TestAuthenticatedRequests(t *testing.T) {
	for _, credentials := range []string{"environment", "saved login", "anonymous", "unreadable"} {
		t.Run(credentials, func(t *testing.T) {
			home := isolateAuthEnv(t)
			wantAuth := ""
			switch credentials {
			case "environment":
				t.Setenv("HF_TOKEN", "test-token")
				wantAuth = "Bearer test-token"
			case "saved login":
				writeTokenFile(t, filepath.Join(home, ".cache", "huggingface", "token"), "test-token\n")
				wantAuth = "Bearer test-token"
			case "unreadable":
				t.Setenv("HF_TOKEN_PATH", home)
			}
			for _, repo := range []string{"owner/repo", "datasets/owner/repo"} {
				for _, operation := range []string{"list", "download", "resolve"} {
					for _, status := range []int{http.StatusOK, http.StatusUnauthorized, http.StatusForbidden} {
						t.Run(fmt.Sprintf("%s/%s/%d", repo, operation, status), func(t *testing.T) {
							requests := 0
							useHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
								requests++
								if got := req.Header.Get("Authorization"); got != wantAuth {
									t.Errorf("Authorization = %q, want %q", got, wantAuth)
								}
								wantMethod := http.MethodGet
								if operation == "resolve" {
									wantMethod = http.MethodHead
								}
								if req.Method != wantMethod || req.Header.Get("Range") != "" {
									t.Errorf("unexpected request: %s, Range=%q", req.Method, req.Header.Get("Range"))
								}
								body := "file contents"
								if operation == "list" {
									body = `{"siblings":[{"rfilename":"file.txt"}]}`
								}
								return &http.Response{
									StatusCode: status, Status: http.StatusText(status),
									Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)),
									ContentLength: int64(len(body)), Request: req,
								}, nil
							})})
							p := Path{Repo: repo, File: "file.txt"}
							var err error
							switch operation {
							case "list":
								_, err = ListFiles(t.Context(), Path{Repo: repo})
							case "download":
								_, err = Download(t.Context(), p)
							case "resolve":
								_, _, err = ResolveDirectURL(t.Context(), p)
							}
							if credentials == "unreadable" {
								var pathErr *os.PathError
								if !errors.As(err, &pathErr) || requests != 0 {
									t.Fatalf("expected token error before HTTP request, got %v, %d requests", err, requests)
								}
								return
							}
							if requests != 1 {
								t.Fatalf("got %d requests, want 1", requests)
							}
							if status == http.StatusOK {
								if err != nil {
									t.Fatal(err)
								}
							} else {
								var statusErr *HTTPStatusError
								if !errors.As(err, &statusErr) || statusErr.StatusCode != status {
									t.Fatalf("got %v, want HTTPStatusError %d", err, status)
								}
							}
						})
					}
				}
			}
		})
	}
}

func TestRedirectAuthorization(t *testing.T) {
	isolateAuthEnv(t)
	t.Setenv("HF_TOKEN", "test-token")
	for _, target := range []string{
		"https://huggingface.co/api/resolve-cache/file",
		"https://huggingface.co:443/api/resolve-cache/file",
		"https://cdn-lfs.huggingface.co/file?sig=abc",
		"https://cas-bridge.xethub.hf.co/file?sig=abc",
		"https://huggingface.co.evil.example/file",
		"http://huggingface.co/file",
		"https://huggingface.co:8443/file",
	} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			t.Run(method+"/"+target, func(t *testing.T) {
				requests := 0
				useHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					requests++
					wantAuth := ""
					if requests == 1 || target == "https://huggingface.co/api/resolve-cache/file" ||
						target == "https://huggingface.co:443/api/resolve-cache/file" {
						wantAuth = "Bearer test-token"
					}
					if got := req.Header.Get("Authorization"); got != wantAuth {
						t.Errorf("request %d Authorization = %q, want %q", requests, got, wantAuth)
					}
					if req.Method != method || req.Header.Get("Range") != "" {
						t.Errorf("unexpected redirect method or range: %s, %q", req.Method, req.Header.Get("Range"))
					}
					resp := &http.Response{
						StatusCode: http.StatusOK, Header: make(http.Header),
						Body: io.NopCloser(strings.NewReader("file")), ContentLength: 4, Request: req,
					}
					if requests == 1 {
						resp.StatusCode = http.StatusFound
						resp.Header.Set("Location", target)
					} else if req.URL.String() != target {
						t.Errorf("redirected to %s, want %s", req.URL, target)
					}
					return resp, nil
				})})
				p := Path{Repo: "owner/repo", File: "file.txt"}
				if method == http.MethodHead {
					got, size, err := ResolveDirectURL(t.Context(), p)
					if err != nil || got != target || size != 4 {
						t.Fatalf("ResolveDirectURL = %q, %d, %v", got, size, err)
					}
				} else {
					data, err := Download(t.Context(), p)
					if err != nil || string(data) != "file" {
						t.Fatalf("Download = %q, %v", data, err)
					}
				}
				if requests != 2 {
					t.Fatalf("got %d requests, want 2", requests)
				}
			})
		}
	}
}

func TestHubClientPreservesConfiguration(t *testing.T) {
	isolateAuthEnv(t)
	stop := errors.New("custom redirect policy")
	base := &http.Client{
		Timeout: time.Second,
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"/next"}},
				Body: io.NopCloser(strings.NewReader("")), Request: req,
			}, nil
		}),
	}
	wrapped := hubClient(base)
	if wrapped.Timeout != base.Timeout || base.CheckRedirect != nil {
		t.Fatal("client configuration changed")
	}
	useHTTPClient(t, nil)
	original := http.DefaultClient
	http.DefaultClient = base
	t.Cleanup(func() { http.DefaultClient = original })
	p := Path{Repo: "owner/repo", File: "file.txt"}
	if _, err := Download(t.Context(), p); err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("redirect limit not preserved: %v", err)
	}
	base.CheckRedirect = func(*http.Request, []*http.Request) error { return stop }
	if _, err := Download(t.Context(), p); !errors.Is(err, stop) {
		t.Fatalf("custom redirect policy not preserved: %v", err)
	}
}
