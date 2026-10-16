package hf

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthTokenWithoutHome(t *testing.T) {
	home := isolateAuthEnv(t)
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	tokenHome := filepath.Join(home, "huggingface")
	tokenPath := filepath.Join(tokenHome, "token")
	writeTokenFile(t, tokenPath, "saved-token\n")
	badCache := filepath.Join(home, "unreadable")
	badHome := filepath.Join(badCache, "huggingface")
	badToken := filepath.Join(badHome, "token")
	if err := os.MkdirAll(badToken, 0o700); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		env     string
		value   string
		want    string
		wantErr string
	}{
		{name: "anonymous"},
		{name: "environment token", env: "HF_TOKEN", value: "env-token", want: "env-token"},
		{name: "legacy token", env: "HUGGING_FACE_HUB_TOKEN", value: "legacy-token", want: "legacy-token"},
		{name: "explicit token path", env: "HF_TOKEN_PATH", value: tokenPath, want: "saved-token"},
		{name: "explicit HF home", env: "HF_HOME", value: tokenHome, want: "saved-token"},
		{name: "explicit XDG cache", env: "XDG_CACHE_HOME", value: home, want: "saved-token"},
		{name: "tilde token path", env: "HF_TOKEN_PATH", value: "~/token", wantErr: "expand Hugging Face token path:"},
		{name: "tilde HF home", env: "HF_HOME", value: "~/huggingface", wantErr: "expand Hugging Face token path:"},
		{name: "tilde XDG cache", env: "XDG_CACHE_HOME", value: "~/.cache", wantErr: "expand Hugging Face token path:"},
		{name: "unreadable token path", env: "HF_TOKEN_PATH", value: badToken, wantErr: "read Hugging Face token:"},
		{name: "unreadable HF home token", env: "HF_HOME", value: badHome, wantErr: "read Hugging Face token:"},
		{name: "unreadable XDG token", env: "XDG_CACHE_HOME", value: badCache, wantErr: "read Hugging Face token:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env != "" {
				t.Setenv(tc.env, tc.value)
			}
			got, err := authToken()
			if tc.wantErr != "" {
				if err == nil || !strings.HasPrefix(err.Error(), tc.wantErr) {
					t.Fatalf("authToken() error = %v, want prefix %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("authToken() = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestAnonymousRequestsWithoutHome(t *testing.T) {
	isolateAuthEnv(t)
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	for _, operation := range []string{"list", "download", "resolve"} {
		t.Run(operation, func(t *testing.T) {
			requests := 0
			useHTTPClient(t, &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if got := req.Header.Get("Authorization"); got != "" {
					t.Errorf("Authorization = %q, want anonymous", got)
				}
				body := "file contents"
				if operation == "list" {
					body = `{"siblings":[{"rfilename":"file.txt"}]}`
				}
				return &http.Response{
					StatusCode: http.StatusOK, Header: make(http.Header),
					Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)), Request: req,
				}, nil
			})})
			p := Path{Repo: "owner/repo", File: "file.txt"}
			var err error
			switch operation {
			case "list":
				_, err = ListFiles(t.Context(), Path{Repo: p.Repo})
			case "download":
				_, err = Download(t.Context(), p)
			case "resolve":
				_, _, err = ResolveDirectURL(t.Context(), p)
			}
			if err != nil || requests != 1 {
				t.Fatalf("%s: error = %v, requests = %d; want success and one request", operation, err, requests)
			}
		})
	}
}
