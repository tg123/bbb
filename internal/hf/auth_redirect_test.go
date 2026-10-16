package hf

import (
	"errors"
	"net/http"
	"testing"
)

func TestHubClientRedirectPolicyHeaders(t *testing.T) {
	const authorization = "Bearer redirect-test-token"
	for _, tc := range []struct {
		name     string
		target   string
		wantAuth string
	}{
		{"Hub", "https://huggingface.co/file", authorization},
		{"Hub HTTPS port", "https://huggingface.co:443/file", authorization},
		{"CDN subdomain", "https://cdn-lfs.huggingface.co/file", ""},
		{"external CDN", "https://cas-bridge.xethub.hf.co/file", ""},
		{"lookalike host", "https://huggingface.co.evil.example/file", ""},
		{"HTTP downgrade", "http://huggingface.co/file", ""},
		{"other port", "https://huggingface.co:8443/file", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests, redirects := 0, 0
			client := hubClient(&http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					redirects++
					req.Header = via[0].Header.Clone()
					req.Header.Set("X-Redirect-Policy", "applied")
					return nil
				},
				Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					requests++
					resp := &http.Response{
						StatusCode: http.StatusOK, Header: make(http.Header),
						Body: http.NoBody, Request: req,
					}
					wantAuth := tc.wantAuth
					if requests == 1 {
						wantAuth = authorization
						resp.StatusCode = http.StatusFound
						resp.Header.Set("Location", tc.target)
					} else {
						if req.URL.String() != tc.target {
							t.Errorf("redirect URL = %q, want %q", req.URL, tc.target)
						}
						if req.Header.Get("X-Redirect-Policy") != "applied" {
							t.Error("custom redirect policy header was lost")
						}
					}
					if got := req.Header.Get("Authorization"); got != wantAuth {
						t.Errorf("request %d Authorization = %q, want %q", requests, got, wantAuth)
					}
					return resp, nil
				}),
			})
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://huggingface.co/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", authorization)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if err := resp.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if requests != 2 || redirects != 1 {
				t.Fatalf("got %d requests and %d policy calls, want 2 and 1", requests, redirects)
			}
			if req.Header.Get("Authorization") != authorization {
				t.Error("original request authorization was changed")
			}
		})
	}
}

func TestHubClientRedirectPolicyError(t *testing.T) {
	for _, policyErr := range []error{errors.New("custom redirect policy"), http.ErrUseLastResponse} {
		t.Run(policyErr.Error(), func(t *testing.T) {
			original, err := http.NewRequest(http.MethodGet, "https://huggingface.co/start", nil)
			if err != nil {
				t.Fatal(err)
			}
			original.Header.Set("Authorization", "Bearer redirect-test-token")
			redirect, err := http.NewRequest(http.MethodGet, "http://huggingface.co/file", nil)
			if err != nil {
				t.Fatal(err)
			}
			client := hubClient(&http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					req.Header = via[0].Header.Clone()
					return policyErr
				},
			})
			if err := client.CheckRedirect(redirect, []*http.Request{original}); err != policyErr {
				t.Errorf("redirect error = %v, want original error %v", err, policyErr)
			}
			if got := redirect.Header.Get("Authorization"); got != "" {
				t.Errorf("redirect Authorization = %q, want empty", got)
			}
		})
	}
}
