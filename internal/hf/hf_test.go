package hf

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestListFilesAPIEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		repo    string
		wantURL string
	}{
		{
			name:    "model",
			repo:    "openai/gpt-oss-120b",
			wantURL: "https://huggingface.co/api/models/openai/gpt-oss-120b?blobs=true",
		},
		{
			name:    "dataset",
			repo:    "datasets/allenai/tulu-3-sft-mixture",
			wantURL: "https://huggingface.co/api/datasets/allenai/tulu-3-sft-mixture?blobs=true",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := http.DefaultClient
			http.DefaultClient = &http.Client{
				Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					if req.URL.String() != tc.wantURL {
						t.Fatalf("unexpected list url: %s", req.URL.String())
					}
					return &http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"siblings":[{"rfilename":"README.md"}]}`)),
						Header:     make(http.Header),
					}, nil
				}),
			}
			t.Cleanup(func() { http.DefaultClient = original })

			files, err := ListFiles(context.Background(), Path{Repo: tc.repo})
			if err != nil {
				t.Fatalf("ListFiles failed: %v", err)
			}
			if len(files) != 1 || files[0] != "README.md" {
				t.Fatalf("unexpected files: %#v", files)
			}
		})
	}
}
