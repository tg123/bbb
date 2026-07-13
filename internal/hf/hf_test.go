package hf

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
			original := doRequest
			doRequest = func(req *http.Request) (*http.Response, error) {
				if req.URL.String() != tc.wantURL {
					t.Fatalf("unexpected list url: %s", req.URL.String())
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"siblings":[{"rfilename":"README.md"}]}`)),
					Header:     make(http.Header),
				}, nil
			}
			t.Cleanup(func() { doRequest = original })

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

func TestResolveDirectURL(t *testing.T) {
	const cdnURL = "https://cdn-lfs.huggingface.co/repo/model.bin?sig=abc"
	original := doRequest
	doRequest = func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Range") != "bytes=0-0" {
			t.Fatalf("expected range header, got %q", req.Header.Get("Range"))
		}
		hdr := make(http.Header)
		hdr.Set("Content-Range", "bytes 0-0/1048576")
		finalReq, _ := http.NewRequest(http.MethodGet, cdnURL, nil)
		return &http.Response{
			StatusCode: http.StatusPartialContent,
			Body:       io.NopCloser(strings.NewReader("x")),
			Header:     hdr,
			Request:    finalReq,
		}, nil
	}
	t.Cleanup(func() { doRequest = original })

	url, size, err := ResolveDirectURL(context.Background(), Path{Repo: "owner/repo", File: "model.bin"})
	if err != nil {
		t.Fatalf("ResolveDirectURL failed: %v", err)
	}
	if url != cdnURL {
		t.Fatalf("unexpected url: %s", url)
	}
	if size != 1048576 {
		t.Fatalf("unexpected size: %d", size)
	}
}

func TestResolveDirectURLXLinkedSize(t *testing.T) {
	original := doRequest
	doRequest = func(req *http.Request) (*http.Response, error) {
		hdr := make(http.Header)
		hdr.Set("X-Linked-Size", "42")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     hdr,
			Request:    req,
		}, nil
	}
	t.Cleanup(func() { doRequest = original })

	_, size, err := ResolveDirectURL(context.Background(), Path{Repo: "owner/repo", File: "a.txt"})
	if err != nil {
		t.Fatalf("ResolveDirectURL failed: %v", err)
	}
	if size != 42 {
		t.Fatalf("unexpected size: %d", size)
	}
}

func TestParseContentRangeTotal(t *testing.T) {
	cases := map[string]int64{
		"bytes 0-0/1048576": 1048576,
		"bytes 0-99/*":      -1,
		"":                  -1,
		"garbage":           -1,
	}
	for in, want := range cases {
		if got := parseContentRangeTotal(in); got != want {
			t.Fatalf("parseContentRangeTotal(%q)=%d want %d", in, got, want)
		}
	}
}
