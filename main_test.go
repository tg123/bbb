package main

import (
	"testing"

	"github.com/tg123/bbb/internal/hf"
)

func TestIsAzHTTPS(t *testing.T) {
	if !isAz("https://myacct.blob.core.windows.net/container") {
		t.Fatalf("expected https blob url to be treated as az path")
	}
	if isAz("https://example.com/file") {
		t.Fatalf("non-blob https url should not be treated as az path")
	}
}

func TestIsAzHTTPEdgeCases(t *testing.T) {
	if !isAz("http://MYACCT.blob.core.windows.net:8080/container/blob.txt?sv=2021#frag") {
		t.Fatalf("expected blob url with port/query/fragment to be az path")
	}
	if isAz("http://bad.blob.core.windows.net/") {
		t.Fatalf("url missing container should not be treated as az path")
	}
	if isAz("ftp://acct.blob.core.windows.net/container") {
		t.Fatalf("non-http scheme should not be treated as az path")
	}
}

func TestIsHF(t *testing.T) {
	if !isHF("hf://openai/gpt-oss-120b") {
		t.Fatalf("expected hf:// path to be detected")
	}
	if isHF("https://huggingface.co/openai/gpt-oss-120b") {
		t.Fatalf("non-hf scheme should not be detected as hf")
	}
}

func TestHFPathDefaults(t *testing.T) {
	p, err := hf.Parse("hf://openai/gpt-oss-120b")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if p.DefaultFilename() != "gpt-oss-120b" {
		t.Fatalf("unexpected default filename: %s", p.DefaultFilename())
	}
	if _, err := p.URL(); err == nil {
		t.Fatalf("expected url error for repo path")
	}

	p, err = hf.Parse("hf://openai/gpt-oss-120b/README.md")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if p.DefaultFilename() != "README.md" {
		t.Fatalf("unexpected file default filename: %s", p.DefaultFilename())
	}
	url, err := p.URL()
	if err != nil {
		t.Fatalf("unexpected url error: %v", err)
	}
	if url != "https://huggingface.co/openai/gpt-oss-120b/resolve/main/README.md" {
		t.Fatalf("unexpected file url: %s", url)
	}
}

func TestHFPathURLEscaping(t *testing.T) {
	p := hf.Path{
		Repo: "openai/gpt-oss-120b",
		File: "nested dir/file #1%?.bin",
	}
	url, err := p.URL()
	if err != nil {
		t.Fatalf("unexpected url error: %v", err)
	}
	expected := "https://huggingface.co/openai/gpt-oss-120b/resolve/main/nested%20dir/file%20%231%25%3F.bin"
	if url != expected {
		t.Fatalf("unexpected escaped url: %s", url)
	}
}

func TestResolveDstPathAzDir(t *testing.T) {
	dst, err := resolveDstPath("az://acct/container/prefix", true, "model.bin", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst != "az://acct/container/prefix/model.bin" {
		t.Fatalf("unexpected destination: %s", dst)
	}
}

func TestHFFilterFiles(t *testing.T) {
	files := []string{"dir/file.txt", "dir/sub/file2.txt", "root.txt"}
	got := hfFilterFiles(files, "/dir")
	if len(got) != 2 || got[0] != "file.txt" || got[1] != "sub/file2.txt" {
		t.Fatalf("unexpected filtered files: %#v", got)
	}
}

func TestHFListEntries(t *testing.T) {
	files := []string{"dir/file.txt", "dir/sub/file2.txt", "root.txt"}
	got := hfListEntries(files, "dir")
	expected := []string{"file.txt", "sub/"}
	if len(got) != len(expected) {
		t.Fatalf("unexpected entry count: %#v", got)
	}
	for i, entry := range expected {
		if got[i] != entry {
			t.Fatalf("unexpected entry at %d: %s", i, got[i])
		}
	}
}
