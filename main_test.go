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
	if p.DefaultFilename() != "gpt-oss-120b.zip" {
		t.Fatalf("unexpected default filename: %s", p.DefaultFilename())
	}
	url, err := p.URL()
	if err != nil {
		t.Fatalf("unexpected url error: %v", err)
	}
	if url != "https://huggingface.co/openai/gpt-oss-120b/archive/main.zip" {
		t.Fatalf("unexpected url: %s", url)
	}

	p, err = hf.Parse("hf://openai/gpt-oss-120b/README.md")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if p.DefaultFilename() != "README.md" {
		t.Fatalf("unexpected file default filename: %s", p.DefaultFilename())
	}
	url, err = p.URL()
	if err != nil {
		t.Fatalf("unexpected url error: %v", err)
	}
	if url != "https://huggingface.co/openai/gpt-oss-120b/resolve/main/README.md" {
		t.Fatalf("unexpected file url: %s", url)
	}
}
