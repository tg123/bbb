package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tg123/bbb/internal/hf"
	"github.com/urfave/cli/v3"
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

func TestCPDirectoryCopiesTree(t *testing.T) {
	srcDir := t.TempDir()
	nested := filepath.Join(srcDir, "nested")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "root.txt"), []byte("root"), 0o644); err != nil {
		t.Fatalf("write root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "child.txt"), []byte("child"), 0o644); err != nil {
		t.Fatalf("write child: %v", err)
	}
	dstDir := t.TempDir()

	cmd := &cli.Command{
		Name: "cp",
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f", Usage: "force overwrite"},
			&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}, Usage: "Suppress output"},
			&cli.IntFlag{Name: "concurrency", Usage: "Number of concurrent requests to use", Value: 1},
		},
		Action: cmdCP,
	}

	if err := cmd.Run(context.Background(), []string{"cp", srcDir, dstDir}); err != nil {
		t.Fatalf("cp run failed: %v", err)
	}

	cases := []struct {
		rel  string
		want string
	}{
		{rel: "root.txt", want: "root"},
		{rel: filepath.Join("nested", "child.txt"), want: "child"},
	}

	for _, tc := range cases {
		data, err := os.ReadFile(filepath.Join(dstDir, tc.rel))
		if err != nil {
			t.Fatalf("read %s: %v", tc.rel, err)
		}
		if string(data) != tc.want {
			t.Fatalf("unexpected content for %s: %q", tc.rel, string(data))
		}
	}
}

func TestHFFilterFiles(t *testing.T) {
	files := []string{"dir/file.txt", "dir/sub/file2.txt", "root.txt"}
	got := hfFilterFiles(files, "/dir")
	if len(got) != 2 || got[0] != "file.txt" || got[1] != "sub/file2.txt" {
		t.Fatalf("unexpected filtered files: %#v", got)
	}
}

func TestNormalizeHFPrefix(t *testing.T) {
	if got := normalizeHFPrefix("///dir/sub"); got != "dir/sub" {
		t.Fatalf("unexpected normalized prefix: %s", got)
	}
	if got := normalizeHFPrefix("/"); got != "" {
		t.Fatalf("expected empty prefix, got: %s", got)
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

func TestHFSplitWildcard(t *testing.T) {
	tests := []struct {
		input      string
		parentPath string
		pattern    string
	}{
		{"hf://owner/repo", "hf://owner/repo", ""},
		{"hf://owner/repo/*.bin", "hf://owner/repo/", "*.bin"},
		{"hf://owner/repo/dir/*.bin", "hf://owner/repo/dir/", "*.bin"},
	}
	for _, tc := range tests {
		parentPath, pattern := hfSplitWildcard(tc.input)
		if parentPath != tc.parentPath || pattern != tc.pattern {
			t.Fatalf("unexpected split for %s: %s %s", tc.input, parentPath, pattern)
		}
	}
}

func TestWriteStreamToFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "nested", "file.txt")
	content := "stream data"
	if err := writeStreamToFile(dst, strings.NewReader(content), 0o644); err != nil {
		t.Fatalf("writeStreamToFile failed: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if string(data) != content {
		t.Fatalf("unexpected content: %s", string(data))
	}
}
