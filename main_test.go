package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
		t.Fatalf("expected hf scheme to be detected")
	}
	if isHF("https://example.com/model") {
		t.Fatalf("non-hf scheme should not be detected")
	}
}

func TestHFPathParseRepoOnly(t *testing.T) {
	path, err := hf.Parse("hf://owner/repo")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if path.File != "" {
		t.Fatalf("expected empty file, got %s", path.File)
	}
}

func TestHFPathStringPreservesSpaces(t *testing.T) {
	path, err := hf.Parse("hf://owner/repo/a b.txt")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if path.String() != "hf://owner/repo/a b.txt" {
		t.Fatalf("unexpected escaped path: %s", path.String())
	}
}

func TestResolveDstPathAzDir(t *testing.T) {
	dst, err := resolveDstPath("az://acct/container/prefix", true, "model.bin", true)
	if err != nil {
		t.Fatalf("resolveDstPath failed: %v", err)
	}
	if dst != "az://acct/container/prefix/model.bin" {
		t.Fatalf("unexpected dst: %s", dst)
	}
}

func TestSyncHFFiles(t *testing.T) {
	files := []string{"file.txt", "dir/file2.txt", "dir/skip.txt"}
	list := syncHFFilesFromList(files, func(name string) bool { return strings.Contains(name, "skip") })
	if len(list) != 2 {
		t.Fatalf("unexpected list length: %d", len(list))
	}
}

func TestCmdSyncRejectsHFFilePath(t *testing.T) {
	app := &cli.Command{
		Action: cmdSync,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "dry-run"},
			&cli.BoolFlag{Name: "delete"},
			&cli.StringFlag{Name: "x"},
			&cli.IntFlag{Name: "concurrency", Value: 1},
			&cli.IntFlag{Name: "retry-count"},
			&cli.BoolFlag{Name: "q"},
		},
	}
	err := app.Run(context.Background(), []string{"sync", "hf://owner/repo/file.txt", "az://acct/container"})
	if err == nil {
		t.Fatalf("expected error for hf file path")
	}
}

func TestCPDirectoryCopiesTree(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	srcFile := filepath.Join(srcDir, "sub", "file.txt")
	if err := os.WriteFile(srcFile, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", srcDir, dstDir}); err != nil {
		t.Fatalf("cp failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "sub", "file.txt")); err != nil {
		t.Fatalf("expected copied file: %v", err)
	}
}

func TestRunOpPoolProcessesAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	items := []int{1, 2, 3}
	seen := make(map[int]bool, len(items))
	var mu sync.Mutex
	err := runOpPool(ctx, 2, func(pending chan<- int) error {
		for _, item := range items {
			if err := sendOp(ctx, pending, item); err != nil {
				return err
			}
		}
		return nil
	}, func(item int) error {
		mu.Lock()
		seen[item] = true
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("runOpPool failed: %v", err)
	}
	if len(seen) != len(items) {
		t.Fatalf("expected %d items, got %d", len(items), len(seen))
	}
}

func TestRetryOpRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	err := retryOp(ctx, 2, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryOp failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestRunOpPoolWithRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	items := []int{1, 2, 3}
	attempts := make(map[int]int, len(items))
	var mu sync.Mutex
	err := runOpPoolWithRetry(ctx, 2, 1, func(pending chan<- int) error {
		for _, item := range items {
			if err := sendOp(ctx, pending, item); err != nil {
				return err
			}
		}
		return nil
	}, func(item int) error {
		mu.Lock()
		attempts[item]++
		count := attempts[item]
		mu.Unlock()
		if count == 1 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("runOpPoolWithRetry failed: %v", err)
	}
	for _, item := range items {
		if attempts[item] != 2 {
			t.Fatalf("expected item %d to retry once, got %d attempts", item, attempts[item])
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
		parentPath, pattern := splitWildcard(tc.input)
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
		t.Fatalf("unexpected content: %s", data)
	}
}
