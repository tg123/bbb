package bbbfs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveReadLocal(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, "sample.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	fs := Resolve(path)
	if err := readDummy(fs, path); err != nil {
		t.Fatalf("expected local read to succeed: %v", err)
	}
}

func TestResolveReadHF(t *testing.T) {
	fs := Resolve("hf://owner/repo/file.txt")
	if _, ok := fs.(hfFS); !ok {
		t.Fatalf("expected hfFS, got %T", fs)
	}
}

func TestResolveReadAz(t *testing.T) {
	fs := Resolve("az://account/container/blob")
	if _, ok := fs.(azFS); !ok {
		t.Fatalf("expected azFS, got %T", fs)
	}
}

func readDummy(fs FS, path string) error {
	rc, err := fs.Read(context.Background(), path)
	if err != nil {
		return err
	}
	return rc.Close()
}
