package bbbfs

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/tg123/bbb/internal/azblob"
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

func TestListRecursiveLocalNestedPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write sub/b.txt: %v", err)
	}

	var got []string
	for result := range ListRecursive(context.Background(), root) {
		if result.Err != nil {
			t.Fatalf("ListRecursive failed: %v", result.Err)
		}
		got = append(got, result.Entry.Name)
	}

	want := []string{"a.txt", filepath.Join("sub", "b.txt")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected recursive entries: got %v want %v", got, want)
	}
}

func TestProvidersImplementRecursiveLister(t *testing.T) {
	if _, ok := any(azFS{}).(recursiveLister); !ok {
		t.Fatalf("azFS should implement recursiveLister")
	}
	if _, ok := any(hfFS{}).(recursiveLister); !ok {
		t.Fatalf("hfFS should implement recursiveLister")
	}
}

func TestRegisterAzAccountRolesDistinctAccounts(t *testing.T) {
	defer azblob.ClearAccountRole("srcacct")
	defer azblob.ClearAccountRole("dstacct")

	RegisterAzAccountRoles(
		[]string{"az://srcacct/c/"},
		[]string{"az://dstacct/c/"},
	)

	role, ok := azblob.AccountRole("srcacct")
	if !ok || role != "SRC" {
		t.Fatalf("expected SRC for srcacct, got %q (ok=%v)", role, ok)
	}
	role, ok = azblob.AccountRole("dstacct")
	if !ok || role != "DST" {
		t.Fatalf("expected DST for dstacct, got %q (ok=%v)", role, ok)
	}
}

func TestRegisterAzAccountRolesOverlapSkipped(t *testing.T) {
	defer azblob.ClearAccountRole("shared")

	RegisterAzAccountRoles(
		[]string{"az://shared/c/"},
		[]string{"az://shared/c/"},
	)

	_, ok := azblob.AccountRole("shared")
	if ok {
		t.Fatal("account appearing in both src and dst should not be tagged")
	}
}

func TestRegisterAzAccountRolesNonAzIgnored(t *testing.T) {
	defer azblob.ClearAccountRole("myacct")

	RegisterAzAccountRoles(
		[]string{"/local/path", "az://myacct/c/"},
		[]string{"hf://org/repo/file"},
	)

	role, ok := azblob.AccountRole("myacct")
	if !ok || role != "SRC" {
		t.Fatalf("expected SRC for myacct, got %q (ok=%v)", role, ok)
	}
}
