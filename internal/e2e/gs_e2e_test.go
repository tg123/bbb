package e2e_test

import (
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	gsBucket = "gstest"
	// gsHost is the fake-gcs-server endpoint. The bbb container shares
	// azurite's network namespace (see docker-compose.yaml), and
	// fake-gcs-server runs in that same namespace listening on :4443, so it is
	// reachable on localhost.
	gsHost = "localhost:4443"
)

func gsPath(parts ...string) string {
	p := "gs://" + gsBucket
	if len(parts) > 0 {
		p += "/" + strings.Join(parts, "/")
	}
	return p
}

func TestGSBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}
	if !waitForEndpointReady(gsHost) {
		t.Skipf("fake-gcs-server endpoint %s not reachable", gsHost)
	}

	// create bucket
	{
		if _, err := runBBB("gs", "mkbucket", gsPath()); err != nil {
			t.Fatal(err)
		}
	}

	// start from a clean bucket so reruns are deterministic
	cleanFolder(t, gsPath())

	// touch + ls + rm
	{
		touchPath := gsPath("touched.txt")
		if _, err := runBBB("touch", touchPath); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs(gsPath(), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{touchPath}
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files after touch: got %v, want %v", files, expected)
		}
		if _, err := runBBB("rm", touchPath); err != nil {
			t.Fatal(err)
		}
	}

	tmpFile, err := os.CreateTemp("", "bbb-gs-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if rerr := os.Remove(tmpFile.Name()); rerr != nil {
			t.Logf("cleanup temp file: %v", rerr)
		}
	}()
	content := []byte("hello world")
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatal(err)
	}

	// upload to bucket prefix (keeps the local file name)
	if _, err := runBBB("cp", tmpFile.Name(), gsPath()); err != nil {
		t.Fatal(err)
	}
	// upload to an explicit key
	if _, err := runBBB("cp", tmpFile.Name(), gsPath("testfile.txt")); err != nil {
		t.Fatal(err)
	}
	// upload into a nested "directory"
	if _, err := runBBB("cp", tmpFile.Name(), gsPath("dir", "testfile.txt")); err != nil {
		t.Fatal(err)
	}

	uploadedName := filepath.Base(tmpFile.Name())

	// ls (non-recursive) returns direct children and the pseudo-directory
	{
		files, err := bbbLs(gsPath(), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			gsPath(uploadedName),
			gsPath("dir"),
			gsPath("testfile.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected ls: got %v, want %v", files, expected)
		}
	}

	// ls single file (Stat fallback for exact key)
	{
		singleFile := gsPath("testfile.txt")
		files, err := bbbLs(singleFile, false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{singleFile}
		if !slices.Equal(files, expected) {
			t.Errorf("ls single file: got %v, want %v", files, expected)
		}
	}

	// ll single file
	{
		singleFile := gsPath("testfile.txt")
		files, err := bbbLL(singleFile)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{singleFile}
		if !slices.Equal(files, expected) {
			t.Errorf("ll single file: got %v, want %v", files, expected)
		}
	}

	// lsr (recursive) returns all object keys
	{
		files, err := bbbLs(gsPath(), true)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			gsPath(uploadedName),
			gsPath("dir", "testfile.txt"),
			gsPath("testfile.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected lsr: got %v, want %v", files, expected)
		}
	}

	// server-side copy within GCS
	{
		if _, err := runBBB("cp", gsPath("testfile.txt"), gsPath("testfile2.txt")); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs(gsPath("testfile*"), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			gsPath("testfile.txt"),
			gsPath("testfile2.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("server-side copy ls: got %v, want %v", files, expected)
		}
	}

	// ls with ? wildcard
	{
		files, err := bbbLs(gsPath("testfile?.txt"), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{gsPath("testfile2.txt")}
		if !slices.Equal(files, expected) {
			t.Errorf("ls ? wildcard: got %v, want %v", files, expected)
		}
	}

	// ll with * wildcard
	{
		files, err := bbbLL(gsPath("testfile*"))
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			gsPath("testfile.txt"),
			gsPath("testfile2.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("ll * wildcard: got %v, want %v", files, expected)
		}
	}

	// llr with * wildcard (filename component matches across subdirs)
	{
		files, err := bbbLLR(gsPath("testfile*"))
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			gsPath("dir", "testfile.txt"),
			gsPath("testfile.txt"),
			gsPath("testfile2.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("llr * wildcard: got %v, want %v", files, expected)
		}
	}

	// cat
	{
		stdout, err := runBBB("cat", gsPath("testfile.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if string(stdout) != "hello world" {
			t.Errorf("unexpected cat output: %s", stdout)
		}
	}

	// md5sum
	{
		expected := fmt.Sprintf("%x", md5.Sum(content))
		stdout, err := runBBB("md5sum", gsPath("testfile.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := parseMD5Output(stdout); got != expected {
			t.Fatalf("unexpected gs md5sum: got %s, want %s", got, expected)
		}
	}

	// download back to local
	{
		downloadPath := tmpFile.Name() + ".downloaded"
		defer func() {
			if rerr := os.Remove(downloadPath); rerr != nil {
				t.Logf("cleanup download file: %v", rerr)
			}
		}()
		if _, err := runBBB("cp", gsPath("testfile.txt"), downloadPath); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(downloadPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != "hello world" {
			t.Errorf("unexpected downloaded content: %s", data)
		}
	}

	// sync local dir -> gs prefix
	t.Run("sync local to gs", func(t *testing.T) {
		localDir, err := os.MkdirTemp("", "bbb-gs-sync-")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if rerr := os.RemoveAll(localDir); rerr != nil {
				t.Logf("cleanup local dir: %v", rerr)
			}
		}()
		if err := os.WriteFile(filepath.Join(localDir, "1.txt"), content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(localDir, "2.txt"), content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(localDir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(localDir, "sub", "3.txt"), content, 0o644); err != nil {
			t.Fatal(err)
		}

		dstPrefix := gsPath(fmt.Sprintf("sync-%d", time.Now().UnixNano())) + "/"
		t.Cleanup(func() {
			cleanFolder(t, dstPrefix)
		})
		if _, err := runBBB("sync", localDir, dstPrefix); err != nil {
			t.Fatal(err)
		}

		files, err := bbbLs(dstPrefix, true)
		if err != nil {
			t.Fatal(err)
		}
		base := strings.TrimSuffix(dstPrefix, "/")
		expected := []string{
			base + "/1.txt",
			base + "/2.txt",
			base + "/sub/3.txt",
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected files after sync: got %v, want %v", files, expected)
		}
	})

	// rmtree removes a whole prefix
	t.Run("rmtree prefix", func(t *testing.T) {
		prefix := gsPath(fmt.Sprintf("rmtree-%d", time.Now().UnixNano()))
		if _, err := runBBB("cp", tmpFile.Name(), prefix+"/a.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := runBBB("cp", tmpFile.Name(), prefix+"/nested/b.txt"); err != nil {
			t.Fatal(err)
		}
		if _, err := runBBB("rmtree", prefix); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs(prefix, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 0 {
			t.Errorf("expected no files after rmtree, got %v", files)
		}
	})

	// final cleanup
	cleanFolder(t, gsPath())
}
