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
	s3Bucket = "test"
	// s3Host is the MinIO endpoint. The bbb container shares azurite's network
	// namespace (see docker-compose.yaml), and MinIO runs in that same
	// namespace listening on :9000, so it is reachable on localhost.
	s3Host = "localhost:9000"
)

func s3Path(parts ...string) string {
	p := "s3://" + s3Bucket
	if len(parts) > 0 {
		p += "/" + strings.Join(parts, "/")
	}
	return p
}

func TestS3Basic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}
	if !waitForEndpointReady(s3Host) {
		t.Skipf("minio endpoint %s not reachable", s3Host)
	}

	// create bucket
	{
		if _, err := runBBB("s3", "mkbucket", s3Path()); err != nil {
			t.Fatal(err)
		}
	}

	// start from a clean bucket so reruns are deterministic
	cleanFolder(t, s3Path())

	// touch + ls + rm
	{
		touchPath := s3Path("touched.txt")
		if _, err := runBBB("touch", touchPath); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs(s3Path(), false)
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

	tmpFile, err := os.CreateTemp("", "bbb-s3-e2e-")
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
	if _, err := runBBB("cp", tmpFile.Name(), s3Path()); err != nil {
		t.Fatal(err)
	}
	// upload to an explicit key
	if _, err := runBBB("cp", tmpFile.Name(), s3Path("testfile.txt")); err != nil {
		t.Fatal(err)
	}
	// upload into a nested "directory"
	if _, err := runBBB("cp", tmpFile.Name(), s3Path("dir", "testfile.txt")); err != nil {
		t.Fatal(err)
	}

	uploadedName := filepath.Base(tmpFile.Name())

	// ls (non-recursive) returns direct children and the pseudo-directory
	{
		files, err := bbbLs(s3Path(), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			s3Path(uploadedName),
			s3Path("dir"),
			s3Path("testfile.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected ls: got %v, want %v", files, expected)
		}
	}

	// ls single file (Stat fallback for exact key)
	{
		singleFile := s3Path("testfile.txt")
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
		singleFile := s3Path("testfile.txt")
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
		files, err := bbbLs(s3Path(), true)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			s3Path(uploadedName),
			s3Path("dir", "testfile.txt"),
			s3Path("testfile.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("unexpected lsr: got %v, want %v", files, expected)
		}
	}

	// server-side copy within S3
	{
		if _, err := runBBB("cp", s3Path("testfile.txt"), s3Path("testfile2.txt")); err != nil {
			t.Fatal(err)
		}
		files, err := bbbLs(s3Path("testfile*"), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			s3Path("testfile.txt"),
			s3Path("testfile2.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("server-side copy ls: got %v, want %v", files, expected)
		}
	}

	// ls with ? wildcard
	{
		files, err := bbbLs(s3Path("testfile?.txt"), false)
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{s3Path("testfile2.txt")}
		if !slices.Equal(files, expected) {
			t.Errorf("ls ? wildcard: got %v, want %v", files, expected)
		}
	}

	// ll with * wildcard
	{
		files, err := bbbLL(s3Path("testfile*"))
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			s3Path("testfile.txt"),
			s3Path("testfile2.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("ll * wildcard: got %v, want %v", files, expected)
		}
	}

	// llr with * wildcard (filename component matches across subdirs)
	{
		files, err := bbbLLR(s3Path("testfile*"))
		if err != nil {
			t.Fatal(err)
		}
		expected := []string{
			s3Path("dir", "testfile.txt"),
			s3Path("testfile.txt"),
			s3Path("testfile2.txt"),
		}
		sort.Strings(files)
		sort.Strings(expected)
		if !slices.Equal(files, expected) {
			t.Errorf("llr * wildcard: got %v, want %v", files, expected)
		}
	}

	// cat
	{
		stdout, err := runBBB("cat", s3Path("testfile.txt"))
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
		stdout, err := runBBB("md5sum", s3Path("testfile.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if got := parseMD5Output(stdout); got != expected {
			t.Fatalf("unexpected s3 md5sum: got %s, want %s", got, expected)
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
		if _, err := runBBB("cp", s3Path("testfile.txt"), downloadPath); err != nil {
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

	// sync local dir -> s3 prefix
	t.Run("sync local to s3", func(t *testing.T) {
		localDir, err := os.MkdirTemp("", "bbb-s3-sync-")
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

		dstPrefix := s3Path(fmt.Sprintf("sync-%d", time.Now().UnixNano())) + "/"
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
		prefix := s3Path(fmt.Sprintf("rmtree-%d", time.Now().UnixNano()))
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
	cleanFolder(t, s3Path())
}
