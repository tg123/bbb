package azblob

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

func TestParseHTTPSBlobURL(t *testing.T) {
	ap, err := Parse("https://myacct.blob.core.windows.net/container/path/to/blob.txt")
	if err != nil {
		t.Fatalf("parse https failed: %v", err)
	}
	if ap.Account != "myacct" || ap.Container != "container" || ap.Blob != "path/to/blob.txt" {
		t.Fatalf("unexpected parse result: %+v", ap)
	}
}

func TestParseHTTPBlobWithPort(t *testing.T) {
	ap, err := Parse("http://devstoreaccount1.blob.localhost:10000/container")
	if err != nil {
		t.Fatalf("parse http with port failed: %v", err)
	}
	if ap.Account != "devstoreaccount1" || ap.Container != "container" || ap.Blob != "" {
		t.Fatalf("unexpected parse result: %+v", ap)
	}
}

func TestParseHTTPSWithQueryAndFragment(t *testing.T) {
	raw := "https://myacct.blob.core.windows.net/container/path/to/blob.txt?sv=2021&sig=abc#section"
	ap, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse https with query/fragment failed: %v", err)
	}
	if ap.Account != "myacct" || ap.Container != "container" || ap.Blob != "path/to/blob.txt" {
		t.Fatalf("unexpected parse result: %+v", ap)
	}
}

func TestParseHTTPSInvalidContainer(t *testing.T) {
	if _, err := Parse("https://acct.blob.core.windows.net/UPPER"); err == nil {
		t.Fatal("expected invalid container error")
	}
	if _, err := Parse("https://acct.blob.core.windows.net/x"); err == nil {
		t.Fatal("expected invalid container length error")
	}
}

func TestParseRejectsNonBlobHTTPS(t *testing.T) {
	if _, err := Parse("https://example.com/container/blob"); err == nil {
		t.Fatal("expected error for non blob https url")
	}
}

func TestCopyBlobServerSideRejectsDirLike(t *testing.T) {
	ctx := context.Background()
	src := AzurePath{Account: "acct", Container: "container"}
	dst := AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	if err := CopyBlobServerSide(ctx, src, dst, nil); err == nil {
		t.Fatal("expected error for dir-like source")
	}
	src = AzurePath{Account: "acct", Container: "container", Blob: "dir/"}
	if err := CopyBlobServerSide(ctx, src, dst, nil); err == nil {
		t.Fatal("expected error for trailing slash source")
	}
	src = AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	dst = AzurePath{Account: "acct", Container: "container"}
	if err := CopyBlobServerSide(ctx, src, dst, nil); err == nil {
		t.Fatal("expected error for dir-like destination")
	}
	dst = AzurePath{Account: "acct", Container: "container", Blob: "dir/"}
	if err := CopyBlobServerSide(ctx, src, dst, nil); err == nil {
		t.Fatal("expected error for trailing slash destination")
	}
}

func TestCopyBlobServerSideCrossAccountRequiresCredentials(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to prevent real HTTP calls
	src := AzurePath{Account: "acct1", Container: "container", Blob: "file.txt"}
	dst := AzurePath{Account: "acct2", Container: "container", Blob: "file.txt"}
	err := CopyBlobServerSide(ctx, src, dst, nil)
	if err == nil {
		t.Fatal("expected error for cross-account copy without credentials")
	}
}

func TestCopyBlobServerSideFallsBackToUserDelegation(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to prevent real HTTP calls
	src := AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	dst := AzurePath{Account: "acct", Container: "container", Blob: "other.txt"}
	err := CopyBlobServerSide(ctx, src, dst, nil)
	// Without real Azure credentials the user delegation path will fail,
	// but it must NOT be a MissingSharedKeyCredential error since we now
	// attempt the delegation path instead.
	if errors.Is(err, bloberror.MissingSharedKeyCredential) {
		t.Fatalf("should not require shared key, got %v", err)
	}
	if err == nil {
		t.Fatal("expected error without real credentials")
	}
}

func TestParseCopyProgress(t *testing.T) {
	copied, total, ok := parseCopyProgress("1024/2048")
	if !ok || copied != 1024 || total != 2048 {
		t.Fatalf("expected 1024/2048, got %d/%d ok=%v", copied, total, ok)
	}
	copied, total, ok = parseCopyProgress("0/0")
	if !ok || copied != 0 || total != 0 {
		t.Fatalf("expected 0/0, got %d/%d ok=%v", copied, total, ok)
	}
	if _, _, ok := parseCopyProgress("invalid"); ok {
		t.Fatal("expected false for invalid input")
	}
	if _, _, ok := parseCopyProgress("abc/def"); ok {
		t.Fatal("expected false for non-numeric input")
	}
	if _, _, ok := parseCopyProgress(""); ok {
		t.Fatal("expected false for empty input")
	}
}

func TestUploadStreamBlockSizeWithinLimit(t *testing.T) {
	blockSize := uploadStreamBlockSize(100000 * uploadStreamBlockMin)
	if blockSize != uploadStreamBlockMin {
		t.Fatalf("expected block size %d, got %d", uploadStreamBlockMin, blockSize)
	}
}

func TestUploadStreamBlockSizeOverLimit(t *testing.T) {
	blockSize := uploadStreamBlockSize((100000 * uploadStreamBlockMin) + 1)
	if blockSize <= uploadStreamBlockMin {
		t.Fatalf("expected block size > %d, got %d", uploadStreamBlockMin, blockSize)
	}
	if blockSize > uploadStreamBlockMax {
		t.Fatalf("expected block size <= %d, got %d", uploadStreamBlockMax, blockSize)
	}
}

func TestUploadStreamBlockSizeUnknown(t *testing.T) {
	blockSize := uploadStreamBlockSize(-1)
	if blockSize != uploadStreamBlockBase {
		t.Fatalf("expected block size %d, got %d", uploadStreamBlockBase, blockSize)
	}
}

func TestUploadStreamBlockSizeZero(t *testing.T) {
	blockSize := uploadStreamBlockSize(0)
	if blockSize != uploadStreamBlockMin {
		t.Fatalf("expected block size %d, got %d", uploadStreamBlockMin, blockSize)
	}
}

func TestUploadStreamBlockSizeMaxClamp(t *testing.T) {
	blockSize := uploadStreamBlockSize((int64(uploadStreamMaxBlocks) * uploadStreamBlockMax) + 1)
	if blockSize != uploadStreamBlockMax {
		t.Fatalf("expected block size %d, got %d", uploadStreamBlockMax, blockSize)
	}
}

func TestUploadStreamBlockSizeUsesEnvOverrides(t *testing.T) {
	t.Setenv(uploadStreamBlockMinEnv, "512")
	t.Setenv(uploadStreamBlockMaxEnv, "1024")
	t.Setenv(uploadStreamBlockBaseEnv, "768")
	blockSize := uploadStreamBlockSize(-1)
	if blockSize != 768*uploadStreamMiB {
		t.Fatalf("expected block size %d, got %d", 768*uploadStreamMiB, blockSize)
	}
	blockSize = uploadStreamBlockSize(0)
	if blockSize != 512*uploadStreamMiB {
		t.Fatalf("expected block size %d, got %d", 512*uploadStreamMiB, blockSize)
	}
}

func TestUploadStreamBlockSizeIgnoresInvalidEnv(t *testing.T) {
	t.Setenv(uploadStreamBlockMinEnv, "nope")
	t.Setenv(uploadStreamBlockMaxEnv, "-2")
	t.Setenv(uploadStreamBlockBaseEnv, "0")
	blockSize := uploadStreamBlockSize(-1)
	if blockSize != uploadStreamBlockBase {
		t.Fatalf("expected block size %d, got %d", uploadStreamBlockBase, blockSize)
	}
}

func TestUploadStreamBlockLimitsClampEnv(t *testing.T) {
	t.Setenv(uploadStreamBlockMinEnv, "5000")
	t.Setenv(uploadStreamBlockMaxEnv, "1")
	t.Setenv(uploadStreamBlockBaseEnv, "0")
	blockSize := uploadStreamBlockSize(-1)
	if blockSize != uploadStreamBlockMax {
		t.Fatalf("expected block size %d, got %d", uploadStreamBlockMax, blockSize)
	}
}

func TestReaderSizeUsesFileInfo(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/data.bin"
	data := []byte("hello")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open file: %v", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			t.Errorf("close file: %v", cerr)
		}
	}()
	if got := readerSize(file); got != int64(len(data)) {
		t.Fatalf("expected size %d, got %d", len(data), got)
	}
	contents, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if string(contents) != string(data) {
		t.Fatalf("expected file contents %q, got %q", data, contents)
	}
}

func TestReaderSizeUsesSeeker(t *testing.T) {
	reader := io.NewSectionReader(strings.NewReader("size"), 0, 4)
	if got := readerSize(reader); got != 4 {
		t.Fatalf("expected size 4, got %d", got)
	}
}

type failingSeeker struct {
	read *strings.Reader
}

func (f failingSeeker) Read(p []byte) (int, error) {
	return f.read.Read(p)
}

func (f failingSeeker) Seek(int64, int) (int64, error) {
	return 0, errors.New("seek failed")
}

func TestReaderSizeSeekerFailureRestores(t *testing.T) {
	reader := io.NewSectionReader(strings.NewReader("size"), 0, 4)
	if _, err := reader.Seek(2, io.SeekStart); err != nil {
		t.Fatalf("seek start: %v", err)
	}
	if got := readerSize(reader); got != 4 {
		t.Fatalf("expected size 4, got %d", got)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatalf("read remaining: %v", err)
	}
	if string(buf) != "ze" {
		t.Fatalf("expected remaining %q, got %q", "ze", buf)
	}
}

func TestReaderSizeSeekError(t *testing.T) {
	reader := failingSeeker{read: strings.NewReader("size")}
	if got := readerSize(reader); got != -1 {
		t.Fatalf("expected size -1, got %d", got)
	}
}

func int64Ptr(v int64) *int64 { return &v }

func TestExtractFirstLevelDirectoryFromNestedBlob(t *testing.T) {
	// Scenario from bug report: only deeply nested blobs exist (no direct children).
	// Listing the parent should return the subdirectory.
	entries := []flatBlobEntry{
		{Name: "zz/file", Size: int64Ptr(100)},
	}
	var got []BlobMeta
	if err := extractFirstLevel(entries, "", func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(got), got)
	}
	if got[0].Name != "zz/" {
		t.Fatalf("expected directory name 'zz/', got %q", got[0].Name)
	}
	if got[0].Size != 0 {
		t.Fatalf("expected directory size 0, got %d", got[0].Size)
	}
}

func TestExtractFirstLevelDirectoryFromNilContentLength(t *testing.T) {
	// Azure ADLS Gen2 / HNS may return directory-marker blobs with nil
	// ContentLength. These blobs should still contribute to directory
	// detection when their name contains a "/".
	entries := []flatBlobEntry{
		{Name: "dir/subdir/file", Size: nil}, // nil ContentLength
	}
	var got []BlobMeta
	if err := extractFirstLevel(entries, "", func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry, got %d: %+v", len(got), got)
	}
	if got[0].Name != "dir/" {
		t.Fatalf("expected directory name 'dir/', got %q", got[0].Name)
	}
}

func TestExtractFirstLevelSkipsNilContentLengthFile(t *testing.T) {
	// A first-level blob with nil ContentLength should be skipped (e.g.
	// directory-marker blobs without a trailing slash).
	entries := []flatBlobEntry{
		{Name: "marker", Size: nil},
	}
	var got []BlobMeta
	if err := extractFirstLevel(entries, "", func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 entries, got %d: %+v", len(got), got)
	}
}

func TestExtractFirstLevelMixedEntries(t *testing.T) {
	entries := []flatBlobEntry{
		{Name: "prefix/file.txt", Size: int64Ptr(42)},
		{Name: "prefix/dir/a.txt", Size: int64Ptr(10)},
		{Name: "prefix/dir/b.txt", Size: int64Ptr(20)},
		{Name: "prefix/other/deep/c.txt", Size: int64Ptr(30)},
	}
	var got []BlobMeta
	if err := extractFirstLevel(entries, "prefix/", func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d: %+v", len(got), got)
	}
	want := map[string]int64{"file.txt": 42, "dir/": 0, "other/": 0}
	for _, bm := range got {
		wantSize, ok := want[bm.Name]
		if !ok {
			t.Fatalf("unexpected entry %q", bm.Name)
		}
		if bm.Size != wantSize {
			t.Fatalf("entry %q: expected size %d, got %d", bm.Name, wantSize, bm.Size)
		}
	}
}

func TestExtractFirstLevelDedup(t *testing.T) {
	entries := []flatBlobEntry{
		{Name: "dir/a.txt", Size: int64Ptr(10)},
		{Name: "dir/b.txt", Size: int64Ptr(20)},
	}
	var got []BlobMeta
	if err := extractFirstLevel(entries, "", func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped directory, got %d: %+v", len(got), got)
	}
	if got[0].Name != "dir/" {
		t.Fatalf("expected 'dir/', got %q", got[0].Name)
	}
}

func TestExtractFirstLevelEmptyPrefix(t *testing.T) {
	// Listing container root (empty prefix) with only nested blobs.
	entries := []flatBlobEntry{
		{Name: "a/b/c", Size: int64Ptr(5)},
		{Name: "x.txt", Size: int64Ptr(3)},
	}
	var got []BlobMeta
	if err := extractFirstLevel(entries, "", func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
}
