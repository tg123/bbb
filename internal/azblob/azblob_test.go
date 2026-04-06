package azblob

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
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
	if err := CopyBlobServerSide(ctx, src, dst, 4, 0, nil); err == nil {
		t.Fatal("expected error for dir-like source")
	}
	src = AzurePath{Account: "acct", Container: "container", Blob: "dir/"}
	if err := CopyBlobServerSide(ctx, src, dst, 4, 0, nil); err == nil {
		t.Fatal("expected error for trailing slash source")
	}
	src = AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	dst = AzurePath{Account: "acct", Container: "container"}
	if err := CopyBlobServerSide(ctx, src, dst, 4, 0, nil); err == nil {
		t.Fatal("expected error for dir-like destination")
	}
	dst = AzurePath{Account: "acct", Container: "container", Blob: "dir/"}
	if err := CopyBlobServerSide(ctx, src, dst, 4, 0, nil); err == nil {
		t.Fatal("expected error for trailing slash destination")
	}
}

func TestCopyBlobServerSideCrossAccountRequiresCredentials(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately to prevent real HTTP calls
	src := AzurePath{Account: "acct1", Container: "container", Blob: "file.txt"}
	dst := AzurePath{Account: "acct2", Container: "container", Blob: "file.txt"}
	err := CopyBlobServerSide(ctx, src, dst, 4, 0, nil)
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
	err := CopyBlobServerSide(ctx, src, dst, 4, 0, nil)
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

func TestPlanBlocksEmpty(t *testing.T) {
	blkSize, ids, err := planBlocks(0, 256*1024*1024, 50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blkSize != 256*1024*1024 {
		t.Fatalf("expected default block size, got %d", blkSize)
	}
	if len(ids) != 0 {
		t.Fatalf("expected 0 block IDs for empty blob, got %d", len(ids))
	}
}

func TestPlanBlocksSingleBlock(t *testing.T) {
	blkSize, ids, err := planBlocks(100, 256*1024*1024, 50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blkSize != 256*1024*1024 {
		t.Fatalf("expected default block size, got %d", blkSize)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 block ID, got %d", len(ids))
	}
}

func TestPlanBlocksMultipleBlocks(t *testing.T) {
	// 512 MiB at 256 MiB block size = 2 blocks
	blkSize, ids, err := planBlocks(512*1024*1024, 256*1024*1024, 50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blkSize != 256*1024*1024 {
		t.Fatalf("expected default block size, got %d", blkSize)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 block IDs, got %d", len(ids))
	}
	// All IDs must have the same length.
	if len(ids[0]) != len(ids[1]) {
		t.Fatalf("block IDs have different lengths: %q vs %q", ids[0], ids[1])
	}
}

func TestPlanBlocksAdjustsBlockSizeWhenExceedsMax(t *testing.T) {
	// maxBlocks=2, 300 bytes at default 100 = 3 blocks → must adjust.
	blkSize, ids, err := planBlocks(300, 100, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if blkSize <= 100 {
		t.Fatalf("expected increased block size, got %d", blkSize)
	}
	if len(ids) > 2 {
		t.Fatalf("expected at most 2 blocks, got %d", len(ids))
	}
	// Verify blocks cover entire size.
	covered := int64(len(ids)) * blkSize
	if covered < 300 {
		t.Fatalf("blocks do not cover total size: %d * %d = %d < 300", len(ids), blkSize, covered)
	}
}

func TestPlanBlocksUniqueIDs(t *testing.T) {
	_, ids, err := planBlocks(1024, 100, 50000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate block ID: %s", id)
		}
		seen[id] = true
	}
}

func TestPlanBlocksNegativeSize(t *testing.T) {
	_, _, err := planBlocks(-1, 256*1024*1024, 50000)
	if err == nil {
		t.Fatal("expected error for negative total size")
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

func strPtr(s string) *string { return &s }

func TestProcessHierarchySegmentPrefixesAndItems(t *testing.T) {
	seg := &container.BlobHierarchyListSegment{
		BlobPrefixes: []*container.BlobPrefix{
			{Name: strPtr("prefix/dir/")},
		},
		BlobItems: []*container.BlobItem{
			{Name: strPtr("prefix/file.txt"), Properties: &container.BlobProperties{ContentLength: int64Ptr(42)}},
		},
	}
	seen := make(map[string]bool)
	var got []BlobMeta
	err := processHierarchySegment(seg, "prefix/", seen, func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	if got[0].Name != "dir/" || got[0].Size != 0 {
		t.Fatalf("expected dir/ with size 0, got %+v", got[0])
	}
	if got[1].Name != "file.txt" || got[1].Size != 42 {
		t.Fatalf("expected file.txt with size 42, got %+v", got[1])
	}
}

func TestProcessHierarchySegmentDedup(t *testing.T) {
	// A directory-marker blob "dir/" appears as both a BlobPrefix and BlobItem.
	seg := &container.BlobHierarchyListSegment{
		BlobPrefixes: []*container.BlobPrefix{
			{Name: strPtr("dir/")},
		},
		BlobItems: []*container.BlobItem{
			// directory-marker blob with nil ContentLength — should be skipped
			{Name: strPtr("dir/"), Properties: nil},
		},
	}
	seen := make(map[string]bool)
	var got []BlobMeta
	err := processHierarchySegment(seg, "", seen, func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry (deduped), got %d: %+v", len(got), got)
	}
	if got[0].Name != "dir/" {
		t.Fatalf("expected 'dir/', got %q", got[0].Name)
	}
}

func TestProcessHierarchySegmentDedupAcrossCalls(t *testing.T) {
	// Simulate two pages returning the same prefix
	seg1 := &container.BlobHierarchyListSegment{
		BlobPrefixes: []*container.BlobPrefix{
			{Name: strPtr("prefix/subdir/")},
		},
	}
	seg2 := &container.BlobHierarchyListSegment{
		BlobPrefixes: []*container.BlobPrefix{
			{Name: strPtr("prefix/subdir/")},
		},
		BlobItems: []*container.BlobItem{
			{Name: strPtr("prefix/new.txt"), Properties: &container.BlobProperties{ContentLength: int64Ptr(10)}},
		},
	}
	seen := make(map[string]bool)
	var got []BlobMeta
	cb := func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	}
	if err := processHierarchySegment(seg1, "prefix/", seen, cb); err != nil {
		t.Fatal(err)
	}
	if err := processHierarchySegment(seg2, "prefix/", seen, cb); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries (subdir/ + new.txt), got %d: %+v", len(got), got)
	}
}

func TestProcessHierarchySegmentSkipsNilContentLength(t *testing.T) {
	seg := &container.BlobHierarchyListSegment{
		BlobItems: []*container.BlobItem{
			{Name: strPtr("marker"), Properties: nil},
			{Name: strPtr("file.txt"), Properties: &container.BlobProperties{ContentLength: int64Ptr(100)}},
			{Name: strPtr("nosize"), Properties: &container.BlobProperties{ContentLength: nil}},
		},
	}
	seen := make(map[string]bool)
	var got []BlobMeta
	err := processHierarchySegment(seg, "", seen, func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 entry (only file.txt), got %d: %+v", len(got), got)
	}
	if got[0].Name != "file.txt" || got[0].Size != 100 {
		t.Fatalf("expected file.txt with size 100, got %+v", got[0])
	}
}

func TestProcessHierarchySegmentSkipsNilEntries(t *testing.T) {
	seg := &container.BlobHierarchyListSegment{
		BlobPrefixes: []*container.BlobPrefix{nil, {Name: nil}, {Name: strPtr("dir/")}},
		BlobItems:    []*container.BlobItem{nil, {Name: nil}, {Name: strPtr("f"), Properties: &container.BlobProperties{ContentLength: int64Ptr(1)}}},
	}
	seen := make(map[string]bool)
	var got []BlobMeta
	err := processHierarchySegment(seg, "", seen, func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
}

func TestProcessHierarchySegmentPrefixTrimming(t *testing.T) {
	seg := &container.BlobHierarchyListSegment{
		BlobPrefixes: []*container.BlobPrefix{
			{Name: strPtr("root/sub/")},
		},
		BlobItems: []*container.BlobItem{
			{Name: strPtr("root/data.bin"), Properties: &container.BlobProperties{ContentLength: int64Ptr(50)}},
		},
	}
	seen := make(map[string]bool)
	var got []BlobMeta
	err := processHierarchySegment(seg, "root/", seen, func(bm BlobMeta) error {
		got = append(got, bm)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 entries, got %d: %+v", len(got), got)
	}
	if got[0].Name != "sub/" {
		t.Fatalf("expected prefix trimmed to 'sub/', got %q", got[0].Name)
	}
	if got[1].Name != "data.bin" {
		t.Fatalf("expected prefix trimmed to 'data.bin', got %q", got[1].Name)
	}
}

// --- normalizeRootPrefix tests ---

func TestNormalizeRootPrefixEmpty(t *testing.T) {
	if got := normalizeRootPrefix(""); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestNormalizeRootPrefixNoSlash(t *testing.T) {
	if got := normalizeRootPrefix("data"); got != "data/" {
		t.Fatalf("expected 'data/', got %q", got)
	}
}

func TestNormalizeRootPrefixAlreadySlash(t *testing.T) {
	if got := normalizeRootPrefix("data/"); got != "data/" {
		t.Fatalf("expected 'data/', got %q", got)
	}
}

func TestNormalizeRootPrefixNestedPath(t *testing.T) {
	if got := normalizeRootPrefix("a/b/c"); got != "a/b/c/" {
		t.Fatalf("expected 'a/b/c/', got %q", got)
	}
}

// --- ListRecursiveStream context cancellation test ---

func TestListRecursiveStreamCancelledContext(t *testing.T) {
	// ListRecursiveStream should return immediately with a cancelled context
	// without invoking the callback.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	ap := AzurePath{Account: "fakeaccount", Container: "fakecontainer", Blob: "prefix"}
	err := ListRecursiveStream(ctx, ap, 4, func(bm BlobMeta) error {
		t.Fatal("callback should never be invoked with cancelled context")
		return nil
	})
	// Both nil (early exit before client creation) and non-nil (context error
	// from getAzBlobClient) are acceptable — the key invariant is that the
	// callback was never invoked.
	_ = err
}

// --- Name rewriting tests ---

func TestNameRewriteWithRootPrefix(t *testing.T) {
	// Verify that blob names are correctly trimmed relative to rootPrefix.
	// This tests the inline TrimPrefix logic used in walkPrefix.
	rootPrefix := normalizeRootPrefix("mydata")
	blobName := "mydata/subdir/file.txt"
	got := strings.TrimPrefix(blobName, rootPrefix)
	if got != "subdir/file.txt" {
		t.Fatalf("expected 'subdir/file.txt', got %q", got)
	}
}

func TestNameRewriteEmptyRootPrefix(t *testing.T) {
	rootPrefix := normalizeRootPrefix("")
	blobName := "top-level.txt"
	got := strings.TrimPrefix(blobName, rootPrefix)
	if got != "top-level.txt" {
		t.Fatalf("expected 'top-level.txt', got %q", got)
	}
}

func TestNameRewriteNestedPrefix(t *testing.T) {
	rootPrefix := normalizeRootPrefix("a/b")
	blobName := "a/b/c/d.txt"
	got := strings.TrimPrefix(blobName, rootPrefix)
	if got != "c/d.txt" {
		t.Fatalf("expected 'c/d.txt', got %q", got)
	}
}

// --- Tenant discovery / challenge parsing tests ---

func TestParseTenantFromChallengeValid(t *testing.T) {
	header := `Bearer authorization_uri="https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/authorize" resource_id="https://storage.azure.com"`
	tid := parseTenantFromChallenge(header)
	if tid != "72f988bf-86f1-41af-91ab-2d7cd011db47" {
		t.Fatalf("expected tenant ID '72f988bf-86f1-41af-91ab-2d7cd011db47', got %q", tid)
	}
}

func TestParseTenantFromChallengeNoQuotes(t *testing.T) {
	header := `Bearer authorization_uri=https://login.microsoftonline.com/abcdef01-2345-6789-abcd-ef0123456789/oauth2/authorize`
	tid := parseTenantFromChallenge(header)
	if tid != "abcdef01-2345-6789-abcd-ef0123456789" {
		t.Fatalf("expected tenant ID 'abcdef01-2345-6789-abcd-ef0123456789', got %q", tid)
	}
}

func TestParseTenantFromChallengeEmpty(t *testing.T) {
	if tid := parseTenantFromChallenge(""); tid != "" {
		t.Fatalf("expected empty tenant ID, got %q", tid)
	}
}

func TestParseTenantFromChallengeNoMatch(t *testing.T) {
	if tid := parseTenantFromChallenge("Bearer realm=example.com"); tid != "" {
		t.Fatalf("expected empty tenant ID, got %q", tid)
	}
}

func TestParseTenantFromChallengeMalformedUUID(t *testing.T) {
	// 35 chars instead of 36 — should not match.
	header := `Bearer authorization_uri="https://login.microsoftonline.com/short-uuid/oauth2/authorize"`
	if tid := parseTenantFromChallenge(header); tid != "" {
		t.Fatalf("expected empty tenant ID for short UUID, got %q", tid)
	}
}

func TestAccountTenantIDEnvUpperCase(t *testing.T) {
	t.Setenv("BBB_AZ_TENANT_MYACCOUNT", "env-tenant-upper")
	tid := accountTenantID(context.Background(), "myaccount")
	if tid != "env-tenant-upper" {
		t.Fatalf("expected 'env-tenant-upper', got %q", tid)
	}
}

func TestAccountTenantIDEnvExactCase(t *testing.T) {
	t.Setenv("BBB_AZ_TENANT_myMixed", "env-tenant-exact")
	tid := accountTenantID(context.Background(), "myMixed")
	if tid != "env-tenant-exact" {
		t.Fatalf("expected 'env-tenant-exact', got %q", tid)
	}
}

func TestAccountTenantIDEnvUpperPrecedence(t *testing.T) {
	t.Setenv("BBB_AZ_TENANT_MYACCT", "upper-wins")
	t.Setenv("BBB_AZ_TENANT_myacct", "exact-loses")
	tid := accountTenantID(context.Background(), "myacct")
	if tid != "upper-wins" {
		t.Fatalf("expected upper-case env to take precedence, got %q", tid)
	}
}

func TestAccountTenantIDFallsBackToDiscovery(t *testing.T) {
	// Pre-populate the tenant cache to avoid real HTTP calls.
	tenantCache.Store("cachedacct", "cached-tenant-id")
	defer tenantCache.Delete("cachedacct")
	tid := accountTenantID(context.Background(), "cachedacct")
	if tid != "cached-tenant-id" {
		t.Fatalf("expected 'cached-tenant-id', got %q", tid)
	}
}

func TestDiscoverTenantIDUsesCache(t *testing.T) {
	tenantCache.Store("testacct", "from-cache")
	defer tenantCache.Delete("testacct")
	tid := discoverTenantID(context.Background(), "testacct")
	if tid != "from-cache" {
		t.Fatalf("expected 'from-cache', got %q", tid)
	}
}

// roundTripFunc implements http.RoundTripper for test stubbing.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDiscoverTenantIDFromHTTP(t *testing.T) {
	// Replace the default HTTP client with a stubbed transport.
	origClient := defaultHTTPClientVal
	defaultHTTPClientOnce.Do(func() {}) // ensure Once is done
	defaultHTTPClientVal = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 401,
				Header: http.Header{
					"Www-Authenticate": []string{
						`Bearer authorization_uri="https://login.microsoftonline.com/aabbccdd-1122-3344-5566-778899001122/oauth2/authorize"`,
					},
				},
				Body: io.NopCloser(strings.NewReader("")),
			}, nil
		}),
	}
	defer func() { defaultHTTPClientVal = origClient }()

	// Clear any cached value for this account.
	tenantCache.Delete("stubacct")
	defer tenantCache.Delete("stubacct")

	tid := discoverTenantID(context.Background(), "stubacct")
	if tid != "aabbccdd-1122-3344-5566-778899001122" {
		t.Fatalf("expected discovered tenant 'aabbccdd-1122-3344-5566-778899001122', got %q", tid)
	}

	// Verify it was cached.
	cached, ok := tenantCache.Load("stubacct")
	if !ok || cached.(string) != "aabbccdd-1122-3344-5566-778899001122" {
		t.Fatal("expected tenant ID to be cached after discovery")
	}
}

func TestDiscoverTenantIDHTTPError(t *testing.T) {
	origClient := defaultHTTPClientVal
	defaultHTTPClientOnce.Do(func() {})
	defaultHTTPClientVal = &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("network error")
		}),
	}
	defer func() { defaultHTTPClientVal = origClient }()

	tenantCache.Delete("erroracct")
	tid := discoverTenantID(context.Background(), "erroracct")
	if tid != "" {
		t.Fatalf("expected empty tenant ID on HTTP error, got %q", tid)
	}
}
