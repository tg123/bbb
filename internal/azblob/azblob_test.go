package azblob

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// makeJWT builds a minimal unsigned JWT-shaped string with the given payload
// claims, used to test tenantIDFromAccessToken. It is NOT a valid signed
// token — only the header.payload.signature shape is required.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".sig"
}

func TestTenantIDFromAccessToken(t *testing.T) {
	tok := makeJWT(t, map[string]any{"tid": "11111111-2222-3333-4444-555555555555", "aud": "https://storage.azure.com"})
	if got := tenantIDFromAccessToken(tok); got != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("expected tid from JWT, got %q", got)
	}
}

func TestTenantIDFromAccessTokenNoTid(t *testing.T) {
	tok := makeJWT(t, map[string]any{"aud": "https://storage.azure.com"})
	if got := tenantIDFromAccessToken(tok); got != "" {
		t.Fatalf("expected empty tid when claim missing, got %q", got)
	}
}

func TestTenantIDFromAccessTokenNotJWT(t *testing.T) {
	if got := tenantIDFromAccessToken("opaque-token-not-a-jwt"); got != "" {
		t.Fatalf("expected empty tid for non-JWT, got %q", got)
	}
	if got := tenantIDFromAccessToken("a.b"); got != "" {
		t.Fatalf("expected empty tid for 2-part token, got %q", got)
	}
}

func TestTenantIDFromAccessTokenBadBase64(t *testing.T) {
	// Middle segment not valid base64-url.
	if got := tenantIDFromAccessToken("aaa.!!!.bbb"); got != "" {
		t.Fatalf("expected empty tid for bad base64 payload, got %q", got)
	}
}

func TestTenantIDFromAccessTokenBadJSON(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte("not-json"))
	tok := header + "." + payload + ".sig"
	if got := tenantIDFromAccessToken(tok); got != "" {
		t.Fatalf("expected empty tid for non-JSON payload, got %q", got)
	}
}

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

func TestUploadInitialConcurrencyForSize(t *testing.T) {
	const (
		mib = int64(1024 * 1024)
		gib = 1024 * mib
	)
	cases := []struct {
		name   string
		caller int
		size   int64
		want   int
	}{
		{"small file keeps caller value", 8, 10 * mib, 8},
		{"100 MiB keeps caller value", 16, 100 * mib, 16},
		{"500 MiB just under threshold keeps caller", 16, 500 * mib, 16},
		{"512 MiB boosts to 64", 16, 512 * mib, 64},
		{"1 GiB boosts to 64", 32, 1 * gib, 64},
		{"1 GiB caller above floor wins", 96, 1 * gib, 96},
		{"4 GiB boosts to 128", 32, 4 * gib, 128},
		{"10 GiB caller above 128 wins", 200, 10 * gib, 200},
		{"caller above hard cap is clamped", 1024, 10 * gib, uploadHardConcurrencyCap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := uploadInitialConcurrencyForSize(tc.caller, tc.size); got != tc.want {
				t.Fatalf("uploadInitialConcurrencyForSize(%d, %d) = %d, want %d", tc.caller, tc.size, got, tc.want)
			}
		})
	}
}

// TestUploadAdaptiveBoundsRespectFloor verifies that the size-based initial
// concurrency boost lifts only `initial` and `maxC`, while `minC` (the floor
// the adaptive controller can shrink back to) stays at the caller's
// --concurrency value. This lets the controller drop back if the boosted
// concurrency causes throughput regression.
func TestUploadAdaptiveBoundsRespectFloor(t *testing.T) {
	const gib = int64(1024 * 1024 * 1024)
	caller := 32
	size := int64(10) * gib

	_, callerMin, _, _ := adaptiveBounds(caller, uploadHardConcurrencyCap, uploadBlockMaxConcurrencyEnv)
	boosted := uploadInitialConcurrencyForSize(caller, size)
	boostedInitial, _, boostedMax, _ := adaptiveBounds(boosted, uploadHardConcurrencyCap, uploadBlockMaxConcurrencyEnv)

	if callerMin != caller {
		t.Fatalf("expected caller-derived minC to equal caller (%d), got %d", caller, callerMin)
	}
	if boostedInitial != boosted {
		t.Fatalf("expected boosted initial = %d, got %d", boosted, boostedInitial)
	}
	if boostedMax <= callerMin {
		t.Fatalf("expected boosted maxC (%d) > caller minC (%d) so controller can grow", boostedMax, callerMin)
	}
	if boostedInitial <= callerMin {
		t.Fatalf("expected boosted initial (%d) > caller minC (%d) so we start above the floor", boostedInitial, callerMin)
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

func TestRegisterAccountRoleStoresUpperCase(t *testing.T) {
	defer accountRoles.Delete("testacct")
	RegisterAccountRole("testacct", "src")
	v, ok := accountRoles.Load("testacct")
	if !ok || v.(string) != "SRC" {
		t.Fatalf("expected SRC, got %v", v)
	}
}

func TestAccountKeyRolePrefixedTakesPrecedence(t *testing.T) {
	defer accountRoles.Delete("acctkey1")
	RegisterAccountRole("acctkey1", "SRC")
	t.Setenv("SRC_BBB_AZBLOB_ACCOUNTKEY", "src-key-123")
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "global-key")
	if got := accountKey("acctkey1"); got != "src-key-123" {
		t.Fatalf("expected role-prefixed key, got %q", got)
	}
}

func TestAccountKeyFallsBackToGlobal(t *testing.T) {
	defer accountRoles.Delete("acctkey2")
	RegisterAccountRole("acctkey2", "DST")
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "global-key")
	// No DST_BBB_AZBLOB_ACCOUNTKEY set
	if got := accountKey("acctkey2"); got != "global-key" {
		t.Fatalf("expected global key fallback, got %q", got)
	}
}

func TestAccountKeyNoRoleUsesGlobal(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "global-only")
	if got := accountKey("noroleacct"); got != "global-only" {
		t.Fatalf("expected global key, got %q", got)
	}
}

func TestAccountKeyNoEnvReturnsEmpty(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "")
	if got := accountKey("emptyacct"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestRoleEnvVarsCoversAllExpectedVars(t *testing.T) {
	expected := map[string]bool{
		"AZURE_CLIENT_ID":                     false,
		"AZURE_TENANT_ID":                     false,
		"AZURE_CLIENT_SECRET":                 false,
		"AZURE_CLIENT_CERTIFICATE_PATH":       false,
		"AZURE_CLIENT_CERTIFICATE_PASSWORD":   false,
		"AZURE_CLIENT_SEND_CERTIFICATE_CHAIN": false,
		"AZURE_FEDERATED_TOKEN_FILE":          false,
		"IDENTITY_ENDPOINT":                   false,
		"IDENTITY_HEADER":                     false,
		"MSI_ENDPOINT":                        false,
		"MSI_SECRET":                          false,
		"IMDS_ENDPOINT":                       false,
		"AZURE_AUTHORITY_HOST":                false,
		"AZURE_USERNAME":                      false,
		"AZURE_CONFIG_DIR":                    false,
	}
	for _, v := range roleEnvVars {
		if _, ok := expected[v]; !ok {
			t.Errorf("unexpected var in roleEnvVars: %s", v)
		}
		expected[v] = true
	}
	for k, found := range expected {
		if !found {
			t.Errorf("missing var in roleEnvVars: %s", k)
		}
	}
}

func TestGetCredentialForRoleReturnsNilWhenNoEnvSet(t *testing.T) {
	// Clear any cached credential for "TESTROLE".
	roleCredCache.Delete("TESTROLE")
	// Ensure no TESTROLE_ env vars are set, and no unprefixed defaults that
	// the role would otherwise inherit.
	for _, v := range roleEnvVars {
		t.Setenv("TESTROLE_"+v, "")
		t.Setenv(v, "")
	}
	cred, err := getCredentialForRole("TESTROLE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Fatal("expected nil credential when no env vars set")
	}
}

func TestGetCredentialForRoleIgnoresHelperOnlyEnv(t *testing.T) {
	roleCredCache.Delete("HELPERONLY")
	for _, v := range roleEnvVars {
		t.Setenv("HELPERONLY_"+v, "")
		t.Setenv(v, "")
	}

	t.Setenv("AZURE_CONFIG_DIR", t.TempDir())
	t.Setenv("HELPERONLY_AZURE_USERNAME", "user@example.com")

	cred, err := getCredentialForRole("HELPERONLY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Fatal("expected nil credential when only helper env vars are set")
	}
}

func TestGetCredentialForRoleIgnoresUnprefixedClientIDOnly(t *testing.T) {
	roleCredCache.Delete("CLIENTIDONLY")
	for _, v := range roleEnvVars {
		t.Setenv("CLIENTIDONLY_"+v, "")
		t.Setenv(v, "")
	}

	t.Setenv("AZURE_CLIENT_ID", "client-id-only")

	cred, err := getCredentialForRole("CLIENTIDONLY")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred != nil {
		t.Fatal("expected nil credential when only unprefixed AZURE_CLIENT_ID is set")
	}
}

func TestGetCredentialForRoleAcceptsRolePrefixedClientIDOnly(t *testing.T) {
	roleCredCache.Delete("USERASSIGNED")
	for _, v := range roleEnvVars {
		t.Setenv("USERASSIGNED_"+v, "")
		t.Setenv(v, "")
	}

	t.Setenv("USERASSIGNED_AZURE_CLIENT_ID", "user-assigned-client-id")

	cred, err := getCredentialForRole("USERASSIGNED")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential when role-prefixed AZURE_CLIENT_ID is set")
	}
}

func TestGetCredentialForRoleRemapsEnvVars(t *testing.T) {
	// Clear cached credential.
	roleCredCache.Delete("REMAP")

	// Set role-prefixed env vars for a client-secret credential.
	t.Setenv("REMAP_AZURE_TENANT_ID", "test-tenant")
	t.Setenv("REMAP_AZURE_CLIENT_ID", "test-client")
	t.Setenv("REMAP_AZURE_CLIENT_SECRET", "test-secret")

	// Clear any global env vars that could interfere.
	for _, v := range roleEnvVars {
		t.Setenv(v, "")
	}

	cred, err := getCredentialForRole("REMAP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected non-nil credential")
	}

	// Verify env vars were restored (cleared).
	for _, v := range roleEnvVars {
		if got := os.Getenv(v); got != "" {
			t.Errorf("env var %s not restored, got %q", v, got)
		}
	}
}

func TestGetCredentialForRoleRestoresOriginalEnv(t *testing.T) {
	roleCredCache.Delete("RESTORE")

	// Set original values.
	t.Setenv("AZURE_TENANT_ID", "original-tenant")
	t.Setenv("AZURE_CLIENT_ID", "original-client")
	t.Setenv("AZURE_CLIENT_SECRET", "original-secret")

	// Set role-prefixed values.
	t.Setenv("RESTORE_AZURE_TENANT_ID", "role-tenant")
	t.Setenv("RESTORE_AZURE_CLIENT_ID", "role-client")
	t.Setenv("RESTORE_AZURE_CLIENT_SECRET", "role-secret")

	_, err := getCredentialForRole("RESTORE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify originals are restored.
	if got := os.Getenv("AZURE_TENANT_ID"); got != "original-tenant" {
		t.Errorf("AZURE_TENANT_ID not restored, got %q", got)
	}
	if got := os.Getenv("AZURE_CLIENT_ID"); got != "original-client" {
		t.Errorf("AZURE_CLIENT_ID not restored, got %q", got)
	}
	if got := os.Getenv("AZURE_CLIENT_SECRET"); got != "original-secret" {
		t.Errorf("AZURE_CLIENT_SECRET not restored, got %q", got)
	}
}

func TestGetCredentialForRoleInheritsUnprefixedDefaults(t *testing.T) {
	// An unprefixed AZURE_* var must be interpreted as a default shared by both
	// roles, i.e. AZURE_xxx behaves like SRC_AZURE_xxx and DST_AZURE_xxx.
	roleCredCache.Delete("INHERIT")

	// Ensure no role-prefixed values are set.
	for _, v := range roleEnvVars {
		t.Setenv("INHERIT_"+v, "")
		t.Setenv(v, "")
	}
	// Configure only unprefixed service-principal vars.
	t.Setenv("AZURE_TENANT_ID", "00000000-0000-0000-0000-000000000000")
	t.Setenv("AZURE_CLIENT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_SECRET", "secret")

	cred, err := getCredentialForRole("INHERIT")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential built from unprefixed AZURE_* defaults")
	}

	// Unprefixed defaults must remain intact after the call.
	if got := os.Getenv("AZURE_TENANT_ID"); got != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("AZURE_TENANT_ID not preserved, got %q", got)
	}
}

func TestGetCredentialForRolePrefixedOverridesUnprefixed(t *testing.T) {
	roleCredCache.Delete("OVERRIDE")

	// Unprefixed defaults.
	t.Setenv("AZURE_TENANT_ID", "default-tenant")
	t.Setenv("AZURE_CLIENT_ID", "default-client")
	t.Setenv("AZURE_CLIENT_SECRET", "default-secret")

	// Role-prefixed override for one var only; the others fall back to defaults.
	t.Setenv("OVERRIDE_AZURE_CLIENT_ID", "role-client")

	_, err := getCredentialForRole("OVERRIDE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Unprefixed defaults must be restored after the call.
	if got := os.Getenv("AZURE_CLIENT_ID"); got != "default-client" {
		t.Errorf("AZURE_CLIENT_ID not restored, got %q", got)
	}
	if got := os.Getenv("AZURE_TENANT_ID"); got != "default-tenant" {
		t.Errorf("AZURE_TENANT_ID not restored, got %q", got)
	}
}

func TestGetCredentialForRoleCachesResult(t *testing.T) {
	roleCredCache.Delete("CACHED")

	t.Setenv("CACHED_AZURE_TENANT_ID", "t")
	t.Setenv("CACHED_AZURE_CLIENT_ID", "c")
	t.Setenv("CACHED_AZURE_CLIENT_SECRET", "s")
	for _, v := range roleEnvVars {
		t.Setenv(v, "")
	}

	cred1, err := getCredentialForRole("CACHED")
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	cred2, err := getCredentialForRole("CACHED")
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}

	// Both calls should return the same cached instance.
	if cred1 != cred2 {
		t.Error("expected cached credential to be reused")
	}
}

func TestMonotonicProgressNilCallback(t *testing.T) {
	var last atomic.Int64
	emit := monotonicProgress(&last, nil)
	emit(100)
	emit(50)
	if got := last.Load(); got != 0 {
		t.Fatalf("expected last to remain 0 when onProgress nil, got %d", got)
	}
}

func TestMonotonicProgressDeliversLeadingZero(t *testing.T) {
	// UploadFile seeds last=-1 so a 0-byte upload's onProgress(0) is still
	// delivered instead of being swallowed as a non-increasing value.
	var last atomic.Int64
	last.Store(-1)
	var calls []int64
	emit := monotonicProgress(&last, func(v int64) { calls = append(calls, v) })

	emit(0) // leading zero: must be delivered when seeded at -1
	emit(0) // duplicate: dropped

	if len(calls) != 1 || calls[0] != 0 {
		t.Fatalf("expected exactly one 0 delivery, got %v", calls)
	}
	if got := last.Load(); got != 0 {
		t.Fatalf("expected last=0, got %d", got)
	}
}

func TestMonotonicProgressFiltersStale(t *testing.T) {
	var last atomic.Int64
	var calls []int64
	var mu sync.Mutex
	emit := monotonicProgress(&last, func(v int64) {
		mu.Lock()
		calls = append(calls, v)
		mu.Unlock()
	})

	emit(10)
	emit(5)  // stale: must be dropped
	emit(10) // duplicate: must be dropped
	emit(20)
	emit(15) // stale relative to 20: dropped
	emit(30)

	mu.Lock()
	defer mu.Unlock()
	want := []int64{10, 20, 30}
	if len(calls) != len(want) {
		t.Fatalf("expected %v, got %v", want, calls)
	}
	for i, v := range want {
		if calls[i] != v {
			t.Fatalf("call %d: want %d got %d", i, v, calls[i])
		}
	}
	if got := last.Load(); got != 30 {
		t.Fatalf("expected last=30, got %d", got)
	}
}

func TestMonotonicProgressConcurrent(t *testing.T) {
	var last atomic.Int64
	var maxSeen atomic.Int64
	var ordered atomic.Bool
	ordered.Store(true)

	emit := monotonicProgress(&last, func(v int64) {
		for {
			prev := maxSeen.Load()
			if v <= prev {
				ordered.Store(false)
				return
			}
			if maxSeen.CompareAndSwap(prev, v) {
				return
			}
		}
	})

	const goroutines = 32
	const perG = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(base int64) {
			defer wg.Done()
			for i := 1; i <= perG; i++ {
				// each goroutine emits values from disjoint ranges,
				// mimicking concurrent ranged-GETs producing increasing
				// cumulative totals out of order.
				emit(base*int64(perG) + int64(i))
			}
		}(int64(g))
	}
	wg.Wait()

	if !ordered.Load() {
		t.Fatal("onProgress observed a non-monotonic cumulative value")
	}
	if got := last.Load(); got != goroutines*perG {
		t.Fatalf("expected high water %d, got %d", goroutines*perG, got)
	}
}

type errReader struct {
	data    []byte
	n       int
	err     error
	maxRead int // if >0, cap each Read at this many bytes (simulates TLS records)
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.n >= len(r.data) {
		return 0, r.err
	}
	want := len(p)
	if r.maxRead > 0 && want > r.maxRead {
		want = r.maxRead
	}
	avail := len(r.data) - r.n
	if want > avail {
		want = avail
	}
	n := copy(p[:want], r.data[r.n:r.n+want])
	r.n += n
	if r.n >= len(r.data) {
		return n, r.err
	}
	return n, nil
}

func TestCopyRangeToOffsetBatchesWrites(t *testing.T) {
	// Simulate small TLS-record-sized reads: 17 chunks of 16 KiB = ~272 KiB.
	// maxRead caps each Read at 16 KiB so io.ReadFull must loop to fill the
	// 1 MiB buffer — exercising the very batching the test asserts about.
	const chunk = 16 * 1024
	const chunks = 17
	src := make([]byte, chunk*chunks)
	for i := range src {
		src[i] = byte(i)
	}
	r := &errReader{data: src, err: io.EOF, maxRead: chunk}

	dst := &countingWriterAt{}
	buf := make([]byte, 1*1024*1024)
	n, err := copyRangeToOffset(dst, 100, r, buf)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != int64(len(src)) {
		t.Fatalf("n=%d want %d", n, len(src))
	}
	// 272 KiB fits in one 1 MiB buffer, so we expect exactly ONE WriteAt
	// instead of 17 (io.CopyBuffer would have produced 17).
	if dst.calls != 1 {
		t.Fatalf("expected 1 WriteAt, got %d", dst.calls)
	}
	if dst.firstOffset != 100 {
		t.Fatalf("expected offset 100, got %d", dst.firstOffset)
	}
	if !bytes.Equal(dst.bytes, src) {
		t.Fatalf("written bytes do not match source")
	}
}

func TestCopyRangeToOffsetMultipleBufferLoads(t *testing.T) {
	// 2.5x buffer size → should produce 3 writes (full, full, partial).
	// Cap per-read at 100 B so io.ReadFull is forced to loop within each
	// buffer fill, ensuring the test exercises real batching behavior
	// regardless of how the underlying reader chunks its output.
	buf := make([]byte, 1024)
	src := make([]byte, 2560)
	for i := range src {
		src[i] = byte(i * 31)
	}
	r := &errReader{data: src, err: io.EOF, maxRead: 100}
	dst := &countingWriterAt{}
	n, err := copyRangeToOffset(dst, 0, r, buf)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != int64(len(src)) {
		t.Fatalf("n=%d", n)
	}
	if dst.calls != 3 {
		t.Fatalf("expected 3 WriteAt calls, got %d", dst.calls)
	}
	if !bytes.Equal(dst.bytes, src) {
		t.Fatalf("byte mismatch")
	}
}

func TestCopyRangeToOffsetPropagatesReadError(t *testing.T) {
	r := &errReader{data: []byte("hi"), err: errors.New("boom")}
	dst := &countingWriterAt{}
	_, err := copyRangeToOffset(dst, 0, r, make([]byte, 4))
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected boom error, got %v", err)
	}
}

type countingWriterAt struct {
	calls       int
	firstOffset int64
	bytes       []byte
}

func (w *countingWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if w.calls == 0 {
		w.firstOffset = off
	}
	w.calls++
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}

func TestAdaptiveBoundsClampsCallerToHardCap(t *testing.T) {
	// Caller supplies 1000 but hardCap is 512 — neither initial, min, nor
	// max should exceed 512.
	initial, minC, maxC, _ := adaptiveBounds(1000, 512, "")
	if initial > 512 || minC > 512 || maxC > 512 {
		t.Fatalf("expected all bounds <= 512, got initial=%d min=%d max=%d", initial, minC, maxC)
	}
	if initial != 512 || minC != 512 || maxC != 512 {
		t.Fatalf("expected all bounds clamped to 512, got initial=%d min=%d max=%d", initial, minC, maxC)
	}
}

func TestAdaptiveBoundsClampsEnvOverrideToHardCap(t *testing.T) {
	t.Setenv("TEST_ADAPTIVE_MAX_ENV", "9999")
	_, _, maxC, _ := adaptiveBounds(8, 512, "TEST_ADAPTIVE_MAX_ENV")
	if maxC > 512 {
		t.Fatalf("expected maxC <= hardCap=512, got %d", maxC)
	}
	if maxC != 512 {
		t.Fatalf("expected maxC clamped to 512, got %d", maxC)
	}
}

func TestAdaptiveBoundsEnvOverrideWithinCap(t *testing.T) {
	t.Setenv("TEST_ADAPTIVE_MAX_ENV", "64")
	_, _, maxC, _ := adaptiveBounds(8, 512, "TEST_ADAPTIVE_MAX_ENV")
	if maxC != 64 {
		t.Fatalf("expected env override to set maxC=64, got %d", maxC)
	}
}

func TestAdaptiveBoundsEnvOverrideClampsCallerDown(t *testing.T) {
	// --concurrency 64 with env max 8 must produce a semaphore capped at 8
	// (env var is documented as a hard upper bound).
	t.Setenv("TEST_ADAPTIVE_MAX_ENV", "8")
	initial, minC, maxC, _ := adaptiveBounds(64, 512, "TEST_ADAPTIVE_MAX_ENV")
	if initial != 8 || minC != 8 || maxC != 8 {
		t.Fatalf("expected env override to clamp all bounds to 8, got initial=%d min=%d max=%d", initial, minC, maxC)
	}
}

// --- S2S copy: block size + concurrency cap regression tests ---

func TestCopyBlockSizeDefault(t *testing.T) {
	t.Setenv(copyBlockSizeEnv, "")
	if got := copyBlockSizeBytes(0); got != int64(copyBlockSize) {
		t.Fatalf("expected default block size %d, got %d", copyBlockSize, got)
	}
	if got := copyBlockSizeBytes(1 << 30); got != int64(copyBlockSize) {
		t.Fatalf("expected default block size %d for 1 GiB transfer, got %d", copyBlockSize, got)
	}
}

func TestCopyBlockSizeEnvOverride(t *testing.T) {
	t.Setenv(copyBlockSizeEnv, "32")
	if got := copyBlockSizeBytes(1 << 30); got != 32*1024*1024 {
		t.Fatalf("expected env override to 32 MiB, got %d", got)
	}
}

func TestCopyBlockSizeInvalidEnvIgnored(t *testing.T) {
	for _, v := range []string{"", "0", "-1", "abc"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv(copyBlockSizeEnv, v)
			if got := copyBlockSizeBytes(1 << 20); got != int64(copyBlockSize) {
				t.Fatalf("expected invalid env %q to fall back to default, got %d", v, got)
			}
		})
	}
}

func TestCopyBlockSizeAutoGrowsAboveMaxBlocks(t *testing.T) {
	// A blob far larger than copyBlockSize * MaxBlocks must auto-grow the
	// block size so the plan fits under blockblob.MaxBlocks=50000.
	t.Setenv(copyBlockSizeEnv, "")
	const size = int64(copyBlockSize) * 60000 // 60k * 8 MiB > MaxBlocks
	got := copyBlockSizeBytes(size)
	maxBlocks := int64(50000) // blockblob.MaxBlocks
	if got < int64(copyBlockSize) {
		t.Fatalf("block size should not shrink, got %d", got)
	}
	if (size+got-1)/got > maxBlocks {
		t.Fatalf("auto-grown block size %d still produces > MaxBlocks blocks for size %d", got, size)
	}
}

// TestCopyConcurrencyCapBypassesAdaptiveThrottling guards against a
// regression where the adaptive controller derived maxC=32 from the caller's
// default concurrency=4 and immediately throttled S2S parallelism down to
// 32, even when 256 concurrent StageBlockFromURL calls would still be cheap
// (no client-side buffering). The S2S path now uses copyConcurrencyCap
// directly, which ignores the caller's concurrency (S2S has no client-side
// buffering, so per-blob fan-out is decoupled from the CLI --concurrency)
// and always starts from copyDefaultConcurrency.
func TestCopyConcurrencyCapBypassesAdaptiveThrottling(t *testing.T) {
	t.Setenv(copyMaxConcurrencyEnv, "")
	// Pre-fix behavior: adaptiveBounds(4, 256, env) returned maxC=32, so the
	// controller would throttle a fresh sem(initial=256, max=32) to 32.
	// Post-fix: copyConcurrencyCap ignores the caller's concurrency (which
	// only governs client-side I/O) and uses the S2S default, clamped to
	// the hard cap. So copyConcurrencyCap(4, 1000) == copyHardConcurrencyCap.
	if got := copyConcurrencyCap(4, 1000); got != copyHardConcurrencyCap {
		t.Fatalf("expected cap to ignore caller concurrency and clamp at hard cap %d, got %d", copyHardConcurrencyCap, got)
	}
	if got := copyConcurrencyCap(1024, 5000); got != copyHardConcurrencyCap {
		t.Fatalf("expected cap to clamp at hard cap %d, got %d", copyHardConcurrencyCap, got)
	}
}

func TestCopyConcurrencyCapDefaultsWhenZero(t *testing.T) {
	// The caller's concurrency is ignored for S2S; the cap always starts
	// from copyDefaultConcurrency regardless of the value passed in.
	t.Setenv(copyMaxConcurrencyEnv, "")
	if got := copyConcurrencyCap(0, 10000); got != copyDefaultConcurrency {
		t.Fatalf("expected default %d when caller concurrency=0, got %d", copyDefaultConcurrency, got)
	}
	if got := copyConcurrencyCap(-1, 10000); got != copyDefaultConcurrency {
		t.Fatalf("expected default %d when caller concurrency<0, got %d", copyDefaultConcurrency, got)
	}
}

func TestCopyConcurrencyCapClampsToBlockCount(t *testing.T) {
	t.Setenv(copyMaxConcurrencyEnv, "")
	if got := copyConcurrencyCap(64, 5); got != 5 {
		t.Fatalf("expected cap clamped to blockCount=5, got %d", got)
	}
}

func TestCopyConcurrencyCapEnvOverridesCaller(t *testing.T) {
	t.Setenv(copyMaxConcurrencyEnv, "16")
	if got := copyConcurrencyCap(128, 10000); got != 16 {
		t.Fatalf("expected env override to set cap=16, got %d", got)
	}
}

func TestCopyConcurrencyCapEnvOverrideClampedByHardCap(t *testing.T) {
	t.Setenv(copyMaxConcurrencyEnv, "9999")
	if got := copyConcurrencyCap(8, 10000); got != copyHardConcurrencyCap {
		t.Fatalf("expected env override clamped to hard cap %d, got %d", copyHardConcurrencyCap, got)
	}
}

func TestCopyConcurrencyCapMinimumOne(t *testing.T) {
	t.Setenv(copyMaxConcurrencyEnv, "")
	if got := copyConcurrencyCap(0, 1); got != 1 {
		t.Fatalf("expected minimum cap of 1 for single-block transfer, got %d", got)
	}
}

func TestPathEscapeBlobName(t *testing.T) {
	cases := map[string]string{
		"simple.bin":       "simple.bin",
		"dir/sub/blob.bin": "dir/sub/blob.bin",
		"with space.bin":   "with%20space.bin",
		"weird#name?.bin":  "weird%23name%3F.bin",
		"a/b c/d#e":        "a/b%20c/d%23e",
	}
	for in, want := range cases {
		if got := pathEscapeBlobName(in); got != want {
			t.Errorf("pathEscapeBlobName(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestCopySourceOAuthURLNoDoubleSlash verifies that BBB_AZBLOB_ENDPOINT
// values with a trailing slash (e.g. "https://%s.blob.core.windows.net/")
// do not produce a malformed "host//container/blob" URL, which previously
// broke StageBlockFromURL when the benchmark harness configured the
// endpoint with the trailing slash.
func TestCopySourceOAuthURLNoDoubleSlash(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ENDPOINT", "https://%s.blob.core.windows.net/")
	endpoint := strings.TrimRight(getEndpoint("acct"), "/")
	src := AzurePath{Account: "acct", Container: "c", Blob: "dir/blob name.bin"}
	srcURL := endpoint + "/" + url.PathEscape(src.Container) + "/" + pathEscapeBlobName(src.Blob)
	want := "https://acct.blob.core.windows.net/c/dir/blob%20name.bin"
	if srcURL != want {
		t.Fatalf("source URL = %q, want %q", srcURL, want)
	}
}

// TestCopyBlobFromURLServerSideSelfHealsInvalidBlobOrBlock verifies that when
// StageBlockFromURL is rejected with InvalidBlobOrBlock (a destination blob
// poisoned by stale uncommitted blocks of a different ID length), the copy
// path deletes the poisoned blob and retries the stage+commit exactly once,
// ultimately succeeding.
func TestCopyBlobFromURLServerSideSelfHealsInvalidBlobOrBlock(t *testing.T) {
	prev := sharedHTTPClient.Load()
	t.Cleanup(func() { sharedHTTPClient.Store(prev) })

	account := "selfhealcheck"
	blobClientCache.Delete(account)
	t.Cleanup(func() { blobClientCache.Delete(account) })

	// Shared-key credential bypasses token acquisition network calls.
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "dGVzdGtleQ==") // base64("testkey")

	var stageCalls, commitCalls, deleteCalls atomic.Int64
	var deleted atomic.Bool

	nopBody := func() io.ReadCloser { return io.NopCloser(strings.NewReader("")) }
	SetHTTPTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		comp := req.URL.Query().Get("comp")
		switch {
		case req.Method == http.MethodDelete:
			deleteCalls.Add(1)
			deleted.Store(true)
			return &http.Response{StatusCode: 202, Header: http.Header{}, Body: nopBody(), Request: req}, nil
		case req.Method == http.MethodPut && comp == "block":
			stageCalls.Add(1)
			if !deleted.Load() {
				// Poisoned: reject staging with InvalidBlobOrBlock until the
				// blob is cleared.
				return &http.Response{
					StatusCode: 400,
					Header:     http.Header{"X-Ms-Error-Code": []string{string(bloberror.InvalidBlobOrBlock)}},
					Body:       io.NopCloser(strings.NewReader(`<?xml version="1.0"?><Error><Code>InvalidBlobOrBlock</Code><Message>poisoned</Message></Error>`)),
					Request:    req,
				}, nil
			}
			return &http.Response{StatusCode: 201, Header: http.Header{}, Body: nopBody(), Request: req}, nil
		case req.Method == http.MethodPut && comp == "blocklist":
			commitCalls.Add(1)
			return &http.Response{StatusCode: 201, Header: http.Header{}, Body: nopBody(), Request: req}, nil
		default:
			return &http.Response{StatusCode: 201, Header: http.Header{}, Body: nopBody(), Request: req}, nil
		}
	}))
	t.Cleanup(func() { SetHTTPTransport(nil) })

	dst := AzurePath{Account: account, Container: "c", Blob: "poisoned.bin"}
	var lastCopied, lastTotal int64
	err := CopyBlobFromURLServerSide(context.Background(), dst,
		"https://source.example/blob?sig=abc", 8, 1, func(copied, total int64) {
			lastCopied, lastTotal = copied, total
		})
	if err != nil {
		t.Fatalf("CopyBlobFromURLServerSide should self-heal and succeed, got: %v", err)
	}
	if got := deleteCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 delete (self-heal), got %d", got)
	}
	if got := stageCalls.Load(); got < 2 {
		t.Fatalf("expected at least 2 stage attempts (initial failure + retry), got %d", got)
	}
	if got := commitCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 successful commit after retry, got %d", got)
	}
	if lastCopied != 8 || lastTotal != 8 {
		t.Fatalf("expected final progress 8/8, got %d/%d", lastCopied, lastTotal)
	}
}

// TestCopyBlobFromURLServerSideUnknownSizeUsesAsyncCopy verifies that when the
// source size is unknown (negative), the server-side copy does not hard-fail
// but instead routes to the async StartCopyFromURL path, which does not need a
// pre-known size.
func TestCopyBlobFromURLServerSideUnknownSizeUsesAsyncCopy(t *testing.T) {
	prev := sharedHTTPClient.Load()
	t.Cleanup(func() { sharedHTTPClient.Store(prev) })

	account := "asynccopycheck"
	blobClientCache.Delete(account)
	t.Cleanup(func() { blobClientCache.Delete(account) })

	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "dGVzdGtleQ==") // base64("testkey")

	var startCopyCalls, getPropsCalls, stageCalls atomic.Int64
	nopBody := func() io.ReadCloser { return io.NopCloser(strings.NewReader("")) }
	SetHTTPTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodPut && req.URL.Query().Get("comp") == "block":
			stageCalls.Add(1)
			return &http.Response{StatusCode: 201, Header: http.Header{}, Body: nopBody(), Request: req}, nil
		case req.Method == http.MethodPut && req.URL.Query().Get("comp") == "":
			// StartCopyFromURL: PUT to the blob with no comp param.
			startCopyCalls.Add(1)
			h := http.Header{}
			h.Set("x-ms-copy-status", "success")
			return &http.Response{StatusCode: 202, Header: h, Body: nopBody(), Request: req}, nil
		case req.Method == http.MethodHead:
			getPropsCalls.Add(1)
			h := http.Header{}
			h.Set("x-ms-copy-status", "success")
			h.Set("x-ms-copy-progress", "1024/1024")
			return &http.Response{StatusCode: 200, Header: h, Body: nopBody(), Request: req}, nil
		default:
			return &http.Response{StatusCode: 201, Header: http.Header{}, Body: nopBody(), Request: req}, nil
		}
	}))
	t.Cleanup(func() { SetHTTPTransport(nil) })

	dst := AzurePath{Account: account, Container: "c", Blob: "unknown-size.bin"}
	var lastCopied, lastTotal int64
	err := CopyBlobFromURLServerSide(context.Background(), dst,
		"https://source.example/blob?sig=abc", -1, 4, func(copied, total int64) {
			lastCopied, lastTotal = copied, total
		})
	if err != nil {
		t.Fatalf("expected unknown-size copy to succeed via async path, got: %v", err)
	}
	if got := startCopyCalls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 StartCopyFromURL, got %d", got)
	}
	if got := stageCalls.Load(); got != 0 {
		t.Fatalf("expected no StageBlockFromURL calls for unknown-size copy, got %d", got)
	}
	// Progress is reported from the service (1024/1024), not from the unknown
	// caller-provided size.
	if lastCopied != 1024 || lastTotal != 1024 {
		t.Fatalf("expected service-reported progress 1024/1024, got %d/%d", lastCopied, lastTotal)
	}
}
