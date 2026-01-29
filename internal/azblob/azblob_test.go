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
	if err := CopyBlobServerSide(ctx, src, dst); err == nil {
		t.Fatal("expected error for dir-like source")
	}
	src = AzurePath{Account: "acct", Container: "container", Blob: "dir/"}
	if err := CopyBlobServerSide(ctx, src, dst); err == nil {
		t.Fatal("expected error for trailing slash source")
	}
	src = AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	dst = AzurePath{Account: "acct", Container: "container"}
	if err := CopyBlobServerSide(ctx, src, dst); err == nil {
		t.Fatal("expected error for dir-like destination")
	}
	dst = AzurePath{Account: "acct", Container: "container", Blob: "dir/"}
	if err := CopyBlobServerSide(ctx, src, dst); err == nil {
		t.Fatal("expected error for trailing slash destination")
	}
}

func TestCopyBlobServerSideRequiresSameAccount(t *testing.T) {
	ctx := context.Background()
	src := AzurePath{Account: "acct1", Container: "container", Blob: "file.txt"}
	dst := AzurePath{Account: "acct2", Container: "container", Blob: "file.txt"}
	err := CopyBlobServerSide(ctx, src, dst)
	if err == nil {
		t.Fatal("expected error for cross-account copy")
	}
}

func TestCopyBlobServerSideRequiresSharedKey(t *testing.T) {
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "")
	ctx := context.Background()
	src := AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	dst := AzurePath{Account: "acct", Container: "container", Blob: "other.txt"}
	err := CopyBlobServerSide(ctx, src, dst)
	if !errors.Is(err, bloberror.MissingSharedKeyCredential) {
		t.Fatalf("expected missing shared key error, got %v", err)
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
