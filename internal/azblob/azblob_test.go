package azblob

import (
	"context"
	"errors"
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
	src = AzurePath{Account: "acct", Container: "container", Blob: "file.txt"}
	dst = AzurePath{Account: "acct", Container: "container"}
	if err := CopyBlobServerSide(ctx, src, dst); err == nil {
		t.Fatal("expected error for dir-like destination")
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
