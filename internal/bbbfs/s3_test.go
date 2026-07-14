package bbbfs

import (
	"errors"
	"net/http"
	"testing"

	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestEscapeS3KeyPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"file.txt", "file.txt"},
		{"dir/file.txt", "dir/file.txt"},
		{"a b/c#d", "a%20b/c%23d"},
		{"weird?name%.bin", "weird%3Fname%25.bin"},
		{"keep//slash", "keep//slash"},
	}
	for _, c := range cases {
		if got := escapeS3KeyPath(c.in); got != c.want {
			t.Errorf("escapeS3KeyPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestS3ShareInfoEndpointPathPrefix(t *testing.T) {
	// Virtual-host style: endpoint path prefix must be preserved between the
	// bucket host and the key.
	t.Setenv("BBB_S3_ENDPOINT", "https://proxy.example.com/minio")
	t.Setenv("BBB_S3_FORCE_PATH_STYLE", "")
	portal, direct, err := s3FS{}.ShareInfo("s3://mybucket/a b.txt")
	if err != nil {
		t.Fatalf("ShareInfo error: %v", err)
	}
	want := "https://mybucket.proxy.example.com/minio/a%20b.txt"
	if direct != want || portal != want {
		t.Errorf("vhost: portal=%q direct=%q, want %q", portal, direct, want)
	}

	// Path style: endpoint path prefix is naturally kept since the whole base
	// (including prefix) precedes bucket/key.
	t.Setenv("BBB_S3_FORCE_PATH_STYLE", "true")
	_, direct, err = s3FS{}.ShareInfo("s3://mybucket/a b.txt")
	if err != nil {
		t.Fatalf("ShareInfo (path style) error: %v", err)
	}
	wantPath := "https://proxy.example.com/minio/mybucket/a%20b.txt"
	if direct != wantPath {
		t.Errorf("path style: direct=%q, want %q", direct, wantPath)
	}
}

func TestS3ShareInfoAWSEscaping(t *testing.T) {
	// Force the AWS branch (no custom endpoint).
	t.Setenv("BBB_S3_ENDPOINT", "")

	portal, direct, err := s3FS{}.ShareInfo("s3://mybucket/a b/c#d.bin")
	if err != nil {
		t.Fatalf("ShareInfo error: %v", err)
	}
	wantPortal := "https://s3.console.aws.amazon.com/s3/object/mybucket?prefix=a+b%2Fc%23d.bin"
	if portal != wantPortal {
		t.Errorf("portal = %q, want %q", portal, wantPortal)
	}
	wantDirect := "https://mybucket.s3.amazonaws.com/a%20b/c%23d.bin"
	if direct != wantDirect {
		t.Errorf("direct = %q, want %q", direct, wantDirect)
	}

	// Empty key must not produce a trailing "//" or a dangling prefix.
	portal, direct, err = s3FS{}.ShareInfo("s3://mybucket")
	if err != nil {
		t.Fatalf("ShareInfo(bucket) error: %v", err)
	}
	if portal != "https://s3.console.aws.amazon.com/s3/object/mybucket" {
		t.Errorf("bucket portal = %q", portal)
	}
	if direct != "https://mybucket.s3.amazonaws.com" {
		t.Errorf("bucket direct = %q", direct)
	}
}

type fakeNotFound struct{}

func (fakeNotFound) Error() string  { return "missing" }
func (fakeNotFound) NotFound() bool { return true }

func TestIsNonRetryableHTTPErrS3(t *testing.T) {
	// AWS SDK HTTP responses (smithy) with 401/403/404 are non-retryable.
	for _, code := range []int{401, 403, 404} {
		err := &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: code}},
			Err:      errors.New("boom"),
		}
		if !IsNonRetryableHTTPErr(err) {
			t.Errorf("smithy %d should be non-retryable", code)
		}
	}
	// A 500 should still be retryable.
	err500 := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 500}},
		Err:      errors.New("boom"),
	}
	if IsNonRetryableHTTPErr(err500) {
		t.Error("smithy 500 should be retryable")
	}
	// Typed not-found errors implementing NotFound() are non-retryable.
	if !IsNonRetryableHTTPErr(fakeNotFound{}) {
		t.Error("NotFound() error should be non-retryable")
	}
	// Unrelated errors are retryable.
	if IsNonRetryableHTTPErr(errors.New("transient")) {
		t.Error("generic error should be retryable")
	}
}
