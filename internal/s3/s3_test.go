package s3

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
)

func TestTouchRejectsDirLike(t *testing.T) {
	// The guard must fire before any client/network access, so these calls
	// return the directory-like error rather than a backend/config error.
	for _, sp := range []S3Path{
		{Bucket: "b"},              // bucket root, empty key
		{Bucket: "b", Key: "dir/"}, // trailing slash
	} {
		err := Touch(context.Background(), sp)
		if err == nil {
			t.Fatalf("Touch(%s) = nil, want directory-like error", sp.String())
		}
		if !strings.Contains(err.Error(), "directory-like") {
			t.Fatalf("Touch(%s) error = %v, want directory-like error", sp.String(), err)
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		wantB   string
		wantK   string
		wantErr bool
	}{
		{"s3://bucket", "bucket", "", false},
		{"s3://bucket/key", "bucket", "key", false},
		{"s3://bucket/dir/sub/file.txt", "bucket", "dir/sub/file.txt", false},
		{"s3://bucket/dir/", "bucket", "dir/", false},
		{"s3://", "", "", true},
		{"s3:///key", "", "", true},
		{"az://account/container", "", "", true},
		{"/local/path", "", "", true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q): expected error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q): unexpected error: %v", c.in, err)
			continue
		}
		if got.Bucket != c.wantB || got.Key != c.wantK {
			t.Errorf("Parse(%q) = {%q,%q}, want {%q,%q}", c.in, got.Bucket, got.Key, c.wantB, c.wantK)
		}
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		p    S3Path
		want string
	}{
		{S3Path{Bucket: "b"}, "s3://b"},
		{S3Path{Bucket: "b", Key: "k"}, "s3://b/k"},
		{S3Path{Bucket: "b", Key: "d/k"}, "s3://b/d/k"},
		{S3Path{}, "s3://"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("%+v.String() = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, in := range []string{"s3://bucket", "s3://bucket/key", "s3://bucket/a/b/c.txt"} {
		p, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got := p.String(); got != in {
			t.Errorf("round trip %q -> %q", in, got)
		}
	}
}

func TestIsDirLike(t *testing.T) {
	cases := []struct {
		p    S3Path
		want bool
	}{
		{S3Path{Bucket: "b"}, true},
		{S3Path{Bucket: "b", Key: "dir/"}, true},
		{S3Path{Bucket: "b", Key: "file.txt"}, false},
	}
	for _, c := range cases {
		if got := c.p.IsDirLike(); got != c.want {
			t.Errorf("%+v.IsDirLike() = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestChild(t *testing.T) {
	cases := []struct {
		parent S3Path
		rel    string
		want   string
	}{
		{S3Path{Bucket: "b"}, "file.txt", "s3://b/file.txt"},
		{S3Path{Bucket: "b", Key: "dir"}, "file.txt", "s3://b/dir/file.txt"},
		{S3Path{Bucket: "b", Key: "dir/"}, "file.txt", "s3://b/dir/file.txt"},
		{S3Path{Bucket: "b", Key: "a/b"}, "c/d", "s3://b/a/b/c/d"},
		// S3 keys are opaque: "."/".." and duplicate slashes must be preserved,
		// not normalized away, or listing round-trips misaddress objects.
		{S3Path{Bucket: "b", Key: "dir"}, "../escape.txt", "s3://b/dir/../escape.txt"},
		{S3Path{Bucket: "b", Key: "a/./b"}, "c", "s3://b/a/./b/c"},
		{S3Path{Bucket: "b", Key: "weird//key"}, "child", "s3://b/weird//key/child"},
	}
	for _, c := range cases {
		if got := c.parent.Child(c.rel).String(); got != c.want {
			t.Errorf("%+v.Child(%q) = %q, want %q", c.parent, c.rel, got, c.want)
		}
	}
}

func TestEscapeKey(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"simple.txt", "simple.txt"},
		{"dir/file.txt", "dir/file.txt"},
		{"a b.txt", "a%20b.txt"},
		{"name+plus", "name%2Bplus"},
		{"tab\tend", "tab%09end"},
		{"nl\nend", "nl%0Aend"},
	}
	for _, c := range cases {
		if got := escapeKey(c.in); got != c.want {
			t.Errorf("escapeKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizePrefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"dir", "dir/"},
		{"dir/", "dir/"},
		{"a/b", "a/b/"},
	}
	for _, c := range cases {
		if got := normalizePrefix(c.in); got != c.want {
			t.Errorf("normalizePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestR2EndpointAndRegion(t *testing.T) {
	cases := []struct {
		name         string
		env          map[string]string
		wantEndpoint string
		wantRegion   string
		wantR2       bool
		wantAccount  string
	}{
		{
			name:         "aws default",
			wantEndpoint: "",
			wantRegion:   defaultRegion,
		},
		{
			name:         "account id derives endpoint and auto region",
			env:          map[string]string{"BBB_R2_ACCOUNT_ID": "abc123"},
			wantEndpoint: "https://abc123." + r2EndpointSuffix,
			wantRegion:   r2Region,
			wantR2:       true,
			wantAccount:  "abc123",
		},
		{
			name:         "explicit endpoint wins over account id",
			env:          map[string]string{"BBB_R2_ACCOUNT_ID": "abc123", "BBB_S3_ENDPOINT": "http://127.0.0.1:9000"},
			wantEndpoint: "http://127.0.0.1:9000",
			wantRegion:   defaultRegion,
		},
		{
			name:         "explicit r2 endpoint detected",
			env:          map[string]string{"BBB_S3_ENDPOINT": "https://abc123.eu." + r2EndpointSuffix + "/"},
			wantEndpoint: "https://abc123.eu." + r2EndpointSuffix + "/",
			wantRegion:   r2Region,
			wantR2:       true,
			wantAccount:  "abc123",
		},
		{
			name:         "explicit region wins over auto",
			env:          map[string]string{"BBB_R2_ACCOUNT_ID": "abc123", "BBB_S3_REGION": "wnam"},
			wantEndpoint: "https://abc123." + r2EndpointSuffix,
			wantRegion:   "wnam",
			wantR2:       true,
			wantAccount:  "abc123",
		},
		{
			name:         "aws region ignored for r2",
			env:          map[string]string{"BBB_R2_ACCOUNT_ID": "abc123", "AWS_REGION": "us-west-2"},
			wantEndpoint: "https://abc123." + r2EndpointSuffix,
			wantRegion:   r2Region,
			wantR2:       true,
			wantAccount:  "abc123",
		},
		{
			name:         "lookalike host is not r2",
			env:          map[string]string{"BBB_S3_ENDPOINT": "https://notr2.cloudflarestorage.com.evil.test"},
			wantEndpoint: "https://notr2.cloudflarestorage.com.evil.test",
			wantRegion:   defaultRegion,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, k := range []string{"BBB_R2_ACCOUNT_ID", "BBB_S3_ENDPOINT", "BBB_S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"} {
				t.Setenv(k, "")
			}
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			if got := endpoint(); got != c.wantEndpoint {
				t.Errorf("endpoint() = %q, want %q", got, c.wantEndpoint)
			}
			if got := region(); got != c.wantRegion {
				t.Errorf("region() = %q, want %q", got, c.wantRegion)
			}
			if got := isR2(); got != c.wantR2 {
				t.Errorf("isR2() = %v, want %v", got, c.wantR2)
			}
			if got := r2AccountID(); got != c.wantAccount {
				t.Errorf("r2AccountID() = %q, want %q", got, c.wantAccount)
			}
		})
	}
}

func TestClientLoadOptionsChecksums(t *testing.T) {
	cases := []struct {
		name         string
		endpoint     string
		wantRequest  aws.RequestChecksumCalculation
		wantResponse aws.ResponseChecksumValidation
	}{
		{
			name:         "aws keeps SDK defaults",
			wantRequest:  aws.RequestChecksumCalculationUnset,
			wantResponse: aws.ResponseChecksumValidationUnset,
		},
		{
			name:         "non-r2 endpoint keeps SDK defaults",
			endpoint:     "http://127.0.0.1:9000",
			wantRequest:  aws.RequestChecksumCalculationUnset,
			wantResponse: aws.ResponseChecksumValidationUnset,
		},
		{
			name:         "r2 uses checksums only when required",
			endpoint:     "https://abc123." + r2EndpointSuffix,
			wantRequest:  aws.RequestChecksumCalculationWhenRequired,
			wantResponse: aws.ResponseChecksumValidationWhenRequired,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("BBB_R2_ACCOUNT_ID", "")
			t.Setenv("BBB_S3_ENDPOINT", c.endpoint)
			var got awsconfig.LoadOptions
			for _, option := range clientLoadOptions() {
				if err := option(&got); err != nil {
					t.Fatalf("applying client option: %v", err)
				}
			}
			if got.RequestChecksumCalculation != c.wantRequest {
				t.Errorf("request checksum mode = %v, want %v", got.RequestChecksumCalculation, c.wantRequest)
			}
			if got.ResponseChecksumValidation != c.wantResponse {
				t.Errorf("response checksum mode = %v, want %v", got.ResponseChecksumValidation, c.wantResponse)
			}
		})
	}
}

func TestCreateBucketInputLocationConstraint(t *testing.T) {
	t.Run("aws non-default region includes constraint", func(t *testing.T) {
		t.Setenv("BBB_R2_ACCOUNT_ID", "")
		t.Setenv("BBB_S3_ENDPOINT", "")
		t.Setenv("BBB_S3_REGION", "us-west-2")
		input := createBucketInput("bucket")
		if input.CreateBucketConfiguration == nil {
			t.Fatal("CreateBucketConfiguration = nil, want location constraint")
		}
		if got := input.CreateBucketConfiguration.LocationConstraint; got != "us-west-2" {
			t.Errorf("LocationConstraint = %q, want %q", got, "us-west-2")
		}
	})

	t.Run("r2 omits constraint", func(t *testing.T) {
		t.Setenv("BBB_R2_ACCOUNT_ID", "abc123")
		t.Setenv("BBB_S3_ENDPOINT", "")
		t.Setenv("BBB_S3_REGION", "")
		input := createBucketInput("bucket")
		if input.CreateBucketConfiguration != nil {
			t.Errorf("CreateBucketConfiguration = %+v, want nil", input.CreateBucketConfiguration)
		}
	})
}
