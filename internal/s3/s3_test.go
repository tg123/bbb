package s3

import "testing"

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
