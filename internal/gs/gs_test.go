package gs

import (
	"context"
	"strings"
	"testing"
)

func TestTouchRejectsDirLike(t *testing.T) {
	// The guard must fire before any client/network access, so these calls
	// return the directory-like error rather than a backend/config error.
	for _, gp := range []GSPath{
		{Bucket: "b"},                 // bucket root, empty object
		{Bucket: "b", Object: "dir/"}, // trailing slash
	} {
		err := Touch(context.Background(), gp)
		if err == nil {
			t.Fatalf("Touch(%s) = nil, want directory-like error", gp.String())
		}
		if !strings.Contains(err.Error(), "directory-like") {
			t.Fatalf("Touch(%s) error = %v, want directory-like error", gp.String(), err)
		}
	}
}

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		wantB   string
		wantO   string
		wantErr bool
	}{
		{"gs://bucket", "bucket", "", false},
		{"gs://bucket/obj", "bucket", "obj", false},
		{"gs://bucket/dir/sub/file.txt", "bucket", "dir/sub/file.txt", false},
		{"gs://bucket/dir/", "bucket", "dir/", false},
		{"gs://", "", "", true},
		{"gs:///obj", "", "", true},
		{"s3://bucket/key", "", "", true},
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
		if got.Bucket != c.wantB || got.Object != c.wantO {
			t.Errorf("Parse(%q) = {%q,%q}, want {%q,%q}", c.in, got.Bucket, got.Object, c.wantB, c.wantO)
		}
	}
}

func TestString(t *testing.T) {
	cases := []struct {
		p    GSPath
		want string
	}{
		{GSPath{Bucket: "b"}, "gs://b"},
		{GSPath{Bucket: "b", Object: "o"}, "gs://b/o"},
		{GSPath{Bucket: "b", Object: "d/o"}, "gs://b/d/o"},
		{GSPath{}, "gs://"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("%+v.String() = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	for _, in := range []string{"gs://bucket", "gs://bucket/obj", "gs://bucket/a/b/c.txt"} {
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
		p    GSPath
		want bool
	}{
		{GSPath{Bucket: "b"}, true},
		{GSPath{Bucket: "b", Object: "dir/"}, true},
		{GSPath{Bucket: "b", Object: "file.txt"}, false},
	}
	for _, c := range cases {
		if got := c.p.IsDirLike(); got != c.want {
			t.Errorf("%+v.IsDirLike() = %v, want %v", c.p, got, c.want)
		}
	}
}

func TestWithDir(t *testing.T) {
	cases := []struct {
		p    GSPath
		want string
	}{
		{GSPath{Bucket: "b"}, "gs://b"},
		{GSPath{Bucket: "b", Object: "dir"}, "gs://b/dir/"},
		{GSPath{Bucket: "b", Object: "dir/"}, "gs://b/dir/"},
	}
	for _, c := range cases {
		if got := c.p.WithDir().String(); got != c.want {
			t.Errorf("%+v.WithDir() = %q, want %q", c.p, got, c.want)
		}
	}
}

func TestChild(t *testing.T) {
	cases := []struct {
		parent GSPath
		rel    string
		want   string
	}{
		{GSPath{Bucket: "b"}, "file.txt", "gs://b/file.txt"},
		{GSPath{Bucket: "b", Object: "dir"}, "file.txt", "gs://b/dir/file.txt"},
		{GSPath{Bucket: "b", Object: "dir/"}, "file.txt", "gs://b/dir/file.txt"},
		{GSPath{Bucket: "b", Object: "a/b"}, "c/d", "gs://b/a/b/c/d"},
		// Object names are opaque: "."/".." and duplicate slashes must be
		// preserved, not normalized away, or listing round-trips misaddress
		// objects.
		{GSPath{Bucket: "b", Object: "dir"}, "../escape.txt", "gs://b/dir/../escape.txt"},
		{GSPath{Bucket: "b", Object: "a/./b"}, "c", "gs://b/a/./b/c"},
		{GSPath{Bucket: "b", Object: "weird//name"}, "child", "gs://b/weird//name/child"},
	}
	for _, c := range cases {
		if got := c.parent.Child(c.rel).String(); got != c.want {
			t.Errorf("%+v.Child(%q) = %q, want %q", c.parent, c.rel, got, c.want)
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

func TestEndpoint(t *testing.T) {
	cases := []struct {
		bbbEnv, emulatorEnv, want string
	}{
		{"", "", ""},
		{"http://127.0.0.1:4443", "", "http://127.0.0.1:4443"},
		{"127.0.0.1:4443/", "", "http://127.0.0.1:4443"},
		{"", "localhost:4443", "http://localhost:4443"},
		{"", "https://localhost:4443", "https://localhost:4443"},
		// BBB_GS_ENDPOINT wins over STORAGE_EMULATOR_HOST.
		{"http://a:1", "b:2", "http://a:1"},
	}
	for _, c := range cases {
		t.Setenv("BBB_GS_ENDPOINT", c.bbbEnv)
		t.Setenv("STORAGE_EMULATOR_HOST", c.emulatorEnv)
		if got := Endpoint(); got != c.want {
			t.Errorf("Endpoint(BBB_GS_ENDPOINT=%q, STORAGE_EMULATOR_HOST=%q) = %q, want %q", c.bbbEnv, c.emulatorEnv, got, c.want)
		}
	}
}

func TestProject(t *testing.T) {
	t.Setenv("BBB_GS_PROJECT", "")
	t.Setenv("GOOGLE_CLOUD_PROJECT", "")
	t.Setenv("GCLOUD_PROJECT", "")
	t.Setenv("CLOUDSDK_CORE_PROJECT", "")
	if got := Project(); got != "" {
		t.Errorf("Project() = %q, want empty", got)
	}
	t.Setenv("GOOGLE_CLOUD_PROJECT", "fallback")
	if got := Project(); got != "fallback" {
		t.Errorf("Project() = %q, want %q", got, "fallback")
	}
	t.Setenv("BBB_GS_PROJECT", "explicit")
	if got := Project(); got != "explicit" {
		t.Errorf("Project() = %q, want %q", got, "explicit")
	}
}
