package bbbfs

import (
	"fmt"
	"testing"

	gspkg "github.com/tg123/bbb/internal/gs"
	"google.golang.org/api/googleapi"
)

func TestGSListingChildPath(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"/", "gs://bucket/a//"},
		{"//", "gs://bucket/a///"},
		{"child/", "gs://bucket/a/child"},
		{"child//", "gs://bucket/a/child//"},
		{"file", "gs://bucket/a/file"},
		{"child//file", "gs://bucket/a/child//file"},
	} {
		if got := gsChildPath(gspkg.GSPath{Bucket: "bucket", Object: "a/"}, tc.name); got != tc.want {
			t.Errorf("gsChildPath(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestGSChildPathPreservesOpaqueNames(t *testing.T) {
	for _, name := range []string{`nested\file.txt`, "../file", "/file", "nested//file", "./file", "a #?%.txt"} {
		t.Run(name, func(t *testing.T) {
			for _, parent := range []string{"gs://bucket", "gs://bucket/prefix/"} {
				want := parent + "/" + name
				if parent == "gs://bucket/prefix/" {
					want = parent + name
				}
				if got := (gsFS{}).ChildPath(parent, name); got != want {
					t.Errorf("ChildPath(%q, %q) = %q, want %q", parent, name, got, want)
				}
			}
		})
	}
}

func TestIsNonRetryableHTTPErrGS(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 408, 409, 412, 429, 500, 502, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			want := status == 401 || status == 403 || status == 404
			var err error = &googleapi.Error{Code: status}
			for range 3 {
				if got := IsNonRetryableHTTPErr(err); got != want {
					t.Errorf("IsNonRetryableHTTPErr(%v) = %v, want %v", err, got, want)
				}
				err = fmt.Errorf("wrapped: %w", err)
			}
		})
	}
}

func TestGSMatch(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"gs://bucket/obj", true},
		{"gs://bucket", true},
		{"s3://bucket/key", false},
		{"az://account/container", false},
		{"/local/path", false},
	}
	for _, c := range cases {
		if got := (gsFS{}).Match(c.in); got != c.want {
			t.Errorf("gsFS.Match(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	// Resolve must route gs:// paths to the GCS provider, not the local
	// fallback.
	if _, ok := Resolve("gs://bucket/obj").(gsFS); !ok {
		t.Errorf("Resolve(gs://...) did not return gsFS")
	}
	if !IsGS("gs://bucket/obj") || !IsObjectStore("gs://bucket/obj") || !IsRemote("gs://bucket/obj") {
		t.Error("gs:// path should be recognised as a remote object store")
	}
}

func TestGSResolveDstPath(t *testing.T) {
	cases := []struct {
		dst       string
		base      string
		mustBeDir bool
		want      string
		wantErr   bool
	}{
		{"gs://b", "f.txt", false, "gs://b/f.txt", false},
		{"gs://b/dir/", "f.txt", false, "gs://b/dir/f.txt", false},
		{"gs://b/dir", "f.txt", true, "gs://b/dir/f.txt", false},
		{"gs://b/f2.txt", "f.txt", false, "gs://b/f2.txt", false},
	}
	for _, c := range cases {
		got, err := (gsFS{}).ResolveDstPath(c.dst, c.base, c.mustBeDir)
		if c.wantErr {
			if err == nil {
				t.Errorf("ResolveDstPath(%q) expected error", c.dst)
			}
			continue
		}
		if err != nil {
			t.Errorf("ResolveDstPath(%q): %v", c.dst, err)
			continue
		}
		if got != c.want {
			t.Errorf("ResolveDstPath(%q, %q, %v) = %q, want %q", c.dst, c.base, c.mustBeDir, got, c.want)
		}
	}
}

func TestGSShareInfo(t *testing.T) {
	t.Setenv("BBB_GS_ENDPOINT", "")
	t.Setenv("STORAGE_EMULATOR_HOST", "")

	portal, direct, err := (gsFS{}).ShareInfo("gs://mybucket/a b/c#d.bin")
	if err != nil {
		t.Fatalf("ShareInfo error: %v", err)
	}
	wantPortal := "https://console.cloud.google.com/storage/browser/mybucket?prefix=a+b%2Fc%23d.bin"
	if portal != wantPortal {
		t.Errorf("portal = %q, want %q", portal, wantPortal)
	}
	wantDirect := "https://storage.googleapis.com/mybucket/a%20b/c%23d.bin"
	if direct != wantDirect {
		t.Errorf("direct = %q, want %q", direct, wantDirect)
	}

	// Empty object must not produce a trailing "/" or a dangling prefix.
	portal, direct, err = (gsFS{}).ShareInfo("gs://mybucket")
	if err != nil {
		t.Fatalf("ShareInfo(bucket) error: %v", err)
	}
	if portal != "https://console.cloud.google.com/storage/browser/mybucket" {
		t.Errorf("bucket portal = %q", portal)
	}
	if direct != "https://storage.googleapis.com/mybucket" {
		t.Errorf("bucket direct = %q", direct)
	}

	// With an emulator endpoint both links point at the emulator object URL.
	t.Setenv("BBB_GS_ENDPOINT", "http://localhost:4443/")
	portal, direct, err = (gsFS{}).ShareInfo("gs://mybucket/a b.txt")
	if err != nil {
		t.Fatalf("ShareInfo(emulator) error: %v", err)
	}
	want := "http://localhost:4443/mybucket/a%20b.txt"
	if portal != want || direct != want {
		t.Errorf("emulator: portal=%q direct=%q, want %q", portal, direct, want)
	}
}
