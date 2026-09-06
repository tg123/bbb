package gs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/api/googleapi"
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

func useTestServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("BBB_GS_ENDPOINT", server.URL)
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	cachedClientOnce = sync.Once{}
	cachedClient, cachedClientErr = nil, nil
	t.Cleanup(func() {
		if cachedClient != nil {
			if err := cachedClient.Close(); err != nil {
				t.Errorf("close client: %v", err)
			}
		}
		cachedClientOnce = sync.Once{}
		cachedClient, cachedClientErr = nil, nil
	})
}

type failingReader struct {
	err error
}

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestUploadAbortsOnSourceError(t *testing.T) {
	for _, size := range []int{7, downloadChunkSize + 7} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			var committed atomic.Bool
			useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Query().Get("uploadType") == "resumable" {
					w.Header().Set("Location", "http://"+r.Host+"/upload-session")
					_, _ = io.WriteString(w, "{}")
					return
				}
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					return
				}
				if strings.HasSuffix(r.Header.Get("Content-Range"), "/*") {
					w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", downloadChunkSize-1))
					w.Header().Set("X-Http-Status-Code-Override", "308")
					w.WriteHeader(http.StatusOK)
					return
				}
				committed.Store(true)
				_, _ = fmt.Fprintf(w, `{"bucket":"b","name":"o","size":"%d"}`, size)
			})
			sourceErr := errors.New("source read failed")
			reader := io.MultiReader(bytes.NewReader(bytes.Repeat([]byte("x"), size)), failingReader{sourceErr})
			ctx := t.Context()
			err := UploadStream(ctx, GSPath{Bucket: "b", Object: "o"}, reader, 1)
			if !errors.Is(err, sourceErr) {
				t.Fatalf("UploadStream error = %v, want %v", err, sourceErr)
			}
			if ctx.Err() != nil {
				t.Fatal("upload canceled the caller's context")
			}
			if committed.Load() {
				t.Fatal("failed upload committed truncated content")
			}
		})
	}
}

func TestUploadCommitsCompleteContent(t *testing.T) {
	content := "complete content"
	var uploaded string
	useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Errorf("parse content type: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Errorf("read upload part: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			data, err := io.ReadAll(part)
			if err != nil {
				t.Errorf("read upload data: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			uploaded = string(data)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"bucket":"b","name":"o","size":"%d"}`, len(content))
	})
	if err := UploadStream(t.Context(), GSPath{Bucket: "b", Object: "o"}, strings.NewReader(content), 1); err != nil {
		t.Fatal(err)
	}
	if uploaded != content {
		t.Fatalf("uploaded = %q, want %q", uploaded, content)
	}
}

func TestNotExistError(t *testing.T) {
	err := fmt.Errorf("delete failed: %w", notExistError("gs://b/missing"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error %v does not wrap os.ErrNotExist", err)
	}
}

func TestMkBucketPreservesConflict(t *testing.T) {
	t.Setenv("BBB_GS_PROJECT", "requested-project")
	var reads atomic.Int64
	useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			if got := r.URL.Query().Get("project"); got != "requested-project" {
				t.Errorf("project = %q", got)
			}
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"error":{"code":409,"message":"bucket name is taken"}}`)
			return
		}
		reads.Add(1)
		_, _ = io.WriteString(w, `{"name":"shared-bucket","projectNumber":"123"}`)
	})
	err := MkBucket(t.Context(), "shared-bucket")
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusConflict {
		t.Fatalf("MkBucket error = %v, want conflict", err)
	}
	if reads.Load() != 0 {
		t.Fatal("bucket readability must not be used as proof of ownership")
	}
}

func TestCopyServerSideNotFound(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNotFound, http.StatusForbidden} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			var sourceReads atomic.Int64
			useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, `{"error":{"code":404,"message":"rewrite target not found"}}`)
					return
				}
				sourceReads.Add(1)
				w.WriteHeader(status)
				if status == http.StatusOK {
					_, _ = io.WriteString(w, `{"name":"source","size":"7"}`)
				} else {
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"source lookup failed"}}`, status)
				}
			})
			err := CopyServerSide(t.Context(), GSPath{Bucket: "b", Object: "source"}, GSPath{Bucket: "dest", Object: "o"}, 1, 0, nil)
			if sourceReads.Load() != 1 {
				t.Fatal("expected a source lookup after ambiguous rewrite 404")
			}
			if status == http.StatusNotFound {
				if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "gs://b/source") {
					t.Fatalf("error = %v, want missing source", err)
				}
			} else {
				var apiErr *googleapi.Error
				if !errors.As(err, &apiErr) || apiErr.Code != http.StatusNotFound || !strings.Contains(err.Error(), "rewrite target not found") {
					t.Fatalf("error = %v, want original rewrite error", err)
				}
			}
		})
	}
}

func TestDownloadFileParallel(t *testing.T) {
	const size = 2*downloadChunkSize + 123
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i*31 + i/downloadChunkSize)
	}
	var ranges atomic.Int64
	allStarted := make(chan struct{})
	useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/b/b/o/o" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"name":"o","size":"%d","generation":"42"}`, size)
			return
		}
		if r.URL.Path != "/b/o" || r.URL.Query().Get("generation") != "42" {
			t.Errorf("unexpected unpinned range URL: %s", r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var start, end int
		if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil || start < 0 || end >= size || start > end {
			t.Errorf("invalid range: %q", r.Header.Get("Range"))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if ranges.Add(1) == 3 {
			close(allStarted)
		}
		select {
		case <-allStarted:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
		w.Header().Set("X-Goog-Generation", "42")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(payload[start : end+1])
	})
	file, err := os.Create(filepath.Join(t.TempDir(), "download"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var progress []int64
	var concurrentCallback atomic.Bool
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	n, err := DownloadFile(ctx, GSPath{Bucket: "b", Object: "o"}, file, 3, func(n int64) {
		if concurrentCallback.Swap(true) {
			t.Error("progress callbacks are not serialized")
			return
		}
		defer concurrentCallback.Store(false)
		runtime.Gosched()
		progress = append(progress, n)
	})
	if err != nil {
		t.Fatal(err)
	}
	if n != size || ranges.Load() != 3 {
		t.Fatalf("downloaded %d bytes in %d ranges, want %d in 3", n, ranges.Load(), size)
	}
	if len(progress) == 0 || progress[len(progress)-1] != size || !slices.IsSorted(progress) {
		t.Fatalf("non-monotonic or incomplete progress: %v", progress)
	}
	got, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("range assembly changed the payload")
	}
}

func TestDownloadFileStopsScheduling(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelRequest), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var ranges atomic.Int64
			useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/storage/v1/b/b/o/o" {
					w.Header().Set("Content-Type", "application/json")
					// An enormous virtual object exposes scheduling after failure
					// without allocating or downloading its contents.
					_, _ = fmt.Fprintf(w, `{"size":"%d","generation":"42"}`, int64(1)<<60)
					return
				}
				ranges.Add(1)
				if cancelRequest {
					cancel()
					<-r.Context().Done()
					return
				}
				w.WriteHeader(http.StatusForbidden)
			})
			file, err := os.Create(filepath.Join(t.TempDir(), "download"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			result := make(chan error, 1)
			go func() {
				_, err := DownloadFile(ctx, GSPath{Bucket: "b", Object: "o"}, file, 1, nil)
				result <- err
			}()
			select {
			case err := <-result:
				if cancelRequest {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("error = %v, want context canceled", err)
					}
				} else {
					var apiErr *googleapi.Error
					if !errors.As(err, &apiErr) || apiErr.Code != http.StatusForbidden {
						t.Fatalf("error = %v, want original range failure", err)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("download kept scheduling after cancellation")
			}
			if ranges.Load() != 1 {
				t.Fatalf("scheduled %d requests, want 1", ranges.Load())
			}
		})
	}
}
