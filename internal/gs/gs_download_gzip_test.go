package gs

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func gzipDownloadPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func serveGzipDownload(t *testing.T, encoding string, payload, compressed []byte) (*atomic.Int64, *atomic.Int64) {
	t.Helper()
	var requests, ranges atomic.Int64
	useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/b/b/o/o" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"name":"o","size":"%d","generation":"42","contentEncoding":%q}`, len(compressed), encoding)
			return
		}
		if r.URL.Path != "/b/o" || r.URL.Query().Get("generation") != "42" {
			t.Errorf("unexpected unpinned download URL: %s", r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests.Add(1)
		if r.Header.Get("Range") != "" {
			ranges.Add(1)
		}
		w.Header().Set("X-Goog-Generation", "42")
		w.Header().Set("X-Goog-Stored-Content-Encoding", "gzip")
		w.Header().Set("X-Goog-Stored-Content-Length", strconv.Itoa(len(compressed)))
		body := payload
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			body = compressed
		}
		// Like GCS transcoding, serve the whole decoded body even for a range.
		// A normal full read can instead be transparently decoded by net/http.
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	})
	return &requests, &ranges
}

func TestDownloadFileGzip(t *testing.T) {
	largePayload := make([]byte, downloadChunkSize+123)
	if _, err := rand.New(rand.NewSource(42)).Read(largePayload); err != nil {
		t.Fatal(err)
	}
	largePayload = append(largePayload, bytes.Repeat([]byte("decoded suffix"), 128*1024)...)
	largeCompressed := gzipDownloadPayload(t, largePayload)
	if len(largeCompressed) <= downloadChunkSize || len(largeCompressed) >= len(largePayload) {
		t.Fatal("fixture must span stored chunks and expand when decoded")
	}
	smallPayload := bytes.Repeat([]byte("decoded content"), 1024)
	for _, tc := range []struct {
		name       string
		encoding   string
		payload    []byte
		compressed []byte
	}{
		{"small", "gzip", smallPayload, gzipDownloadPayload(t, smallPayload)},
		{"large", "gzip", largePayload, largeCompressed},
		{"mixed-case", "GZip", largePayload, largeCompressed},
		{"empty", "gzip", nil, gzipDownloadPayload(t, nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests, ranges := serveGzipDownload(t, tc.encoding, tc.payload, tc.compressed)
			file, err := os.Create(filepath.Join(t.TempDir(), "download"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			// DownloadFile uses WriterAt semantics, not the file's seek position.
			const cursor = 17
			if _, err := file.Seek(cursor, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			var progress []int64
			n, err := DownloadFile(t.Context(), GSPath{Bucket: "b", Object: "o"}, file, 3, func(n int64) {
				progress = append(progress, n)
			})
			if err != nil {
				t.Fatal(err)
			}
			if n != int64(len(tc.payload)) {
				t.Errorf("downloaded %d bytes, want %d decoded bytes", n, len(tc.payload))
			}
			if requests.Load() != 1 || ranges.Load() != 0 {
				t.Errorf("download made %d requests (%d ranged), want one full read", requests.Load(), ranges.Load())
			}
			if len(progress) == 0 || progress[len(progress)-1] != n || !slices.IsSorted(progress) {
				t.Errorf("non-monotonic or incomplete decoded progress: %v", progress)
			}
			if pos, err := file.Seek(0, io.SeekCurrent); err != nil || pos != cursor {
				t.Errorf("file cursor = %d, %v, want %d", pos, err, cursor)
			}
			got, err := os.ReadFile(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.payload) {
				t.Errorf("decoded download differs: got %d bytes, want %d", len(got), len(tc.payload))
			}
		})
	}
}

func TestDownloadFileGzipWriteFailure(t *testing.T) {
	payload := []byte(strings.Repeat("decoded content", 1024))
	serveGzipDownload(t, "gzip", payload, gzipDownloadPayload(t, payload))
	name := filepath.Join(t.TempDir(), "read-only")
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var progress []int64
	n, err := DownloadFile(t.Context(), GSPath{Bucket: "b", Object: "o"}, file, 3, func(n int64) {
		progress = append(progress, n)
	})
	if err == nil {
		t.Fatal("download into a read-only file succeeded")
	}
	if n != 0 || len(progress) != 0 {
		t.Fatalf("failed write reported %d bytes and progress %v", n, progress)
	}
}
