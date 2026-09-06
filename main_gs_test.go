package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gspkg "github.com/tg123/bbb/internal/gs"
	"github.com/urfave/cli/v3"
	"google.golang.org/api/googleapi"
)

func TestCopyDestinationNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"", ".", "..", "../escape", "nested/../../escape", "nested/../file",
		"/absolute", `\absolute`, `..\escape`, `nested\..\escape`,
		`C:\escape`, "C:escape", `\\server\share\file`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := copyDestination("gs://bucket/source/", root, name); err == nil {
				t.Errorf("accepted unsafe local name %q", name)
			}
			// The same names are opaque object keys for a remote destination.
			got, err := copyDestination("gs://bucket/source/", "gs://bucket/dest/", name)
			if err != nil || got != "gs://bucket/dest/"+name {
				t.Errorf("remote name changed: got %q, %v", got, err)
			}
		})
	}
	for _, name := range []string{"file.txt", "nested/file.txt", "has..dots/file.txt"} {
		got, err := copyDestination("gs://bucket/source/", root, name)
		want := filepath.Join(root, filepath.FromSlash(name))
		if err != nil || got != want {
			t.Errorf("valid name %q: got %q, %v; want %q", name, got, err, want)
		}
	}
	localName := filepath.Join("nested", "file.txt")
	got, err := copyDestination(root, "gs://bucket/dest/", localName)
	if err != nil || got != "gs://bucket/dest/nested/file.txt" {
		t.Fatalf("local relative name was not normalized: %q, %v", got, err)
	}
	got, err = copyDestination("gs://bucket/source/", "gs://bucket/dest/", `nested\file.txt`)
	if err != nil || got != `gs://bucket/dest/nested\file.txt` {
		t.Fatalf("remote backslash name changed: %q, %v", got, err)
	}
}

func TestWriteCopyDestinationConfinesSymlinks(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(fmt.Sprintf("directory=%v", directory), func(t *testing.T) {
			root := t.TempDir()
			outside := t.TempDir()
			secret := filepath.Join(outside, "file.txt")
			if err := os.WriteFile(secret, []byte("untouched"), 0o644); err != nil {
				t.Fatal(err)
			}
			linkTarget, linkName, name := secret, "file.txt", "file.txt"
			if directory {
				linkTarget, linkName, name = outside, "nested", "nested/file.txt"
			}
			if err := os.Symlink(linkTarget, filepath.Join(root, linkName)); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			target := &localCopyTarget{root: root, name: name}
			err := writeCopyDestination(t.Context(), "", target, strings.NewReader("overwrite"))
			if err == nil {
				t.Fatal("write followed a symlink outside the destination root")
			}
			got, err := os.ReadFile(secret)
			if err != nil || string(got) != "untouched" {
				t.Fatalf("outside file changed: %q, %v", got, err)
			}
		})
	}
}

func TestExpandCPTaskLocalNamesForGS(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "file.txt"), []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	var tasks []cpTask
	err := expandCPTask(t.Context(), taskPair{src: root, dst: "gs://bucket/dest/"}, func(task cpTask) error {
		tasks = append(tasks, task)
		return nil
	})
	if err != nil || len(tasks) != 1 {
		t.Fatalf("expandCPTask: %v, tasks = %#v", err, tasks)
	}
	if tasks[0].src != filepath.Join(root, "nested", "file.txt") || tasks[0].dst != "gs://bucket/dest/nested/file.txt" {
		t.Fatalf("unexpected paths: %#v", tasks[0])
	}
}

func TestRetryOpGSStatus(t *testing.T) {
	t.Setenv("BBB_RETRY_JITTER", "0")
	for _, status := range []int{401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			attempts := 0
			err := retryOp(t.Context(), 2, func() error {
				attempts++
				return fmt.Errorf("GCS: %w", &googleapi.Error{Code: status})
			})
			want := 3
			if status == 401 || status == 403 || status == 404 {
				want = 1
			}
			if err == nil || attempts != want {
				t.Fatalf("retryOp: %v, attempts = %d, want %d", err, attempts, want)
			}
		})
	}
}

type gsIntegrationTransport struct {
	mu      sync.RWMutex
	handler http.Handler
}

func (transport *gsIntegrationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	transport.mu.RLock()
	defer transport.mu.RUnlock()
	if transport.handler == nil {
		return nil, errors.New("GCS integration handler is not installed")
	}
	response := httptest.NewRecorder()
	transport.handler.ServeHTTP(response, r)
	return response.Result(), nil
}

var gsIntegrationClient = &http.Client{Transport: &gsIntegrationTransport{}}

func TestGCSCopySyncAndRemove(t *testing.T) {
	// Reuse the transport across test runs because the GCS client is
	// process-cached; replacing its handler also supports go test -count=N.
	var mu sync.Mutex
	name := "nested/file.txt"
	reads := 0
	missingSource := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodDelete || (missingSource && !strings.HasSuffix(r.URL.Path, "/o")) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"code":404,"message":"missing"}}`)
			return
		}
		if r.URL.Query().Get("alt") == "media" || strings.HasPrefix(r.URL.Path, "/bucket/") {
			reads++
			w.Header().Set("Content-Length", "7")
			_, _ = io.WriteString(w, "payload")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		object := map[string]string{"bucket": "bucket", "name": "source/" + name, "size": "7", "generation": "1"}
		if strings.HasSuffix(r.URL.Path, "/o") {
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{object}})
			return
		}
		_ = json.NewEncoder(w).Encode(object)
	})
	transport := gsIntegrationClient.Transport.(*gsIntegrationTransport)
	transport.mu.Lock()
	transport.handler = handler
	transport.mu.Unlock()
	t.Cleanup(func() {
		transport.mu.Lock()
		transport.handler = nil
		transport.mu.Unlock()
	})
	t.Setenv("BBB_GS_ENDPOINT", "http://gcs.test")
	t.Setenv("STORAGE_EMULATOR_HOST", "")
	gspkg.SetHTTPClient(gsIntegrationClient)
	t.Cleanup(func() { gspkg.SetHTTPClient(nil) })

	copies := []struct {
		name string
		run  func(context.Context, string, string) error
		dry  bool
	}{
		{"tree", func(ctx context.Context, src, dst string) error {
			return copyTree(ctx, src, dst, true, true, "cp", 1, 0)
		}, false},
		{"cp", func(ctx context.Context, src, dst string) error {
			return cmdCPPaths(ctx, true, true, 1, 0, []string{src}, dst, 0, false, nil)
		}, false},
		{"task-stream", func(ctx context.Context, src, dst string) error {
			return runCPTaskStream(ctx, func(emit func(taskPair) error) error {
				return emit(taskPair{src: src, dst: dst})
			}, true, true, 1, 0, "")
		}, false},
		{"sync", func(ctx context.Context, src, dst string) error {
			return cmdSyncPaths(ctx, false, false, true, "", 1, 0, src, dst)
		}, false},
		{"sync-dry", func(ctx context.Context, src, dst string) error {
			return cmdSyncPaths(ctx, true, false, true, "", 1, 0, src, dst)
		}, true},
	}
	for _, copy := range copies {
		for _, remoteName := range []string{"nested/file.txt", "../escape", "/absolute", `..\escape`, `C:\escape`} {
			t.Run(copy.name+"/"+remoteName, func(t *testing.T) {
				mu.Lock()
				name, reads = remoteName, 0
				mu.Unlock()
				dir := t.TempDir()
				dst := filepath.Join(dir, "output")
				err := copy.run(t.Context(), "gs://bucket/source/", dst)
				if remoteName != "nested/file.txt" {
					if err == nil || !strings.Contains(err.Error(), "unsafe local destination") {
						t.Fatalf("malicious name: got %v", err)
					}
					mu.Lock()
					gotReads := reads
					mu.Unlock()
					if gotReads != 0 {
						t.Fatalf("read %d objects before rejecting the name", gotReads)
					}
					if _, err := os.Stat(filepath.Join(dir, "escape")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("outside destination was created: %v", err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				if copy.dry {
					if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("dry run created destination: %v", err)
					}
					return
				}
				got, err := os.ReadFile(filepath.Join(dst, "nested", "file.txt"))
				if err != nil || string(got) != "payload" {
					t.Fatalf("nested file: %q, %v", got, err)
				}
			})
		}
		t.Run(copy.name+"/symlink", func(t *testing.T) {
			if copy.dry {
				t.Skip("dry run does not write")
			}
			mu.Lock()
			name = "nested/file.txt"
			mu.Unlock()
			dst, outside := t.TempDir(), t.TempDir()
			secret := filepath.Join(outside, "file.txt")
			if err := os.WriteFile(secret, []byte("untouched"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dst, "nested")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if err := copy.run(t.Context(), "gs://bucket/source/", dst); err == nil {
				t.Fatal("followed destination symlink outside root")
			}
			got, err := os.ReadFile(secret)
			if err != nil || string(got) != "untouched" {
				t.Fatalf("outside file changed: %q, %v", got, err)
			}
		})
	}
	t.Run("scoped-file", func(t *testing.T) {
		dst := t.TempDir()
		target := &localCopyTarget{root: dst, name: "nested/file.txt"}
		ctx := context.WithValue(t.Context(), localCopyTargetKey{}, target)
		if err := cmdCPPaths(ctx, true, true, 1, 0, []string{"gs://bucket/source/file.txt"},
			filepath.Join(dst, "nested", "file.txt"), 7, false, nil); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dst, "nested", "file.txt"))
		if err != nil || string(got) != "payload" {
			t.Fatalf("scoped file: %q, %v", got, err)
		}
	})
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprintf("scoped-symlink-missing-source=%v", missing), func(t *testing.T) {
			t.Setenv("BBB_PARALLEL_DOWNLOAD", "1")
			dst, outside := t.TempDir(), t.TempDir()
			secret := filepath.Join(outside, "file.txt")
			if err := os.WriteFile(secret, []byte("untouched"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, filepath.Join(dst, "nested")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			mu.Lock()
			missingSource = missing
			mu.Unlock()
			defer func() {
				mu.Lock()
				missingSource = false
				mu.Unlock()
			}()
			target := &localCopyTarget{root: dst, name: "nested/file.txt"}
			ctx := context.WithValue(t.Context(), localCopyTargetKey{}, target)
			err := cmdCPPaths(ctx, true, true, 1, 0, []string{"gs://bucket/source/file.txt"},
				filepath.Join(dst, "nested", "file.txt"), 7, false, nil)
			if err == nil {
				t.Fatal("scoped copy followed destination symlink")
			}
			if missing && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing file was retried as a directory: %v", err)
			}
			got, err := os.ReadFile(secret)
			if err != nil || string(got) != "untouched" {
				t.Fatalf("outside file changed: %q, %v", got, err)
			}
		})
	}
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("rm-force=%v", force), func(t *testing.T) {
			command := &cli.Command{
				Name: "rm",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "f"},
					&cli.BoolFlag{Name: "q", Value: true},
					&cli.IntFlag{Name: "concurrency", Value: 1},
					&cli.IntFlag{Name: "retry-count"},
				},
				Action: cmdRM,
			}
			args := []string{"rm"}
			if force {
				args = append(args, "-f")
			}
			args = append(args, "gs://bucket/missing")
			err := command.Run(t.Context(), args)
			if force && err != nil {
				t.Fatalf("forced missing delete failed: %v", err)
			}
			if !force && !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing delete error = %v, want os.ErrNotExist", err)
			}
		})
	}
}
