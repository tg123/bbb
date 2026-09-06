package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tg123/bbb/internal/bbbfs"
	"google.golang.org/api/googleapi"
)

func TestGCSRemoteDestinationNames(t *testing.T) {
	for _, dst := range []string{"az://account/container/prefix/", "s3://bucket/prefix/"} {
		for _, name := range []string{"../escape", "a/../../escape", "a/./file", "a//file", "/escape", `a\file`} {
			t.Run(dst+"/"+name, func(t *testing.T) {
				if _, err := copyDestination("gs://bucket/source/", dst, name); err == nil {
					t.Fatalf("accepted a remote name the destination may normalize: %q", name)
				}
			})
		}
		got, err := copyDestination("gs://bucket/source/", dst, "nested/file")
		if err != nil || got != dst+"nested/file" {
			t.Fatalf("valid remote name: %q, %v", got, err)
		}
	}

	for _, mode := range []string{"tree", "cp", "sync", "expand"} {
		t.Run(mode, func(t *testing.T) {
			var reads atomic.Int64
			useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/o") {
					_, _ = io.WriteString(w, `{"items":[{"name":"source/../escape","size":"7"}]}`)
					return
				}
				reads.Add(1)
				w.WriteHeader(http.StatusBadRequest)
			}))
			src, dst := "gs://bucket/source/", "az://account/container/prefix/"
			var err error
			switch mode {
			case "tree":
				err = copyTree(t.Context(), src, dst, true, true, "cp", 4, 0)
			case "cp":
				err = cmdCPPaths(t.Context(), true, true, 4, 0, []string{src}, dst, 0, false, nil)
			case "sync":
				err = cmdSyncPaths(t.Context(), false, false, true, "", 4, 0, src, dst)
			case "expand":
				err = expandCPTask(t.Context(), taskPair{src: src, dst: dst}, func(cpTask) error {
					t.Error("unsafe task was emitted")
					return nil
				})
			}
			if err == nil || !strings.Contains(err.Error(), "cannot preserve object name") {
				t.Fatalf("error = %v, want rejected remote name", err)
			}
			if reads.Load() != 0 {
				t.Fatalf("read %d objects before rejecting destination name", reads.Load())
			}
		})
	}
}

func TestGCSMissingSourceExpansion(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		for _, hasChildren := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%d/children=%t", status, hasChildren), func(t *testing.T) {
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if strings.HasSuffix(r.URL.Path, "/o") {
						if hasChildren {
							_, _ = io.WriteString(w, `{"items":[{"name":"missing/child","size":"7"}]}`)
						} else {
							_, _ = io.WriteString(w, `{"items":[]}`)
						}
						return
					}
					w.WriteHeader(status)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"original stat failure"}}`, status)
				}))
				var tasks []cpTask
				err := expandCPTask(t.Context(), taskPair{src: "gs://bucket/missing", dst: t.TempDir()}, func(task cpTask) error {
					tasks = append(tasks, task)
					return nil
				})
				if hasChildren {
					if err != nil || len(tasks) != 1 || tasks[0].src != "gs://bucket/missing/child" {
						t.Fatalf("nonempty prefix expansion: %v, %v", tasks, err)
					}
				} else {
					if len(tasks) != 0 {
						t.Fatal("missing source emitted copy tasks")
					}
					if status == http.StatusNotFound {
						if !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("error = %v, want original not-exist error", err)
						}
					} else {
						var apiErr *googleapi.Error
						if !errors.As(err, &apiErr) || apiErr.Code != status {
							t.Fatalf("error = %v, want original status %d", err, status)
						}
					}
				}
			})
		}
	}
}

func TestGCSMissingSourceCannotCheckpoint(t *testing.T) {
	useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/o") {
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":{"code":404,"message":"missing source"}}`)
	}))
	root := t.TempDir()
	statePath := filepath.Join(root, "state")
	src, dst := "gs://bucket/missing", filepath.Join(root, "download")
	err := runCPTaskStream(t.Context(), func(emit func(taskPair) error) error {
		return emit(taskPair{src: src, dst: dst})
	}, true, true, 4, 0, statePath)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("task stream error = %v, want not-exist", err)
	}
	state, checkpoints, err := loadTaskState(statePath)
	if err != nil || len(state) != 0 || len(checkpoints) != 0 {
		t.Fatalf("missing source recorded as completed: %v, %v, %v", state, checkpoints, err)
	}
	for _, destination := range []string{dst, "gs://bucket/destination/"} {
		err := cmdCPPaths(t.Context(), true, true, 4, 0, []string{src}, destination, 0, false, nil)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("direct copy to %s: %v, want not-exist", destination, err)
		}
	}
}

func TestGCSRewriteDoesNotFallBack(t *testing.T) {
	t.Setenv("BBB_AZBLOB_FORCE_S2S", "false")
	var rewrites, media, uploads atomic.Int64
	useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/rewriteTo/"):
			rewrites.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":403,"message":"rewrite denied"}}`)
		case r.Method != http.MethodGet:
			uploads.Add(1)
			_, _ = io.WriteString(w, `{"name":"destination","size":"7"}`)
		case r.URL.Query().Get("alt") == "media" || strings.HasPrefix(r.URL.Path, "/bucket/"):
			media.Add(1)
			_, _ = io.WriteString(w, "payload")
		default:
			_, _ = io.WriteString(w, `{"name":"source","size":"7","generation":"1"}`)
		}
	}))
	err := cmdCPPaths(t.Context(), true, true, 4, 0, []string{"gs://bucket/source"}, "gs://bucket/destination", 7, false, nil)
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != http.StatusForbidden {
		t.Fatalf("copy error = %v, want rewrite failure", err)
	}
	if rewrites.Load() != 1 || media.Load() != 0 || uploads.Load() != 0 {
		t.Fatalf("unexpected fallback: rewrites=%d reads=%d uploads=%d", rewrites.Load(), media.Load(), uploads.Load())
	}
}

func TestGCSLocalAliasesRejectedBeforeWrites(t *testing.T) {
	for _, names := range [][]string{
		{"A.txt", "a.txt"},
		{"nested/A.txt", "nested/a.txt"},
		{"caf\u00e9.txt", "cafe\u0301.txt"},
		{"a", "A/child"},
		{"A/child", "a"},
		{"file", "file"},
		{"file", "file."},
		{"file", "file::$DATA"},
	} {
		for _, mode := range []string{"tree", "cp", "expand", "task-stream", "sync", "sync-dry"} {
			t.Run(strings.Join(names, "+")+"/"+mode, func(t *testing.T) {
				var reads atomic.Int64
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if strings.HasSuffix(r.URL.Path, "/o") {
						// Separate pages ensure nothing is written before the
						// complete name set has been checked.
						i := 0
						response := map[string]any{}
						if r.URL.Query().Get("pageToken") == "" {
							response["nextPageToken"] = "second"
						} else {
							i = 1
						}
						response["items"] = []map[string]string{{"name": "source/" + names[i], "size": "7"}}
						_ = json.NewEncoder(w).Encode(response)
						return
					}
					reads.Add(1)
					_, _ = io.WriteString(w, "payload")
				}))
				root := t.TempDir()
				dst := filepath.Join(root, "output")
				src := "gs://bucket/source/"
				emitted := 0
				var err error
				switch mode {
				case "tree":
					err = copyTree(t.Context(), src, dst, true, true, "cp", 4, 0)
				case "cp":
					err = cmdCPPaths(t.Context(), true, true, 4, 0, []string{src}, dst, 0, false, nil)
				case "expand":
					err = expandCPTask(t.Context(), taskPair{src: src, dst: dst}, func(cpTask) error { emitted++; return nil })
				case "task-stream":
					err = runCPTaskStream(t.Context(), func(emit func(taskPair) error) error {
						return emit(taskPair{src: src, dst: dst})
					}, true, true, 4, 0, "")
				default:
					err = cmdSyncPaths(t.Context(), mode == "sync-dry", false, true, "", 4, 0, src, dst)
				}
				if err == nil || !strings.Contains(err.Error(), "unsafe local destination") {
					t.Fatalf("error = %v, want alias rejection", err)
				}
				if emitted != 0 || reads.Load() != 0 {
					t.Fatalf("work started before preflight: %d tasks, %d reads", emitted, reads.Load())
				}
				if _, err := os.Stat(dst); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("created output before rejecting aliases: %v", err)
				}
			})
		}
	}
}

func TestGCSPreflightSelection(t *testing.T) {
	useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[{"name":"source/A.txt","size":"7"},{"name":"source/a.txt","size":"7"}]}`)
	}))
	for _, dst := range []string{t.TempDir(), "gs://bucket/destination/"} {
		var emitted []string
		var exclude func(string) bool
		if !bbbfs.IsRemote(dst) {
			exclude = func(name string) bool { return name == "A.txt" }
		}
		err := listCopyEntries(t.Context(), "gs://bucket/source/", dst, nil, exclude, func(entry bbbfs.Entry) error {
			emitted = append(emitted, entry.Name)
			return nil
		})
		want := 2
		if exclude != nil {
			want = 1
		}
		if err != nil || len(emitted) != want {
			t.Fatalf("selection for %s: %v, %v", dst, emitted, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	stop := errors.New("stop emission")
	err := listCopyEntries(ctx, "gs://bucket/source/", "gs://bucket/destination/", nil, nil, func(bbbfs.Entry) error {
		cancel()
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("callback error was lost: %v", err)
	}
}
