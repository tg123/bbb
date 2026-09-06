package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tg123/bbb/internal/bbbfs"
	"github.com/tg123/bbb/internal/gs"
)

func TestGCSOverlappingTreePrefixesRejected(t *testing.T) {
	pairs := []struct {
		name string
		src  string
		dst  string
	}{
		{"descendant", "gs://bucket/a/", "gs://bucket/a/backup/"},
		{"descendant-no-slashes", "gs://bucket/a", "gs://bucket/a/backup"},
		{"ancestor", "gs://bucket/a/backup/", "gs://bucket/a/"},
		{"same", "gs://bucket/a/", "gs://bucket/a/"},
		{"same-destination-alias", "gs://bucket/a/", "gs://bucket/a"},
		{"same-source-alias", "gs://bucket/a", "gs://bucket/a/"},
		{"source-root", "gs://bucket", "gs://bucket/a/"},
		{"destination-root", "gs://bucket/a/", "gs://bucket/"},
		{"root-alias", "gs://bucket/", "gs://bucket"},
		{"repeated-slash-descendant", "gs://bucket/a/", "gs://bucket/a//backup"},
		{"literal-dot-descendant", "gs://bucket/a/../b/", "gs://bucket/a/../b/backup/"},
	}
	for _, pair := range pairs {
		for _, mode := range []string{"tree", "cp", "expand", "task-stream", "sync", "sync-dry"} {
			t.Run(pair.name+"/"+mode, func(t *testing.T) {
				var stats, lists, operations atomic.Int64
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method != http.MethodGet || r.URL.Query().Get("alt") == "media":
						operations.Add(1)
					case strings.HasSuffix(r.URL.Path, "/o"):
						lists.Add(1)
					default:
						stats.Add(1)
					}
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, `{"error":{"code":404,"message":"no exact source object"}}`)
				}))
				emitted := 0
				var err error
				switch mode {
				case "tree":
					err = copyTree(t.Context(), pair.src, pair.dst, true, true, "cp", 4, 0)
				case "cp":
					err = cmdCPPaths(t.Context(), true, true, 4, 0, []string{pair.src}, pair.dst, 0, false, nil)
				case "expand":
					err = expandCPTask(t.Context(), taskPair{src: pair.src, dst: pair.dst}, func(cpTask) error {
						emitted++
						return nil
					})
				case "task-stream":
					err = runCPTaskStream(t.Context(), func(emit func(taskPair) error) error {
						return emit(taskPair{src: pair.src, dst: pair.dst})
					}, true, true, 4, 0, "")
				default:
					err = cmdSyncPaths(t.Context(), mode == "sync-dry", false, true, "", 4, 0, pair.src, pair.dst)
				}
				if err == nil || !strings.Contains(err.Error(), "overlapping GCS source and destination prefixes") {
					t.Fatalf("error = %v, want overlap rejection", err)
				}
				if emitted != 0 || lists.Load() != 0 || operations.Load() != 0 {
					t.Fatalf("work started before rejection: %d emitted, %d lists, %d operations", emitted, lists.Load(), operations.Load())
				}
				// Only the existing exact-object check for an ambiguous source
				// may run. Overlap validation must not add cloud requests.
				wantStats := int64(0)
				if !bbbfs.IsDirLikeFromPath(pair.src) && (mode == "cp" || mode == "expand" || mode == "task-stream") {
					wantStats = 1
				}
				if stats.Load() != wantStats {
					t.Fatalf("source metadata requests = %d, want %d", stats.Load(), wantStats)
				}
			})
		}
	}
}

func TestGCSDisjointTreePrefixesKeepStreaming(t *testing.T) {
	pairs := []struct {
		name string
		src  string
		dst  string
	}{
		{"siblings", "gs://bucket/a/", "gs://bucket/b/"},
		{"prefix-boundary", "gs://bucket/a", "gs://bucket/ab"},
		{"reverse-prefix-boundary", "gs://bucket/ab/", "gs://bucket/a/"},
		{"different-buckets", "gs://bucket/a/", "gs://other/a/backup/"},
		{"different-bucket-roots", "gs://bucket/", "gs://other"},
		{"literal-dot", "gs://bucket/a/../b/", "gs://bucket/b/"},
		{"literal-current-dot", "gs://bucket/a/./", "gs://bucket/a/b/"},
		{"repeated-slash", "gs://bucket/a//", "gs://bucket/a/b/"},
		{"leading-slash", "gs://bucket//", "gs://bucket/a/"},
		{"percent-encoding", "gs://bucket/a%2Fb/", "gs://bucket/a/b/"},
		{"backslash", `gs://bucket/a\b/`, "gs://bucket/a/b/"},
	}
	for _, pair := range pairs {
		t.Run(pair.name, func(t *testing.T) {
			source, err := gs.Parse(pair.src)
			if err != nil {
				t.Fatal(err)
			}
			var entries []bbbfs.Entry
			pages := 0
			useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/o") {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if got := r.URL.Query().Get("prefix"); got != source.WithDir().Object {
					t.Errorf("listing prefix = %q, want %q", got, source.WithDir().Object)
				}
				pages++
				name := "first"
				response := map[string]any{}
				if r.URL.Query().Get("pageToken") == "" {
					response["nextPageToken"] = "second"
				} else {
					name = "second"
					if len(entries) != 1 {
						t.Errorf("non-overlapping listing stopped streaming: %d entries before second page", len(entries))
					}
				}
				response["items"] = []map[string]string{{"name": source.WithDir().Object + name, "size": "7"}}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			}))
			err = listCopyEntries(t.Context(), pair.src, pair.dst, nil, nil, func(entry bbbfs.Entry) error {
				entries = append(entries, entry)
				return nil
			})
			if err != nil || pages != 2 || len(entries) != 2 {
				t.Fatalf("listing: %v, %d pages, entries = %#v", err, pages, entries)
			}
			for i, name := range []string{"first", "second"} {
				if entries[i].Name != name || entries[i].Path != source.Child(name).String() {
					t.Errorf("entry %d = %#v, want opaque source child %q", i, entries[i], source.Child(name).String())
				}
			}
		})
	}
}

func TestGCSOverlappingObjectCopyStillAllowed(t *testing.T) {
	for _, mode := range []string{"cp", "expand", "task-stream"} {
		t.Run(mode, func(t *testing.T) {
			var rewrites atomic.Int64
			src, dst := "gs://bucket/a", "gs://bucket/a/backup"
			useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.Contains(r.URL.Path, "/rewriteTo/") {
					rewrites.Add(1)
					_, _ = io.WriteString(w, `{"done":true,"totalBytesRewritten":"7","objectSize":"7","resource":{"bucket":"bucket","name":"a/backup","size":"7"}}`)
					return
				}
				if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/o/a") {
					_, _ = io.WriteString(w, `{"bucket":"bucket","name":"a","size":"7","generation":"1"}`)
					return
				}
				t.Errorf("unexpected request: %s %s", r.Method, r.URL)
				w.WriteHeader(http.StatusBadRequest)
			}))
			var err error
			switch mode {
			case "cp":
				err = cmdCPPaths(t.Context(), true, true, 4, 0, []string{src}, dst, 7, false, nil)
			case "expand":
				emitted := 0
				err = expandCPTask(t.Context(), taskPair{src: src, dst: dst}, func(task cpTask) error {
					emitted++
					if task.src != src || task.dst != dst {
						return fmt.Errorf("changed exact object task: %#v", task)
					}
					return nil
				})
				if emitted != 1 {
					t.Errorf("emitted = %d, want 1 exact object task", emitted)
				}
			case "task-stream":
				err = runCPTaskStream(t.Context(), func(emit func(taskPair) error) error {
					return emit(taskPair{src: src, dst: dst})
				}, true, true, 4, 0, "")
			}
			if err != nil {
				t.Fatalf("exact object copy: %v", err)
			}
			wantRewrites := int64(1)
			if mode == "expand" {
				wantRewrites = 0
			}
			if rewrites.Load() != wantRewrites {
				t.Fatalf("rewrites = %d, want %d", rewrites.Load(), wantRewrites)
			}
		})
	}
}
