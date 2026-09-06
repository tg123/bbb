package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tg123/bbb/internal/bbbfs"
)

func TestCopyConcurrency(t *testing.T) {
	for _, budget := range []int{1, 2, 3, 8, 32, 33} {
		files, blocks := copyConcurrency("gs://bucket/destination", budget)
		if files != budget || blocks != 1 {
			t.Errorf("GCS budget %d: files=%d blocks=%d", budget, files, blocks)
		}
		for _, dst := range []string{"az://account/container", "s3://bucket"} {
			files, blocks := copyConcurrency(dst, budget)
			wantFiles := min(budget, max(2, budget/4))
			if files != wantFiles || blocks != budget/wantFiles {
				t.Errorf("%s budget %d: files=%d blocks=%d", dst, budget, files, blocks)
			}
		}
	}
}

func TestGCSUsesFullFileConcurrency(t *testing.T) {
	const budget = 8
	local := t.TempDir()
	var localFiles, remoteFiles []string
	var objects []map[string]string
	for i := range budget {
		name := fmt.Sprintf("file-%d", i)
		localPath := filepath.Join(local, name)
		if err := os.WriteFile(localPath, []byte("payload"), 0o644); err != nil {
			t.Fatal(err)
		}
		localFiles = append(localFiles, localPath)
		remoteFiles = append(remoteFiles, "gs://bucket/source/"+name)
		objects = append(objects, map[string]string{"bucket": "bucket", "name": "source/" + name, "size": "7", "generation": "1"})
	}
	for _, remoteSource := range []bool{false, true} {
		src, files := local, localFiles
		if remoteSource {
			src, files = "gs://bucket/source/", remoteFiles
		}
		dst := "gs://bucket/destination/"
		runners := []struct {
			name string
			run  func(context.Context) error
		}{
			{"files", func(ctx context.Context) error {
				return cmdCPPaths(ctx, true, true, budget, 0, files, dst, 0, false, nil)
			}},
			{"tree", func(ctx context.Context) error {
				return copyTree(ctx, src, dst, true, true, "cp", budget, 0)
			}},
			{"sync", func(ctx context.Context) error {
				return cmdSyncPaths(ctx, false, false, true, "", budget, 0, src, dst)
			}},
			{"task-stream", func(ctx context.Context) error {
				return runCPTaskStream(ctx, func(emit func(taskPair) error) error {
					return emit(taskPair{src: src, dst: dst})
				}, true, true, budget, 0, "")
			}},
		}
		for _, runner := range runners {
			t.Run(fmt.Sprintf("%s/remote=%t", runner.name, remoteSource), func(t *testing.T) {
				var started atomic.Int64
				allStarted := make(chan struct{})
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodGet {
						if strings.HasSuffix(r.URL.Path, "/o") {
							if r.URL.Query().Get("prefix") == "source/" {
								_ = json.NewEncoder(w).Encode(map[string]any{"items": objects})
							} else {
								_, _ = io.WriteString(w, `{"items":[]}`)
							}
						} else if strings.Contains(r.URL.Path, "/o/destination/") {
							w.WriteHeader(http.StatusNotFound)
							_, _ = io.WriteString(w, `{"error":{"code":404,"message":"missing destination"}}`)
						} else {
							_ = json.NewEncoder(w).Encode(objects[0])
						}
						return
					}
					if r.Body != nil {
						if _, err := io.Copy(io.Discard, r.Body); err != nil {
							t.Errorf("read request: %v", err)
							return
						}
					}
					if started.Add(1) == budget {
						close(allStarted)
					}
					select {
					case <-allStarted:
					case <-r.Context().Done():
						w.WriteHeader(http.StatusRequestTimeout)
						return
					}
					if strings.Contains(r.URL.Path, "/rewriteTo/") {
						_ = json.NewEncoder(w).Encode(map[string]any{
							"done": true, "totalBytesRewritten": "7", "objectSize": "7", "resource": objects[0],
						})
					} else {
						_ = json.NewEncoder(w).Encode(objects[0])
					}
				}))
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				if err := runner.run(ctx); err != nil {
					t.Fatalf("only %d/%d transfers started: %v", started.Load(), budget, err)
				}
				if started.Load() != budget {
					t.Fatalf("started %d transfers, want %d", started.Load(), budget)
				}
			})
		}
	}
}

func TestGCSListingEmptySegment(t *testing.T) {
	useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch prefix := r.URL.Query().Get("prefix"); prefix {
		case "a/":
			_, _ = io.WriteString(w, `{"prefixes":["a//"]}`)
		case "a//":
			_, _ = io.WriteString(w, `{"items":[{"name":"a//file","size":"7"}]}`)
		default:
			t.Errorf("unexpected prefix %q", prefix)
		}
	}))
	fs := bbbfs.Resolve("gs://bucket/a/")
	entries, err := fs.List(t.Context(), "gs://bucket/a/")
	if err != nil || len(entries) != 1 {
		t.Fatalf("listing: %v, %v", entries, err)
	}
	if entries[0].Path != "gs://bucket/a//" || !entries[0].IsDir {
		t.Fatalf("lost empty segment: %+v", entries[0])
	}
	entries, err = fs.List(t.Context(), entries[0].Path)
	if err != nil || len(entries) != 1 || entries[0].Path != "gs://bucket/a//file" {
		t.Fatalf("nested listing: %v, %v", entries, err)
	}
}
