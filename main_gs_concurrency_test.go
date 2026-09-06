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
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tg123/bbb/internal/bbbfs"
	"golang.org/x/sync/semaphore"
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

func TestGCSTaskStreamSharesExpansionBudget(t *testing.T) {
	const budget = 8
	for _, expansion := range []string{"page", "metadata"} {
		t.Run(expansion, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var active, peak, transfers atomic.Int64
				expansionStarted := make(chan struct{})
				var expansionOnce sync.Once
				finishExpansion := make(chan struct{})
				finishTransfers := make(chan struct{})
				var objects []map[string]string
				for i := range budget - 1 {
					objects = append(objects, map[string]string{
						"bucket": "bucket", "name": fmt.Sprintf("source/file-%d", i), "size": "7", "generation": "1",
					})
				}
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := active.Add(1)
					defer active.Add(-1)
					for old := peak.Load(); old < n && !peak.CompareAndSwap(old, n); old = peak.Load() {
					}
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodGet {
						isList := strings.HasSuffix(r.URL.Path, "/o")
						if isList && r.URL.Query().Get("pageToken") == "" {
							response := map[string]any{"items": objects}
							if expansion == "page" {
								response["nextPageToken"] = "next"
							}
							_ = json.NewEncoder(w).Encode(response)
							return
						}
						if isList || strings.HasSuffix(r.URL.Path, "/o/probe") {
							expansionOnce.Do(func() { close(expansionStarted) })
							select {
							case <-finishExpansion:
							case <-r.Context().Done():
								return
							}
							if isList {
								_, _ = io.WriteString(w, `{"items":[]}`)
							} else {
								_ = json.NewEncoder(w).Encode(objects[0])
							}
							return
						}
						_ = json.NewEncoder(w).Encode(objects[0])
						return
					}
					if r.Body != nil {
						_, _ = io.Copy(io.Discard, r.Body)
					}
					transfers.Add(1)
					select {
					case <-finishTransfers:
					case <-r.Context().Done():
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"done": true, "totalBytesRewritten": "7", "objectSize": "7", "resource": objects[0],
					})
				}))
				errCh := make(chan error, 1)
				go func() {
					errCh <- runCPTaskStream(ctx, func(emit func(taskPair) error) error {
						if err := emit(taskPair{src: "gs://bucket/source/", dst: "gs://bucket/destination/"}); err != nil {
							return err
						}
						if expansion == "metadata" {
							if err := emit(taskPair{src: "gs://bucket/probe", dst: "gs://bucket/probed"}); err != nil {
								return err
							}
						}
						<-expansionStarted
						return emit(taskPair{src: "gs://bucket/extra", dst: "gs://bucket/extra-copy"})
					}, true, true, budget, 0, "")
				}()
				synctest.Wait()
				if got := transfers.Load(); got != budget-1 {
					t.Errorf("transfers while expansion is active = %d, want %d", got, budget-1)
				}
				if got := peak.Load(); got > budget {
					t.Errorf("aggregate request peak = %d, exceeds budget %d", got, budget)
				}
				close(finishExpansion)
				synctest.Wait()
				if got := active.Load(); got != budget {
					t.Errorf("transfers after expansion finishes = %d, want %d", got, budget)
				}
				close(finishTransfers)
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
				if got := peak.Load(); got > budget {
					t.Errorf("aggregate request peak = %d, exceeds budget %d", got, budget)
				}
			})
		})
	}
}

func TestGCSTaskStreamSingleSlotBackpressure(t *testing.T) {
	const count = 4096 + 2
	for _, outcome := range []string{"complete", "cancel", "failure"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var transfers atomic.Int64
				finishTransfers := make(chan struct{})
				var objects []map[string]string
				for i := range count {
					objects = append(objects, map[string]string{
						"bucket": "bucket", "name": fmt.Sprintf("source/file-%d", i), "size": "7", "generation": "1",
					})
				}
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if r.Method == http.MethodGet {
						if strings.HasSuffix(r.URL.Path, "/o") {
							_ = json.NewEncoder(w).Encode(map[string]any{"items": objects})
						} else {
							_ = json.NewEncoder(w).Encode(objects[0])
						}
						return
					}
					transfers.Add(1)
					select {
					case <-finishTransfers:
					case <-r.Context().Done():
						return
					}
					if outcome == "failure" {
						w.WriteHeader(http.StatusForbidden)
						_, _ = io.WriteString(w, `{"error":{"code":403,"message":"transfer failed"}}`)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"done": true, "totalBytesRewritten": "7", "objectSize": "7", "resource": objects[0],
					})
				}))
				errCh := make(chan error, 1)
				go func() {
					errCh <- runCPTaskStream(ctx, func(emit func(taskPair) error) error {
						return emit(taskPair{src: "gs://bucket/source/", dst: "gs://bucket/destination/"})
					}, true, true, 1, 0, "")
				}()
				synctest.Wait()
				if got := transfers.Load(); got != 1 {
					t.Errorf("transfers at backpressure = %d, want 1", got)
				}
				if outcome == "cancel" {
					cancel()
				} else {
					close(finishTransfers)
				}
				err := <-errCh
				switch outcome {
				case "complete":
					if err != nil || transfers.Load() != count {
						t.Fatalf("completed %d/%d transfers: %v", transfers.Load(), count, err)
					}
				case "cancel":
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("error = %v, want cancellation", err)
					}
				case "failure":
					if err == nil || !strings.Contains(err.Error(), "transfer failed") {
						t.Fatalf("error = %v, want transfer failure", err)
					}
				}
			})
		})
	}
}

func TestCPExpansionBudgetYieldsToBlockedEmitter(t *testing.T) {
	for _, outcome := range []string{"complete", "emit-error", "cancel-reacquire"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				slots := semaphore.NewWeighted(1)
				pending := make(chan cpTask, 1)
				pending <- cpTask{}
				emitErr := errors.New("emit failed")
				errCh := make(chan error, 1)
				go func() {
					errCh <- expandCPTaskWithBudget(ctx, taskPair{src: "missing", dst: "unused"}, slots, func(task cpTask) error {
						pending <- task
						if outcome == "emit-error" {
							return emitErr
						}
						return nil
					})
				}()
				synctest.Wait()
				if !slots.TryAcquire(1) {
					t.Fatal("expansion retained the only slot while blocked on a full channel")
				}
				<-pending
				synctest.Wait()
				if outcome == "cancel-reacquire" {
					cancel()
				} else {
					slots.Release(1)
				}
				err := <-errCh
				switch outcome {
				case "complete":
					if err != nil {
						t.Fatal(err)
					}
				case "emit-error":
					if !errors.Is(err, emitErr) {
						t.Fatalf("error = %v, want emitter error", err)
					}
				case "cancel-reacquire":
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("error = %v, want cancellation", err)
					}
					slots.Release(1)
				}
				if !slots.TryAcquire(1) {
					t.Fatal("expansion leaked its slot")
				}
				slots.Release(1)
			})
		})
	}
}

func TestGCSTaskStreamMixedTransferWeights(t *testing.T) {
	const budget = 8
	local := t.TempDir()
	src, dst := filepath.Join(local, "source"), filepath.Join(local, "destination")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		finishTransfers := make(chan struct{})
		emitLocal := make(chan struct{})
		var transfers atomic.Int64
		useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			object := map[string]string{"bucket": "bucket", "name": "source", "size": "7", "generation": "1"}
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(object)
				return
			}
			transfers.Add(1)
			<-finishTransfers
			_ = json.NewEncoder(w).Encode(map[string]any{
				"done": true, "totalBytesRewritten": "7", "objectSize": "7", "resource": object,
			})
		}))
		errCh := make(chan error, 1)
		go func() {
			errCh <- runCPTaskStream(t.Context(), func(emit func(taskPair) error) error {
				for i := range budget {
					if err := emit(taskPair{src: "gs://bucket/source", dst: fmt.Sprintf("gs://bucket/copy-%d", i)}); err != nil {
						return err
					}
				}
				<-emitLocal
				return emit(taskPair{src: src, dst: dst})
			}, true, true, budget, 0, "")
		}()
		synctest.Wait()
		if got := transfers.Load(); got != budget {
			t.Errorf("active GCS transfers = %d, want %d", got, budget)
		}
		close(emitLocal)
		synctest.Wait()
		close(finishTransfers)
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(dst); err != nil || string(data) != "payload" {
			t.Fatalf("weighted non-GCS task did not complete: %q, %v", data, err)
		}
	})
}

func TestGCSTaskStreamCheckpointsCopiesFinishedDuringExpansion(t *testing.T) {
	for _, retryListing := range []bool{false, true} {
		t.Run(fmt.Sprintf("retry=%t", retryListing), func(t *testing.T) {
			stateFile := filepath.Join(t.TempDir(), "tasks.state")
			synctest.Test(t, func(t *testing.T) {
				finishListing := make(chan struct{})
				var secondPages, transfers atomic.Int64
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					object := map[string]string{"bucket": "bucket", "name": "source/file", "size": "7", "generation": "1"}
					if r.Method == http.MethodGet {
						if strings.HasSuffix(r.URL.Path, "/o") {
							if r.URL.Query().Get("pageToken") == "" {
								_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{object}, "nextPageToken": "next"})
							} else {
								attempt := secondPages.Add(1)
								<-finishListing
								if retryListing && attempt == 1 {
									_, _ = io.WriteString(w, `{`)
								} else {
									_, _ = io.WriteString(w, `{"items":[]}`)
								}
							}
						} else {
							_ = json.NewEncoder(w).Encode(object)
						}
						return
					}
					transfers.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"done": true, "totalBytesRewritten": "7", "objectSize": "7", "resource": object,
					})
				}))
				errCh := make(chan error, 1)
				pair := taskPair{src: "gs://bucket/source/", dst: "gs://bucket/destination/"}
				go func() {
					errCh <- runCPTaskStream(t.Context(), func(emit func(taskPair) error) error {
						return emit(pair)
					}, true, true, 2, 1, stateFile)
				}()
				synctest.Wait()
				if got := transfers.Load(); got != 1 {
					t.Errorf("copies finished before listing = %d, want 1", got)
				}
				close(finishListing)
				if err := <-errCh; err != nil {
					t.Fatal(err)
				}
				state, checkpoints, err := loadTaskState(stateFile)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := checkpoints[taskCheckpointKey(pair.src, pair.dst)]; !ok {
					t.Errorf("missing completed task checkpoint: %v", checkpoints)
				}
				if len(state) != 1 || transfers.Load() != 1 {
					t.Errorf("copied or checkpointed files more than once: state=%v, transfers=%d", state, transfers.Load())
				}
				if retryListing && secondPages.Load() != 2 {
					t.Errorf("listing attempts = %d, want 2", secondPages.Load())
				}
			})
		})
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
