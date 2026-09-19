package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/api/googleapi"
)

func TestGCSRewriteFailureRetriesWithoutStreaming(t *testing.T) {
	t.Setenv("BBB_AZBLOB_FORCE_S2S", "false")
	t.Setenv("BBB_RETRY_JITTER", "0")
	for _, status := range []int{http.StatusForbidden, http.StatusConflict} {
		for _, overwrite := range []bool{false, true} {
			for _, progress := range []bool{false, true} {
				t.Run(fmt.Sprintf("status=%d/overwrite=%t/progress=%t", status, overwrite, progress), func(t *testing.T) {
					var rewrites, media, uploads, destinationStats, progressBytes atomic.Int64
					useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Content-Type", "application/json")
						switch {
						case strings.Contains(r.URL.Path, "/rewriteTo/"):
							rewrites.Add(1)
							if r.URL.Query().Get("rewriteToken") == "" {
								_, _ = io.WriteString(w, `{"done":false,"totalBytesRewritten":"3","objectSize":"7","rewriteToken":"continue"}`)
								return
							}
							if token := r.URL.Query().Get("rewriteToken"); token != "continue" {
								t.Errorf("rewrite token = %q, want continue", token)
							}
							w.WriteHeader(status)
							_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"rewrite failed after progress"}}`, status)
						case r.Method != http.MethodGet:
							uploads.Add(1)
							w.WriteHeader(http.StatusBadRequest)
							_, _ = io.WriteString(w, `{"error":{"code":400,"message":"unexpected client upload"}}`)
						case r.URL.Query().Get("alt") == "media" || strings.HasPrefix(r.URL.Path, "/bucket/"):
							media.Add(1)
							w.Header().Set("Content-Length", "7")
							_, _ = io.WriteString(w, "payload")
						case strings.HasSuffix(r.URL.Path, "/o/destination"):
							destinationStats.Add(1)
							w.WriteHeader(http.StatusNotFound)
							_, _ = io.WriteString(w, `{"error":{"code":404,"message":"destination absent"}}`)
						case strings.HasSuffix(r.URL.Path, "/o/source"):
							_, _ = io.WriteString(w, `{"name":"source","size":"7","generation":"1"}`)
						default:
							t.Errorf("unexpected request: %s %s", r.Method, r.URL)
							w.WriteHeader(http.StatusBadRequest)
						}
					}))
					var onBytes func(int64)
					if progress {
						onBytes = func(n int64) { progressBytes.Add(n) }
					}
					err := cmdCPPaths(t.Context(), overwrite, !progress, 4, 2,
						[]string{"gs://bucket/source"}, "gs://other-bucket/destination", 0, progress, onBytes)
					var apiErr *googleapi.Error
					if !errors.As(err, &apiErr) || apiErr.Code != status ||
						!strings.Contains(err.Error(), "rewrite failed after progress") {
						t.Fatalf("copy error = %v, want original rewrite failure with status %d", err, status)
					}
					attempts := int64(1)
					// Conflict bypasses SDK retries but exercises bbb's normal retry loop.
					if status == http.StatusConflict {
						attempts = 3
					}
					if rewrites.Load() != 2*attempts || media.Load() != 0 || uploads.Load() != 0 {
						t.Fatalf("rewrites=%d reads=%d uploads=%d, want %d rewrites and no streaming",
							rewrites.Load(), media.Load(), uploads.Load(), 2*attempts)
					}
					wantDestinationStats := attempts
					if overwrite {
						wantDestinationStats = 0
					}
					if destinationStats.Load() != wantDestinationStats {
						t.Errorf("destination checks = %d, want %d", destinationStats.Load(), wantDestinationStats)
					}
					if progress && progressBytes.Load() == 0 {
						t.Error("rewrite progress was not reported before failure")
					}
				})
			}
		}
	}
}
