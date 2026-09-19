package gs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/api/googleapi"
)

func TestDeletePrefixStopsScheduling(t *testing.T) {
	for _, cancelRequest := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%t", cancelRequest), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var deletes atomic.Int64
			var pages atomic.Int64
			full := make(chan struct{})
			useTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					pages.Add(1)
					objects := make([]map[string]string, 4*deleteConcurrency)
					for i := range objects {
						objects[i] = map[string]string{"name": fmt.Sprintf("prefix/object-%d", i)}
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"items": objects, "nextPageToken": "more"})
					return
				}
				request := deletes.Add(1)
				if request == deleteConcurrency {
					close(full)
				}
				select {
				case <-full:
				case <-r.Context().Done():
					return
				}
				if request == 1 {
					if cancelRequest {
						cancel()
					} else {
						w.WriteHeader(http.StatusForbidden)
						return
					}
				}
				<-r.Context().Done()
			})
			err := DeletePrefix(ctx, GSPath{Bucket: "b", Object: "prefix/"})
			if cancelRequest {
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("error = %v, want cancellation", err)
				}
			} else {
				var apiErr *googleapi.Error
				if !errors.As(err, &apiErr) || apiErr.Code != http.StatusForbidden {
					t.Fatalf("error = %v, want first delete failure", err)
				}
			}
			if deletes.Load() != deleteConcurrency || pages.Load() != 1 {
				t.Fatalf("continued after cancellation: %d deletes, %d pages", deletes.Load(), pages.Load())
			}
		})
	}
}
