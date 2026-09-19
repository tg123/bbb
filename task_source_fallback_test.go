package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/tg123/bbb/internal/bbbfs"
	"google.golang.org/api/googleapi"
)

func TestMissingSourceFallbackPreservesErrorIdentity(t *testing.T) {
	useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	src := "gs://bucket/missing"
	sourceErr := &os.PathError{Op: "stat", Path: src, Err: os.ErrNotExist}
	for _, dst := range []string{".", "gs://bucket/destination/"} {
		t.Run(dst, func(t *testing.T) {
			err := listCopyEntries(t.Context(), src, dst, sourceErr, nil, func(bbbfs.Entry) error {
				t.Error("missing source emitted an entry")
				return nil
			})
			if err != sourceErr {
				t.Fatalf("fallback error = %v, want identical source error %v", err, sourceErr)
			}
		})
	}
}

func TestMissingSourceFallbackListingFailure(t *testing.T) {
	for _, dst := range []string{".", "gs://bucket/destination/"} {
		for _, hasFirstPage := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/first-page=%t", dst, hasFirstPage), func(t *testing.T) {
				useGSIntegrationHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					if !strings.HasSuffix(r.URL.Path, "/o") {
						w.WriteHeader(http.StatusNotFound)
						_, _ = io.WriteString(w, `{"error":{"code":404,"message":"original stat failure"}}`)
						return
					}
					if hasFirstPage && r.URL.Query().Get("pageToken") == "" {
						_, _ = io.WriteString(w, `{"items":[{"name":"missing/child","size":"7"}],"nextPageToken":"second"}`)
						return
					}
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `{"error":{"code":403,"message":"fallback listing denied"}}`)
				}))
				var tasks []cpTask
				err := expandCPTask(t.Context(), taskPair{src: "gs://bucket/missing", dst: dst}, func(task cpTask) error {
					tasks = append(tasks, task)
					return nil
				})
				var apiErr *googleapi.Error
				if !errors.As(err, &apiErr) || apiErr.Code != http.StatusForbidden || apiErr.Message != "fallback listing denied" {
					t.Fatalf("expansion error = %v, want fallback listing failure", err)
				}
				if errors.Is(err, os.ErrNotExist) {
					t.Fatalf("listing failure was replaced by original Stat error: %v", err)
				}
				wantTasks := 0
				if hasFirstPage && bbbfs.IsRemote(dst) {
					wantTasks = 1
				}
				if len(tasks) != wantTasks {
					t.Fatalf("emitted %d tasks, want %d", len(tasks), wantTasks)
				}
				if len(tasks) != 0 && tasks[0].src != "gs://bucket/missing/child" {
					t.Fatalf("unexpected source task: %#v", tasks[0])
				}
			})
		}
	}
}
