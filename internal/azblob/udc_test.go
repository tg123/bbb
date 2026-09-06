package azblob

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type udcTestCredential string

func (c udcTestCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: string(c), ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestAccountRoleChangeDuringUDCRefresh(t *testing.T) {
	for _, change := range []string{"register", "clear"} {
		t.Run(change, func(t *testing.T) {
			const account = "udcrolechange"
			RegisterAccountRole(account, "DST")
			t.Cleanup(func() {
				ClearAccountRole(account)
				udcCacheMu.Lock()
				delete(udcCache, account)
				udcCacheMu.Unlock()
			})
			for _, role := range []string{"SRC", "DST"} {
				previous, loaded := roleCredCache.Swap(role, udcTestCredential(role))
				t.Cleanup(func() {
					if loaded {
						roleCredCache.Store(role, previous)
					} else {
						roleCredCache.Delete(role)
					}
				})
			}
			t.Setenv("BBB_AZBLOB_ENDPOINT", "https://%s.blob.core.windows.net/")
			previousTransport := sharedHTTPClient.Load()
			t.Cleanup(func() { sharedHTTPClient.Store(previousTransport) })

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			t.Cleanup(cancel)
			started := make(chan struct{})
			releaseCh := make(chan struct{})
			release := sync.OnceFunc(func() { close(releaseCh) })
			var calls atomic.Int64
			SetHTTPTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Query().Get("comp") != "userdelegationkey" {
					return nil, fmt.Errorf("unexpected request: %s", req.URL)
				}
				role := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
				if calls.Add(1) == 1 {
					close(started)
					select {
					case <-releaseCh:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
				}
				body := fmt.Sprintf(`<UserDelegationKey>
<SignedOid>%s</SignedOid><SignedTid>tenant</SignedTid>
<SignedStart>%s</SignedStart><SignedExpiry>%s</SignedExpiry>
<SignedService>b</SignedService><SignedVersion>2023-11-03</SignedVersion>
<Value>dGVzdGtleQ==</Value></UserDelegationKey>`,
					role, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
				return &http.Response{
					StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/xml"}},
					Body: io.NopCloser(strings.NewReader(body)), Request: req,
				}, nil
			}))

			path := AzurePath{Account: account, Container: "c", Blob: "test.txt"}
			var oldURL string
			var oldErr error
			done := make(chan struct{})
			go func() {
				defer close(done)
				oldURL, oldErr = blobDelegationSASURL(ctx, path)
			}()
			t.Cleanup(func() {
				release()
				cancel()
				<-done
			})
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("initial delegation refresh did not start")
			}
			if change == "register" {
				RegisterAccountRole(account, "SRC")
			} else {
				ClearAccountRole(account)
			}

			assertSRC := func(signedURL string, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("generate delegation SAS: %v", err)
				}
				parsed, err := url.Parse(signedURL)
				if err != nil {
					t.Fatalf("parse SAS: %v", err)
				}
				if got := parsed.Query().Get("skoid"); got != "SRC" {
					t.Fatalf("delegation credential belongs to %q, want SRC", got)
				}
			}
			// The new role must authenticate without waiting for the old request.
			assertSRC(blobDelegationSASURL(ctx, path))
			release()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("stale refresh did not finish")
			}
			assertSRC(oldURL, oldErr)
			assertSRC(blobDelegationSASURL(ctx, path))
			if got := calls.Load(); got != 2 {
				t.Fatalf("delegation requests = %d, want 2 (one per role)", got)
			}
		})
	}
}
