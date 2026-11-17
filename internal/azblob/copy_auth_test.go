package azblob

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type copyTokenCredentialFunc func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error)

func (f copyTokenCredentialFunc) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return f(ctx, opts)
}

func setupCopyAuthTest(t *testing.T, credential azcore.TokenCredential, transport roundTripFunc) (AzurePath, AzurePath) {
	t.Helper()
	src := AzurePath{Account: "copyauthsrc", Container: "models", Blob: "dir/blob name"}
	dst := AzurePath{Account: "copyauthdst", Container: "models", Blob: "copy"}
	for _, ap := range []AzurePath{src, dst} {
		ClearAccountRole(ap.Account)
		t.Cleanup(func() { ClearAccountRole(ap.Account) })
	}
	RegisterAccountRole(src.Account, "SRC")
	RegisterAccountRole(dst.Account, "DST")
	for role, cred := range map[string]azcore.TokenCredential{"SRC": credential, "DST": udcTestCredential("destination")} {
		previous, loaded := roleCredCache.Swap(role, cred)
		t.Cleanup(func() {
			if loaded {
				roleCredCache.Store(role, previous)
			} else {
				roleCredCache.Delete(role)
			}
		})
	}
	t.Setenv("BBB_AZBLOB_ENDPOINT", "https://%s.blob.core.windows.net")
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "")
	t.Setenv("SRC_BBB_AZBLOB_ACCOUNTKEY", "")
	t.Setenv("DST_BBB_AZBLOB_ACCOUNTKEY", "")
	t.Setenv(copyBlockSizeEnv, "1")
	t.Setenv(copyMaxConcurrencyEnv, "1")
	previous := sharedHTTPClient.Load()
	t.Cleanup(func() { sharedHTTPClient.Store(previous) })
	SetHTTPTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Generated SDK requests use lower-case map keys; normalize like an
		// HTTP server would before inspecting headers in the fake transport.
		headers := make(http.Header)
		for name, values := range req.Header {
			for _, value := range values {
				headers.Add(name, value)
			}
		}
		req.Header = headers
		return transport(req)
	}))
	return src, dst
}

func copyAuthResponse(req *http.Request, status int, code, sourceStatus string) *http.Response {
	header := http.Header{}
	body := ""
	if code != "" {
		header.Set("x-ms-error-code", code)
		body = fmt.Sprintf(`<Error><Code>%s</Code><CopySourceStatusCode>%s</CopySourceStatusCode><CopySourceErrorCode>InvalidAuthenticationInfo</CopySourceErrorCode></Error>`, code, sourceStatus)
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestCopySourceAuthRefreshAcrossBlocksAndSDKRetries(t *testing.T) {
	for _, sdkRetry := range []bool{false, true} {
		t.Run(fmt.Sprintf("sdkRetry=%t", sdkRetry), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var acquisitions, stages, commits atomic.Int64
				credential := copyTokenCredentialFunc(func(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
					if len(opts.Scopes) != 1 || opts.Scopes[0] != "https://storage.azure.com/.default" {
						return azcore.AccessToken{}, errors.New("unexpected token scope")
					}
					return azcore.AccessToken{
						Token: fmt.Sprintf("source-%d", acquisitions.Add(1)), ExpiresOn: time.Now().Add(time.Minute),
					}, nil
				})
				var firstBlock string
				src, dst := setupCopyAuthTest(t, credential, func(req *http.Request) (*http.Response, error) {
					if req.Header.Get("Authorization") != "Bearer destination" {
						return nil, errors.New("destination authentication changed")
					}
					switch req.URL.Query().Get("comp") {
					case "block":
						n := stages.Add(1)
						want := "Bearer source-2"
						if n == 1 || (sdkRetry && n == 2) {
							want = "Bearer source-1"
						}
						if got := req.Header.Get("x-ms-copy-source-authorization"); got != want {
							return nil, fmt.Errorf("stage %d source auth = %q, want %q", n, got, want)
						}
						if req.Header.Get("x-ms-copy-source") != "https://copyauthsrc.blob.core.windows.net/models/dir/blob%20name" {
							return nil, errors.New("source URL changed")
						}
						if n == 1 {
							firstBlock = req.URL.RawQuery
							time.Sleep(2 * time.Minute)
							if sdkRetry {
								return copyAuthResponse(req, 503, "ServerBusy", ""), nil
							}
						}
						if sdkRetry && n <= 3 && req.URL.RawQuery != firstBlock {
							return nil, errors.New("auth recovery changed the block ID")
						}
						if sdkRetry && n == 2 {
							return copyAuthResponse(req, 401, "CannotVerifyCopySource", "401"), nil
						}
						return copyAuthResponse(req, 201, "", ""), nil
					case "blocklist":
						commits.Add(1)
						if req.Header.Get("x-ms-copy-source-authorization") != "" {
							return nil, errors.New("source token leaked to block commit")
						}
						return copyAuthResponse(req, 201, "", ""), nil
					default:
						return nil, fmt.Errorf("unexpected request: %s", req.URL)
					}
				})
				if err := CopyBlobServerSide(context.Background(), src, dst, 1, 4<<20, nil); err != nil {
					t.Fatal(err)
				}
				wantStages := int64(4)
				if sdkRetry {
					wantStages += 2
				}
				if acquisitions.Load() != 2 || stages.Load() != wantStages || commits.Load() != 1 {
					t.Fatalf("acquisitions/stages/commits = %d/%d/%d", acquisitions.Load(), stages.Load(), commits.Load())
				}
			})
		})
	}
}

func TestCopySourceAuthRecoveryIsBounded(t *testing.T) {
	refreshFailure := errors.New("source refresh failed")
	for _, tc := range []struct {
		name                    string
		code, sourceStatus      string
		unchanged, alwaysReject bool
		refreshErr              error
		wantStages, wantTokens  int64
		wantSuccess             bool
	}{
		{name: "renewed", code: "CannotVerifyCopySource", sourceStatus: "401", wantStages: 2, wantTokens: 2, wantSuccess: true},
		{name: "same token", code: "CannotVerifyCopySource", sourceStatus: "401", unchanged: true, wantStages: 1, wantTokens: 2},
		{name: "permanent rejection", code: "CannotVerifyCopySource", sourceStatus: "401", alwaysReject: true, wantStages: 2, wantTokens: 2},
		{name: "refresh error", code: "CannotVerifyCopySource", sourceStatus: "401", refreshErr: refreshFailure, wantStages: 1, wantTokens: 2},
		{name: "destination auth", code: "InvalidAuthenticationInfo", sourceStatus: "401", wantStages: 1, wantTokens: 1},
		{name: "source forbidden", code: "CannotVerifyCopySource", sourceStatus: "403", wantStages: 1, wantTokens: 1},
		{name: "missing source status", code: "CannotVerifyCopySource", wantStages: 1, wantTokens: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var acquisitions, stages, commits atomic.Int64
			credential := copyTokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
				n := acquisitions.Add(1)
				if n > 1 && tc.refreshErr != nil {
					return azcore.AccessToken{}, tc.refreshErr
				}
				if tc.unchanged {
					n = 1
				}
				return azcore.AccessToken{Token: fmt.Sprintf("source-%d", n), ExpiresOn: time.Now().Add(time.Hour)}, nil
			})
			src, dst := setupCopyAuthTest(t, credential, func(req *http.Request) (*http.Response, error) {
				switch req.URL.Query().Get("comp") {
				case "block":
					n := stages.Add(1)
					if n == 1 || tc.alwaysReject {
						return copyAuthResponse(req, 401, tc.code, tc.sourceStatus), nil
					}
					if req.Header.Get("x-ms-copy-source-authorization") != "Bearer source-2" {
						return nil, errors.New("retry didn't renew source auth")
					}
					return copyAuthResponse(req, 201, "", ""), nil
				case "blocklist":
					commits.Add(1)
					return copyAuthResponse(req, 201, "", ""), nil
				default:
					return nil, fmt.Errorf("unexpected request: %s", req.URL)
				}
			})
			err := CopyBlobServerSide(context.Background(), src, dst, 1, 1, nil)
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("success = %v, error = %v", tc.wantSuccess, err)
			}
			if tc.refreshErr != nil && !errors.Is(err, tc.refreshErr) {
				t.Fatalf("missing refresh error: %v", err)
			}
			if !tc.wantSuccess {
				var responseErr *azcore.ResponseError
				if !errors.As(err, &responseErr) || responseErr.StatusCode != 401 {
					t.Fatalf("original 401 was not preserved: %v", err)
				}
			}
			if acquisitions.Load() != tc.wantTokens || stages.Load() != tc.wantStages {
				t.Fatalf("acquisitions/stages = %d/%d, want %d/%d", acquisitions.Load(), stages.Load(), tc.wantTokens, tc.wantStages)
			}
			if (commits.Load() == 1) != tc.wantSuccess {
				t.Fatalf("unexpected commits: %d", commits.Load())
			}
		})
	}
}

func TestCopySourceAuthConcurrentRecovery(t *testing.T) {
	const blocks = 32
	var acquisitions, rejected, completed atomic.Int64
	credential := copyTokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		return azcore.AccessToken{
			Token: fmt.Sprintf("source-%d", acquisitions.Add(1)), ExpiresOn: time.Now().Add(time.Hour),
		}, nil
	})
	allStarted := make(chan struct{})
	src, dst := setupCopyAuthTest(t, credential, func(req *http.Request) (*http.Response, error) {
		if req.URL.Query().Get("comp") == "block" {
			if req.Header.Get("x-ms-copy-source-authorization") == "Bearer source-1" {
				if rejected.Add(1) == blocks {
					close(allStarted)
				}
				select {
				case <-allStarted:
				case <-req.Context().Done():
					return nil, req.Context().Err()
				}
				return copyAuthResponse(req, 401, "CannotVerifyCopySource", "401"), nil
			}
			completed.Add(1)
		}
		return copyAuthResponse(req, 201, "", ""), nil
	})
	t.Setenv(copyMaxConcurrencyEnv, fmt.Sprint(blocks))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := CopyBlobServerSide(ctx, src, dst, blocks, blocks<<20, nil); err != nil {
		t.Fatal(err)
	}
	if acquisitions.Load() != 2 || completed.Load() != blocks {
		t.Fatalf("acquisitions/completed = %d/%d, want 2/%d", acquisitions.Load(), completed.Load(), blocks)
	}
}

func TestCopySourceAuthRefreshFailureStopsBeforeNextBlock(t *testing.T) {
	for _, invalidToken := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalidToken=%t", invalidToken), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				refreshFailure := errors.New("source credential unavailable")
				var acquisitions, stages, commits atomic.Int64
				credential := copyTokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
					if acquisitions.Add(1) > 1 {
						if invalidToken {
							return azcore.AccessToken{Token: "expired", ExpiresOn: time.Now().Add(-time.Minute)}, nil
						}
						return azcore.AccessToken{}, refreshFailure
					}
					return azcore.AccessToken{Token: "source", ExpiresOn: time.Now().Add(time.Minute)}, nil
				})
				src, dst := setupCopyAuthTest(t, credential, func(req *http.Request) (*http.Response, error) {
					if req.URL.Query().Get("comp") == "block" {
						stages.Add(1)
						time.Sleep(2 * time.Minute)
					} else {
						commits.Add(1)
					}
					return copyAuthResponse(req, 201, "", ""), nil
				})
				err := CopyBlobServerSide(context.Background(), src, dst, 1, 2<<20, nil)
				if err == nil || (!invalidToken && !errors.Is(err, refreshFailure)) {
					t.Fatalf("missing refresh failure: %v", err)
				}
				if acquisitions.Load() != 2 || stages.Load() != 1 || commits.Load() != 0 {
					t.Fatalf("acquisitions/stages/commits = %d/%d/%d", acquisitions.Load(), stages.Load(), commits.Load())
				}
			})
		})
	}
}

func TestCopySourceAuthLeavesSASPathsUnchanged(t *testing.T) {
	for _, sharedKeySource := range []bool{false, true} {
		t.Run(fmt.Sprintf("sharedKeySource=%t", sharedKeySource), func(t *testing.T) {
			var acquisitions, stages atomic.Int64
			credential := copyTokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
				acquisitions.Add(1)
				return azcore.AccessToken{}, errors.New("unexpected OAuth acquisition")
			})
			const signedURL = "https://source.example/blob?sig=test"
			src, dst := setupCopyAuthTest(t, credential, func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("x-ms-copy-source-authorization") != "" {
					return nil, errors.New("unexpected source OAuth header on SAS path")
				}
				if req.URL.Query().Get("comp") == "block" {
					stages.Add(1)
					sourceURL := req.Header.Get("x-ms-copy-source")
					if sharedKeySource {
						if !strings.Contains(sourceURL, "sig=") {
							return nil, errors.New("missing source SAS signature")
						}
					} else if sourceURL != signedURL {
						return nil, errors.New("signed source URL changed")
					}
				}
				return copyAuthResponse(req, 201, "", ""), nil
			})
			var err error
			if sharedKeySource {
				t.Setenv("SRC_BBB_AZBLOB_ACCOUNTKEY", "dGVzdGtleQ==")
				err = CopyBlobServerSide(context.Background(), src, dst, 1, 1, nil)
			} else {
				err = CopyBlobFromURLServerSide(context.Background(), dst, signedURL, 1, 1, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if acquisitions.Load() != 0 || stages.Load() != 1 {
				t.Fatalf("acquisitions/stages = %d/%d, want 0/1", acquisitions.Load(), stages.Load())
			}
		})
	}
}

func TestCopySourceAuthWithSharedKeyDestination(t *testing.T) {
	var acquisitions, stages atomic.Int64
	credential := copyTokenCredentialFunc(func(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
		return azcore.AccessToken{
			Token: fmt.Sprintf("source-%d", acquisitions.Add(1)), ExpiresOn: time.Now().Add(time.Hour),
		}, nil
	})
	src, dst := setupCopyAuthTest(t, credential, func(req *http.Request) (*http.Response, error) {
		// Independently verify the wire signature includes the current source
		// header, both before and after renewal.
		var canonicalHeaders []string
		for name := range req.Header {
			name = strings.ToLower(name)
			if strings.HasPrefix(name, "x-ms-") {
				canonicalHeaders = append(canonicalHeaders, name)
			}
		}
		sort.Strings(canonicalHeaders)
		for i, name := range canonicalHeaders {
			canonicalHeaders[i] = name + ":" + strings.Join(req.Header.Values(name), ",")
		}
		resource := "/copyauthdst" + req.URL.EscapedPath()
		var query []string
		for name, values := range req.URL.Query() {
			sort.Strings(values)
			query = append(query, strings.ToLower(name)+":"+strings.Join(values, ","))
		}
		sort.Strings(query)
		resource += "\n" + strings.Join(query, "\n")
		length := req.Header.Get("Content-Length")
		if length == "0" {
			length = ""
		}
		signature := strings.Join([]string{
			req.Method, "", "", length, "", req.Header.Get("Content-Type"), "", "", "", "", "", "",
			strings.Join(canonicalHeaders, "\n") + "\n" + resource,
		}, "\n")
		mac := hmac.New(sha256.New, []byte("testkey"))
		_, _ = mac.Write([]byte(signature))
		want := "SharedKey copyauthdst:" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if req.Header.Get("Authorization") != want {
			return nil, errors.New("destination signature does not cover the source header")
		}
		if req.URL.Query().Get("comp") == "block" && stages.Add(1) == 1 {
			return copyAuthResponse(req, 401, "CannotVerifyCopySource", "401"), nil
		}
		return copyAuthResponse(req, 201, "", ""), nil
	})
	t.Setenv("DST_BBB_AZBLOB_ACCOUNTKEY", "dGVzdGtleQ==")
	if err := CopyBlobServerSide(context.Background(), src, dst, 1, 1, nil); err != nil {
		t.Fatal(err)
	}
	if acquisitions.Load() != 2 || stages.Load() != 2 {
		t.Fatalf("acquisitions/stages = %d/%d", acquisitions.Load(), stages.Load())
	}
}
