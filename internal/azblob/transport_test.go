package azblob

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// TestSharedTransportPropagatesToSDKClient verifies that a transport
// installed via SetHTTPTransport is actually used by SDK clients built
// by getAzBlobClient — i.e. the fix for BBB_DNS_PIN affecting Azure SDK
// traffic is wired up end-to-end.
func TestSharedTransportPropagatesToSDKClient(t *testing.T) {
	// Save and restore the shared transport.
	prev := sharedHTTPClient.Load()
	t.Cleanup(func() {
		sharedHTTPClient.Store(prev)
	})

	// Clear any cached client for our test account.
	account := "transportcheck"
	blobClientCache.Delete(account)
	t.Cleanup(func() { blobClientCache.Delete(account) })

	// Install a counting RoundTripper as the shared transport. If the
	// shared transport is threaded through to the SDK, every outbound
	// request from the SDK client will land here.
	var count int64
	SetHTTPTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt64(&count, 1)
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Length": []string{"0"}},
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	}))

	// Use a shared-key credential to bypass token acquisition network
	// calls (those would otherwise also flow through our transport but
	// require a more elaborate stub).
	t.Setenv("BBB_AZBLOB_ACCOUNTKEY", "dGVzdGtleQ==") // base64("testkey")

	cli, err := getAzBlobClient(context.Background(), account)
	if err != nil {
		t.Fatalf("getAzBlobClient: %v", err)
	}

	// Issuing any request that reaches the HTTP layer must go through
	// our shared transport. Use the container client's ListBlobs pager
	// and consume one page — ListBlobsFlat returns a pager that does
	// the network call on NextPage.
	pager := cli.NewListContainersPager(nil)
	if _, err := pager.NextPage(context.Background()); err != nil {
		// Our stub returns an empty-but-200 body which the XML parser
		// may reject; we only care that the transport was invoked.
	}

	if atomic.LoadInt64(&count) == 0 {
		t.Fatal("shared transport was not invoked by SDK client — BBB_DNS_PIN would not apply to Azure SDK traffic")
	}
}

// TestSharedTransportSetClear verifies SetHTTPTransport(nil) clears the
// override so subsequent callers see no shared transport configured.
func TestSharedTransportSetClear(t *testing.T) {
	prev := sharedHTTPClient.Load()
	t.Cleanup(func() {
		sharedHTTPClient.Store(prev)
	})

	SetHTTPTransport(roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, nil
	}))
	if getSharedTransporter() == nil {
		t.Fatal("expected shared transport to be set")
	}
	if azClientOptions() == nil {
		t.Fatal("expected azClientOptions to be non-nil after SetHTTPTransport")
	}

	SetHTTPTransport(nil)
	if getSharedTransporter() != nil {
		t.Fatal("expected shared transport to be cleared by SetHTTPTransport(nil)")
	}
	if azClientOptions() != nil {
		t.Fatal("expected azClientOptions to be nil when no shared transport is set")
	}
}
