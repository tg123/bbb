package azblob

import (
	"net/http"
	"sync/atomic"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// sharedHTTPClient holds an optional *http.Client used by all Azure SDK
// clients created in this package. When set, it ensures features like
// DNS pinning/caching installed on the underlying *http.Transport are
// applied uniformly to every outbound HTTP connection made via the SDK
// pipeline (data plane, UDC acquisition and OAuth token calls).
//
// Ordering: SetHTTPTransport must be called before any SDK client is
// constructed. In bbb this happens in the cli Before: hook in main.go,
// which runs before any command Action.
var sharedHTTPClient atomic.Pointer[http.Client]

// SetHTTPTransport installs a shared HTTP RoundTripper that will be used
// by every Azure SDK client constructed in this package. The RoundTripper
// is wrapped in an *http.Client so it satisfies policy.Transporter.
// Passing nil clears any previously configured transport.
//
// This must be called before any SDK client is constructed; already-created
// clients keep their existing transport.
func SetHTTPTransport(rt http.RoundTripper) {
	if rt == nil {
		sharedHTTPClient.Store(nil)
		return
	}
	sharedHTTPClient.Store(&http.Client{Transport: rt})
}

// getSharedTransporter returns the configured shared transporter, or nil
// if none has been set.
func getSharedTransporter() policy.Transporter {
	c := sharedHTTPClient.Load()
	if c == nil {
		return nil
	}
	return c
}

// azClientOptions returns azcore client options with Transport populated
// from the shared transport when configured, otherwise returns nil (which
// tells the SDK to use its default transport).
func azClientOptions() *azcore.ClientOptions {
	t := getSharedTransporter()
	if t == nil {
		return nil
	}
	return &azcore.ClientOptions{Transport: t}
}

// azblobClientOptions returns *azblob.ClientOptions threading the shared
// transport, or nil.
func azblobClientOptions() *azblob.ClientOptions {
	co := azClientOptions()
	if co == nil {
		return nil
	}
	return &azblob.ClientOptions{ClientOptions: *co}
}

// serviceClientOptions returns *service.ClientOptions threading the shared
// transport, or nil.
func serviceClientOptions() *service.ClientOptions {
	co := azClientOptions()
	if co == nil {
		return nil
	}
	return &service.ClientOptions{ClientOptions: *co}
}

// applyTransportToIdentityOptions mutates the provided azcore.ClientOptions
// in place, setting Transport from the shared transport when configured.
// Used to thread the transport into azidentity credential option structs.
func applyTransportToIdentityOptions(co *azcore.ClientOptions) {
	if co == nil {
		return
	}
	if t := getSharedTransporter(); t != nil && co.Transport == nil {
		co.Transport = t
	}
}
