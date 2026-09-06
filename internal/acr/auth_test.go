package acr

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// fakeCredential stands in for DefaultAzureCredential.
type fakeCredential struct {
	token  string
	scopes []string
}

func (c *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.scopes = append(c.scopes, opts.Scopes...)
	return azcore.AccessToken{Token: c.token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// recordedRequest captures one intercepted exchange.
type recordedRequest struct {
	path string
	form url.Values
}

// Registry credentials must not be offered to every host an invocation
// touches, or one registry's password reaches another.
func TestBasicCredentialsAreHostScoped(t *testing.T) {
	t.Setenv("BBB_ACR_USERNAME", "user")
	t.Setenv("BBB_ACR_PASSWORD", "pass")

	// An Azure suffix is not a scope: anyone can own a *.azurecr.io registry,
	// so credentials sit unused until the host is named.
	for _, registry := range []string{"myreg.azurecr.io", "ghcr.io", "registry.example.com", "localhost:5000"} {
		if _, _, ok := basicCredentials(registry); ok {
			t.Errorf("credentials must not be offered to %s without a scope", registry)
		}
	}

	// A scope names exactly where they go.
	t.Setenv("BBB_ACR_REGISTRY", "myreg.azurecr.io")
	if _, _, ok := basicCredentials("myreg.azurecr.io"); !ok {
		t.Error("expected the scoped registry to receive them")
	}
	for _, registry := range []string{"other.azurecr.io", "ghcr.io"} {
		if _, _, ok := basicCredentials(registry); ok {
			t.Errorf("a scope must exclude %s, including another ACR", registry)
		}
	}

	// Without a password there is nothing to offer.
	t.Setenv("BBB_ACR_PASSWORD", "")
	if _, _, ok := basicCredentials("myreg.azurecr.io"); ok {
		t.Error("expected incomplete credentials to be ignored")
	}
}

// Scoping follows the registry's effective transport. Over HTTP, host and
// host:443 are different services, so a scope naming one must not leak the
// password to the other.
func TestBasicCredentialScopeFollowsEffectiveTransport(t *testing.T) {
	t.Setenv("BBB_ACR_USERNAME", "user")
	t.Setenv("BBB_ACR_PASSWORD", "pass")
	t.Setenv("BBB_ACR_REGISTRY", "registry.example.com:443")
	t.Setenv("BBB_ACR_INSECURE", "registry.example.com")

	if _, _, ok := basicCredentials("registry.example.com"); ok {
		t.Error("a scope for :443 must not cover the plaintext host on :80")
	}
	if _, _, ok := basicCredentials("registry.example.com:443"); !ok {
		t.Error("expected the scoped endpoint itself to be covered")
	}

	// With no plaintext opt-in the host is reached over HTTPS, where :443 is
	// the default port and the two spellings are the same endpoint.
	t.Setenv("BBB_ACR_INSECURE", "")
	if _, _, ok := basicCredentials("registry.example.com"); !ok {
		t.Error("expected :443 to collapse to the bare host over HTTPS")
	}
}

// The Entra flow is the default ACR login, so a wrong service, scope or grant
// would compile and only fail in production. Drive both exchanges directly.
func TestExchangeEntraToken(t *testing.T) {
	const registry = "myreg.azurecr.io"

	credential := &fakeCredential{token: "aad-token"}
	originalCredential := tokenCredential
	tokenCredential = func(context.Context, string) (azcore.TokenCredential, error) { return credential, nil }
	t.Cleanup(func() { tokenCredential = originalCredential })

	var requests []recordedRequest
	client := &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		requests = append(requests, recordedRequest{path: req.URL.Path, form: form})

		payload := map[string]string{}
		switch req.URL.Path {
		case "/oauth2/exchange":
			payload["refresh_token"] = "refresh-token"
		case "/oauth2/token":
			payload["access_token"] = "registry-token"
		default:
			return &http.Response{StatusCode: http.StatusNotFound, Body: http.NoBody, Request: req}, nil
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(string(encoded))),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    req,
		}, nil
	})}
	SetHTTPClient(client)
	t.Cleanup(func() { SetHTTPClient(nil) })

	token, err := exchangeEntraToken(t.Context(), registry)
	if err != nil {
		t.Fatalf("exchangeEntraToken failed: %v", err)
	}
	// The refresh token is returned, not an access token: ACR access tokens are
	// repository-scoped, so go-containerregistry asks for the exact scope from
	// each challenge instead.
	if token != "refresh-token" {
		t.Fatalf("token = %q, want the registry refresh token", token)
	}

	if len(credential.scopes) != 1 || credential.scopes[0] != defaultARMScope {
		t.Fatalf("credential scopes = %v, want [%s]", credential.scopes, defaultARMScope)
	}
	if len(requests) != 1 {
		t.Fatalf("expected exactly one exchange, got %d requests", len(requests))
	}

	first := requests[0]
	if first.path != "/oauth2/exchange" {
		t.Errorf("request path = %s, want /oauth2/exchange", first.path)
	}
	if got := first.form.Get("grant_type"); got != "access_token" {
		t.Errorf("grant_type = %q, want access_token", got)
	}
	if got := first.form.Get("service"); got != registry {
		t.Errorf("service = %q, want %s", got, registry)
	}
	if got := first.form.Get("access_token"); got != "aad-token" {
		t.Errorf("the Entra token was not forwarded, got %q", got)
	}
}

// A token for the public-cloud audience is not valid in a sovereign cloud.
func TestARMScopeFollowsTheCloud(t *testing.T) {
	for registry, want := range map[string]string{
		"myreg.azurecr.io":      "https://management.azure.com/.default",
		"myreg.azurecr.cn":      "https://management.chinacloudapi.cn/.default",
		"myreg.azurecr.us":      "https://management.usgovcloudapi.net/.default",
		"myreg.azurecr.io:443":  "https://management.azure.com/.default",
		"registry.corp.example": defaultARMScope,
	} {
		if got := armScope(registry); got != want {
			t.Errorf("armScope(%q) = %q, want %q", registry, got, want)
		}
	}
}

// The cloud belongs to the credential, not only to the scope: a token from the
// public-cloud authority is no use to a sovereign registry, whatever audience
// was asked for.
func TestDefaultCredentialFollowsTheCloud(t *testing.T) {
	for registry, want := range map[string]cloud.Configuration{
		"myreg.azurecr.io":      cloud.AzurePublic,
		"myreg.azurecr.cn":      cloud.AzureChina,
		"myreg.azurecr.us":      cloud.AzureGovernment,
		"myreg.azurecr.us:443":  cloud.AzureGovernment,
		"registry.corp.example": cloud.AzurePublic,
	} {
		got := registryCloud(registry)
		if got.ActiveDirectoryAuthorityHost != want.ActiveDirectoryAuthorityHost {
			t.Errorf("registryCloud(%q) authority = %q, want %q",
				registry, got.ActiveDirectoryAuthorityHost, want.ActiveDirectoryAuthorityHost)
		}
	}

	// One credential per cloud, so a run touching two is not served by
	// whichever registry it happened to reach first.
	defaultCreds.Clear()
	t.Cleanup(defaultCreds.Clear)
	public, err := getCredential("myreg.azurecr.io")
	if err != nil {
		t.Skipf("no ambient Azure credential available: %v", err)
	}
	again, err := getCredential("other.azurecr.io")
	if err != nil {
		t.Fatalf("second public-cloud call failed: %v", err)
	}
	if public != again {
		t.Error("two registries in one cloud must share a credential")
	}
	china, err := getCredential("myreg.azurecr.cn")
	if err != nil {
		t.Fatalf("sovereign call failed: %v", err)
	}
	if china == public {
		t.Error("a sovereign registry must not reuse the public-cloud credential")
	}
}

// Both auth locks are held across network and interactive work, so a caller
// queued behind one must be able to give up when its own transfer is
// cancelled — otherwise a browser prompt nobody answers holds it indefinitely.
func TestAuthWaitsAreContextAware(t *testing.T) {
	const registry = "waiter.azurecr.io"
	authCache.Clear()
	t.Cleanup(authCache.Clear)

	entered := make(chan struct{})
	release := make(chan struct{})
	original := exchangeToken
	exchangeToken = func(ctx context.Context, _ string) (string, error) {
		close(entered)
		select {
		case <-release:
			return "token", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	t.Cleanup(func() { exchangeToken = original })

	// One caller holds the gate inside the exchange.
	holder := make(chan struct{})
	go func() {
		defer close(holder)
		authOption(context.Background(), registry)
	}()
	<-entered

	// A second caller for the same registry must not be stuck behind it.
	ctx, cancel := context.WithCancel(context.Background())
	waited := make(chan remote.Option, 1)
	go func() { waited <- authOption(ctx, registry) }()
	select {
	case <-waited:
		t.Fatal("the second caller should still be waiting")
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled caller stayed blocked on the auth gate")
	}

	close(release)
	<-holder
}

// A token refresh reaches the network, so a caller queued behind one must be
// able to abandon the wait, and must not be handed a token it no longer wants.
func TestAuthorizationContextHonoursCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	original := exchangeToken
	exchangeToken = func(ctx context.Context, _ string) (string, error) {
		close(entered)
		select {
		case <-release:
			return "token", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	t.Cleanup(func() { exchangeToken = original })

	auth := &acrAuthenticator{registry: "waiter.azurecr.io"}
	holder := make(chan struct{})
	go func() {
		defer close(holder)
		_, _ = auth.AuthorizationContext(context.Background())
	}()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	waited := make(chan error, 1)
	go func() {
		_, err := auth.AuthorizationContext(ctx)
		waited <- err
	}()
	cancel()
	select {
	case err := <-waited:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want the caller's own cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled caller stayed blocked on the token refresh")
	}

	close(release)
	<-holder
}

// A failed exchange must surface rather than yield an empty credential.
func TestExchangeEntraTokenPropagatesFailure(t *testing.T) {
	credential := &fakeCredential{token: "aad-token"}
	originalCredential := tokenCredential
	tokenCredential = func(context.Context, string) (azcore.TokenCredential, error) { return credential, nil }
	t.Cleanup(func() { tokenCredential = originalCredential })

	var calls atomic.Int64
	SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Body:       io.NopCloser(strings.NewReader(`{"errors":[{"code":"UNAUTHORIZED"}]}`)),
			Request:    req,
		}, nil
	})})
	t.Cleanup(func() { SetHTTPClient(nil) })

	if _, err := exchangeEntraToken(t.Context(), "myreg.azurecr.io"); err == nil {
		t.Fatal("expected a rejected exchange to fail")
	}
	if calls.Load() == 0 {
		t.Fatal("expected the exchange to be attempted")
	}
}
