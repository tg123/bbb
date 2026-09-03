package acr

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
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

	// Unscoped credentials reach Azure Container Registry only.
	if _, _, ok := basicCredentials("myreg.azurecr.io"); !ok {
		t.Error("expected credentials to apply to an ACR host")
	}
	for _, registry := range []string{"ghcr.io", "registry.example.com", "localhost:5000"} {
		if _, _, ok := basicCredentials(registry); ok {
			t.Errorf("credentials must not be offered to %s", registry)
		}
	}

	// An explicit scope moves them, rather than widening them.
	t.Setenv("BBB_ACR_REGISTRY", "ghcr.io")
	if _, _, ok := basicCredentials("ghcr.io"); !ok {
		t.Error("expected the explicit scope to apply")
	}
	if _, _, ok := basicCredentials("myreg.azurecr.io"); ok {
		t.Error("an explicit scope must exclude other hosts, including ACR")
	}

	// Without a password there is nothing to offer.
	t.Setenv("BBB_ACR_PASSWORD", "")
	if _, _, ok := basicCredentials("ghcr.io"); ok {
		t.Error("expected incomplete credentials to be ignored")
	}
}

// The Entra flow is the default ACR login, so a wrong service, scope or grant
// would compile and only fail in production. Drive both exchanges directly.
func TestExchangeEntraToken(t *testing.T) {
	const registry = "myreg.azurecr.io"

	credential := &fakeCredential{token: "aad-token"}
	originalCredential := tokenCredential
	tokenCredential = func() (azcore.TokenCredential, error) { return credential, nil }
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
		"myreg.azurecr.de":      "https://management.microsoftazure.de/.default",
		"myreg.azurecr.io:443":  "https://management.azure.com/.default",
		"registry.corp.example": defaultARMScope,
	} {
		if got := armScope(registry); got != want {
			t.Errorf("armScope(%q) = %q, want %q", registry, got, want)
		}
	}
}

// A failed exchange must surface rather than yield an empty credential.
func TestExchangeEntraTokenPropagatesFailure(t *testing.T) {
	credential := &fakeCredential{token: "aad-token"}
	originalCredential := tokenCredential
	tokenCredential = func() (azcore.TokenCredential, error) { return credential, nil }
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
