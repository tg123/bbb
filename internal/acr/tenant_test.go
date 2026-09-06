package acr

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// jwtWithClaims builds an unsigned token whose payload is claims. Only the
// payload is ever read, so a signature would serve no purpose.
func jwtWithClaims(claims string) string {
	return "h." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".s"
}

func TestTenantIDFromAccessToken(t *testing.T) {
	for _, tc := range []struct {
		name  string
		token string
		want  string
	}{
		{"tid claim", jwtWithClaims(`{"tid":"11111111-2222-3333-4444-555555555555","aud":"x"}`), "11111111-2222-3333-4444-555555555555"},
		{"no tid", jwtWithClaims(`{"aud":"x"}`), ""},
		{"not a jwt", "opaque-token", ""},
		{"two segments", "a.b", ""},
		{"bad base64", "aaa.!!!.bbb", ""},
		{"bad json", jwtWithClaims(`{"tid":`), ""},
	} {
		if got := tenantIDFromAccessToken(tc.token); got != tc.want {
			t.Errorf("%s: tenantIDFromAccessToken = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The host form must win over the short name, so one endpoint can override a
// broader default.
func TestRegistryTenantID(t *testing.T) {
	if got := registryTenantID("myreg.azurecr.io"); got != "" {
		t.Fatalf("expected no tenant by default, got %q", got)
	}

	t.Setenv("BBB_ACR_TENANT", "global")
	if got := registryTenantID("myreg.azurecr.io"); got != "global" {
		t.Errorf("global default = %q, want global", got)
	}

	t.Setenv("BBB_ACR_TENANT_MYREG", "short")
	if got := registryTenantID("myreg.azurecr.io"); got != "short" {
		t.Errorf("short name = %q, want short", got)
	}

	t.Setenv("BBB_ACR_TENANT_MYREG_AZURECR_IO", "host")
	if got := registryTenantID("myreg.azurecr.io"); got != "host" {
		t.Errorf("host form = %q, want host", got)
	}

	// A port is not part of the identity, and another registry must not pick
	// up this one's setting.
	if got := registryTenantID("myreg.azurecr.io:443"); got != "host" {
		t.Errorf("host with port = %q, want host", got)
	}
	if got := registryTenantID("other.azurecr.io"); got != "global" {
		t.Errorf("unrelated registry = %q, want the global default", got)
	}
}

// The message ACR returns is the only signal that a failure is about identity
// rather than something a retry would fix.
func TestRejectedTenant(t *testing.T) {
	acrError := errors.New(`POST https://reg.azurecr.io/oauth2/exchange
RESPONSE 401: 401 Unauthorized
{"errors":[{"code":"UNAUTHORIZED","message":"token validation failed: the received access token has unknown tenantId \"72f988bf-86f1-41af-91ab-2d7cd011db47\" CorrelationId: abc"}]}`)
	got, ok := rejectedTenant(acrError)
	if !ok || got != "72f988bf-86f1-41af-91ab-2d7cd011db47" {
		t.Fatalf("rejectedTenant = (%q, %v), want the presented tenant", got, ok)
	}

	for _, tc := range []error{
		nil,
		errors.New("RESPONSE 401: UNAUTHORIZED: authentication required"),
		errors.New("dial tcp: i/o timeout"),
	} {
		if _, ok := rejectedTenant(tc); ok {
			t.Errorf("rejectedTenant(%v) matched, want no match", tc)
		}
	}
}

// The error has to survive being reformatted, because authOption classifies it
// after exchangeEntraToken has already turned it into advice.
func TestTenantMismatchErrorIsRecognisable(t *testing.T) {
	err := tenantMismatchError("myreg.azurecr.io:443", "72f988bf-86f1-41af-91ab-2d7cd011db47")
	if !errors.Is(err, errTenantMismatch) {
		t.Fatal("expected the formatted error to remain identifiable")
	}
	message := err.Error()
	for _, want := range []string{
		"myreg.azurecr.io",
		"72f988bf-86f1-41af-91ab-2d7cd011db47",
		"BBB_ACR_TENANT_MYREG_AZURECR_IO",
		"az login --tenant",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error message is missing %q:\n%s", want, message)
		}
	}
}

// go-containerregistry cannot be told to abandon a request, so the reason is
// reported when it asks for credentials.
func TestFailedAuthenticatorReportsTheCause(t *testing.T) {
	cause := errors.New("boom")
	auth := &failedAuthenticator{err: cause}
	if _, err := auth.Authorization(); !errors.Is(err, cause) {
		t.Errorf("Authorization returned %v, want the cause", err)
	}
	if _, err := auth.AuthorizationContext(context.Background()); !errors.Is(err, cause) {
		t.Errorf("AuthorizationContext returned %v, want the cause", err)
	}
}

// tenantCredential returns a credential whose token carries the given tenant.
type tenantCredentialStub struct{ tenant string }

func (c *tenantCredentialStub) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     jwtWithClaims(`{"tid":"` + c.tenant + `"}`),
		ExpiresOn: time.Now().Add(time.Hour),
	}, nil
}

// failingCredential stands in for an Azure CLI that knows the account but
// cannot refresh it unattended.
type failingCredential struct{}

func (failingCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, errors.New("Status_InteractionRequired")
}

func stubTenantCredentials(t *testing.T, cli func(string) (azcore.TokenCredential, error), login func(context.Context, string, string, string) (azcore.TokenCredential, error)) {
	t.Helper()
	originalCLI, originalLogin, originalTenants := cliCredentialFor, interactiveLogin, cliTenantList
	cliCredentialFor, interactiveLogin = cli, login
	// Default to knowing no tenants, so a test never shells out to a real
	// Azure CLI; a test that cares overrides this afterwards.
	cliTenantList = func(context.Context) []string { return nil }
	t.Cleanup(func() {
		cliCredentialFor, interactiveLogin, cliTenantList = originalCLI, originalLogin, originalTenants
		tenantCredCache.Clear()
		tenantCredInflight.Clear()
		explainedTenants.Clear()
	})
	tenantCredCache.Clear()
	tenantCredInflight.Clear()
	explainedTenants.Clear()
}

// The Azure CLI can hold a token only for the home tenant and return it
// whatever tenant was asked for. Presenting that would fail at the registry
// with the very mismatch this check exists to avoid.
func TestCredentialForRegistryRejectsAWrongTenantCLIToken(t *testing.T) {
	const want = "8b9ebe14-d942-49e7-ace9-14496d0caff0"
	t.Setenv("BBB_ACR_TENANT_MYREG_AZURECR_IO", want)

	signedIn := &tenantCredentialStub{tenant: want}
	var logins int
	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) {
			return &tenantCredentialStub{tenant: "72f988bf-86f1-41af-91ab-2d7cd011db47"}, nil
		},
		func(_ context.Context, _, tenant, _ string) (azcore.TokenCredential, error) {
			logins++
			if tenant != want {
				t.Errorf("signed in to tenant %q, want %q", tenant, want)
			}
			return signedIn, nil
		})

	got, err := credentialForRegistry(t.Context(), "myreg.azurecr.io")
	if err != nil {
		t.Fatalf("credentialForRegistry failed: %v", err)
	}
	if got != signedIn {
		t.Fatal("expected the interactive credential to be used")
	}

	// The result is cached per tenant, so a second registry request does not
	// open another prompt.
	if _, err := credentialForRegistry(t.Context(), "myreg.azurecr.io"); err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if logins != 1 {
		t.Fatalf("opened %d sign-ins, want exactly one", logins)
	}
}

func TestCredentialForRegistryUsesTheCLIWhenItMatches(t *testing.T) {
	const want = "8b9ebe14-d942-49e7-ace9-14496d0caff0"
	t.Setenv("BBB_ACR_TENANT_MYREG_AZURECR_IO", want)

	cli := &tenantCredentialStub{tenant: want}
	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) { return cli, nil },
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("must not sign in interactively when the CLI already serves the tenant")
			return nil, errors.New("unexpected")
		})

	got, err := credentialForRegistry(t.Context(), "myreg.azurecr.io")
	if err != nil {
		t.Fatalf("credentialForRegistry failed: %v", err)
	}
	if got != cli {
		t.Fatal("expected the CLI credential to be used")
	}
}

// An unattended CLI failure is the common case: az knows the account but its
// cached token has lapsed.
func TestCredentialForRegistrySignsInWhenTheCLICannot(t *testing.T) {
	t.Setenv("BBB_ACR_TENANT_MYREG_AZURECR_IO", "8b9ebe14-d942-49e7-ace9-14496d0caff0")

	signedIn := &tenantCredentialStub{tenant: "8b9ebe14-d942-49e7-ace9-14496d0caff0"}
	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) { return failingCredential{}, nil },
		func(context.Context, string, string, string) (azcore.TokenCredential, error) { return signedIn, nil })

	got, err := credentialForRegistry(t.Context(), "myreg.azurecr.io")
	if err != nil {
		t.Fatalf("credentialForRegistry failed: %v", err)
	}
	if got != signedIn {
		t.Fatal("expected the interactive credential to be used")
	}
}

// Without a configured tenant nothing changes: the process default credential
// is used, and no sign-in is provoked.
func TestCredentialForRegistryWithoutATenantUsesTheDefault(t *testing.T) {
	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) {
			t.Error("must not build a CLI credential without a configured tenant")
			return nil, errors.New("unexpected")
		},
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("must not sign in without a configured tenant")
			return nil, errors.New("unexpected")
		})

	// DefaultAzureCredential construction can legitimately fail in a bare
	// environment; what matters is that this path is the one taken.
	if _, err := credentialForRegistry(t.Context(), "myreg.azurecr.io"); err != nil {
		t.Logf("default credential unavailable in this environment: %v", err)
	}
}

// A sign-in that discovered the tenant is reused for the rest of the run, so a
// token refresh does not prompt a second time.
func TestCredentialForRegistryReusesADiscoveredTenant(t *testing.T) {
	const tenant = "8b9ebe14-d942-49e7-ace9-14496d0caff0"
	cli := &tenantCredentialStub{tenant: tenant}
	stubTenantCredentials(t,
		func(got string) (azcore.TokenCredential, error) {
			if got != tenant {
				t.Errorf("asked the CLI for tenant %q, want the discovered %q", got, tenant)
			}
			return cli, nil
		},
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("must not sign in again once the tenant is known")
			return nil, errors.New("unexpected")
		})

	discoveredTenants.Store(registryKey("myreg.azurecr.io"), tenant)
	t.Cleanup(func() { discoveredTenants.Clear() })

	got, err := credentialForRegistry(t.Context(), "myreg.azurecr.io")
	if err != nil {
		t.Fatalf("credentialForRegistry failed: %v", err)
	}
	if got != cli {
		t.Fatal("expected the discovered tenant to be used")
	}
}

// A sign-in nobody can answer would hang a pipeline until the credential timed
// out, so it is offered only when someone is there to answer it.
func TestCanPromptRespectsTheEnvironment(t *testing.T) {
	t.Setenv("BBB_ACR_NO_LOGIN", "1")
	if canPrompt() {
		t.Error("BBB_ACR_NO_LOGIN must suppress the sign-in")
	}
	t.Setenv("BBB_ACR_NO_LOGIN", "false")
	// Under `go test` the standard streams are pipes, so this reflects the
	// no-terminal decision rather than the opt-out.
	if canPrompt() && !isCharDevice(os.Stdin) && !isCharDevice(os.Stderr) {
		t.Error("expected no prompt without a terminal")
	}
}

// An interrupted sign-in must not be reopened by whoever was queued behind it,
// or cancelling once asks again.
func TestCredentialForRegistryStopsOnCancellation(t *testing.T) {
	t.Setenv("BBB_ACR_TENANT_MYREG_AZURECR_IO", "8b9ebe14-d942-49e7-ace9-14496d0caff0")
	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) { return failingCredential{}, nil },
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("must not sign in once the caller has gone")
			return nil, errors.New("unexpected")
		})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := credentialForRegistry(ctx, "myreg.azurecr.io"); !errors.Is(err, context.Canceled) {
		t.Fatalf("credentialForRegistry = %v, want the cancellation", err)
	}
}

// The Azure CLI knows which tenants the user is signed in to, and the registry
// will not say which one it wants, so those are worth trying before asking.
func TestExchangeTriesTenantsTheCLIKnows(t *testing.T) {
	const green = "8b9ebe14-d942-49e7-ace9-14496d0caff0"
	const corp = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	greenToken := jwtWithClaims(`{"tid":"` + green + `"}`)
	accepted := greenToken
	attempts := 0
	rejectingExchange(t, &accepted, &attempts)

	original := tokenCredential
	tokenCredential = func(context.Context, string) (azcore.TokenCredential, error) {
		return &tenantCredentialStub{tenant: corp}, nil
	}
	t.Cleanup(func() { tokenCredential = original })

	stubTenantCredentials(t,
		func(tenant string) (azcore.TokenCredential, error) {
			return &tenantCredentialStub{tenant: tenant}, nil
		},
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("a tenant the CLI already serves must not prompt")
			return nil, errors.New("unexpected")
		})

	originalTenants := cliTenantList
	var asked bool
	cliTenantList = func(context.Context) []string {
		asked = true
		// The rejected tenant is listed too, and must be skipped rather than
		// retried against the registry that just refused it.
		return []string{corp, green}
	}
	originalPrompt := promptAllowed
	promptAllowed = func() bool { return true }
	t.Cleanup(func() {
		cliTenantList = originalTenants
		promptAllowed = originalPrompt
		discoveredTenants.Clear()
	})
	token, err := exchangeEntraToken(t.Context(), "myreg.azurecr.io")
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}
	if token != "acr-refresh" {
		t.Fatalf("token = %q, want the refresh token", token)
	}
	if !asked {
		t.Error("expected the Azure CLI tenants to be consulted")
	}
	// The tenant that worked is remembered, so a refresh does not rediscover it.
	if found, ok := discoveredTenants.Load(registryKey("myreg.azurecr.io")); !ok || found.(string) != green {
		t.Errorf("discovered tenant = %v, want %s", found, green)
	}
}

// rejectingExchange serves a tenant rejection until sign-in happens, then a
// refresh token, mimicking ACR's behaviour across the retry.
func rejectingExchange(t *testing.T, accepted *string, attempts *int) {
	t.Helper()
	SetHTTPClient(&http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		form, _ := url.ParseQuery(string(body))
		*attempts++
		if *accepted == "" || form.Get("access_token") != *accepted {
			return &http.Response{
				StatusCode: http.StatusUnauthorized,
				Body: io.NopCloser(strings.NewReader(
					`{"errors":[{"code":"UNAUTHORIZED","message":"token validation failed: the received access token has unknown tenantId \"72f988bf-86f1-41af-91ab-2d7cd011db47\""}]}`)),
				Request: req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"refresh_token":"acr-refresh"}`)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    req,
		}, nil
	})})
	t.Cleanup(func() { SetHTTPClient(nil) })
}

// An ACR endpoint never says which tenant it belongs to, so the rejection is
// the first evidence there is a problem. Rather than reporting it, offer the
// sign-in that can fix it and retry.
func TestExchangeSignsInWhenTheRegistryRejectsTheTenant(t *testing.T) {
	const goodToken = "token-from-the-right-tenant"
	accepted := goodToken
	attempts := 0
	rejectingExchange(t, &accepted, &attempts)

	original := tokenCredential
	tokenCredential = func(context.Context, string) (azcore.TokenCredential, error) {
		return &fakeCredential{token: "home-tenant-token"}, nil
	}
	t.Cleanup(func() { tokenCredential = original })

	var logins int
	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) { return nil, errors.New("no cli") },
		func(_ context.Context, _, tenant, _ string) (azcore.TokenCredential, error) {
			logins++
			if tenant != "" {
				t.Errorf("signed in to tenant %q, want the account picker", tenant)
			}
			return &fakeCredential{token: goodToken}, nil
		})

	originalPrompt := promptAllowed
	promptAllowed = func() bool { return true }
	t.Cleanup(func() { promptAllowed = originalPrompt })

	token, err := exchangeEntraToken(t.Context(), "myreg.azurecr.io")
	if err != nil {
		t.Fatalf("exchange failed after sign-in: %v", err)
	}
	if token != "acr-refresh" {
		t.Fatalf("token = %q, want the refresh token from the retry", token)
	}
	if logins != 1 {
		t.Fatalf("opened %d sign-ins, want exactly one", logins)
	}
	if attempts < 2 {
		t.Fatalf("made %d exchange attempts, want a retry after signing in", attempts)
	}
}

// With no one to answer, the rejection has to be reported instead, and the
// message must say what to set.
func TestExchangeReportsTheMismatchWhenItCannotPrompt(t *testing.T) {
	accepted := ""
	attempts := 0
	rejectingExchange(t, &accepted, &attempts)

	original := tokenCredential
	tokenCredential = func(context.Context, string) (azcore.TokenCredential, error) {
		return &fakeCredential{token: "home-tenant-token"}, nil
	}
	t.Cleanup(func() { tokenCredential = original })

	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) { return nil, errors.New("no cli") },
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("must not sign in when prompting is unavailable")
			return nil, errors.New("unexpected")
		})

	originalPrompt := promptAllowed
	promptAllowed = func() bool { return false }
	t.Cleanup(func() { promptAllowed = originalPrompt })

	_, err := exchangeEntraToken(t.Context(), "myreg.azurecr.io")
	if !errors.Is(err, errTenantMismatch) {
		t.Fatalf("error = %v, want a tenant mismatch", err)
	}
	if !strings.Contains(err.Error(), "BBB_ACR_TENANT_MYREG_AZURECR_IO") {
		t.Errorf("error should name the setting to use:\n%v", err)
	}
}

// A tenant that was named explicitly and still rejected is a wrong setting;
// signing in would only ask the same question again.
func TestExchangeDoesNotPromptForAConfiguredTenant(t *testing.T) {
	t.Setenv("BBB_ACR_TENANT_MYREG_AZURECR_IO", "8b9ebe14-d942-49e7-ace9-14496d0caff0")
	accepted := ""
	attempts := 0
	rejectingExchange(t, &accepted, &attempts)

	original := tokenCredential
	tokenCredential = func(context.Context, string) (azcore.TokenCredential, error) {
		return &fakeCredential{token: "wrong-token"}, nil
	}
	t.Cleanup(func() { tokenCredential = original })

	stubTenantCredentials(t,
		func(string) (azcore.TokenCredential, error) { return nil, errors.New("no cli") },
		func(context.Context, string, string, string) (azcore.TokenCredential, error) {
			t.Error("must not sign in when the tenant was configured explicitly")
			return nil, errors.New("unexpected")
		})

	originalPrompt := promptAllowed
	promptAllowed = func() bool { return true }
	t.Cleanup(func() { promptAllowed = originalPrompt })

	if _, err := exchangeEntraToken(t.Context(), "myreg.azurecr.io"); !errors.Is(err, errTenantMismatch) {
		t.Fatalf("error = %v, want a tenant mismatch", err)
	}
}

// A transient exchange failure must not be turned into an anonymous request: a
// private registry answers that with a 401 the retry layer treats as final, so
// a passing outage would become a permanent failure with the cause replaced.
func TestAuthOptionSurfacesATransientFailure(t *testing.T) {
	const registry = "myreg.azurecr.io"
	var exchanges atomic.Int64
	original := exchangeToken
	exchangeToken = func(context.Context, string) (string, error) {
		exchanges.Add(1)
		return "", context.DeadlineExceeded
	}
	t.Cleanup(func() {
		exchangeToken = original
		authCache.Clear()
	})
	authCache.Clear()

	option := authOption(t.Context(), registry)
	if option == nil {
		t.Fatal("expected an auth option")
	}
	// The entry stays unresolved, so the next attempt tries the exchange again
	// rather than being stuck with the outage.
	authOption(t.Context(), registry)
	if got := exchanges.Load(); got != 2 {
		t.Fatalf("ran %d exchanges, want the transient failure retried", got)
	}
}

// Not every failure is transient: with no Azure credential at all there is
// nothing to retry, and an anonymous pull is a legitimate outcome.
func TestAuthOptionFallsBackWhenNoCredentialExists(t *testing.T) {
	const registry = "myreg.azurecr.io"
	original := exchangeToken
	exchangeToken = func(context.Context, string) (string, error) {
		return "", errors.New("DefaultAzureCredential: no credential was available")
	}
	t.Cleanup(func() {
		exchangeToken = original
		authCache.Clear()
	})
	authCache.Clear()

	if option := authOption(t.Context(), registry); option == nil {
		t.Fatal("expected the keychain fallback rather than a failure")
	}
}

// `ls -l` resolves credentials from more than one goroutine at once. Each must
// wait for the first attempt rather than opening a sign-in of its own, and a
// rejection must be remembered so a later request does not reopen a prompt the
// user has already answered.
func TestAuthOptionSerialisesTheSignIn(t *testing.T) {
	const registry = "myreg.azurecr.io"
	var exchanges atomic.Int64
	original := exchangeToken
	exchangeToken = func(context.Context, string) (string, error) {
		exchanges.Add(1)
		// Hold the attempt open so the other callers pile up behind it, which
		// is exactly when a second prompt used to appear.
		time.Sleep(50 * time.Millisecond)
		return "", tenantMismatchError(registry, "72f988bf-86f1-41af-91ab-2d7cd011db47")
	}
	t.Cleanup(func() {
		exchangeToken = original
		authCache.Clear()
	})
	authCache.Clear()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			authOption(t.Context(), registry)
		}()
	}
	wg.Wait()

	// A later request, after everything has settled, must reuse the answer too.
	authOption(t.Context(), registry)

	if got := exchanges.Load(); got != 1 {
		t.Fatalf("ran %d exchanges, want exactly one shared attempt", got)
	}
}

// A definitive failure is resolved once: with no Azure credential available
// the keychain is the answer for the rest of the run, not something to
// rediscover on every operation.
func TestAuthOptionResolvesADefinitiveFailureOnce(t *testing.T) {
	const registry = "myreg.azurecr.io"
	var exchanges atomic.Int64
	original := exchangeToken
	exchangeToken = func(context.Context, string) (string, error) {
		exchanges.Add(1)
		return "", errors.New("DefaultAzureCredential: no credential was available")
	}
	t.Cleanup(func() {
		exchangeToken = original
		authCache.Clear()
	})
	authCache.Clear()

	authOption(t.Context(), registry)
	authOption(t.Context(), registry)

	if got := exchanges.Load(); got != 1 {
		t.Fatalf("ran %d exchanges, want the fallback resolved once", got)
	}
}

// Authentication has to be able to recover: an error kept from a failed
// attempt would outlive the retry that succeeded, since it is reported ahead
// of the credential.
func TestAuthOptionRecoversAfterATransientFailure(t *testing.T) {
	const registry = "myreg.azurecr.io"
	var attempts atomic.Int64
	original := exchangeToken
	exchangeToken = func(context.Context, string) (string, error) {
		if attempts.Add(1) == 1 {
			return "", context.DeadlineExceeded
		}
		return "recovered", nil
	}
	t.Cleanup(func() {
		exchangeToken = original
		authCache.Clear()
	})
	authCache.Clear()

	authOption(t.Context(), registry)
	authOption(t.Context(), registry)

	value, ok := authCache.Load(registryKey(registry))
	if !ok {
		t.Fatal("expected a cached entry")
	}
	entry := value.(*authEntry)
	if err := entry.gate.acquire(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer entry.gate.release()
	if entry.err != nil {
		t.Errorf("the failure outlived its retry: %v", entry.err)
	}
	if entry.auth == nil {
		t.Error("expected the recovered credential to be used")
	}
}
