package acr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// aadScope is the scope used when requesting an Entra ID token to exchange for
// an ACR refresh token. ACR expects a token scoped to the ARM resource.
const aadScope = "https://management.azure.com/.default"

// acrTokenUsername is the sentinel username ACR expects when the password is a
// registry access token.
const acrTokenUsername = "00000000-0000-0000-0000-000000000000"

// azureRegistrySuffixes are the Azure Container Registry DNS suffixes across
// the public and sovereign clouds.
var azureRegistrySuffixes = []string{
	".azurecr.io",
	".azurecr.cn",
	".azurecr.us",
	".azurecr.de",
}

// registryHost strips any port from a registry authority.
func registryHost(registry string) string {
	host := registry
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// trustedEntraHosts returns extra registry hosts explicitly opted in via
// BBB_ACR_ENTRA_HOSTS, for ACR deployments behind a custom domain.
func trustedEntraHosts() []string {
	raw := strings.TrimSpace(os.Getenv("BBB_ACR_ENTRA_HOSTS"))
	if raw == "" {
		return nil
	}
	hosts := strings.Split(raw, ",")
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" {
			out = append(out, host)
		}
	}
	return out
}

// isACR reports whether registry is an Azure Container Registry endpoint that
// may be offered Entra credentials.
//
// The exchange posts a live Azure access token to the registry, so it must not
// be attempted against any host that merely answers with a bearer challenge —
// a private ghcr.io repository would otherwise receive the caller's Azure
// credential. Everything else falls through to the Docker keychain.
func isACR(registry string) bool {
	host := registryHost(registry)
	if slices.Contains(trustedEntraHosts(), host) {
		return true
	}
	for _, suffix := range azureRegistrySuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// basicCredentials returns explicitly configured registry credentials.
func basicCredentials() (string, string, bool) {
	user := os.Getenv("BBB_ACR_USERNAME")
	pass := os.Getenv("BBB_ACR_PASSWORD")
	if user == "" || pass == "" {
		return "", "", false
	}
	return user, pass, true
}

var (
	credOnce sync.Once
	cred     azcore.TokenCredential
	credErr  error
)

func getCredential() (azcore.TokenCredential, error) {
	credOnce.Do(func() {
		opts := &azidentity.DefaultAzureCredentialOptions{}
		if c := sharedClient.Load(); c != nil {
			opts.Transport = c
		}
		cred, credErr = azidentity.NewDefaultAzureCredential(opts)
	})
	return cred, credErr
}

// acrAuthenticator supplies an ACR access token, re-exchanging it when it
// expires.
//
// ACR access tokens are short-lived (about three hours). Caching one for the
// process lifetime would make every request in a long transfer fail with 401
// once it lapsed, because go-containerregistry can only refresh its own
// challenge token by presenting this credential again.
type acrAuthenticator struct {
	registry string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// tokenRefreshMargin renews a token slightly before it actually expires, so a
// request already in flight cannot land after the lapse.
const tokenRefreshMargin = 5 * time.Minute

// tokenExchangeTimeout bounds a renewal, which happens without a caller
// context because authn.Authenticator takes none.
const tokenExchangeTimeout = 2 * time.Minute

// exchangeToken is indirected so tests can drive token renewal without
// contacting Entra ID or a registry.
var exchangeToken = exchangeEntraToken

func (a *acrAuthenticator) Authorization() (*authn.AuthConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == "" || time.Now().After(a.expires) {
		ctx, cancel := context.WithTimeout(context.Background(), tokenExchangeTimeout)
		defer cancel()
		token, err := exchangeToken(ctx, a.registry)
		if err != nil {
			return nil, err
		}
		a.token = token
		a.expires = tokenExpiry(token)
		slog.Debug("acr: refreshed registry access token", "registry", a.registry, "expires", a.expires)
	}
	return &authn.AuthConfig{
		Username: acrTokenUsername,
		Password: a.token,
	}, nil
}

// tokenExpiry reads the exp claim of a registry access token, so renewal is
// driven by the token itself. The token is not verified: this only decides when
// to refresh, never whether to trust anything.
//
// The fallback covers tokens whose expiry cannot be read at all. A token that
// parses but is already expired, or within the refresh margin, deliberately
// yields a past time so the next Authorization re-exchanges immediately.
func tokenExpiry(token string) time.Time {
	const fallback = 30 * time.Minute
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Now().Add(fallback)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Now().Add(fallback)
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Now().Add(fallback)
	}
	return time.Unix(claims.Exp, 0).Add(-tokenRefreshMargin)
}

// authEntry memoises the credentials for one registry. A nil authenticator
// means "fall back to the Docker keychain".
type authEntry struct {
	once sync.Once
	auth authn.Authenticator
}

// authCache holds one entry per registry so a multi-file transfer performs the
// Entra exchange once rather than per request.
var authCache sync.Map

// authOption resolves credentials for registry, in order:
//
//  1. BBB_ACR_USERNAME / BBB_ACR_PASSWORD
//  2. Entra ID, but only for Azure Container Registry endpoints
//  3. the Docker keychain (config.json, credential helpers), which also covers
//     `docker login` against any other OCI registry
//
// The first resolution for a registry performs network I/O, so entries are
// keyed individually: concurrent callers for the same registry wait for one
// exchange, while a slow login to one registry never blocks another.
func authOption(ctx context.Context, registry string) remote.Option {
	if user, pass, ok := basicCredentials(); ok {
		return remote.WithAuth(&authn.Basic{Username: user, Password: pass})
	}

	value, _ := authCache.LoadOrStore(registry, &authEntry{})
	entry := value.(*authEntry)
	entry.once.Do(func() {
		if !isACR(registry) {
			slog.Debug("acr: not an Azure Container Registry endpoint, using the Docker keychain",
				"registry", registry)
			return
		}
		// Exchange once up front so an unusable credential falls back to the
		// keychain now rather than failing mid-transfer; the authenticator
		// renews itself from then on.
		token, err := exchangeToken(ctx, registry)
		if err != nil {
			slog.Debug("acr: Entra ID authentication unavailable, falling back to the Docker keychain",
				"registry", registry, "error", err)
			return
		}
		entry.auth = &acrAuthenticator{
			registry: registry,
			token:    token,
			expires:  tokenExpiry(token),
		}
	})
	if entry.auth != nil {
		return remote.WithAuth(entry.auth)
	}
	return remote.WithAuthFromKeychain(authn.DefaultKeychain)
}

// exchangeEntraToken trades an Entra ID access token for an ACR refresh token
// and then for a registry access token, using the Azure SDK rather than a
// hand-rolled OAuth flow.
func exchangeEntraToken(ctx context.Context, registry string) (string, error) {
	credential, err := getCredential()
	if err != nil {
		return "", err
	}
	options := &azcontainerregistry.AuthenticationClientOptions{}
	if c := sharedClient.Load(); c != nil {
		options.Transport = c
	}
	client, err := azcontainerregistry.NewAuthenticationClient("https://"+registry, options)
	if err != nil {
		return "", err
	}
	aadToken, err := credential.GetToken(ctx, policyTokenRequest(aadScope))
	if err != nil {
		return "", err
	}
	refresh, err := client.ExchangeAADAccessTokenForACRRefreshToken(
		ctx,
		azcontainerregistry.PostContentSchemaGrantTypeAccessToken,
		registry,
		&azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
			AccessToken: &aadToken.Token,
		},
	)
	if err != nil {
		return "", err
	}
	if refresh.RefreshToken == nil {
		return "", errEmptyToken
	}
	// A wildcard scope keeps one token valid for every repository touched by a
	// single bbb invocation.
	grant := azcontainerregistry.TokenGrantTypeRefreshToken
	access, err := client.ExchangeACRRefreshTokenForACRAccessToken(
		ctx,
		registry,
		"repository:*:pull,push",
		*refresh.RefreshToken,
		&azcontainerregistry.AuthenticationClientExchangeACRRefreshTokenForACRAccessTokenOptions{
			GrantType: &grant,
		},
	)
	if err != nil {
		return "", err
	}
	if access.AccessToken == nil {
		return "", errEmptyToken
	}
	return *access.AccessToken, nil
}
