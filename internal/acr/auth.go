package acr

import (
	"context"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"

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

// authCache memoises one ACR authenticator per registry so a multi-file
// transfer performs the Entra exchange once rather than per request. A nil
// entry means "fall back to the Docker keychain".
var (
	authCacheMu sync.Mutex
	authCache   = map[string]authn.Authenticator{}
)

// authOption resolves credentials for registry, in order:
//
//  1. BBB_ACR_USERNAME / BBB_ACR_PASSWORD
//  2. Entra ID, but only for Azure Container Registry endpoints
//  3. the Docker keychain (config.json, credential helpers), which also covers
//     `docker login` against any other OCI registry
func authOption(ctx context.Context, registry string) remote.Option {
	if user, pass, ok := basicCredentials(); ok {
		return remote.WithAuth(&authn.Basic{Username: user, Password: pass})
	}

	authCacheMu.Lock()
	defer authCacheMu.Unlock()
	auth, cached := authCache[registry]
	if !cached {
		if isACR(registry) {
			token, err := exchangeEntraToken(ctx, registry)
			if err != nil {
				slog.Debug("acr: Entra ID authentication unavailable, falling back to the Docker keychain",
					"registry", registry, "error", err)
			} else {
				auth = &authn.Basic{Username: acrTokenUsername, Password: token}
			}
		} else {
			slog.Debug("acr: not an Azure Container Registry endpoint, using the Docker keychain",
				"registry", registry)
		}
		authCache[registry] = auth
	}
	if auth != nil {
		return remote.WithAuth(auth)
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
