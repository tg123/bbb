package acr

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/containers/azcontainerregistry"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// armScopes maps an Azure Container Registry suffix to the Resource Manager
// audience of its cloud, and to the identity authority that issues for it. A
// token for the public-cloud audience is not valid in a sovereign cloud, and
// nor is one obtained from the public-cloud authority.
//
// Azure Germany is absent because it was decommissioned: pairing its audience
// with the only authority the SDK still offers would produce a sign-in that
// cannot issue for it, which is worse than not claiming support.
var armScopes = []struct {
	suffix string
	scope  string
	cloud  cloud.Configuration
}{
	{".azurecr.cn", "https://management.chinacloudapi.cn/.default", cloud.AzureChina},
	{".azurecr.us", "https://management.usgovcloudapi.net/.default", cloud.AzureGovernment},
	{".azurecr.io", "https://management.azure.com/.default", cloud.AzurePublic},
}

// defaultARMScope is the public-cloud audience, used for custom-domain hosts
// opted in via BBB_ACR_ENTRA_HOSTS.
const defaultARMScope = "https://management.azure.com/.default"

// armScope returns the Resource Manager audience to request for registry.
func armScope(registry string) string {
	host := registryHost(registry)
	for _, candidate := range armScopes {
		if strings.HasSuffix(host, candidate.suffix) {
			return candidate.scope
		}
	}
	return defaultARMScope
}

// registryCloud returns the identity authority that issues tokens for a
// registry's cloud. Requesting a sovereign audience from the public-cloud
// authority does not work, so an interactive sign-in has to be pointed at the
// same cloud the scope belongs to.
func registryCloud(registry string) cloud.Configuration {
	host := registryHost(registry)
	for _, candidate := range armScopes {
		if strings.HasSuffix(host, candidate.suffix) {
			return candidate.cloud
		}
	}
	return cloud.AzurePublic
}

// acrTokenUsername is the sentinel username ACR expects when the password is a
// registry refresh token.
const acrTokenUsername = "00000000-0000-0000-0000-000000000000"

// azureRegistrySuffixes are the Azure Container Registry DNS suffixes across
// the public and sovereign clouds. Azure Germany is omitted: it was
// decommissioned, and its authority is no longer one the SDK can sign in
// against.
var azureRegistrySuffixes = []string{
	".azurecr.io",
	".azurecr.cn",
	".azurecr.us",
}

// registryHost strips any port and IPv6 brackets from a registry authority.
func registryHost(registry string) string {
	host := registry
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// authorityList splits a comma separated list and canonicalises each entry with
// the caller's scheme semantics, so an allowlist is compared the same way the
// endpoint it guards will actually be reached.
func authorityList(raw string, canonical func(string) string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	entries := strings.Split(raw, ",")
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry = strings.TrimSpace(entry); entry != "" {
			out = append(out, canonical(entry))
		}
	}
	return out
}

// httpsAuthority canonicalises for an endpoint that is always reached over
// HTTPS, so only :443 collapses.
func httpsAuthority(registry string) string {
	return canonicalAuthority(registry, "https")
}

// trustedEntraHosts returns extra registry hosts explicitly opted in via
// BBB_ACR_ENTRA_HOSTS, for ACR deployments behind a custom domain.
//
// Entries use HTTPS semantics because the Entra exchange always posts over
// HTTPS, whatever BBB_ACR_INSECURE says: an entry for :80 must not collapse to
// a bare host and thereby authorise sending a live Azure token to :443.
func trustedEntraHosts() []string {
	return authorityList(os.Getenv("BBB_ACR_ENTRA_HOSTS"), httpsAuthority)
}

// hasAzureSuffix reports whether host is an Azure Container Registry endpoint
// by DNS suffix.
func hasAzureSuffix(host string) bool {
	for _, suffix := range azureRegistrySuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// isACR reports whether registry is an Azure Container Registry endpoint that
// may be offered Entra credentials.
//
// The exchange posts a live Azure access token to the registry, so it must not
// be attempted against any host that merely answers with a bearer challenge —
// a private ghcr.io repository would otherwise receive the caller's Azure
// credential. Everything else falls through to the Docker keychain.
func isACR(registry string) bool {
	return slices.Contains(trustedEntraHosts(), httpsAuthority(registry)) ||
		hasAzureSuffix(registryHost(registry))
}

// basicCredentials returns explicitly configured registry credentials for
// registry, if they apply to it.
//
// One invocation can address several registries, so these are only ever sent
// to the hosts named in BBB_ACR_REGISTRY. An Azure suffix is not a scope:
// anyone can own a *.azurecr.io registry, so a taskfile touching two of them
// would send credentials meant for one to the other — the same disclosure the
// Entra gate exists to prevent, against a password rather than a token.
func basicCredentials(registry string) (string, string, bool) {
	user := os.Getenv("BBB_ACR_USERNAME")
	pass := os.Getenv("BBB_ACR_PASSWORD")
	if user == "" || pass == "" {
		return "", "", false
	}
	// Scoped with the registry's effective transport, so an insecure endpoint
	// keeps host and host:443 distinct: over HTTP they are different services,
	// and the password must not follow the collapse.
	scoped := authorityList(os.Getenv("BBB_ACR_REGISTRY"), registryKey)
	if len(scoped) == 0 {
		slog.Debug("acr: registry credentials are ignored until BBB_ACR_REGISTRY names the hosts they belong to",
			"registry", registry)
		return "", "", false
	}
	if !slices.Contains(scoped, registryKey(registry)) {
		return "", "", false
	}
	return user, pass, true
}

// defaultCreds holds one process credential per cloud, keyed by that cloud's
// identity authority.
var defaultCreds sync.Map

type defaultCredential struct {
	once sync.Once
	cred azcore.TokenCredential
	err  error
}

// getCredential returns the ambient credential — CLI login, service principal,
// managed identity, workload identity — for a registry's cloud.
//
// The cloud belongs to the credential and not only to the scope asked of it: a
// service principal or workload identity authenticates against an authority,
// and the public-cloud one issues nothing for .azurecr.cn or .azurecr.us. One
// credential per cloud also lets a single run address more than one, which a
// process-wide credential built from whichever registry came first cannot.
func getCredential(registry string) (azcore.TokenCredential, error) {
	config := registryCloud(registry)
	entry, _ := defaultCreds.LoadOrStore(config.ActiveDirectoryAuthorityHost, &defaultCredential{})
	e := entry.(*defaultCredential)
	e.once.Do(func() {
		opts := &azidentity.DefaultAzureCredentialOptions{}
		opts.Cloud = config
		if c := sharedClient.Load(); c != nil {
			opts.Transport = c
		}
		e.cred, e.err = azidentity.NewDefaultAzureCredential(opts)
	})
	return e.cred, e.err
}

// tenantClaims is the subset of an Entra access token used to tell which
// tenant issued it.
type tenantClaims struct {
	Tid string `json:"tid"`
}

// tenantIDFromAccessToken returns the tid claim of an Entra access token, or
// "" when it cannot be read.
//
// The token is not verified. This only decides whether the credential we hold
// belongs to the tenant we need, never whether to trust anything: presenting a
// home-tenant token to a registry in another tenant is the mistake being
// caught, and the registry still validates it properly.
func tenantIDFromAccessToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims tenantClaims
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Tid
}

// envAuthorityKey renders a registry authority as an environment variable
// suffix, so a host can name its own setting.
func envAuthorityKey(authority string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, authority)
}

// registryTenantID returns the Entra tenant a registry should be authenticated
// against, or "" to use the credential's own default.
//
// Unlike a storage account, an ACR endpoint does not advertise its tenant: the
// WWW-Authenticate challenge carries only realm and service, with no
// authorization_uri to discover one from, and a registry in another tenant is
// invisible to Resource Manager until you already hold a token for it. The
// tenant therefore has to be configured whenever it is not the credential's
// home tenant, which is why the mismatch is reported so explicitly below.
//
// The host form wins over the short name, so a specific endpoint can override
// a broader default.
func registryTenantID(registry string) string {
	host := registryHost(registry)
	keys := []string{host}
	if short, _, found := strings.Cut(host, "."); found && short != "" {
		keys = append(keys, short)
	}
	for _, key := range keys {
		name := "BBB_ACR_TENANT_" + envAuthorityKey(key)
		if v := strings.TrimSpace(os.Getenv(strings.ToUpper(name))); v != "" {
			return v
		}
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(os.Getenv("BBB_ACR_TENANT"))
}

var (
	// tenantCredCache holds one credential per tenant, and tenantCredInflight
	// serialises acquisition so concurrent transfers open a single login
	// prompt rather than one each.
	//
	// The tenant alone is the key: an Entra tenant exists in exactly one
	// sovereign instance, so a tenant ID already implies its cloud. The
	// ambient credential is keyed by cloud instead, since it has no tenant to
	// imply one.
	tenantCredCache    sync.Map // map[string]azcore.TokenCredential
	tenantCredInflight sync.Map // map[string]*sync.Mutex
)

// discoveredTenants records the tenant an interactive sign-in turned out to be
// for, keyed by registry, so a token refresh later in the run goes straight to
// the credential that worked instead of prompting again.
var discoveredTenants sync.Map // map[string]string

// promptAllowed is indirected so tests can exercise the sign-in path without a
// terminal.
var promptAllowed = canPrompt

// canPrompt reports whether it is reasonable to ask the user to sign in.
//
// A sign-in that nobody can answer is worse than an error: it would hang a
// pipeline until the credential timed out. BBB_ACR_NO_LOGIN forces the same
// decision for an interactive shell that should never prompt.
func canPrompt() bool {
	if disabled, err := strconv.ParseBool(os.Getenv("BBB_ACR_NO_LOGIN")); err == nil && disabled {
		return false
	}
	return isCharDevice(os.Stdin) || isCharDevice(os.Stderr)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// interactiveLogin and cliCredentialFor are indirected so tests never open a
// browser or depend on the Azure CLI being installed.
var (
	interactiveLogin = browserOrDeviceCodeCredential
	cliCredentialFor = func(tenant string) (azcore.TokenCredential, error) {
		return azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{TenantID: tenant})
	}
)

// credentialForRegistry returns the credential to authenticate registry with.
//
// Without a configured tenant this is the process default, matching how every
// other Azure-backed path in bbb behaves. With one, it mirrors az://: try the
// Azure CLI for that tenant, confirm the token really is for it, and otherwise
// sign in interactively.
func credentialForRegistry(ctx context.Context, registry string) (azcore.TokenCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tid := registryTenantID(registry)
	if tid == "" {
		// A sign-in earlier in this run already established which tenant this
		// registry answers to, so reuse it rather than repeating the exchange
		// failure that discovered it.
		if found, ok := discoveredTenants.Load(registryKey(registry)); ok {
			tid = found.(string)
		}
	}
	if tid == "" {
		return getCredential(registry)
	}
	if cached, ok := tenantCredCache.Load(tid); ok {
		return cached.(azcore.TokenCredential), nil
	}

	inflight, _ := tenantCredInflight.LoadOrStore(tid, newGate())
	if err := inflight.(gate).acquire(ctx); err != nil {
		return nil, err
	}
	defer inflight.(gate).release()
	if cached, ok := tenantCredCache.Load(tid); ok {
		return cached.(azcore.TokenCredential), nil
	}
	// Waiting for the gate can outlast the caller: a sign-in that was
	// interrupted must not be restarted by whoever was queued behind it.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	scope := armScope(registry)
	if cli, err := cliCredentialFor(tid); err == nil {
		token, tokenErr := cli.GetToken(ctx, policyTokenRequest(scope))
		switch {
		case tokenErr != nil:
			// Typically Status_InteractionRequired: az knows the account but
			// its cached token has lapsed and it cannot refresh unattended.
			slog.Debug("acr: the Azure CLI cannot serve this tenant, signing in interactively",
				"registry", registry, "tenant", tid, "error", tokenErr)
			explainCLIFallback(tid)
		case !tenantMatches(token.Token, tid):
			// az can hold a token only for the home tenant and hand that back
			// regardless of what was asked for; presenting it would fail at
			// the registry with the same mismatch this exists to avoid.
			slog.Debug("acr: the Azure CLI returned a token for another tenant, signing in interactively",
				"registry", registry, "want", tid, "got", tenantIDFromAccessToken(token.Token))
			explainCLIFallback(tid)
		default:
			slog.Debug("acr: using the Azure CLI credential", "registry", registry, "tenant", tid)
			tenantCredCache.Store(tid, cli)
			return cli, nil
		}
	}

	if !promptAllowed() {
		// The same gate the tenant-mismatch path uses: a sign-in nobody can
		// answer would hang a pipeline until the credential timed out.
		return nil, fmt.Errorf(
			"acr: the Azure CLI has no usable token for tenant %s and signing in is unavailable; run: az login --tenant %s",
			tid, tid)
	}
	credential, err := interactiveLogin(ctx, registry, tid, scope)
	if err != nil {
		return nil, err
	}
	tenantCredCache.Store(tid, credential)
	return credential, nil
}

// explainCLIFallback says why a sign-in is being opened despite the Azure CLI
// being available.
//
// Without this the prompt looks like the CLI was ignored, when in fact it was
// asked and could not answer: a profile can be signed in to a tenant and still
// hold no usable token for it, which is invisible unless it is said out loud.
// explainedTenants ensures the fallback is explained once per tenant, not once
// per caller: `ls` resolves credentials from more than one place, and repeating
// the same paragraph reads like something went wrong twice.
var explainedTenants sync.Map

func explainCLIFallback(tenant string) {
	if _, seen := explainedTenants.LoadOrStore(tenant, struct{}{}); seen {
		return
	}
	fmt.Fprintf(os.Stderr,
		"\n  The Azure CLI has no usable token for tenant %s; `az login --tenant %s` would avoid this prompt.\n",
		tenant, tenant)
}

// cliTenantList is indirected so tests do not depend on the Azure CLI.
var cliTenantList = azureCLITenants

// cliListTimeout bounds the tenant lookup, which is a convenience rather than
// something worth stalling a transfer for.
const cliListTimeout = 15 * time.Second

// maxTenantAttempts caps how many tenants are tried before falling back to
// asking, so a user signed in to many tenants is not made to wait through all
// of them.
const maxTenantAttempts = 8

// azureCLITenants returns the tenants the Azure CLI has accounts for.
//
// An ACR endpoint never says which tenant it belongs to, so when the default
// credential is rejected the next best source is the set of tenants the user
// has already signed in to. Asking az rather than Resource Manager matters: a
// tenant reached with a separate account is absent from ARM's /tenants for the
// current one, which is exactly the case that fails.
//
// AZURE_CONFIG_DIR is honoured because az reads it, so this follows whichever
// profile the caller selected.
func azureCLITenants(ctx context.Context) []string {
	ctx, cancel := context.WithTimeout(ctx, cliListTimeout)
	defer cancel()

	args := []string{"account", "list", "--all", "--query", "[].tenantId", "-o", "tsv"}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// az ships as a batch file on Windows, which is not directly
		// executable.
		cmd = exec.CommandContext(ctx, "cmd.exe", append([]string{"/c", "az"}, args...)...)
	} else {
		cmd = exec.CommandContext(ctx, "az", args...)
	}
	out, err := cmd.Output()
	if err != nil {
		slog.Debug("acr: could not list Azure CLI tenants", "error", err)
		return nil
	}
	var tenants []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if tenant := strings.TrimSpace(line); tenant != "" && !slices.Contains(tenants, tenant) {
			tenants = append(tenants, tenant)
		}
	}
	return tenants
}

// tenantMatches reports whether a token was issued by the expected tenant. An
// unreadable tid is accepted rather than triggering a needless login: the
// registry is the real authority, and this is only an early check.
func tenantMatches(token, tenant string) bool {
	got := tenantIDFromAccessToken(token)
	return got == "" || strings.EqualFold(got, tenant)
}

// browserOrDeviceCodeCredential signs the user in, falling back to the device
// code flow when no browser can be opened. bbb is routinely run over SSH and
// inside WSL, where the browser flow cannot complete, and a device code still
// lets the sign-in finish.
//
// An empty tenant means the registry's tenant is unknown, which is the normal
// case: the sign-in then uses the default multi-tenant authority so the user
// can pick an account that belongs to the registry's tenant.
func browserOrDeviceCodeCredential(ctx context.Context, registry, tenant, scope string) (azcore.TokenCredential, error) {
	if tenant == "" {
		fmt.Fprintf(os.Stderr, "\n  Your Azure sign-in is not valid for %q.\n"+
			"  Opening a browser — choose an account in the registry's tenant.\n", registry)
	} else {
		fmt.Fprintf(os.Stderr, "\n  Registry %q requires an Entra sign-in to tenant %s.\n  Opening a browser...\n", registry, tenant)
	}
	browserOpts := &azidentity.InteractiveBrowserCredentialOptions{TenantID: tenant}
	browserOpts.Cloud = registryCloud(registry)
	if c := sharedClient.Load(); c != nil {
		browserOpts.Transport = c
	}
	browser, err := azidentity.NewInteractiveBrowserCredential(browserOpts)
	if err == nil {
		// Acquire eagerly so the prompt appears here, once, rather than from
		// whichever parallel transfer happens to need a token first.
		if _, tokenErr := browser.GetToken(ctx, policyTokenRequest(scope)); tokenErr == nil {
			return browser, nil
		} else if ctx.Err() != nil {
			return nil, tokenErr
		} else {
			slog.Debug("acr: browser sign-in unavailable, falling back to a device code",
				"registry", registry, "tenant", tenant, "error", tokenErr)
		}
	}

	deviceOpts := &azidentity.DeviceCodeCredentialOptions{
		TenantID: tenant,
		UserPrompt: func(_ context.Context, message azidentity.DeviceCodeMessage) error {
			fmt.Fprintf(os.Stderr, "\n  %s\n\n", message.Message)
			return nil
		},
	}
	deviceOpts.Cloud = registryCloud(registry)
	if c := sharedClient.Load(); c != nil {
		deviceOpts.Transport = c
	}
	device, err := azidentity.NewDeviceCodeCredential(deviceOpts)
	if err != nil {
		return nil, fmt.Errorf("acr: interactive sign-in: %w", err)
	}
	if _, err := device.GetToken(ctx, policyTokenRequest(scope)); err != nil {
		return nil, fmt.Errorf("acr: interactive sign-in: %w", err)
	}
	return device, nil
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

// tokenExchangeTimeout is an upper bound on a renewal, so a hung Entra or
// registry endpoint cannot stall a transfer indefinitely. It is applied on top
// of the caller's context rather than replacing it.
const tokenExchangeTimeout = 2 * time.Minute

// exchangeToken is indirected so tests can drive token renewal without
// contacting Entra ID or a registry.
var exchangeToken = exchangeEntraToken

// go-containerregistry hands the in-flight request's context to
// AuthorizationContext when an authenticator implements it, and falls back to
// Authorization when it does not. Implementing both means a renewal triggered
// mid-transfer is cancelled with the transfer instead of running on to the
// timeout.
var (
	_ authn.Authenticator        = (*acrAuthenticator)(nil)
	_ authn.ContextAuthenticator = (*acrAuthenticator)(nil)
)

func (a *acrAuthenticator) Authorization() (*authn.AuthConfig, error) {
	return a.AuthorizationContext(context.Background())
}

func (a *acrAuthenticator) AuthorizationContext(ctx context.Context) (*authn.AuthConfig, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.token == "" || time.Now().After(a.expires) {
		ctx, cancel := context.WithTimeout(ctx, tokenExchangeTimeout)
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

// authEntry memoises the credentials for one registry. A nil authenticator on a
// resolved entry means "fall back to the Docker keychain".
//
// The lock is held across the whole attempt, not just the bookkeeping, because
// the attempt can open an interactive sign-in: a second caller for the same
// registry must wait for that to finish and reuse the result rather than
// opening a prompt of its own.
type authEntry struct {
	mu       sync.Mutex
	resolved bool
	auth     authn.Authenticator
	// err records a failure that no retry can fix, so it is reported rather
	// than replaced by an anonymous request.
	err error
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
	if user, pass, ok := basicCredentials(registry); ok {
		return remote.WithAuth(&authn.Basic{Username: user, Password: pass})
	}

	value, _ := authCache.LoadOrStore(registryKey(registry), &authEntry{})
	entry := value.(*authEntry)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if !entry.resolved {
		entry.resolve(ctx, registry)
	}

	switch {
	case entry.err != nil:
		return remote.WithAuth(&failedAuthenticator{err: entry.err})
	case entry.auth != nil:
		return remote.WithAuth(entry.auth)
	default:
		return remote.WithAuthFromKeychain(authn.DefaultKeychain)
	}
}

// resolve performs the Entra exchange for registry. The caller holds e.mu.
//
// A transient failure deliberately leaves the entry unresolved so the next
// attempt tries again: a timeout or network blip must not disable Entra for
// the rest of the run, long after it recovered.
func (e *authEntry) resolve(ctx context.Context, registry string) {
	// A previous transient failure must not outlive the attempt that retries
	// it: authOption reports e.err ahead of e.auth, so leaving it set would
	// keep serving the outage even once a token had been obtained.
	e.err = nil
	if !isACR(registry) {
		slog.Debug("acr: not an Azure Container Registry endpoint, using the Docker keychain",
			"registry", registry)
		e.resolved = true
		return
	}
	// Exchange once up front so an unusable credential falls back to the
	// keychain now rather than failing mid-transfer; the authenticator renews
	// itself from then on.
	token, err := exchangeToken(ctx, registry)
	if err == nil {
		e.auth = &acrAuthenticator{
			registry: registry,
			token:    token,
			expires:  tokenExpiry(token),
		}
		e.resolved = true
		return
	}

	if _, rejected := rejectedTenant(err); rejected || errors.Is(err, errTenantMismatch) {
		// The identity is wrong and retrying cannot fix it, so this is
		// remembered: another request must not reopen the sign-in that was
		// just declined. Falling through to an anonymous request would also
		// replace the explanation with a bare 401 from the registry, so the
		// error is kept unless the keychain can actually serve this registry.
		e.resolved = true
		if keychainCanServe(registry) {
			slog.Debug("acr: Entra rejected the tenant, using a stored registry credential",
				"registry", registry, "error", err)
			return
		}
		e.err = err
		return
	}
	if isTransient(err) && !keychainCanServe(registry) {
		// A timeout or a cancelled exchange says nothing about whether the
		// caller may read this registry. Falling through would send an
		// anonymous request, and a private registry answers that with a 401
		// the retry layer treats as final — turning a passing outage into a
		// permanent failure with the cause replaced. The entry stays
		// unresolved so the next attempt tries the exchange again.
		e.err = err
		return
	}
	slog.Debug("acr: Entra ID authentication unavailable, falling back to the Docker keychain",
		"registry", registry, "error", err)
	// Definitive: there is no Azure credential to be had, so the keychain is
	// the answer for the rest of the run rather than something to rediscover
	// on every operation.
	e.resolved = true
}

// isTransient reports whether an exchange failure is worth retrying, as
// opposed to meaning no Azure credential is available at all — the latter is a
// legitimate reason to fall back to the keychain and to anonymous pull.
func isTransient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		// The registry or Entra was unable to answer rather than unwilling.
		return responseErr.StatusCode >= 500 || responseErr.StatusCode == http.StatusTooManyRequests
	}
	return false
}

// keychainCanServe reports whether a stored registry credential exists, so a
// user who has run `docker login` is not blocked by an Entra problem that does
// not apply to them.
func keychainCanServe(registry string) bool {
	parsed, err := name.NewRegistry(registry, name.WeakValidation)
	if err != nil {
		return false
	}
	auth, err := authn.DefaultKeychain.Resolve(parsed)
	if err != nil || auth == authn.Anonymous {
		return false
	}
	config, err := auth.Authorization()
	if err != nil || config == nil {
		return false
	}
	return config.Username != "" || config.Password != "" ||
		config.Auth != "" || config.IdentityToken != "" || config.RegistryToken != ""
}

// failedAuthenticator reports why authentication could not be established.
//
// go-containerregistry has no way to refuse a request up front, so the reason
// is carried here and surfaced the moment a token is needed. Without it the
// request proceeds anonymously and the user sees the registry's 401 instead of
// the actual cause.
type failedAuthenticator struct{ err error }

func (a *failedAuthenticator) Authorization() (*authn.AuthConfig, error) {
	return nil, a.err
}

func (a *failedAuthenticator) AuthorizationContext(context.Context) (*authn.AuthConfig, error) {
	return nil, a.err
}

// exchangeTransport returns the HTTP client used to post an Entra token to a
// registry's token endpoint.
//
// The request body carries a live Azure access token, so a redirect must not
// be followed: a 307 or 308 preserves the method and body, and the Go client
// would replay both to wherever the Location points, including a host inside
// the caller's network. The registry has no legitimate reason to redirect this
// call, so any redirect is refused rather than validated.
func exchangeTransport(registry string) *http.Client {
	base := http.DefaultClient
	if c := sharedClient.Load(); c != nil {
		base = c
	}
	client := *base
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		return fmt.Errorf("acr: refusing to follow a redirect from the %s token endpoint to %s", registry, req.URL.Host)
	}
	return &client
}

var tokenCredential = credentialForRegistry

// tenantMismatchRe matches the rejection ACR returns for a token issued by a
// tenant it does not know, which is the usual outcome of running against a
// registry outside the credential's home tenant.
var tenantMismatchRe = regexp.MustCompile(`unknown tenant[iI]d\s*\\?"([0-9a-fA-F-]{36})\\?"`)

// rejectedTenant reports the tenant a registry refused, if that is why an
// exchange failed. The tenant named is the one that was presented, not the one
// the registry wants: ACR never reveals which tenant it belongs to.
func rejectedTenant(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	match := tenantMismatchRe.FindStringSubmatch(err.Error())
	if match == nil {
		return "", false
	}
	return match[1], true
}

// tenantMismatchError explains a rejected tenant in terms of what to do about
// it, because the alternative is an anonymous request and a bare 401 from the
// registry that says nothing about the cause.
// errTenantMismatch marks a rejection that reflects the identity in use rather
// than a transient problem, so callers can recognise it after formatting.
var errTenantMismatch = errors.New("acr: registry rejected the credential's tenant")

func tenantMismatchError(registry, presented string) error {
	host := registryHost(registry)
	return fmt.Errorf(
		"%w: %s was sent a token issued for tenant %s, which it does not recognise.\n"+
			"The registry belongs to a different Entra tenant, and an ACR endpoint does not advertise which one.\n"+
			"Set BBB_ACR_TENANT_%s=<tenant-id> to have bbb sign in to it, or run: az login --tenant <tenant-id>",
		errTenantMismatch, host, presented, strings.ToUpper(envAuthorityKey(host)))
}

// exchangeEntraToken trades an Entra ID access token for an ACR refresh token,
// using the Azure SDK rather than a hand-rolled OAuth flow.
//
// It deliberately stops at the refresh token. ACR access tokens are scoped to
// specific repositories — there is no all-repository wildcard — so requesting
// one here would either be rejected or be valid for the wrong repository.
// go-containerregistry instead presents the refresh token per request and lets
// the registry's challenge name the exact scope, which is the same flow docker
// uses after `az acr login`.
//
// When the registry turns out to belong to another tenant, the sign-in is
// offered here rather than reported as an error. az:// can discover a storage
// account's tenant from the authorization_uri in its challenge and prompt
// before ever making a request; no ACR endpoint returns one — every challenge
// carries only realm, service and scope — so the rejection is the first and
// only evidence, and the prompt has to come after it.
func exchangeEntraToken(ctx context.Context, registry string) (string, error) {
	credential, err := tokenCredential(ctx, registry)
	if err != nil {
		return "", err
	}
	configured := registryTenantID(registry)
	token, err := exchangeWithCredential(ctx, registry, credential, configured)
	if err == nil {
		return token, nil
	}
	presented, mismatch := rejectedTenant(err)
	if !mismatch {
		return "", err
	}
	// A tenant that was named explicitly and still rejected is a wrong
	// setting; signing in again would only ask the same question.
	if configured != "" {
		return "", tenantMismatchError(registry, presented)
	}

	// Serialised so two registries in the same foreign tenant do not each open
	// a sign-in: whoever waits here re-checks the cached credentials first.
	if err := unknownTenantRecovery.acquire(ctx); err != nil {
		return "", err
	}
	defer unknownTenantRecovery.release()

	// The registry will not say which tenant it belongs to, but a sign-in
	// earlier in this run, or the Azure CLI, may already have one that works.
	// Trying those costs nothing visible and avoids a prompt whenever one of
	// them is the answer.
	if token, tenant, ok := exchangeViaKnownTenants(ctx, registry, presented); ok {
		slog.Debug("acr: authenticated with a tenant the Azure CLI already knows",
			"registry", registry, "tenant", tenant)
		discoveredTenants.Store(registryKey(registry), tenant)
		return token, nil
	}

	if !promptAllowed() {
		return "", tenantMismatchError(registry, presented)
	}
	// An interrupted sign-in must not be reopened by the next caller.
	if err := ctx.Err(); err != nil {
		return "", err
	}

	signedIn, err := interactiveLogin(ctx, registry, "", armScope(registry))
	if err != nil {
		return "", errors.Join(tenantMismatchError(registry, presented), err)
	}
	token, err = exchangeWithCredential(ctx, registry, signedIn, "")
	if err != nil {
		if rejected, ok := rejectedTenant(err); ok {
			return "", tenantMismatchError(registry, rejected)
		}
		return "", err
	}
	rememberTenant(ctx, registry, signedIn)
	return token, nil
}

// gate is a mutex a waiter can abandon.
//
// Acquisition here can sit behind an interactive sign-in, which lasts as long
// as the user takes. A plain sync.Mutex would keep a cancelled caller blocked
// for all of it, so waiters select on their own context instead.
type gate chan struct{}

func newGate() gate {
	g := make(gate, 1)
	g <- struct{}{}
	return g
}

func (g gate) acquire(ctx context.Context) error {
	select {
	case <-g:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g gate) release() { g <- struct{}{} }

// unknownTenantRecovery serialises the tenant-unknown path, so two registries
// in the same foreign tenant do not each open a sign-in. The cached credential
// the first one obtained is tried before anything is asked of the user.
var unknownTenantRecovery = newGate()

// exchangeViaKnownTenants retries the exchange with tenants already available:
// those an interactive sign-in established earlier in this run, then those the
// Azure CLI is signed in to. The tenant the registry just rejected is skipped.
//
// Each attempt is silent: a tenant whose session has lapsed fails immediately
// rather than prompting, so this only ever converts a sign-in into no sign-in.
func exchangeViaKnownTenants(ctx context.Context, registry, rejected string) (token, tenant string, ok bool) {
	// A credential obtained for another registry in the same tenant is the
	// cheapest answer, and the reason the one-sign-in-per-tenant guarantee
	// holds across registries rather than only within one.
	var cached []string
	tenantCredCache.Range(func(key, _ any) bool {
		cached = append(cached, key.(string))
		return true
	})
	for _, candidate := range cached {
		if strings.EqualFold(candidate, rejected) {
			continue
		}
		value, loaded := tenantCredCache.Load(candidate)
		if !loaded {
			continue
		}
		credential := value.(azcore.TokenCredential)
		if refresh, err := exchangeWithCredential(ctx, registry, credential, candidate); err == nil {
			return refresh, candidate, true
		}
	}

	tenants := cliTenantList(ctx)
	attempts := 0
	for _, candidate := range tenants {
		if strings.EqualFold(candidate, rejected) || slices.Contains(cached, candidate) {
			continue
		}
		if attempts >= maxTenantAttempts {
			break
		}
		attempts++

		credential, err := cliCredentialFor(candidate)
		if err != nil {
			continue
		}
		aad, err := credential.GetToken(ctx, policyTokenRequest(armScope(registry)))
		if err != nil || !tenantMatches(aad.Token, candidate) {
			// A lapsed session reports that it needs interaction, and az can
			// return a home-tenant token whatever was asked for; neither is
			// worth presenting to the registry.
			continue
		}
		refresh, err := exchangeWithCredential(ctx, registry, credential, candidate)
		if err != nil {
			continue
		}
		tenantCredCache.Store(candidate, credential)
		return refresh, candidate, true
	}
	return "", "", false
}

// rememberTenant caches a credential obtained interactively under the tenant
// that issued it, so a token refresh or another registry in the same tenant
// does not prompt again, and tells the user how to skip the prompt next run.
func rememberTenant(ctx context.Context, registry string, credential azcore.TokenCredential) {
	token, err := credential.GetToken(ctx, policyTokenRequest(armScope(registry)))
	if err != nil {
		return
	}
	tenant := tenantIDFromAccessToken(token.Token)
	if tenant == "" {
		return
	}
	tenantCredCache.Store(tenant, credential)
	discoveredTenants.Store(registryKey(registry), tenant)
	fmt.Fprintf(os.Stderr, "  Signed in to tenant %s. Set BBB_ACR_TENANT_%s=%s to skip this prompt.\n\n",
		tenant, strings.ToUpper(envAuthorityKey(registryHost(registry))), tenant)
}

// exchangeWithCredential performs the ACR half of the exchange. tenant, when
// known, is passed along because it is how ACR resolves a guest identity.
func exchangeWithCredential(ctx context.Context, registry string, credential azcore.TokenCredential, tenant string) (string, error) {
	options := &azcontainerregistry.AuthenticationClientOptions{}
	options.Transport = exchangeTransport(registry)
	client, err := azcontainerregistry.NewAuthenticationClient("https://"+registry, options)
	if err != nil {
		return "", err
	}
	aadToken, err := credential.GetToken(ctx, policyTokenRequest(armScope(registry)))
	if err != nil {
		return "", err
	}
	exchange := &azcontainerregistry.AuthenticationClientExchangeAADAccessTokenForACRRefreshTokenOptions{
		AccessToken: &aadToken.Token,
	}
	if tenant != "" {
		exchange.Tenant = &tenant
	}
	refresh, err := client.ExchangeAADAccessTokenForACRRefreshToken(
		ctx,
		azcontainerregistry.PostContentSchemaGrantTypeAccessToken,
		registry,
		exchange,
	)
	if err != nil {
		return "", err
	}
	if refresh.RefreshToken == nil {
		return "", errEmptyToken
	}
	return *refresh.RefreshToken, nil
}
