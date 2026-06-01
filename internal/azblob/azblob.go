package azblob

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/streaming"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/service"
)

// --- Cached credentials and clients ---
// These are safe for concurrent use and amortize the cost of credential
// acquisition across all API calls in the process lifetime.

var (
	cachedDefaultCred     *azidentity.DefaultAzureCredential
	cachedDefaultCredOnce sync.Once
	cachedDefaultCredErr  error

	// Per-account blob client cache (thread-safe via sync.Map).
	blobClientCache sync.Map // map[string]*azblob.Client

	// Per-tenant credential cache (thread-safe via sync.Map).
	tenantCredCache    sync.Map // map[string]azcore.TokenCredential
	tenantCredInflight sync.Map // map[string]*sync.Mutex — serializes credential acquisition per tenant

	// Per-account role mapping for multi-tenant env var support.
	// Maps account name → role ("SRC" or "DST").
	accountRoles sync.Map // map[string]string

	// Per-role credential cache for SRC_AZURE_* / DST_AZURE_* env vars.
	roleCredCache sync.Map // map[string]azcore.TokenCredential
)

// MkContainer creates a new Azure Blob container
func MkContainer(ctx context.Context, account, container string) error {
	client, err := getAzBlobClient(ctx, account)
	if err != nil {
		return err
	}
	containerClient := client.ServiceClient().NewContainerClient(container)
	_, err = containerClient.Create(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "ContainerAlreadyExists" {
			// ignore if already exists (idempotent)
			return nil
		}
		return err
	}
	return nil
}

// AzurePath represents an az:// path (account/container/blob)
type AzurePath struct {
	Account   string
	Container string
	Blob      string // may be empty or end with '/' for virtual directory
}

var accountNameRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`) // compiled once during package initialization
var containerNameRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
var validBlobSuffixes = []string{
	".blob.core.windows.net",
	".blob.core.chinacloudapi.cn",
	".blob.core.usgovcloudapi.net",
	".blob.core.cloudapi.de",
	".blob.localhost",
}

const (
	defaultCopySASExpiry     = time.Hour
	clockSkewTolerance       = 5 * time.Minute   // backdate SAS start to tolerate clock differences
	copyBlockSize            = 8 * 1024 * 1024 // Default 8 MiB per StageBlockFromURL block; matches azcopy's S2S sweet spot. Smaller blocks let Azure's destination pipeline more PBFU operations in parallel per blob, dramatically improving S2S throughput vs the 256 MiB used for client-side uploads.
	copyBlockSizeEnv         = "BBB_AZBLOB_COPY_BLOCK_MIB"
	copyPollInitialDelay     = 100 * time.Millisecond
	copyPollMaxDelay         = 2 * time.Second
	uploadStreamMiB          = 1 << 20
	uploadStreamBlockMin     = 256 * uploadStreamMiB  // Default UploadStream minimum block size.
	uploadStreamBlockMax     = 4000 * uploadStreamMiB // Azure UploadStream maximum block size.
	uploadStreamBlockBase    = 256 * uploadStreamMiB  // Default block size when stream size is unknown.
	uploadStreamMaxBlocks    = 100000                 // Azure block upload limit (newer API).
	uploadStreamBlockMinEnv  = "AZ_BLOB_UPLOAD_STREAM_BLOCK_MIN_MIB"
	uploadStreamBlockMaxEnv  = "AZ_BLOB_UPLOAD_STREAM_BLOCK_MAX_MIB"
	uploadStreamBlockBaseEnv = "AZ_BLOB_UPLOAD_STREAM_BLOCK_BASE_MIB"
)

// IsBlobURL performs a lightweight check whether the provided string is a blob endpoint URL.
func IsBlobURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	var matchedSuffix string
	for _, suffix := range validBlobSuffixes {
		if strings.HasSuffix(host, suffix) {
			matchedSuffix = suffix
			break
		}
	}
	if matchedSuffix == "" {
		return false
	}
	hostParts := strings.Split(host, ".")
	if len(hostParts) < 3 || hostParts[0] == "" {
		return false
	}
	if !accountNameRe.MatchString(hostParts[0]) {
		return false
	}
	trimmed := strings.TrimPrefix(u.Path, "/")
	if trimmed == "" {
		return false
	}
	container := strings.SplitN(trimmed, "/", 2)[0]
	return validContainerName(container)
}

func (p AzurePath) IsDirLike() bool { return p.Blob == "" || strings.HasSuffix(p.Blob, "/") }
func (p AzurePath) WithDir() AzurePath {
	if p.Blob == "" || strings.HasSuffix(p.Blob, "/") {
		return p
	}
	p.Blob += "/"
	return p
}
func (p AzurePath) Child(rel string) AzurePath {
	if p.Blob == "" {
		return AzurePath{p.Account, p.Container, rel}
	}
	return AzurePath{p.Account, p.Container, path.Clean(p.Blob + "/" + rel)}
}
func (p AzurePath) String() string {
	// Handle account-only
	if p.Container == "" {
		if p.Blob != "" { // unusual but handle
			return fmt.Sprintf("az://%s/%s", p.Account, p.Blob)
		}
		return fmt.Sprintf("az://%s", p.Account)
	}
	if p.Blob == "" {
		return fmt.Sprintf("az://%s/%s", p.Account, p.Container)
	}
	return fmt.Sprintf("az://%s/%s/%s", p.Account, p.Container, p.Blob)
}

// Parse parses az://account/container[/blob] or https://account.blob.* URLs.
func Parse(raw string) (AzurePath, error) {
	if strings.HasPrefix(raw, "az://") {
		rest := raw[5:]
		if rest == "" {
			return AzurePath{}, errors.New("expected az://account[/container[/blob]]")
		}
		parts := strings.SplitN(rest, "/", 3)
		switch len(parts) {
		case 1:
			// account only
			return AzurePath{Account: parts[0]}, nil
		case 2:
			return AzurePath{Account: parts[0], Container: parts[1]}, nil
		case 3:
			return AzurePath{Account: parts[0], Container: parts[1], Blob: parts[2]}, nil
		default:
			return AzurePath{}, errors.New("invalid az path")
		}
	}

	u, err := url.Parse(raw)
	if err != nil {
		return AzurePath{}, fmt.Errorf("not az:// or https:// path: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "http" || scheme == "https" {
		host := strings.ToLower(u.Hostname()) // Hostname strips port; suffix validation does not require it
		if host == "" {
			return AzurePath{}, fmt.Errorf("not az blob path: %s", raw)
		}
		var matchedSuffix string
		for _, suffix := range validBlobSuffixes {
			if strings.HasSuffix(host, suffix) {
				matchedSuffix = suffix
				break
			}
		}
		if matchedSuffix == "" {
			return AzurePath{}, fmt.Errorf("not az blob path: %s", raw)
		}
		hostParts := strings.Split(host, ".")
		if len(hostParts) < 3 || hostParts[0] == "" {
			return AzurePath{}, fmt.Errorf("not az blob path: %s", raw)
		}
		account := hostParts[0]
		if !accountNameRe.MatchString(account) {
			return AzurePath{}, fmt.Errorf("not az blob path: %s", raw)
		}
		trimmed := strings.TrimPrefix(u.Path, "/")
		if trimmed == "" {
			return AzurePath{Account: account}, nil
		}
		parts := strings.SplitN(trimmed, "/", 2)
		ap := AzurePath{Account: account, Container: parts[0]}
		if !validContainerName(ap.Container) {
			return AzurePath{}, fmt.Errorf("invalid container name: %s", ap.Container)
		}
		if len(parts) == 2 {
			ap.Blob = parts[1]
		}
		return ap, nil
	}

	return AzurePath{}, fmt.Errorf("not az:// or https:// path: %s", raw)
}

// getEndpoint returns the blob service endpoint, using BBB_AZBLOB_ENDPOINT env if set.
func getEndpoint(account string) string {
	if ep := os.Getenv("BBB_AZBLOB_ENDPOINT"); ep != "" {
		if strings.Contains(ep, "%s") {
			return fmt.Sprintf(ep, account)
		}
		return ep
	}
	return fmt.Sprintf("https://%s.blob.core.windows.net", account)
}

// BlobMeta minimal metadata for listing
type BlobMeta struct {
	Name string
	Size int64
}

// flatBlobEntry represents a blob item from a flat listing suitable for
// first-level child extraction. Size is nil when the blob is a
// directory-marker or otherwise lacks a content-length.
type flatBlobEntry struct {
	Name string
	Size *int64
}

// extractFirstLevel derives immediate children (files and virtual dirs)
// from flat blob entries under the given prefix. Directories are emitted
// with a trailing "/" and size 0. Files require a non-nil Size.
func extractFirstLevel(entries []flatBlobEntry, prefix string, cb func(BlobMeta) error) error {
	seen := make(map[string]struct{})
	for _, e := range entries {
		rel := strings.TrimPrefix(e.Name, prefix)
		if rel == "" {
			continue
		}
		parts := strings.SplitN(rel, "/", 2)
		if len(parts) == 1 {
			// file at first level — require valid size
			if e.Size == nil {
				continue
			}
			if _, exists := seen[parts[0]]; exists {
				continue
			}
			seen[parts[0]] = struct{}{}
			if err := cb(BlobMeta{Name: parts[0], Size: *e.Size}); err != nil {
				return err
			}
		} else if len(parts) == 2 {
			// directory — no size needed
			dirName := parts[0] + "/"
			if _, exists := seen[dirName]; exists {
				continue
			}
			seen[dirName] = struct{}{}
			if err := cb(BlobMeta{Name: dirName, Size: 0}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListStream streams immediate children (non-recursive). If dir-like path provided, lists under it.
func ListStream(ctx context.Context, ap AzurePath, cb func(BlobMeta) error) error {
	if ap.Container == "" { // account root: list containers
		client, err := getAzBlobClient(ctx, ap.Account)
		if err != nil {
			return err
		}
		pager := client.ServiceClient().NewListContainersPager(nil)
		for pager.More() {
			resp, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, c := range resp.ContainerItems {
				if err := cb(BlobMeta{Name: *c.Name, Size: 0}); err != nil {
					return err
				}
			}
		}
		return nil
	}
	ap = ap.WithDir()
	prefix := ap.Blob
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return err
	}
	containerClient := client.ServiceClient().NewContainerClient(ap.Container)
	opts := &container.ListBlobsHierarchyOptions{}
	// Use nil Prefix (omit query param) for container root instead of &""
	// to avoid potential Azure SDK/API differences with empty string prefix.
	if prefix != "" {
		opts.Prefix = &prefix
	}
	pager := containerClient.NewListBlobsHierarchyPager("/", opts)
	seen := make(map[string]bool)
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		if resp.Segment == nil {
			return nil
		}
		if err := processHierarchySegment(resp.Segment, prefix, seen, cb); err != nil {
			return err
		}
	}
	return nil
}

// processHierarchySegment emits BlobMeta entries from a hierarchy listing
// segment, de-duplicating across prefixes and items. Directory-marker blobs
// (nil ContentLength) are skipped.
func processHierarchySegment(seg *container.BlobHierarchyListSegment, prefix string, seen map[string]bool, cb func(BlobMeta) error) error {
	// Emit virtual directories (blob prefixes)
	for _, bp := range seg.BlobPrefixes {
		if bp == nil || bp.Name == nil {
			continue
		}
		dirName := strings.TrimPrefix(*bp.Name, prefix)
		if dirName == "" {
			continue
		}
		if seen[dirName] {
			continue
		}
		seen[dirName] = true
		if err := cb(BlobMeta{Name: dirName, Size: 0}); err != nil {
			return err
		}
	}
	// Emit files at this level (skip directory-marker blobs with nil ContentLength)
	for _, blob := range seg.BlobItems {
		if blob == nil || blob.Name == nil {
			continue
		}
		if blob.Properties == nil || blob.Properties.ContentLength == nil {
			continue
		}
		name := strings.TrimPrefix(*blob.Name, prefix)
		if name == "" {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if err := cb(BlobMeta{Name: name, Size: *blob.Properties.ContentLength}); err != nil {
			return err
		}
	}
	return nil
}

// accountTenantID returns the tenant ID for a storage account. It first
// checks the BBB_AZ_TENANT_<ACCOUNT> environment variable, then falls back
// to auto-discovery by probing the storage endpoint's WWW-Authenticate header.
func accountTenantID(ctx context.Context, account string) string {
	if tid := os.Getenv("BBB_AZ_TENANT_" + strings.ToUpper(account)); tid != "" {
		return tid
	}
	if tid := os.Getenv("BBB_AZ_TENANT_" + account); tid != "" {
		return tid
	}
	return discoverTenantID(ctx, account)
}

// tenantCache caches discovered tenant IDs per storage account.
var tenantCache sync.Map // map[string]string

// discoverTenantID makes an unauthenticated request to the storage account
// endpoint and extracts the tenant ID from the WWW-Authenticate challenge
// header. Returns "" if discovery fails.
func discoverTenantID(ctx context.Context, account string) string {
	if cached, ok := tenantCache.Load(account); ok {
		return cached.(string)
	}
	endpoint := getEndpoint(account) + "/?comp=list&restype=container"
	slog.Debug("tenant discovery: probing endpoint", "account", account, "url", endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		slog.Debug("tenant discovery: request creation failed", "account", account, "error", err)
		return ""
	}
	req.Header.Set("x-ms-version", "2020-08-04")
	resp, err := defaultHTTPClient().Do(req)
	if err != nil {
		slog.Debug("tenant discovery: GET failed", "account", account, "error", err)
		return ""
	}
	_ = resp.Body.Close()

	// WWW-Authenticate: Bearer authorization_uri=https://login.microsoftonline.com/<tenant-id>/oauth2/authorize ...
	auth := resp.Header.Get("Www-Authenticate")
	slog.Debug("tenant discovery: response", "account", account, "status", resp.StatusCode, "www-authenticate", auth)
	tid := parseTenantFromChallenge(auth)
	if tid != "" {
		slog.Debug("Discovered tenant for storage account", "account", account, "tenant", tid)
		tenantCache.Store(account, tid)
	}
	return tid
}

// challengeTenantRe extracts the tenant GUID from the authorization_uri in a
// WWW-Authenticate: Bearer challenge response.
var challengeTenantRe = regexp.MustCompile(`authorization_uri="?https://login\.microsoftonline\.com/([0-9a-f-]{36})/`)

func parseTenantFromChallenge(header string) string {
	m := challengeTenantRe.FindStringSubmatch(header)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

var defaultHTTPClientOnce sync.Once
var defaultHTTPClientVal *http.Client

// defaultHTTPClient returns the process-wide HTTP client used for
// non-SDK calls (e.g. tenant discovery probes). It honors the shared
// transport configured via SetHTTPTransport when one has been installed;
// otherwise it falls back to http.DefaultTransport (which bbb's main
// already mutates for DNS caching/pinning).
func defaultHTTPClient() *http.Client {
	defaultHTTPClientOnce.Do(func() {
		rt := http.RoundTripper(http.DefaultTransport)
		if t := getSharedTransporter(); t != nil {
			// Unwrap the *http.Client we stored to get its RoundTripper.
			if c, ok := t.(*http.Client); ok && c.Transport != nil {
				rt = c.Transport
			}
		}
		defaultHTTPClientVal = &http.Client{Timeout: 10 * time.Second, Transport: rt}
	})
	return defaultHTTPClientVal
}

// PreAuthenticate eagerly authenticates to the given storage accounts
// sequentially. This ensures any interactive login popups happen one at a
// time before parallel workers start. It also pre-warms the blob client
// and UDC (User Delegation Credential) caches so that no credential
// acquisition happens during copy.
func PreAuthenticate(ctx context.Context, accounts ...string) error {
	for _, account := range accounts {
		// Trigger tenant discovery + credential acquisition.
		_, err := getAzBlobClient(ctx, account)
		if err != nil {
			return fmt.Errorf("pre-authenticate %s: %w", account, err)
		}
		// Pre-warm the UDC cache so SAS generation doesn't trigger
		// a second credential acquisition later.
		_, _, _, _, err = getUDC(ctx, account)
		if err != nil {
			slog.Debug("pre-authenticate: UDC warm-up failed (non-fatal)", "account", account, "error", err)
		}
	}
	return nil
}

// RegisterAccountRole tags the given storage account with a role ("SRC" or
// "DST"). When role-prefixed Azure identity environment variables are set
// (e.g. SRC_AZURE_TENANT_ID, DST_AZURE_CLIENT_ID, etc.), accounts tagged
// with the matching role will use those credentials instead of AzureCLI or
// interactive browser login. This makes authentication machine-friendly for
// CI/CD and multi-tenant environments.
func RegisterAccountRole(account, role string) {
	accountRoles.Store(account, strings.ToUpper(role))
}

// AccountRole returns the role ("SRC" or "DST") registered for the given
// account, and a boolean indicating whether a role was registered.
func AccountRole(account string) (string, bool) {
	v, ok := accountRoles.Load(account)
	if !ok {
		return "", false
	}
	return v.(string), true
}

// ClearAccountRole removes the role registration for the given account.
// This is used in tests to reset state between subtests.
func ClearAccountRole(account string) {
	accountRoles.Delete(account)
}

// roleEnvVars lists all Azure identity environment variables that are
// remapped from {role}_ prefixed variants (e.g. SRC_AZURE_CLIENT_ID)
// to standard names when creating a role-specific credential.
var roleEnvVars = []string{
	// Core identity
	"AZURE_CLIENT_ID",
	"AZURE_TENANT_ID",
	// Service Principal (secret)
	"AZURE_CLIENT_SECRET",
	// Service Principal (certificate)
	"AZURE_CLIENT_CERTIFICATE_PATH",
	"AZURE_CLIENT_CERTIFICATE_PASSWORD",
	"AZURE_CLIENT_SEND_CERTIFICATE_CHAIN",
	// Workload Identity (OIDC / AKS)
	"AZURE_FEDERATED_TOKEN_FILE",
	// Managed Identity (advanced / injected by Azure)
	"IDENTITY_ENDPOINT",
	"IDENTITY_HEADER",
	"MSI_ENDPOINT",
	"MSI_SECRET",
	"IMDS_ENDPOINT",
	// Cloud / authority
	"AZURE_AUTHORITY_HOST",
	// Developer cache hint
	"AZURE_USERNAME",
	// Azure CLI integration
	"AZURE_CONFIG_DIR",
}

func roleCredentialEnvConfigured(role string) bool {
	has := func(name string) bool {
		v, ok := os.LookupEnv(name)
		return ok && v != ""
	}
	hasRole := func(name string) bool {
		return has(role + "_" + name)
	}
	hasEffective := func(name string) bool {
		return hasRole(name) || has(name)
	}

	if hasEffective("AZURE_CLIENT_ID") &&
		hasEffective("AZURE_TENANT_ID") &&
		(hasEffective("AZURE_CLIENT_SECRET") ||
			hasEffective("AZURE_CLIENT_CERTIFICATE_PATH") ||
			hasEffective("AZURE_FEDERATED_TOKEN_FILE")) {
		return true
	}

	if hasEffective("IDENTITY_ENDPOINT") || hasEffective("MSI_ENDPOINT") || hasEffective("IMDS_ENDPOINT") {
		return true
	}

	// A role-scoped client ID alone can be a valid user-assigned managed identity
	// configuration (with IMDS discovery), while an unprefixed AZURE_CLIENT_ID
	// alone should not force this path.
	return hasRole("AZURE_CLIENT_ID")
}

// roleCredMu serializes env var swapping for role-specific credential
// creation. os.Setenv is process-global, so concurrent credential creation
// for different roles must not interleave env var mutations.
var roleCredMu sync.Mutex

// getCredentialForRole returns a DefaultAzureCredential built from
// {role}_AZURE_* (and {role}_MSI_*, {role}_IDENTITY_*, etc.) environment
// variables. The role-prefixed env vars are temporarily mapped to their
// standard names so the Azure SDK picks them up.
//
// Unprefixed AZURE_* variables act as defaults shared by both roles: a plain
// AZURE_xxx is interpreted as if it were set for both SRC_AZURE_xxx and
// DST_AZURE_xxx, with the role-prefixed variant overriding it when present.
// Returns (nil, nil) when neither role-prefixed nor unprefixed env vars are
// set.
func getCredentialForRole(role string) (azcore.TokenCredential, error) {
	if cached, ok := roleCredCache.Load(role); ok {
		return cached.(azcore.TokenCredential), nil
	}

	// Temporarily swap env vars to create the credential.
	// os.Setenv is process-global, so serialize with a mutex.
	roleCredMu.Lock()
	defer roleCredMu.Unlock()

	// Double-check cache after acquiring the lock.
	if cached, ok := roleCredCache.Load(role); ok {
		return cached.(azcore.TokenCredential), nil
	}

	// Only credential-bearing env vars should activate the DefaultAzureCredential
	// path. Helper vars like AZURE_CONFIG_DIR / AZURE_USERNAME are still
	// inherited, but only after some real credential config is present.
	if !roleCredentialEnvConfigured(role) {
		return nil, nil // not configured
	}

	// Save originals so they can be restored by the deferred cleanup below.
	// Unprefixed values are kept in place to act as defaults; role-prefixed
	// values temporarily override them while the credential is created.
	type envEntry struct {
		value string
		set   bool
	}
	originals := make(map[string]envEntry, len(roleEnvVars))
	for _, v := range roleEnvVars {
		val, ok := os.LookupEnv(v)
		originals[v] = envEntry{value: val, set: ok}
	}
	// Override with the role-prefixed values where present.
	for _, v := range roleEnvVars {
		if prefixed := os.Getenv(role + "_" + v); prefixed != "" {
			_ = os.Setenv(v, prefixed)
		}
	}
	// Restore originals after creating the credential.
	defer func() {
		for _, v := range roleEnvVars {
			if !originals[v].set {
				_ = os.Unsetenv(v)
			} else {
				_ = os.Setenv(v, originals[v].value)
			}
		}
	}()

	opts := &azidentity.DefaultAzureCredentialOptions{}
	if strings.EqualFold(os.Getenv("BBB_AZURE_ALLOW_ANY_TENANT"), "true") {
		opts.AdditionallyAllowedTenants = []string{"*"}
	}
	applyTransportToIdentityOptions(&opts.ClientOptions)
	cred, err := azidentity.NewDefaultAzureCredential(opts)
	if err != nil {
		return nil, fmt.Errorf("%s credential: %w", role, err)
	}
	slog.Debug("Using env credential for role", "role", role)
	actual, _ := roleCredCache.LoadOrStore(role, cred)
	return actual.(azcore.TokenCredential), nil
}

// tenantIDFromAccessToken returns the "tid" claim from a JWT access token,
// or "" when the token is not a JWT, can't be decoded, or has no tid claim.
// Used to detect tenant mismatches between a token issued by AzureCLICredential
// and the tenant we expect (e.g. the one discovered from the storage account
// challenge), so we can trigger an interactive auto-login when they differ.
func tenantIDFromAccessToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Tid string `json:"tid"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Tid
}

// getCredentialForAccount returns a TokenCredential appropriate for the given
// storage account. It first checks for role-specific environment credentials
// (SRC_AZURE_* / DST_AZURE_*), then auto-discovers the tenant from the
// storage endpoint's challenge header (or BBB_AZ_TENANT_<ACCOUNT> env var).
// When a tenant is found, it tries AzureCLICredential first, then falls back
// to InteractiveBrowserCredential (popup login).
//
// Only one browser popup is opened per tenant; concurrent callers wait for
// the first to complete.
func getCredentialForAccount(ctx context.Context, account string) (azcore.TokenCredential, error) {
	// Resolve the role for this account. Accounts tagged during cp/sync use
	// their SRC/DST role; accounts without an explicit role (single-endpoint
	// commands like ls/cat/rm) reuse the SRC role, so SRC_AZURE_* and the
	// unprefixed AZURE_* defaults are honored for them too. When the relevant
	// env vars are unset, getCredentialForRole returns nil and we fall through
	// to tenant discovery and the interactive CLI/browser flow.
	role := "SRC"
	if roleVal, ok := accountRoles.Load(account); ok {
		role = roleVal.(string)
	}
	cred, err := getCredentialForRole(role)
	if err != nil {
		return nil, err
	}
	if cred != nil {
		return cred, nil
	}

	tid := accountTenantID(ctx, account)
	if tid == "" {
		return getDefaultCredential()
	}
	slog.Debug("Using tenant-specific credential", "account", account, "tenant", tid)

	// Return cached credential for this tenant if available.
	if cached, ok := tenantCredCache.Load(tid); ok {
		return cached.(azcore.TokenCredential), nil
	}

	// Serialize credential acquisition per tenant so only one browser
	// popup is shown, even when multiple goroutines race.
	inflightVal, _ := tenantCredInflight.LoadOrStore(tid, &sync.Mutex{})
	mu := inflightVal.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Double-check cache after acquiring the lock.
	if cached, ok := tenantCredCache.Load(tid); ok {
		return cached.(azcore.TokenCredential), nil
	}

	// Try AzureCLICredential first — works if the user has `az login`'d
	// to this tenant. If GetToken fails, or if the returned token is for a
	// different tenant than we expect (e.g. the user's `az` cache only holds
	// a token for their home tenant), fall back to interactive browser login.
	cliCred, err := azidentity.NewAzureCLICredential(&azidentity.AzureCLICredentialOptions{
		TenantID: tid,
	})
	if err == nil {
		// Test if CLI credential actually works for this tenant.
		tok, tokenErr := cliCred.GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{"https://storage.azure.com/.default"},
		})
		if tokenErr == nil {
			// Verify the returned token is actually for the expected tenant.
			// If `az` returned a token for a different tenant (cache mismatch),
			// treat it as a failure so we trigger an interactive login below.
			tokTid := tenantIDFromAccessToken(tok.Token)
			if tokTid != "" && !strings.EqualFold(tokTid, tid) {
				slog.Debug("AzureCLICredential returned token for wrong tenant, falling back to interactive login",
					"expected", tid, "got", tokTid)
			} else {
				slog.Debug("Using AzureCLICredential for tenant", "tenant", tid)
				tenantCredCache.Store(tid, cliCred)
				return cliCred, nil
			}
		} else {
			slog.Debug("AzureCLICredential failed for tenant, falling back to interactive login",
				"tenant", tid, "error", tokenErr)
		}
	}

	// Fall back to interactive browser login for the discovered tenant.
	slog.Info("CLI credential failed for tenant, opening browser login", "account", account, "tenant", tid)
	fmt.Fprintf(os.Stderr, "\n  Storage account %q requires authentication to tenant %s.\n  Opening browser...\n", account, tid)
	browserOpts := &azidentity.InteractiveBrowserCredentialOptions{
		TenantID: tid,
	}
	applyTransportToIdentityOptions(&browserOpts.ClientOptions)
	browserCred, err := azidentity.NewInteractiveBrowserCredential(browserOpts)
	if err != nil {
		return nil, fmt.Errorf("interactive credential for tenant %s: %w", tid, err)
	}

	// Eagerly acquire a CAE-capable token to trigger the browser popup now,
	// before any parallel goroutines need the credential. EnableCAE ensures
	// the cached token includes the CP1 claims that the SDK pipeline will
	// request later, preventing a second browser popup.
	_, err = browserCred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes:    []string{"https://storage.azure.com/.default"},
		EnableCAE: true,
	})
	if err != nil {
		return nil, fmt.Errorf("interactive login for tenant %s: %w", tid, err)
	}

	tenantCredCache.Store(tid, browserCred)
	return browserCred, nil
}

// getDefaultCredential returns a process-wide cached DefaultAzureCredential.
// The credential is thread-safe and handles token refresh internally.
func getDefaultCredential() (*azidentity.DefaultAzureCredential, error) {
	cachedDefaultCredOnce.Do(func() {
		opts := &azidentity.DefaultAzureCredentialOptions{}
		// BBB_AZURE_ALLOW_ANY_TENANT=true permits the default credential to
		// acquire tokens for any tenant. Without this, cross-tenant requests
		// may fail. This is opt-in to limit the trust boundary by default.
		if strings.EqualFold(os.Getenv("BBB_AZURE_ALLOW_ANY_TENANT"), "true") {
			opts.AdditionallyAllowedTenants = []string{"*"}
		}
		applyTransportToIdentityOptions(&opts.ClientOptions)
		cachedDefaultCred, cachedDefaultCredErr = azidentity.NewDefaultAzureCredential(opts)
		if cachedDefaultCredErr == nil && slog.Default().Enabled(context.Background(), slog.LevelDebug) {
			tok, tokErr := cachedDefaultCred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}})
			if tokErr == nil {
				parts := strings.Split(tok.Token, ".")
				if len(parts) == 3 {
					payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
					if decErr == nil {
						slog.Debug("Decoded JWT payload", "payload", string(payload), "tid", tenantIDFromAccessToken(tok.Token))
					} else {
						slog.Debug("Failed to decode JWT payload", "error", decErr)
					}
				} else {
					slog.Debug("Token is not a JWT")
				}
			} else {
				slog.Debug("Failed to get token for JWT debug logging", "error", tokErr)
			}
		}
	})
	return cachedDefaultCred, cachedDefaultCredErr
}

// accountKey returns the shared account key for the given storage account.
// It checks for a role-prefixed key first (e.g. SRC_BBB_AZBLOB_ACCOUNTKEY),
// then falls back to the global BBB_AZBLOB_ACCOUNTKEY.
func accountKey(account string) string {
	if roleVal, ok := accountRoles.Load(account); ok {
		if k := os.Getenv(roleVal.(string) + "_BBB_AZBLOB_ACCOUNTKEY"); k != "" {
			return k
		}
	}
	return os.Getenv("BBB_AZBLOB_ACCOUNTKEY")
}

// getAzBlobClient returns an Azure Blob client for the given account using either a shared key
// from BBB_AZBLOB_ACCOUNTKEY (or role-prefixed SRC_/DST_ variant) or the default Azure credential.
// Clients are cached per account for the process lifetime.
func getAzBlobClient(ctx context.Context, account string) (*azblob.Client, error) {
	// Check cache first.
	if cached, ok := blobClientCache.Load(account); ok {
		return cached.(*azblob.Client), nil
	}
	endpoint := getEndpoint(account)
	var client *azblob.Client
	if key := accountKey(account); key != "" {
		cred, err := azblob.NewSharedKeyCredential(account, key)
		if err != nil {
			return nil, err
		}
		client, err = azblob.NewClientWithSharedKeyCredential(endpoint, cred, azblobClientOptions())
		if err != nil {
			return nil, err
		}
	} else {
		cred, credErr := getCredentialForAccount(ctx, account)
		if credErr != nil {
			return nil, credErr
		}

		var clientErr error
		client, clientErr = azblob.NewClient(endpoint, cred, azblobClientOptions())
		if clientErr != nil {
			return nil, clientErr
		}
	}
	// Store-or-load: if another goroutine raced and stored first, use theirs.
	actual, _ := blobClientCache.LoadOrStore(account, client)
	return actual.(*azblob.Client), nil
}

// List lists immediate children (non-recursive). If dir-like path provided, lists under it.
func List(ctx context.Context, ap AzurePath) ([]BlobMeta, error) {
	var out []BlobMeta
	if err := ListStream(ctx, ap, func(bm BlobMeta) error {
		out = append(out, bm)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListRecursiveStream streams all blobs under path via callback (treats path as prefix root).
// Uses parallel prefix walking (similar to azcopy) to enumerate blobs across multiple
// subdirectories concurrently, dramatically improving scan speed for deep hierarchies.
// scanConcurrency controls how many directory prefixes are listed in parallel.
// When scanConcurrency > 1, cb must be safe for concurrent use by multiple goroutines.
// normalizeRootPrefix ensures the prefix ends with "/" for use as a
// blob name root. An empty prefix stays empty (represents the container root).
func normalizeRootPrefix(blob string) string {
	if blob != "" && !strings.HasSuffix(blob, "/") {
		return blob + "/"
	}
	return blob
}

func ListRecursiveStream(ctx context.Context, ap AzurePath, scanConcurrency int, cb func(BlobMeta) error) error {
	rootPrefix := normalizeRootPrefix(ap.Blob)
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return err
	}
	containerClient := client.ServiceClient().NewContainerClient(ap.Container)

	// Always use flat listing — a single sequential pager that returns all
	// blobs under the prefix. This is faster than hierarchy walking (which
	// must discover directories level-by-level) for typical container sizes
	// because it avoids per-directory round-trips and synchronization
	// overhead. The flat pager returns up to 5000 items per page, so even
	// millions of blobs only require hundreds of sequential API calls —
	// much faster than tree-shaped hierarchy walks with fanout at each level.
	return listRecursiveFlat(ctx, containerClient, ap.Container, rootPrefix, cb)
}

// listRecursiveFlat is the sequential fallback using a flat pager.
func listRecursiveFlat(ctx context.Context, containerClient *container.Client, containerName, prefix string, cb func(BlobMeta) error) error {
	opts := &azblob.ListBlobsFlatOptions{}
	if prefix != "" {
		opts.Prefix = &prefix
	}
	pager := containerClient.NewListBlobsFlatPager(opts)
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.ErrorCode == "ContainerNotFound" {
				return fmt.Errorf("container '%s' not found", containerName)
			}
			return err
		}
		if resp.Segment == nil {
			return nil
		}
		for _, blob := range resp.Segment.BlobItems {
			if blob == nil || blob.Name == nil || blob.Properties == nil || blob.Properties.ContentLength == nil {
				continue
			}
			if err := cb(BlobMeta{Name: strings.TrimPrefix(*blob.Name, prefix), Size: *blob.Properties.ContentLength}); err != nil {
				return err
			}
		}
	}
	return nil
}

// ListRecursive retrieves all blobs under path (treats path as prefix root)
func ListRecursive(ctx context.Context, ap AzurePath) ([]BlobMeta, error) {
	var out []BlobMeta
	if err := ListRecursiveStream(ctx, ap, 1, func(bm BlobMeta) error {
		out = append(out, bm)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// HeadBlob returns size (bytes) of blob
func HeadBlob(ctx context.Context, ap AzurePath) (int64, error) {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return 0, errors.New("path is directory-like")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return 0, err
	}
	blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)
	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "BlobNotFound" {
			return 0, osNotExist(ap.String())
		}
		return 0, err
	}
	return *props.ContentLength, nil
}

// Download returns blob content bytes (for small blobs)
func Download(ctx context.Context, ap AzurePath) ([]byte, error) {
	reader, err := DownloadStream(ctx, ap)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()
	return io.ReadAll(reader)
}

func DownloadStream(ctx context.Context, ap AzurePath) (io.ReadCloser, error) {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return nil, errors.New("cannot download directory")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return nil, err
	}
	blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)
	downloadResp, err := blobClient.DownloadStream(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "BlobNotFound" {
			return nil, osNotExist(ap.String())
		}
		return nil, err
	}
	return downloadResp.Body, nil
}

// downloadBlockSize is the per-range block size used for parallel downloads.
// 16 MiB amortizes per-request HTTP overhead so we can saturate the link with
// a modest number of in-flight ranges; benchmarking against azcopy shows the
// throughput plateaus around this size.
const downloadBlockSize = 16 * 1024 * 1024 // 16 MiB

const downloadBlockSizeEnv = "BBB_AZBLOB_DOWNLOAD_BLOCK_MIB"

// downloadMaxConcurrencyEnv overrides the upper bound the adaptive
// concurrency controller may grow the per-download parallelism to.
const downloadMaxConcurrencyEnv = "BBB_AZBLOB_DOWNLOAD_CONCURRENCY_MAX"

// downloadHardConcurrencyCap caps the download adaptive controller's upper
// bound regardless of caller input. Same rationale as the upload cap.
const downloadHardConcurrencyCap = 512

// downloadBlockSizeBytes returns the configured download block size in bytes,
// honoring BBB_AZBLOB_DOWNLOAD_BLOCK_MIB when set to a positive integer.
func downloadBlockSizeBytes() int64 {
	if v := os.Getenv(downloadBlockSizeEnv); v != "" {
		if mib, err := strconv.ParseInt(v, 10, 64); err == nil && mib > 0 && mib <= math.MaxInt64/(1024*1024) {
			return mib * 1024 * 1024
		}
	}
	return downloadBlockSize
}

// uploadBlockSize is the per-block size used for parallel file uploads.
// It mirrors azcopy's chunked upload model. A larger-than-azcopy default keeps
// per-block HTTP overhead amortized so we close the gap to azcopy without
// requiring the user to bump --concurrency.
const uploadBlockSize = 64 * 1024 * 1024 // 64 MiB

const uploadBlockSizeEnv = "BBB_AZBLOB_UPLOAD_BLOCK_MIB"

// uploadBlockSizeBytes returns the configured upload block size in bytes,
// honoring BBB_AZBLOB_UPLOAD_BLOCK_MIB when set to a positive integer.
// For very large files the block size is grown so the total block count
// stays under Azure's per-blob block limit.
func uploadBlockSizeBytes(size int64) int64 {
	block := int64(uploadBlockSize)
	if v := os.Getenv(uploadBlockSizeEnv); v != "" {
		if mib, err := strconv.ParseInt(v, 10, 64); err == nil && mib > 0 && mib <= math.MaxInt64/(1024*1024) {
			block = mib * 1024 * 1024
		}
	}
	if size > 0 {
		// Azure block blobs are limited to MaxBlocks=50,000 blocks; grow the
		// block size if a small block would exceed that.
		minBlock := (size + int64(blockblob.MaxBlocks) - 1) / int64(blockblob.MaxBlocks)
		if block < minBlock {
			block = minBlock
		}
	}
	return block
}

// uploadBlockMaxConcurrencyEnv overrides the upper bound the adaptive
// concurrency controller may grow the per-upload parallelism to.
const uploadBlockMaxConcurrencyEnv = "BBB_AZBLOB_UPLOAD_CONCURRENCY_MAX"

// uploadHardConcurrencyCap caps the controller's upper bound regardless of
// caller input. Azure's per-blob block staging tolerates hundreds of in-flight
// requests but we set a sensible memory/RAM ceiling.
const uploadHardConcurrencyCap = 512

// UploadFile uploads a local file to a block blob using parallel ranged reads
// and StageBlock requests, mirroring azcopy's chunked upload for higher
// single-file throughput. concurrency is the initial parallelism (and floor);
// an adaptive controller probes higher concurrency while throughput keeps
// improving, up to uploadHardConcurrencyCap (overridable via
// BBB_AZBLOB_UPLOAD_CONCURRENCY_MAX). The optional onProgress callback
// receives the cumulative number of bytes staged.
func UploadFile(ctx context.Context, ap AzurePath, file *os.File, concurrency int, onProgress func(int64)) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("cannot upload to directory-like path")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat upload source: %w", err)
	}
	size := info.Size()
	blockSize := uploadBlockSizeBytes(size)
	blockBlobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)

	// Empty blob: commit an empty block list to create a 0-byte blob.
	if size == 0 {
		_, err := blockBlobClient.CommitBlockList(ctx, nil, nil)
		if err != nil {
			return fmt.Errorf("put failed: %v", err)
		}
		if onProgress != nil {
			onProgress(0)
		}
		return nil
	}

	_, blockIDs, err := planBlocks(size, blockSize, blockblob.MaxBlocks)
	if err != nil {
		return err
	}

	initial, minC, maxC, step := adaptiveBounds(concurrency, uploadHardConcurrencyCap, uploadBlockMaxConcurrencyEnv)
	sem := newAdaptiveSem(initial, maxC)
	var staged atomic.Int64
	ctrlCtx, ctrlCancel := context.WithCancel(ctx)
	defer ctrlCancel()
	done := make(chan struct{})
	go runAdaptiveController(ctrlCtx, sem, &staged, adaptiveControllerConfig{
		Min:        minC,
		Max:        maxC,
		Step:       step,
		Interval:   750 * time.Millisecond,
		Hysteresis: 0.05,
		LogTag:     "upload",
	}, done)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for i, blockID := range blockIDs {
		if err := ctx.Err(); err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			break
		}
		if err := sem.Acquire(ctx); err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			break
		}
		offset := int64(i) * blockSize
		count := min(blockSize, size-offset)
		wg.Add(1)
		go func(blockID string, offset, count int64) {
			defer func() {
				sem.Release()
				wg.Done()
			}()
			body := streaming.NopCloser(io.NewSectionReader(file, offset, count))
			if _, err := blockBlobClient.StageBlock(ctx, blockID, body, nil); err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				cancel()
				return
			}
			cur := staged.Add(count)
			if onProgress != nil {
				onProgress(cur)
			}
		}(blockID, offset, count)
	}

	wg.Wait()
	close(done)

	if firstErr != nil {
		return fmt.Errorf("put failed: %v", firstErr)
	}
	if _, err := blockBlobClient.CommitBlockList(ctx, blockIDs, nil); err != nil {
		return fmt.Errorf("commit block list failed: %w", err)
	}
	if onProgress != nil {
		onProgress(size)
	}
	return nil
}

// downloadCopyBufferSize is the per-range io.CopyBuffer size. The default
// io.Copy buffer is 32 KiB; with 16 MiB ranges that's 512 read/write syscalls
// per range and quickly becomes CPU-bound on multi-GiB downloads. 1 MiB keeps
// the syscall count low without ballooning memory (peak ≈ concurrency × 1 MiB).
const downloadCopyBufferSize = 1 * 1024 * 1024

var downloadCopyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, downloadCopyBufferSize)
		return &buf
	},
}

// copyRangeToOffset streams src into dst at the given offset, accumulating
// reads into buf before issuing a single pwrite per full buffer. io.CopyBuffer
// performs one write per read, but HTTP/TLS reads typically return a single
// TLS record (~16 KiB), which made the old implementation issue one 16 KiB
// pwrite per chunk — ~656k pwrites per 10 GiB blob vs azcopy's ~15k. Batching
// up to len(buf) bytes (1 MiB by default) before writing cuts pwrite count
// ~64× and substantially reduces kernel sys time without changing memory use
// (each in-flight range already owns one pooled buffer).
func copyRangeToOffset(dst io.WriterAt, offset int64, src io.Reader, buf []byte) (int64, error) {
	var total int64
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			if _, werr := dst.WriteAt(buf[:n], offset+total); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		switch rerr {
		case nil:
			continue
		case io.EOF, io.ErrUnexpectedEOF:
			return total, nil
		default:
			return total, rerr
		}
	}
}

// monotonicProgress wraps onProgress so it is invoked with strictly
// increasing cumulative byte counts. DownloadFile fans out concurrent ranged
// GETs; while the atomic counter is monotonic, two goroutines can race to
// call onProgress with their captured value out of order. The mutex
// serializes delivery and drops stale values so callers (and UIs that don't
// already dedupe) never observe the cumulative total going backwards.
func monotonicProgress(last *atomic.Int64, onProgress func(int64)) func(int64) {
	if onProgress == nil {
		return func(int64) {}
	}
	var mu sync.Mutex
	return func(cur int64) {
		mu.Lock()
		defer mu.Unlock()
		if cur <= last.Load() {
			return
		}
		last.Store(cur)
		onProgress(cur)
	}
}

// DownloadFile downloads a blob to a local file using parallel ranged GETs.
// concurrency is the initial parallelism (and floor); an adaptive controller
// probes higher concurrency while throughput keeps improving, up to
// downloadHardConcurrencyCap (overridable via BBB_AZBLOB_DOWNLOAD_CONCURRENCY_MAX).
// The optional onProgress callback receives the cumulative number of bytes
// written. Returns the number of bytes downloaded.
func DownloadFile(ctx context.Context, ap AzurePath, file *os.File, concurrency int, onProgress func(int64)) (int64, error) {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return 0, errors.New("cannot download directory")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return 0, err
	}
	blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)

	props, err := blobClient.GetProperties(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "BlobNotFound" {
			return 0, osNotExist(ap.String())
		}
		return 0, err
	}
	if props.ContentLength == nil {
		return 0, fmt.Errorf("blob %s has no content length", ap.String())
	}
	size := *props.ContentLength
	etag := props.ETag

	if size == 0 {
		if err := file.Truncate(0); err != nil {
			return 0, err
		}
		if onProgress != nil {
			onProgress(0)
		}
		return 0, nil
	}

	if stat, err := file.Stat(); err == nil && stat.Size() != size {
		if err := file.Truncate(size); err != nil {
			return 0, err
		}
	}

	// Preallocate destination extents so per-pwrite cost drops from ~ms
	// (extent allocation + journal commit on ext4/xfs) to ~us. Best-effort:
	// non-extent filesystems and non-Linux platforms fall through unchanged.
	// Pair with FADV_SEQUENTIAL so the kernel sizes writeback IO for the
	// access pattern we know we're about to perform.
	tryFallocate(file, size)
	tryFadviseSequential(file)
	// FADV_DONTNEED on close forces synchronous page eviction during
	// writeback, which reduces page-cache pressure but adds wall-clock
	// latency. Gate behind env for users who care about cache hygiene
	// more than wall time on a single transfer.
	if envOn(envDownloadFadviseDontneed) {
		defer tryFadviseDontneed(file)
	}

	blockSize := downloadBlockSizeBytes()
	initial, minC, maxC, step := adaptiveBounds(concurrency, downloadHardConcurrencyCap, downloadMaxConcurrencyEnv)
	// Downloads are typically shorter than uploads (one-way, no commit), so
	// ramp the adaptive controller faster: bigger step + tighter interval so
	// concurrency reaches its ceiling within a few seconds rather than after
	// the transfer has already finished.
	if step < initial {
		step = initial
	}
	sem := newAdaptiveSem(initial, maxC)
	var written atomic.Int64
	// lastReported guards onProgress to deliver monotonically increasing
	// cumulative byte counts. written.Add returns a monotonic value, but two
	// goroutines may race to invoke onProgress with their captured value in
	// any order. monotonicProgress filters out stale callbacks so callers
	// never see the cumulative total go backwards.
	var lastReported atomic.Int64
	emitProgress := monotonicProgress(&lastReported, onProgress)
	ctrlCtx, ctrlCancel := context.WithCancel(ctx)
	defer ctrlCancel()
	done := make(chan struct{})
	go runAdaptiveController(ctrlCtx, sem, &written, adaptiveControllerConfig{
		Min:        minC,
		Max:        maxC,
		Step:       step,
		Interval:   250 * time.Millisecond,
		Hysteresis: 0.05,
		LogTag:     "download",
	}, done)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for offset := int64(0); offset < size; offset += blockSize {
		if err := ctx.Err(); err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			break
		}
		if err := sem.Acquire(ctx); err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			break
		}
		count := min(blockSize, size-offset)
		wg.Add(1)
		go func(offset, count int64) {
			defer func() {
				sem.Release()
				wg.Done()
			}()
			resp, err := blobClient.DownloadStream(ctx, &blob.DownloadStreamOptions{
				Range: blob.HTTPRange{Offset: offset, Count: count},
				AccessConditions: &blob.AccessConditions{
					ModifiedAccessConditions: &blob.ModifiedAccessConditions{IfMatch: etag},
				},
			})
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				cancel()
				return
			}
			body := resp.NewRetryReader(ctx, nil)
			bufPtr := downloadCopyBufPool.Get().(*[]byte)
			n, copyErr := copyRangeToOffset(file, offset, body, *bufPtr)
			downloadCopyBufPool.Put(bufPtr)
			closeErr := body.Close()
			if copyErr == nil && n != count {
				copyErr = fmt.Errorf("short download for range [%d,%d): got %d bytes", offset, offset+count, n)
			}
			if copyErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = copyErr
				}
				errMu.Unlock()
				cancel()
				return
			}
			if closeErr != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = closeErr
				}
				errMu.Unlock()
				cancel()
				return
			}
			cur := written.Add(n)
			emitProgress(cur)
		}(offset, count)
	}

	wg.Wait()
	close(done)

	if firstErr != nil {
		return 0, firstErr
	}
	emitProgress(size)
	return size, nil
}

// Upload writes blob (overwrite)
func Upload(ctx context.Context, ap AzurePath, data []byte) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("cannot upload to directory-like path")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return err
	}
	blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)
	_, err = blobClient.UploadBuffer(ctx, data, nil)
	if err != nil {
		return fmt.Errorf("put failed: %v", err)
	}
	return nil
}

// uploadStreamBlockSize returns a block size clamped to Azure's limits.
// size is the total stream size, or -1 if unknown.
func uploadStreamBlockSize(size int64) int64 {
	minBlockSize, maxBlockSize, baseBlockSize := uploadStreamBlockLimits()
	return uploadStreamBlockSizeWithLimits(size, minBlockSize, maxBlockSize, baseBlockSize)
}

func uploadStreamBlockLimits() (int64, int64, int64) {
	minBlockSize := int64(uploadStreamBlockMin)
	maxBlockSize := int64(uploadStreamBlockMax)
	baseBlockSize := int64(uploadStreamBlockBase)

	if value, ok := uploadStreamBlockEnvMiB(uploadStreamBlockMinEnv); ok {
		minBlockSize = value
	}
	if value, ok := uploadStreamBlockEnvMiB(uploadStreamBlockMaxEnv); ok {
		maxBlockSize = value
	}
	if minBlockSize < int64(uploadStreamBlockMin) {
		minBlockSize = int64(uploadStreamBlockMin)
	}
	if minBlockSize > int64(uploadStreamBlockMax) {
		minBlockSize = int64(uploadStreamBlockMax)
	}
	if maxBlockSize < int64(uploadStreamBlockMin) {
		maxBlockSize = int64(uploadStreamBlockMin)
	}
	if maxBlockSize > int64(uploadStreamBlockMax) {
		maxBlockSize = int64(uploadStreamBlockMax)
	}
	if maxBlockSize < minBlockSize {
		maxBlockSize = minBlockSize
	}
	if value, ok := uploadStreamBlockEnvMiB(uploadStreamBlockBaseEnv); ok {
		baseBlockSize = value
	}
	if baseBlockSize < minBlockSize {
		baseBlockSize = minBlockSize
	}
	if baseBlockSize > maxBlockSize {
		baseBlockSize = maxBlockSize
	}
	return minBlockSize, maxBlockSize, baseBlockSize
}

func uploadStreamBlockEnvMiB(name string) (int64, bool) {
	raw := os.Getenv(name)
	if raw == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	if parsed > int64(math.MaxInt64/uploadStreamMiB) {
		return 0, false
	}
	return parsed * uploadStreamMiB, true
}

func uploadStreamBlockSizeWithLimits(size, minBlockSize, maxBlockSize, baseBlockSize int64) int64 {
	blockSize := baseBlockSize
	if size >= 0 {
		blockSize = (size + int64(uploadStreamMaxBlocks) - 1) / int64(uploadStreamMaxBlocks)
	}
	if blockSize < minBlockSize {
		blockSize = minBlockSize
	}
	if blockSize > maxBlockSize {
		blockSize = maxBlockSize
	}
	return blockSize
}

// readerSize returns size from Size, Stat, or Seek (restoring position). Returns -1 if unknown.
func readerSize(reader io.Reader) int64 {
	if sizer, ok := reader.(interface{ Size() int64 }); ok {
		size := sizer.Size()
		if size >= 0 {
			return size
		}
	}
	if statter, ok := reader.(interface{ Stat() (os.FileInfo, error) }); ok {
		info, err := statter.Stat()
		if err == nil && info != nil {
			return info.Size()
		}
	}
	if seeker, ok := reader.(io.Seeker); ok {
		current, err := seeker.Seek(0, io.SeekCurrent)
		if err == nil {
			end, err := seeker.Seek(0, io.SeekEnd)
			restoreErr := func() error {
				_, err := seeker.Seek(current, io.SeekStart)
				return err
			}()
			if err == nil && restoreErr == nil && end >= 0 {
				return end
			}
		}
	}
	return -1
}

// UploadStream writes blob content from a reader (overwrite).
func UploadStream(ctx context.Context, ap AzurePath, reader io.Reader, concurrency int) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("cannot upload to directory-like path")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return err
	}
	blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)
	size := readerSize(reader)
	minBlockSize, maxBlockSize, baseBlockSize := uploadStreamBlockLimits()
	blockSize := uploadStreamBlockSizeWithLimits(size, minBlockSize, maxBlockSize, baseBlockSize)
	if size >= 0 && blockSize == maxBlockSize {
		maxSize := int64(uploadStreamMaxBlocks) * maxBlockSize
		if size > maxSize {
			return fmt.Errorf("put failed: stream size %d exceeds %d", size, maxSize)
		}
	}
	if concurrency < 1 {
		concurrency = 1
	}
	_, err = blobClient.UploadStream(ctx, reader, &azblob.UploadStreamOptions{
		BlockSize:   blockSize,
		Concurrency: concurrency,
	})
	if err != nil {
		return fmt.Errorf("put failed: %v", err)
	}
	return nil
}

// planBlocks computes the block size and generates base64-encoded block IDs for
// a server-side copy of totalSize bytes. defaultBlockSize is the preferred block
// size; maxBlocks is the maximum number of blocks allowed by Azure. For empty
// blobs (totalSize == 0) it returns blockSize == defaultBlockSize and an empty
// ID slice. The returned blockSize may exceed defaultBlockSize when totalSize is
// large enough to require more than maxBlocks blocks at the default size.
func planBlocks(totalSize int64, defaultBlockSize int64, maxBlocks int64) (blockSize int64, blockIDs []string, err error) {
	if totalSize < 0 {
		return 0, nil, fmt.Errorf("negative total size: %d", totalSize)
	}
	blockSize = defaultBlockSize
	if blockSize < 1 {
		blockSize = 1
	}

	// For empty blobs, CommitBlockList with an empty list creates a 0-byte blob.
	if totalSize == 0 {
		return blockSize, nil, nil
	}

	numBlocks := (totalSize + blockSize - 1) / blockSize
	if numBlocks > maxBlocks {
		blockSize = (totalSize + maxBlocks - 1) / maxBlocks
		numBlocks = (totalSize + blockSize - 1) / blockSize
	}
	if numBlocks > maxBlocks {
		return 0, nil, fmt.Errorf("blob too large: %d bytes requires more than %d blocks", totalSize, maxBlocks)
	}
	if numBlocks > math.MaxInt {
		return 0, nil, fmt.Errorf("block count %d exceeds platform int limit", numBlocks)
	}

	// Block IDs must all be the same length; 6-digit format supports up to
	// 999,999 which exceeds MaxBlocks (50,000).
	ids := make([]string, int(numBlocks))
	for i := range ids {
		ids[i] = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%06d", i)))
	}
	return blockSize, ids, nil
}

// CopyProgress is called during server-side copy with the number of
// bytes copied so far and the total size in bytes.
type CopyProgress func(copied, total int64)

func CopyBlobServerSide(ctx context.Context, src AzurePath, dst AzurePath, concurrency int, sizeHint int64, onProgress CopyProgress) error {
	if src.Blob == "" || strings.HasSuffix(src.Blob, "/") {
		return errors.New("source path is directory-like")
	}
	if dst.Blob == "" || strings.HasSuffix(dst.Blob, "/") {
		return errors.New("destination path is directory-like")
	}
	if concurrency < 1 {
		concurrency = 1
	}
	client, err := getAzBlobClient(ctx, dst.Account)
	if err != nil {
		return err
	}
	copySource, err := blobSASURL(ctx, src)
	if err != nil {
		return err
	}

	// Use provided size when available to avoid a HeadBlob round-trip.
	totalSize := sizeHint
	if totalSize <= 0 {
		totalSize, err = HeadBlob(ctx, src)
		if err != nil {
			return fmt.Errorf("failed to get source properties: %w", err)
		}
	}

	err = copyBlobBlocks(ctx, client, dst, copySource, totalSize, concurrency, onProgress)
	if err != nil {
		// StageBlockFromURL (Put Block From URL) returns 501 in emulators
		// like Azurite. Fall back to the async StartCopyFromURL approach.
		// The 501 occurs on the very first block attempt (the API is either
		// supported or not), so no partial staged blocks need cleanup —
		// uncommitted blocks are garbage-collected by Azure automatically.
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.StatusCode == 501 {
			slog.Debug("StageBlockFromURL not supported, falling back to StartCopyFromURL", "dst", dst.String())
			return copyBlobAsync(ctx, client, dst, copySource, totalSize, onProgress)
		}
		return err
	}
	return nil
}

// copyHardConcurrencyCap caps the adaptive controller's upper bound for
// server-side StageBlockFromURL copies. Overridable via
// BBB_AZBLOB_COPY_CONCURRENCY_MAX.
const copyHardConcurrencyCap = 256

const copyMaxConcurrencyEnv = "BBB_AZBLOB_COPY_CONCURRENCY_MAX"

// copyBlockSizeBytes returns the StageBlockFromURL block size for a given
// total transfer size. Defaults to 8 MiB (azcopy's S2S sweet spot, ~30×
// smaller than what client-side uploads use). Smaller blocks let Azure's
// destination pipeline far more PBFU operations in parallel per blob;
// measurements on 10 GiB cross-account copies show ~4× throughput vs the
// previous 256 MiB block size. The size is grown if needed to stay under
// blockblob.MaxBlocks=50000, and may be overridden via BBB_AZBLOB_COPY_BLOCK_MIB.
func copyBlockSizeBytes(size int64) int64 {
	block := int64(copyBlockSize)
	if v := os.Getenv(copyBlockSizeEnv); v != "" {
		if mib, err := strconv.ParseInt(v, 10, 64); err == nil && mib > 0 && mib <= math.MaxInt64/(1024*1024) {
			block = mib * 1024 * 1024
		}
	}
	if size > 0 {
		minBlock := (size + int64(blockblob.MaxBlocks) - 1) / int64(blockblob.MaxBlocks)
		if block < minBlock {
			block = minBlock
		}
	}
	return block
}

// copyBlobBlocks copies a blob using parallel StageBlockFromURL + CommitBlockList.
func copyBlobBlocks(ctx context.Context, client *azblob.Client, dst AzurePath, copySource string, totalSize int64, concurrency int, onProgress CopyProgress) error {
	blockBlobClient := client.ServiceClient().NewContainerClient(dst.Container).NewBlockBlobClient(dst.Blob)

	// Plan blocks and generate IDs.
	blkSize, blockIDs, err := planBlocks(totalSize, copyBlockSizeBytes(totalSize), blockblob.MaxBlocks)
	if err != nil {
		return err
	}

	var copiedBytes atomic.Int64

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	initial, minC, maxC, step := adaptiveBounds(concurrency, copyHardConcurrencyCap, copyMaxConcurrencyEnv)
	sem := newAdaptiveSem(initial, maxC)
	ctrlCtx, ctrlCancel := context.WithCancel(ctx)
	defer ctrlCancel()
	done := make(chan struct{})
	go runAdaptiveController(ctrlCtx, sem, &copiedBytes, adaptiveControllerConfig{
		Min:        minC,
		Max:        maxC,
		Step:       step,
		Interval:   750 * time.Millisecond,
		Hysteresis: 0.05,
		LogTag:     "s2s-copy",
	}, done)

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for i, blockID := range blockIDs {
		if err := ctx.Err(); err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			break
		}

		offset := int64(i) * blkSize
		count := min(blkSize, totalSize-offset)

		if err := sem.Acquire(ctx); err != nil {
			errMu.Lock()
			if firstErr == nil {
				firstErr = err
			}
			errMu.Unlock()
			break
		}
		wg.Add(1)
		go func(blockID string, offset, count int64) {
			defer func() {
				sem.Release()
				wg.Done()
			}()

			_, err := blockBlobClient.StageBlockFromURL(ctx, blockID, copySource, &blockblob.StageBlockFromURLOptions{
				Range: blob.HTTPRange{Offset: offset, Count: count},
			})
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				cancel()
				return
			}

			copied := copiedBytes.Add(count)
			if onProgress != nil {
				onProgress(copied, totalSize)
			}
		}(blockID, offset, count)
	}

	wg.Wait()
	close(done)

	if firstErr != nil {
		return firstErr
	}

	// Commit all staged blocks.
	if _, err := blockBlobClient.CommitBlockList(ctx, blockIDs, nil); err != nil {
		return fmt.Errorf("commit block list failed: %w", err)
	}

	if onProgress != nil {
		onProgress(totalSize, totalSize)
	}
	return nil
}

// nextPollDelay doubles the delay up to copyPollMaxDelay.
func nextPollDelay(d time.Duration) time.Duration {
	d *= 2
	if d > copyPollMaxDelay {
		d = copyPollMaxDelay
	}
	return d
}

// copyBlobAsync copies a blob using StartCopyFromURL with polling.
// This is the fallback for environments (e.g. Azurite) that don't support
// StageBlockFromURL.
func copyBlobAsync(ctx context.Context, client *azblob.Client, dst AzurePath, copySource string, totalSize int64, onProgress CopyProgress) error {
	blobClient := client.ServiceClient().NewContainerClient(dst.Container).NewBlobClient(dst.Blob)
	startCopy, err := blobClient.StartCopyFromURL(ctx, copySource, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "PendingCopyOperation" {
			slog.Info("pending copy operation detected, polling progress", "dst", dst.String())
		} else {
			return err
		}
	}

	copyStatus := blob.CopyStatusTypePending
	if startCopy.CopyStatus != nil {
		copyStatus = *startCopy.CopyStatus
	}
	if copyStatus != blob.CopyStatusTypePending {
		props, err := blobClient.GetProperties(ctx, nil)
		if err == nil && props.CopyStatus != nil {
			copyStatus = *props.CopyStatus
			reportCopyProgress(props.CopyProgress, onProgress)
		}
	}
	pollDelay := copyPollInitialDelay
	pollTimer := time.NewTimer(pollDelay)
	defer pollTimer.Stop()
	for copyStatus == blob.CopyStatusTypePending {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-pollTimer.C:
		}
		pollDelay = nextPollDelay(pollDelay)
		pollTimer.Reset(pollDelay)
		props, err := blobClient.GetProperties(ctx, nil)
		if err != nil {
			return err
		}
		if props.CopyStatus == nil {
			return errors.New("copy status missing")
		}
		copyStatus = *props.CopyStatus
		reportCopyProgress(props.CopyProgress, onProgress)
	}
	if copyStatus != blob.CopyStatusTypeSuccess {
		return fmt.Errorf("copy failed with status %s", copyStatus)
	}
	if onProgress != nil {
		onProgress(totalSize, totalSize)
	}
	return nil
}

// reportCopyProgress parses the "bytes_copied/total_bytes" progress string
// from Azure Blob CopyProgress and invokes the callback.
func reportCopyProgress(progress *string, onProgress CopyProgress) {
	if onProgress == nil || progress == nil {
		return
	}
	copied, total, ok := parseCopyProgress(*progress)
	if ok && total > 0 {
		onProgress(copied, total)
	}
}

// parseCopyProgress parses the Azure "bytes_copied/total_bytes" format.
func parseCopyProgress(s string) (copied, total int64, ok bool) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	c, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	t, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return c, t, true
}

// --- Cached User Delegation Credential for SAS URL generation ---

// udcCacheEntry caches a User Delegation Credential for an account.
// The UDK is valid from start to expiry; we refresh when the current time
// exceeds refreshAt (50% of the remaining validity).
type udcCacheEntry struct {
	udc       *service.UserDelegationCredential
	svcClient *service.Client
	start     time.Time
	expiry    time.Time
	refreshAt time.Time
}

var (
	udcCacheMu  sync.Mutex
	udcCache    = make(map[string]*udcCacheEntry) // keyed by account
	udcInflight = make(map[string]chan struct{})  // per-account in-flight guard
)

// getUDC returns a cached User Delegation Credential for the account,
// refreshing it when necessary. Thread-safe. Concurrent refresh requests
// for the same account are deduped: the first goroutine performs the
// network call while others wait for it to finish.
func getUDC(ctx context.Context, account string) (*service.UserDelegationCredential, *service.Client, time.Time, time.Time, error) {
	for {
		udcCacheMu.Lock()
		entry, ok := udcCache[account]
		if ok && time.Now().UTC().Before(entry.refreshAt) {
			udcCacheMu.Unlock()
			return entry.udc, entry.svcClient, entry.start, entry.expiry, nil
		}
		// Check if another goroutine is already refreshing this account.
		if ch, inflight := udcInflight[account]; inflight {
			udcCacheMu.Unlock()
			// Wait for the in-flight refresh to complete, then retry.
			select {
			case <-ch:
			case <-ctx.Done():
				return nil, nil, time.Time{}, time.Time{}, ctx.Err()
			}
			continue
		}
		// Claim the refresh slot for this account.
		ch := make(chan struct{})
		udcInflight[account] = ch
		udcCacheMu.Unlock()

		udc, svcClient, start, expiry, err := refreshUDC(ctx, account)

		udcCacheMu.Lock()
		delete(udcInflight, account)
		close(ch)
		udcCacheMu.Unlock()

		return udc, svcClient, start, expiry, err
	}
}

// refreshUDC performs the actual UDC refresh (network call). Called at most
// once per account at a time, guarded by udcInflight.
func refreshUDC(ctx context.Context, account string) (*service.UserDelegationCredential, *service.Client, time.Time, time.Time, error) {
	cred, err := getCredentialForAccount(ctx, account)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("credential for %s: %w", account, err)
	}
	endpoint := getEndpoint(account)
	svcClient, err := service.NewClient(endpoint, cred, serviceClientOptions())
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("service client: %w", err)
	}
	now := time.Now().UTC().Add(-clockSkewTolerance)
	expiry := now.Add(copySASDuration())
	startStr := now.Format(sas.TimeFormat)
	expiryStr := expiry.Format(sas.TimeFormat)
	udc, err := svcClient.GetUserDelegationCredential(ctx, service.KeyInfo{
		Start:  &startStr,
		Expiry: &expiryStr,
	}, nil)
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("get user delegation credential: %w", err)
	}

	// Refresh at 50% of the key's validity window so we never use an
	// about-to-expire key. Use the same time base (now) for consistency.
	refreshAt := now.Add(copySASDuration() / 2)

	newEntry := &udcCacheEntry{
		udc:       udc,
		svcClient: svcClient,
		start:     now,
		expiry:    expiry,
		refreshAt: refreshAt,
	}
	udcCacheMu.Lock()
	udcCache[account] = newEntry
	udcCacheMu.Unlock()

	return udc, svcClient, now, expiry, nil
}

func blobSASURL(ctx context.Context, ap AzurePath) (string, error) {
	if accountKey(ap.Account) != "" {
		client, err := getAzBlobClient(ctx, ap.Account)
		if err != nil {
			return "", err
		}
		blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlobClient(ap.Blob)
		sasURL, err := blobClient.GetSASURL(sas.BlobPermissions{Read: true}, time.Now().UTC().Add(copySASDuration()), nil)
		if err != nil {
			return "", fmt.Errorf("generate SAS URL: %w", err)
		}
		return sasURL, nil
	}
	return blobDelegationSASURL(ctx, ap)
}

// blobDelegationSASURL generates a SAS URL using a cached User Delegation Key
// obtained via OAuth. This enables cross-account server-side copy within the
// same tenant. The UDK is cached per account and refreshed at 50% of its
// validity period.
func blobDelegationSASURL(ctx context.Context, ap AzurePath) (string, error) {
	udc, svcClient, start, expiry, err := getUDC(ctx, ap.Account)
	if err != nil {
		return "", err
	}
	sasValues := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     start,
		ExpiryTime:    expiry,
		Permissions:   (&sas.BlobPermissions{Read: true}).String(),
		ContainerName: ap.Container,
		BlobName:      ap.Blob,
	}
	qp, err := sasValues.SignWithUserDelegation(udc)
	if err != nil {
		return "", fmt.Errorf("sign user delegation SAS: %w", err)
	}
	containerClient := svcClient.NewContainerClient(ap.Container)
	blobClient := containerClient.NewBlobClient(ap.Blob)
	blobURL := blobClient.URL()
	return fmt.Sprintf("%s?%s", blobURL, qp.Encode()), nil
}

func copySASDuration() time.Duration {
	if raw := os.Getenv("BBB_AZBLOB_COPY_SAS_EXPIRY"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultCopySASExpiry
}

// Delete deletes a single blob
func Delete(ctx context.Context, ap AzurePath) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("path is directory-like; use DeletePrefix")
	}
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return err
	}
	blobClient := client.ServiceClient().NewContainerClient(ap.Container).NewBlockBlobClient(ap.Blob)
	_, err = blobClient.Delete(ctx, nil)
	if err != nil {
		var respErr *azcore.ResponseError
		if errors.As(err, &respErr) && respErr.ErrorCode == "BlobNotFound" {
			return osNotExist(ap.String())
		}
		return err
	}
	return nil
}

// DeletePrefix deletes all blobs under directory-like path
func DeletePrefix(ctx context.Context, ap AzurePath) error {
	list, err := ListRecursive(ctx, ap)
	if err != nil {
		return err
	}
	for _, bm := range list {
		child := ap.Child(bm.Name)
		if err := Delete(ctx, child); err != nil {
			return err
		}
	}
	return nil
}

// Touch ensures the blob exists by creating an empty object when missing.
func Touch(ctx context.Context, ap AzurePath) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("cannot touch directory-like path")
	}

	if _, err := HeadBlob(ctx, ap); err != nil {
		var nf notExistError
		if errors.As(err, &nf) {
			return Upload(ctx, ap, []byte{})
		}
		return err
	}
	return nil
}

// Error helpers
type notExistError string

func (e notExistError) Error() string  { return string(e) + ": not found" }
func (e notExistError) NotFound() bool { return true }
func osNotExist(s string) error        { return notExistError(s) }

func validContainerName(name string) bool {
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	return containerNameRe.MatchString(name)
}

// ListContainers lists all containers in the account
func ListContainers(ctx context.Context, account string) ([]BlobMeta, error) {
	client, err := getAzBlobClient(ctx, account)
	if err != nil {
		return nil, err
	}
	pager := client.ServiceClient().NewListContainersPager(nil)
	var out []BlobMeta
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, c := range resp.ContainerItems {
			out = append(out, BlobMeta{Name: *c.Name, Size: 0})
		}
	}
	return out, nil
}
