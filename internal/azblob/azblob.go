package azblob

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
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
	clockSkewTolerance       = 5 * time.Minute // backdate SAS start to tolerate clock differences
	copyBlockSize            = 256 * 1024 * 1024 // 256 MiB per block for StageBlockFromURL
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

// getDefaultCredential returns a process-wide cached DefaultAzureCredential.
// The credential is thread-safe and handles token refresh internally.
func getDefaultCredential() (*azidentity.DefaultAzureCredential, error) {
	cachedDefaultCredOnce.Do(func() {
		cachedDefaultCred, cachedDefaultCredErr = azidentity.NewDefaultAzureCredential(nil)
	})
	return cachedDefaultCred, cachedDefaultCredErr
}

// getAzBlobClient returns an Azure Blob client for the given account using either a shared key
// from BBB_AZBLOB_ACCOUNTKEY or the default Azure credential.
// Clients are cached per account for the process lifetime.
func getAzBlobClient(ctx context.Context, account string) (*azblob.Client, error) {
	// Check cache first.
	if cached, ok := blobClientCache.Load(account); ok {
		return cached.(*azblob.Client), nil
	}
	endpoint := getEndpoint(account)
	var client *azblob.Client
	if key := os.Getenv("BBB_AZBLOB_ACCOUNTKEY"); key != "" {
		cred, err := azblob.NewSharedKeyCredential(account, key)
		if err != nil {
			return nil, err
		}
		client, err = azblob.NewClientWithSharedKeyCredential(endpoint, cred, nil)
		if err != nil {
			return nil, err
		}
	} else {
		cred, credErr := getDefaultCredential()
		if credErr != nil {
			return nil, credErr
		}

		if slog.Default().Enabled(ctx, slog.LevelDebug) {
			tok, tokErr := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}})
			if tokErr != nil {
				return nil, tokErr
			}

			parts := strings.Split(tok.Token, ".")
			if len(parts) == 3 {
				payload, decErr := base64.RawURLEncoding.DecodeString(parts[1])
				if decErr == nil {
					slog.Debug("Decoded JWT payload", "payload", string(payload))
				} else {
					slog.Debug("Failed to decode JWT payload", "error", decErr)
				}
			} else {
				slog.Debug("Token is not a JWT")
			}
		}
		var clientErr error
		client, clientErr = azblob.NewClient(endpoint, cred, nil)
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

	if scanConcurrency < 1 {
		scanConcurrency = 1
	}

	// For scanConcurrency == 1, use the simpler sequential flat pager.
	if scanConcurrency <= 1 {
		return listRecursiveFlat(ctx, containerClient, ap.Container, rootPrefix, cb)
	}

	// Parallel prefix walking: use hierarchy listing to discover subdirectories
	// and walk them concurrently with bounded parallelism.
	// Callbacks are invoked directly from goroutines without serialization,
	// so callers must provide a thread-safe cb when scanConcurrency > 1.

	// Derived context: cancelled on first error so in-flight and queued
	// API calls (NextPage, semaphore waits) stop promptly.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		firstErr error
		errOnce  sync.Once
	)

	setErr := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	// Semaphore to bound concurrent listing goroutines.
	// Size is scanConcurrency-1 because the root walk runs inline in
	// the caller's goroutine, so total concurrent walks = 1 (root) +
	// len(sem) ≤ scanConcurrency.
	sem := make(chan struct{}, scanConcurrency-1)
	var wg sync.WaitGroup

	// Track seen prefixes to avoid walking the same subdirectory twice
	// (a prefix can appear on multiple pages of a hierarchy listing).
	var prefixMu sync.Mutex
	seenPrefixes := make(map[string]struct{})

	// walkPrefix lists blobs and subdirectories under the given prefix.
	// For each subdirectory, it spawns a goroutine (bounded by sem) to walk recursively.
	var walkPrefix func(prefix string)
	walkPrefix = func(prefix string) {
		defer wg.Done()

		if ctx.Err() != nil {
			return
		}

		opts := &container.ListBlobsHierarchyOptions{}
		if prefix != "" {
			opts.Prefix = &prefix
		}
		pager := containerClient.NewListBlobsHierarchyPager("/", opts)

		for pager.More() {
			if ctx.Err() != nil {
				return
			}
			resp, err := pager.NextPage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					// Context was cancelled (by setErr or caller); don't
					// overwrite firstErr with the cancellation error.
					return
				}
				var respErr *azcore.ResponseError
				if errors.As(err, &respErr) && respErr.ErrorCode == "ContainerNotFound" {
					setErr(fmt.Errorf("container '%s' not found", ap.Container))
				} else {
					setErr(err)
				}
				return
			}
			if resp.Segment == nil {
				return
			}

			// Emit files at this level
			for _, blob := range resp.Segment.BlobItems {
				if blob == nil || blob.Name == nil || blob.Properties == nil || blob.Properties.ContentLength == nil {
					continue
				}
				if ctx.Err() != nil {
					return
				}
				if err := cb(BlobMeta{
					Name: strings.TrimPrefix(*blob.Name, rootPrefix),
					Size: *blob.Properties.ContentLength,
				}); err != nil {
					setErr(err)
					return
				}
			}

			// Spawn parallel walks for subdirectories
			for _, bp := range resp.Segment.BlobPrefixes {
				if bp == nil || bp.Name == nil {
					continue
				}
				if ctx.Err() != nil {
					return
				}
				subPrefix := *bp.Name
				// Deduplicate: a prefix can appear across multiple pages.
				prefixMu.Lock()
				_, already := seenPrefixes[subPrefix]
				if !already {
					seenPrefixes[subPrefix] = struct{}{}
				}
				prefixMu.Unlock()
				if already {
					continue
				}
				wg.Add(1)
				// Try to acquire semaphore; if full, walk inline in current goroutine.
				// Inline walking reuses the parent goroutine's stack. Directory depth
				// in blob storage is typically shallow, so stack growth is bounded.
				// ctx.Done() case: context was cancelled (by setErr or caller);
				// balance the wg.Add(1) above — the parent's defer wg.Done()
				// handles the parent's own wg.Add, not this subdirectory's.
				select {
				case sem <- struct{}{}:
					go func(p string) {
						defer func() { <-sem }()
						walkPrefix(p)
					}(subPrefix)
				case <-ctx.Done():
					wg.Done()
				default:
					walkPrefix(subPrefix)
				}
			}
		}
	}

	// Start root walk. Run inline (no goroutine) — the caller already
	// blocks until wg.Wait() completes, so there's no benefit to a goroutine
	// for root, and starting inline avoids consuming a semaphore slot.
	wg.Add(1)
	walkPrefix(rootPrefix)
	wg.Wait()

	return firstErr
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
func UploadStream(ctx context.Context, ap AzurePath, reader io.Reader) error {
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
	_, err = blobClient.UploadStream(ctx, reader, &azblob.UploadStreamOptions{
		BlockSize: blockSize,
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

// copyBlobBlocks copies a blob using parallel StageBlockFromURL + CommitBlockList.
func copyBlobBlocks(ctx context.Context, client *azblob.Client, dst AzurePath, copySource string, totalSize int64, concurrency int, onProgress CopyProgress) error {
	blockBlobClient := client.ServiceClient().NewContainerClient(dst.Container).NewBlockBlobClient(dst.Blob)

	// Plan blocks and generate IDs.
	blkSize, blockIDs, err := planBlocks(totalSize, copyBlockSize, blockblob.MaxBlocks)
	if err != nil {
		return err
	}

	var copiedBytes atomic.Int64

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error

	for i, blockID := range blockIDs {
		if ctx.Err() != nil {
			break
		}

		offset := int64(i) * blkSize
		count := min(blkSize, totalSize-offset)

		// Acquire semaphore slot, respecting context cancellation so the
		// loop doesn't block forever when a peer goroutine cancels ctx.
		gotSlot := false
		select {
		case sem <- struct{}{}:
			gotSlot = true
		case <-ctx.Done():
		}
		if !gotSlot {
			break
		}
		wg.Add(1)
		go func(blockID string, offset, count int64) {
			defer func() {
				<-sem
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
	udcCacheMu sync.Mutex
	udcCache   = make(map[string]*udcCacheEntry) // keyed by account
)

// getUDC returns a cached User Delegation Credential for the account,
// refreshing it when necessary. Thread-safe.
func getUDC(ctx context.Context, account string) (*service.UserDelegationCredential, *service.Client, time.Time, time.Time, error) {
	udcCacheMu.Lock()
	entry, ok := udcCache[account]
	if ok && time.Now().UTC().Before(entry.refreshAt) {
		udcCacheMu.Unlock()
		return entry.udc, entry.svcClient, entry.start, entry.expiry, nil
	}
	udcCacheMu.Unlock()

	// Acquire or refresh UDK outside the lock.
	cred, err := getDefaultCredential()
	if err != nil {
		return nil, nil, time.Time{}, time.Time{}, fmt.Errorf("default credential: %w", err)
	}
	endpoint := getEndpoint(account)
	svcClient, err := service.NewClient(endpoint, cred, nil)
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
	if os.Getenv("BBB_AZBLOB_ACCOUNTKEY") != "" {
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
