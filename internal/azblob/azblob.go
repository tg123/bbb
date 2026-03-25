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

// getAzBlobClient returns an Azure Blob client for the given account using either a shared key
// from BBB_AZBLOB_ACCOUNTKEY or the default Azure credential.
func getAzBlobClient(ctx context.Context, account string) (*azblob.Client, error) {
	endpoint := getEndpoint(account)
	if key := os.Getenv("BBB_AZBLOB_ACCOUNTKEY"); key != "" {
		cred, err := azblob.NewSharedKeyCredential(account, key)
		if err != nil {
			return nil, err
		}
		return azblob.NewClientWithSharedKeyCredential(endpoint, cred, nil)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		tok, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}})
		if err != nil {
			return nil, err
		}

		parts := strings.Split(tok.Token, ".")
		if len(parts) == 3 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				slog.Debug("Decoded JWT payload", "payload", string(payload))
			} else {
				slog.Debug("Failed to decode JWT payload", "error", err)
			}
		} else {
			slog.Debug("Token is not a JWT")
		}
	}
	return azblob.NewClient(endpoint, cred, nil)
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
// Uses parallel flat-per-partition listing: a single hierarchy listing discovers top-level
// prefixes, then parallel flat listings enumerate all blobs under each prefix concurrently.
// This avoids the overhead of recursive hierarchy listing at every directory level while
// getting full parallelism across top-level partitions.
// scanConcurrency controls how many flat listings run in parallel.
// When scanConcurrency > 1, cb must be safe for concurrent use by multiple goroutines.
func ListRecursiveStream(ctx context.Context, ap AzurePath, scanConcurrency int, cb func(BlobMeta) error) error {
	rootPrefix := ap.Blob
	if rootPrefix != "" && !strings.HasSuffix(rootPrefix, "/") {
		rootPrefix += "/"
	}
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

	// Parallel flat-per-partition: use one level of hierarchy listing to discover
	// top-level prefixes, then run a flat listing for each prefix in parallel.
	// Each flat listing returns ALL blobs under its prefix (no recursive hierarchy
	// overhead). This dramatically reduces API calls compared to recursive hierarchy
	// walking for deep directory structures.
	var (
		firstErr error
		errOnce  sync.Once
		hasError atomic.Bool
	)

	setErr := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			hasError.Store(true)
		})
	}

	hasErr := func() bool {
		return hasError.Load()
	}

	// Semaphore to bound concurrent flat listing goroutines.
	sem := make(chan struct{}, scanConcurrency)
	var wg sync.WaitGroup

	// Track seen prefixes to avoid listing the same partition twice
	// (a prefix can appear on multiple pages of a hierarchy listing).
	seenPrefixes := make(map[string]struct{})

	// flatPartition runs a flat listing for a single prefix and emits
	// results with names relative to rootPrefix.
	flatPartition := func(prefix, relPrefix string) {
		if err := listRecursiveFlat(ctx, containerClient, ap.Container, prefix, func(bm BlobMeta) error {
			if hasErr() {
				return context.Canceled
			}
			bm.Name = relPrefix + bm.Name
			return cb(bm)
		}); err != nil {
			setErr(err)
		}
	}

	// Discover top-level prefixes via hierarchy listing at root level.
	// Blobs directly under rootPrefix are emitted inline; subdirectory
	// prefixes are dispatched to parallel flat listings.
	opts := &container.ListBlobsHierarchyOptions{}
	if rootPrefix != "" {
		opts.Prefix = &rootPrefix
	}
	pager := containerClient.NewListBlobsHierarchyPager("/", opts)

	for pager.More() {
		if ctx.Err() != nil || hasErr() {
			break
		}
		resp, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.ErrorCode == "ContainerNotFound" {
				setErr(fmt.Errorf("container '%s' not found", ap.Container))
			} else {
				setErr(err)
			}
			break
		}
		if resp.Segment == nil {
			break
		}

		// Emit root-level blobs (files directly under rootPrefix).
		for _, blob := range resp.Segment.BlobItems {
			if blob == nil || blob.Name == nil || blob.Properties == nil || blob.Properties.ContentLength == nil {
				continue
			}
			if hasErr() {
				break
			}
			if err := cb(BlobMeta{
				Name: strings.TrimPrefix(*blob.Name, rootPrefix),
				Size: *blob.Properties.ContentLength,
			}); err != nil {
				setErr(err)
				break
			}
		}

		// Launch parallel flat listings for each discovered prefix.
		for _, bp := range resp.Segment.BlobPrefixes {
			if bp == nil || bp.Name == nil {
				continue
			}
			subPrefix := *bp.Name
			if _, seen := seenPrefixes[subPrefix]; seen {
				continue
			}
			seenPrefixes[subPrefix] = struct{}{}

			if hasErr() {
				break
			}

			relPrefix := strings.TrimPrefix(subPrefix, rootPrefix)
			wg.Add(1)
			// Acquire semaphore; block if all slots are busy so
			// hierarchy discovery pauses until capacity frees up.
			select {
			case sem <- struct{}{}:
				go func(prefix, rel string) {
					defer func() { <-sem; wg.Done() }()
					flatPartition(prefix, rel)
				}(subPrefix, relPrefix)
			case <-ctx.Done():
				wg.Done()
			}
		}
	}

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

func CopyBlobServerSide(ctx context.Context, src AzurePath, dst AzurePath, concurrency int, onProgress CopyProgress) error {
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

	// Get source size for block splitting.
	totalSize, err := HeadBlob(ctx, src)
	if err != nil {
		return fmt.Errorf("failed to get source properties: %w", err)
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

// blobDelegationSASURL generates a SAS URL using a User Delegation Key obtained
// via OAuth. This enables cross-account server-side copy within the same tenant.
func blobDelegationSASURL(ctx context.Context, ap AzurePath) (string, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("default credential: %w", err)
	}
	endpoint := getEndpoint(ap.Account)
	svcClient, err := service.NewClient(endpoint, cred, nil)
	if err != nil {
		return "", fmt.Errorf("service client: %w", err)
	}
	now := time.Now().UTC().Add(-5 * time.Minute) // backdate to tolerate clock skew
	expiry := now.Add(copySASDuration())
	startStr := now.Format(sas.TimeFormat)
	expiryStr := expiry.Format(sas.TimeFormat)
	udc, err := svcClient.GetUserDelegationCredential(ctx, service.KeyInfo{
		Start:  &startStr,
		Expiry: &expiryStr,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("get user delegation credential: %w", err)
	}
	sasValues := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPS,
		StartTime:     now,
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
