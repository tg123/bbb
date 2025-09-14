// ListContainers lists all containers in the account
package azblob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"

	"net/http/httptrace"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
)

// withHTTPTrace attaches httptrace to the request for debugging
func withHTTPTrace(req *http.Request) *http.Request {
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			slog.Debug("httptrace: GotConn", "reused", info.Reused, "wasIdle", info.WasIdle)
		},
		DNSStart: func(info httptrace.DNSStartInfo) {
			slog.Debug("httptrace: DNSStart", "host", info.Host)
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			slog.Debug("httptrace: DNSDone", "addrs", info.Addrs, "err", info.Err)
		},
		ConnectStart: func(network, addr string) {
			slog.Debug("httptrace: ConnectStart", "network", network, "addr", addr)
		},
		ConnectDone: func(network, addr string, err error) {
			slog.Debug("httptrace: ConnectDone", "network", network, "addr", addr, "err", err)
		},
		GotFirstResponseByte: func() {
			slog.Debug("httptrace: GotFirstResponseByte")
		},
	}

	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
}

// AzurePath represents an az:// path (account/container/blob)
type AzurePath struct {
	Account   string
	Container string
	Blob      string // may be empty or end with '/' for virtual directory
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

// Parse parses az://account/container[/blob]
func Parse(raw string) (AzurePath, error) {
	if !strings.HasPrefix(raw, "az://") {
		return AzurePath{}, fmt.Errorf("not az:// path: %s", raw)
	}
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

// List lists immediate children (non-recursive). If dir-like path provided, lists under it.
func getAzBlobClient(account string) (*azblob.Client, error) {
	endpoint := getEndpoint(account)
	if key := os.Getenv("BBB_AZBLOB_ACCOUNTKEY"); key != "" {
		cred, err := azblob.NewSharedKeyCredential(account, key)
		if err != nil {
			return nil, err
		}
		return azblob.NewClientWithSharedKeyCredential(endpoint+"/", cred, nil)
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return azblob.NewClient(endpoint+"/", cred, nil)
}

func List(ctx context.Context, ap AzurePath) ([]BlobMeta, error) {
	if ap.Container == "" { // account root: list containers
		return ListContainers(ctx, ap.Account)
	}
	ap = ap.WithDir()
	prefix := ap.Blob
	client, err := getAzBlobClient(ap.Account)
	if err != nil {
		return nil, err
	}
	containerClient := client.ServiceClient().NewContainerClient(ap.Container)
	pager := containerClient.NewListBlobsFlatPager(&azblob.ListBlobsFlatOptions{
		Prefix:  &prefix,
		Include: azblob.ListBlobsInclude{Metadata: true},
	})
	var out []BlobMeta
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if resp.Segment == nil {
			// Check if error is due to missing container
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.ErrorCode == "ContainerNotFound" {
				return nil, fmt.Errorf("container '%s' not found", ap.Container)
			}
			// If Segment is nil but no error, treat as empty container
			return []BlobMeta{}, nil
		}
		for _, blob := range resp.Segment.BlobItems {
			if blob == nil || blob.Name == nil || blob.Properties == nil || blob.Properties.ContentLength == nil {
				continue
			}
			out = append(out, BlobMeta{Name: strings.TrimPrefix(*blob.Name, prefix), Size: *blob.Properties.ContentLength})
		}
	}
	return out, nil
}

// ListRecursive retrieves all blobs under path (treats path as prefix root)
func ListRecursive(ctx context.Context, ap AzurePath) ([]BlobMeta, error) {
	prefix := ap.Blob
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	client, err := getAzBlobClient(ap.Account)
	if err != nil {
		return nil, err
	}
	containerClient := client.ServiceClient().NewContainerClient(ap.Container)
	pager := containerClient.NewListBlobsFlatPager(&azblob.ListBlobsFlatOptions{
		Prefix:  &prefix,
		Include: azblob.ListBlobsInclude{Metadata: true},
	})
	var out []BlobMeta
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if resp.Segment == nil {
			// Check if error is due to missing container
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.ErrorCode == "ContainerNotFound" {
				return nil, fmt.Errorf("container '%s' not found", ap.Container)
			}
			// If Segment is nil but no error, treat as empty container
			return []BlobMeta{}, nil
		}
		for _, blob := range resp.Segment.BlobItems {
			if blob == nil || blob.Name == nil || blob.Properties == nil || blob.Properties.ContentLength == nil {
				continue
			}
			out = append(out, BlobMeta{Name: strings.TrimPrefix(*blob.Name, prefix), Size: *blob.Properties.ContentLength})
		}
	}
	return out, nil
}

// HeadBlob returns size (bytes) of blob
func HeadBlob(ctx context.Context, ap AzurePath) (int64, error) {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return 0, errors.New("path is directory-like")
	}
	client, err := getAzBlobClient(ap.Account)
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
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return nil, errors.New("cannot download directory")
	}
	client, err := getAzBlobClient(ap.Account)
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
	data, err := io.ReadAll(downloadResp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Upload writes blob (overwrite)
func Upload(ctx context.Context, ap AzurePath, data []byte) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("cannot upload to directory-like path")
	}
	client, err := getAzBlobClient(ap.Account)
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

// Delete deletes a single blob
func Delete(ctx context.Context, ap AzurePath) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("path is directory-like; use DeletePrefix")
	}
	client, err := getAzBlobClient(ap.Account)
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

// Error helpers
type notExistError string

func (e notExistError) Error() string  { return string(e) + ": not found" }
func (e notExistError) NotFound() bool { return true }
func osNotExist(s string) error        { return notExistError(s) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ListContainers lists all containers in the account
func ListContainers(ctx context.Context, account string) ([]BlobMeta, error) {
	client, err := getAzBlobClient(account)
	if err != nil {
		return nil, err
	}
	pager := client.ServiceClient().NewListContainersPager(nil)
	var out []BlobMeta
	for pager.More() {
		resp, err := pager.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		for _, c := range resp.ContainerItems {
			out = append(out, BlobMeta{Name: *c.Name, Size: 0})
		}
	}
	return out, nil
}
