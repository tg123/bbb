// ListContainers lists all containers in the account
package azblob

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"net/http/httptrace"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
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
	return fmt.Sprintf("az://%s/%s/%s", p.Account, p.Container, p.Blob)
}

// Parse parses az://account/container[/blob]
func Parse(raw string) (AzurePath, error) {
	if !strings.HasPrefix(raw, "az://") {
		return AzurePath{}, fmt.Errorf("not az:// path: %s", raw)
	}
	parts := strings.SplitN(raw[5:], "/", 3)
	if len(parts) < 2 {
		return AzurePath{}, errors.New("expected az://account/container[/blob]")
	}
	ap := AzurePath{Account: parts[0], Container: parts[1]}
	if len(parts) == 3 {
		ap.Blob = parts[2]
	}
	return ap, nil
}

// token cache
var (
	tokenMu    sync.Mutex
	tokenVal   string
	tokenExp   time.Time
	credential *azidentity.DefaultAzureCredential
)

func getBearer(ctx context.Context) (string, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	if credential == nil {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return "", err
		}
		credential = cred
	}
	if tokenVal != "" && time.Until(tokenExp) > 2*time.Minute {
		return tokenVal, nil
	}
	tok, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://storage.azure.com/.default"}})
	if err != nil {
		return "", err
	}

	if slog.Default().Enabled(ctx, slog.LevelDebug) {
		parts := strings.Split(tok.Token, ".")
		if len(parts) == 3 {
			payload, err := io.ReadAll(
				base64.NewDecoder(base64.RawURLEncoding, strings.NewReader(parts[1])),
			)
			if err == nil {
				slog.Debug("Decoded JWT payload", "payload", string(payload))
			} else {
				slog.Debug("Failed to decode JWT payload", "error", err)
			}
		} else {
			slog.Debug("Token is not a JWT")
		}
	}

	tokenVal = tok.Token
	tokenExp = tok.ExpiresOn
	return tokenVal, nil
}

const apiVersion = "2021-12-02"

// BlobMeta minimal metadata for listing
type BlobMeta struct {
	Name string
	Size int64
}

// List lists immediate children (non-recursive). If dir-like path provided, lists under it.
func List(ctx context.Context, ap AzurePath) ([]BlobMeta, error) {
	// If only account is provided, list containers
	if ap.Container == "" {
		return ListContainers(ctx, ap.Account)
	}
	ap = ap.WithDir()
	prefix := ap.Blob
	listURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", ap.Account, ap.Container)
	if prefix != "" {
		listURL += "&prefix=" + url.QueryEscape(prefix)
	}
	// Use delimiter to simulate hierarchy
	listURL += "&delimiter=/"
	auth, err := getBearer(ctx)
	if err != nil {
		return nil, err
	}
	type blobItem struct {
		Name       string `xml:"Name"`
		Properties struct {
			ContentLength int64 `xml:"Content-Length"`
		} `xml:"Properties"`
	}
	type blobPrefix struct {
		Name string `xml:"Name"`
	}
	type result struct {
		Blobs struct {
			Blob       []blobItem   `xml:"Blob"`
			BlobPrefix []blobPrefix `xml:"BlobPrefix"`
		} `xml:"Blobs"`
		NextMarker string `xml:"NextMarker"`
	}
	var out []BlobMeta
	marker := ""
	for {
		urlStr := listURL
		if marker != "" {
			urlStr += "&marker=" + url.QueryEscape(marker)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		req = withHTTPTrace(req)
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("x-ms-version", apiVersion)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("list failed %s: %s", resp.Status, truncate(string(body), 200))
		}
		var r result
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		for _, bp := range r.Blobs.BlobPrefix {
			out = append(out, BlobMeta{Name: strings.TrimPrefix(bp.Name, prefix), Size: 0})
		}
		for _, b := range r.Blobs.Blob {
			out = append(out, BlobMeta{Name: strings.TrimPrefix(b.Name, prefix), Size: b.Properties.ContentLength})
		}
		if r.NextMarker == "" {
			break
		}
		marker = r.NextMarker
	}
	return out, nil
}

// ListRecursive retrieves all blobs under path (treats path as prefix root)
func ListRecursive(ctx context.Context, ap AzurePath) ([]BlobMeta, error) {
	prefix := ap.Blob
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	listURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s?restype=container&comp=list", ap.Account, ap.Container)
	if prefix != "" {
		listURL += "&prefix=" + url.QueryEscape(prefix)
	}
	auth, err := getBearer(ctx)
	if err != nil {
		return nil, err
	}
	type blobItem struct {
		Name       string `xml:"Name"`
		Properties struct {
			ContentLength int64 `xml:"Content-Length"`
		} `xml:"Properties"`
	}
	type result struct {
		Blobs struct {
			Blob []blobItem `xml:"Blob"`
		} `xml:"Blobs"`
		NextMarker string `xml:"NextMarker"`
	}
	var out []BlobMeta
	marker := ""
	for {
		urlStr := listURL
		if marker != "" {
			urlStr += "&marker=" + url.QueryEscape(marker)
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		req = withHTTPTrace(req)
		req.Header.Set("Authorization", "Bearer "+auth)
		req.Header.Set("x-ms-version", apiVersion)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("list failed %s: %s", resp.Status, truncate(string(body), 200))
		}
		var r result
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		for _, b := range r.Blobs.Blob {
			out = append(out, BlobMeta{Name: strings.TrimPrefix(b.Name, prefix), Size: b.Properties.ContentLength})
		}
		if r.NextMarker == "" {
			break
		}
		marker = r.NextMarker
	}
	return out, nil
}

// HeadBlob returns size (bytes) of blob
func HeadBlob(ctx context.Context, ap AzurePath) (int64, error) {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return 0, errors.New("path is directory-like")
	}
	auth, err := getBearer(ctx)
	if err != nil {
		return 0, err
	}
	urlStr := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", ap.Account, ap.Container, ap.Blob)
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, urlStr, nil)
	req = withHTTPTrace(req)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("x-ms-version", apiVersion)
	req.Header.Set("x-ms-date", time.Now().UTC().Format(http.TimeFormat))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return 0, osNotExist(ap.String())
	}
	if resp.StatusCode >= 300 {
		return 0, fmt.Errorf("head failed: %s", resp.Status)
	}
	var size int64
	fmt.Sscan(resp.Header.Get("Content-Length"), &size)
	return size, nil
}

// Download returns blob content bytes (for small blobs)
func Download(ctx context.Context, ap AzurePath) ([]byte, error) {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return nil, errors.New("cannot download directory")
	}
	auth, err := getBearer(ctx)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", ap.Account, ap.Container, ap.Blob)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	req = withHTTPTrace(req)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("x-ms-version", apiVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, osNotExist(ap.String())
	}
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get failed: %s %s", resp.Status, truncate(string(body), 120))
	}
	return io.ReadAll(resp.Body)
}

// Upload writes blob (overwrite)
func Upload(ctx context.Context, ap AzurePath, data []byte) error {
	if ap.Blob == "" || strings.HasSuffix(ap.Blob, "/") {
		return errors.New("cannot upload to directory-like path")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return err
	}
	client, err := azblob.NewClient(fmt.Sprintf("https://%s.blob.core.windows.net/", ap.Account), cred, nil)
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
	auth, err := getBearer(ctx)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", ap.Account, ap.Container, ap.Blob)
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	req = withHTTPTrace(req)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("x-ms-version", apiVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return osNotExist(ap.String())
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("delete failed: %s", resp.Status)
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
	urlStr := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)
	auth, err := getBearer(ctx)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	req = withHTTPTrace(req)
	req.Header.Set("Authorization", "Bearer "+auth)
	req.Header.Set("x-ms-version", apiVersion)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("list failed %s: %s", resp.Status, truncate(string(body), 200))
	}
	type containerItem struct {
		Name string `xml:"Name"`
	}
	type result struct {
		Containers struct {
			Container []containerItem `xml:"Container"`
		} `xml:"Containers"`
	}
	var r result
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	var out []BlobMeta
	for _, c := range r.Containers.Container {
		out = append(out, BlobMeta{Name: c.Name, Size: 0})
	}
	return out, nil
}
