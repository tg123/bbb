// Package s3 provides a thin wrapper around the AWS SDK for Go v2 that mirrors
// the surface of the internal/azblob package, so that bbb can treat Amazon S3
// (and S3-compatible object stores such as MinIO, Cloudflare R2 and Wasabi) as
// a first-class backend addressed via s3://bucket/key paths.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

const (
	// Scheme is the path prefix that identifies S3 paths.
	Scheme = "s3://"

	// defaultRegion is used when no region is configured via the environment.
	defaultRegion = "us-east-1"

	// s3MaxSingleCopyBytes is the maximum object size (5 GiB) for which the
	// single-request CopyObject API may be used. Larger objects require a
	// multipart copy.
	s3MaxSingleCopyBytes = 5 * 1024 * 1024 * 1024

	// copyPartSize is the part size used for multipart server-side copies.
	copyPartSize = 256 * 1024 * 1024

	// deleteBatchSize is the maximum number of keys per DeleteObjects request.
	deleteBatchSize = 1000
)

// S3Path represents an s3:// path (bucket/key).
type S3Path struct {
	Bucket string
	Key    string // may be empty or end with '/' for a virtual directory
}

// IsDirLike reports whether the path refers to a bucket root or a virtual
// directory (empty key or key ending in '/').
func (p S3Path) IsDirLike() bool { return p.Key == "" || strings.HasSuffix(p.Key, "/") }

// WithDir returns a copy of the path whose key is guaranteed to end with '/'.
func (p S3Path) WithDir() S3Path {
	if p.Key == "" || strings.HasSuffix(p.Key, "/") {
		return p
	}
	p.Key += "/"
	return p
}

// Child returns the path of a relative child of this path.
func (p S3Path) Child(rel string) S3Path {
	if p.Key == "" {
		return S3Path{Bucket: p.Bucket, Key: rel}
	}
	return S3Path{Bucket: p.Bucket, Key: path.Clean(p.Key + "/" + rel)}
}

// String renders the path back into its s3://bucket/key form.
func (p S3Path) String() string {
	if p.Bucket == "" {
		return Scheme
	}
	if p.Key == "" {
		return Scheme + p.Bucket
	}
	return Scheme + p.Bucket + "/" + p.Key
}

// Parse parses an s3://bucket[/key] path.
func Parse(raw string) (S3Path, error) {
	if !strings.HasPrefix(raw, Scheme) {
		return S3Path{}, fmt.Errorf("not an s3:// path: %s", raw)
	}
	rest := raw[len(Scheme):]
	if rest == "" {
		return S3Path{}, errors.New("expected s3://bucket[/key]")
	}
	parts := strings.SplitN(rest, "/", 2)
	sp := S3Path{Bucket: parts[0]}
	if sp.Bucket == "" {
		return S3Path{}, errors.New("expected s3://bucket[/key]")
	}
	if len(parts) == 2 {
		sp.Key = parts[1]
	}
	return sp, nil
}

// ObjectMeta is minimal object metadata used for listing.
type ObjectMeta struct {
	Name string
	Size int64
}

// --- Client construction and caching ---

var (
	sharedHTTPClient atomic.Pointer[http.Client]

	cachedClient     *awss3.Client
	cachedClientOnce sync.Once
	cachedClientErr  error
)

// SetHTTPClient installs a shared *http.Client used by the S3 SDK client. This
// allows DNS pinning/caching and debug logging installed on the underlying
// transport to apply to S3 traffic. Passing nil clears the override. It must be
// called before the client is first constructed.
func SetHTTPClient(c *http.Client) {
	sharedHTTPClient.Store(c)
}

func forcePathStyle() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BBB_S3_FORCE_PATH_STYLE")))
	return v == "1" || v == "true" || v == "yes"
}

func region() string {
	for _, env := range []string{"BBB_S3_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	return defaultRegion
}

func endpoint() string {
	return strings.TrimSpace(os.Getenv("BBB_S3_ENDPOINT"))
}

// Endpoint returns the configured custom S3 endpoint (BBB_S3_ENDPOINT), or an
// empty string when targeting AWS.
func Endpoint() string { return endpoint() }

// ForcePathStyle reports whether path-style addressing is forced
// (BBB_S3_FORCE_PATH_STYLE).
func ForcePathStyle() bool { return forcePathStyle() }

// getClient returns a process-wide cached S3 client. Credentials and region are
// resolved from the standard AWS sources (environment, shared config/credential
// files, IAM roles). The endpoint and path-style addressing can be overridden
// for S3-compatible stores via BBB_S3_ENDPOINT and BBB_S3_FORCE_PATH_STYLE.
func getClient(ctx context.Context) (*awss3.Client, error) {
	cachedClientOnce.Do(func() {
		opts := []func(*awsconfig.LoadOptions) error{
			awsconfig.WithRegion(region()),
		}
		if c := sharedHTTPClient.Load(); c != nil {
			opts = append(opts, awsconfig.WithHTTPClient(c))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			cachedClientErr = err
			return
		}
		ep := endpoint()
		pathStyle := forcePathStyle()
		cachedClient = awss3.NewFromConfig(cfg, func(o *awss3.Options) {
			if ep != "" {
				o.BaseEndpoint = aws.String(ep)
			}
			if pathStyle {
				o.UsePathStyle = true
			}
		})
	})
	return cachedClient, cachedClientErr
}

// --- Errors ---

type notExistError string

func (e notExistError) Error() string  { return string(e) + ": not found" }
func (e notExistError) NotFound() bool { return true }

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nf *s3types.NotFound
	if errors.As(err, &nf) {
		return true
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}

// --- Data plane ---

// DownloadStream opens the object for streaming reads.
func DownloadStream(ctx context.Context, sp S3Path) (io.ReadCloser, error) {
	client, err := getClient(ctx)
	if err != nil {
		return nil, err
	}
	out, err := client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
	})
	if err != nil {
		if isNotFound(err) {
			return nil, notExistError(sp.String())
		}
		return nil, err
	}
	return out.Body, nil
}

// HeadObject returns the size of the object, or an error if it does not exist.
func HeadObject(ctx context.Context, sp S3Path) (int64, error) {
	client, err := getClient(ctx)
	if err != nil {
		return 0, err
	}
	out, err := client.HeadObject(ctx, &awss3.HeadObjectInput{
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
	})
	if err != nil {
		if isNotFound(err) {
			return 0, notExistError(sp.String())
		}
		return 0, err
	}
	if out.ContentLength == nil {
		return 0, nil
	}
	return *out.ContentLength, nil
}

// progressReader wraps an io.Reader and reports cumulative bytes read.
type progressReader struct {
	r          io.Reader
	read       *atomic.Int64
	onProgress func(int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 {
		total := pr.read.Add(int64(n))
		if pr.onProgress != nil {
			pr.onProgress(total)
		}
	}
	return n, err
}

// UploadStream uploads the contents of reader to the object using the S3
// transfer manager with the given concurrency.
func UploadStream(ctx context.Context, sp S3Path, reader io.Reader, concurrency int) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	uploader := manager.NewUploader(client, func(u *manager.Uploader) { //nolint:staticcheck // transfermanager replacement is still a v0.x developer preview; stay on the GA manager API
		u.Concurrency = concurrency
	})
	_, err = uploader.Upload(ctx, &awss3.PutObjectInput{ //nolint:staticcheck // see manager.NewUploader note above
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
		Body:   reader,
	})
	return err
}

// UploadFile uploads a local file to the object using the transfer manager,
// reporting cumulative bytes via onProgress.
func UploadFile(ctx context.Context, sp S3Path, file *os.File, concurrency int, onProgress func(int64)) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	var read atomic.Int64
	var body io.Reader = file
	if onProgress != nil {
		body = &progressReader{r: file, read: &read, onProgress: onProgress}
	}
	uploader := manager.NewUploader(client, func(u *manager.Uploader) { //nolint:staticcheck // transfermanager replacement is still a v0.x developer preview; stay on the GA manager API
		u.Concurrency = concurrency
	})
	_, err = uploader.Upload(ctx, &awss3.PutObjectInput{ //nolint:staticcheck // see manager.NewUploader note above
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
		Body:   body,
	})
	return err
}

// progressWriterAt wraps an io.WriterAt and reports cumulative bytes written.
type progressWriterAt struct {
	w          io.WriterAt
	written    *atomic.Int64
	onProgress func(int64)
}

func (pw *progressWriterAt) WriteAt(p []byte, off int64) (int, error) {
	n, err := pw.w.WriteAt(p, off)
	if n > 0 {
		total := pw.written.Add(int64(n))
		if pw.onProgress != nil {
			pw.onProgress(total)
		}
	}
	return n, err
}

// DownloadFile downloads the object into file using parallel ranged GETs via
// the transfer manager, returning the number of bytes written.
func DownloadFile(ctx context.Context, sp S3Path, file *os.File, concurrency int, onProgress func(int64)) (int64, error) {
	client, err := getClient(ctx)
	if err != nil {
		return 0, err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	downloader := manager.NewDownloader(client, func(d *manager.Downloader) { //nolint:staticcheck // transfermanager replacement is still a v0.x developer preview; stay on the GA manager API
		d.Concurrency = concurrency
	})
	var w io.WriterAt = file
	if onProgress != nil {
		var written atomic.Int64
		w = &progressWriterAt{w: file, written: &written, onProgress: onProgress}
	}
	n, err := downloader.Download(ctx, w, &awss3.GetObjectInput{ //nolint:staticcheck // see manager.NewDownloader note above
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
	})
	if err != nil {
		if isNotFound(err) {
			return 0, notExistError(sp.String())
		}
		return 0, err
	}
	return n, nil
}

// Touch creates an empty object at the path (no-op size 0 PutObject).
func Touch(ctx context.Context, sp S3Path) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
		Body:   strings.NewReader(""),
	})
	return err
}

// Delete removes a single object.
func Delete(ctx context.Context, sp S3Path) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	_, err = client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(sp.Bucket),
		Key:    aws.String(sp.Key),
	})
	return err
}

// MkBucket creates a bucket, ignoring an already-exists/owned error.
func MkBucket(ctx context.Context, bucket string) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	input := &awss3.CreateBucketInput{Bucket: aws.String(bucket)}
	// Outside us-east-1 a LocationConstraint is required.
	if r := region(); r != "" && r != defaultRegion {
		input.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(r),
		}
	}
	_, err = client.CreateBucket(ctx, input)
	if err != nil {
		var ae smithy.APIError
		if errors.As(err, &ae) {
			switch ae.ErrorCode() {
			case "BucketAlreadyOwnedByYou":
				return nil
			case "BucketAlreadyExists":
				// On AWS this means the globally-unique name is taken by
				// someone else, so surface it. Only treat it as idempotent
				// success against S3-compatible endpoints (e.g. MinIO), where
				// bucket names are local and a custom endpoint is configured.
				if endpoint() != "" {
					return nil
				}
			}
		}
		return err
	}
	return nil
}

// --- Listing ---

func normalizePrefix(key string) string {
	if key == "" || strings.HasSuffix(key, "/") {
		return key
	}
	return key + "/"
}

// ListStream lists the immediate children (files and virtual directories) under
// the path, invoking cb for each. Directories are reported with a trailing '/'.
func ListStream(ctx context.Context, sp S3Path, cb func(ObjectMeta) error) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	prefix := normalizePrefix(sp.Key)
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket:    aws.String(sp.Bucket),
		Prefix:    aws.String(prefix),
		Delimiter: aws.String("/"),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, cp := range page.CommonPrefixes {
			if cp.Prefix == nil {
				continue
			}
			name := strings.TrimPrefix(*cp.Prefix, prefix)
			if name == "" {
				continue
			}
			if err := cb(ObjectMeta{Name: name}); err != nil {
				return err
			}
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			name := strings.TrimPrefix(*obj.Key, prefix)
			if name == "" {
				continue // the directory marker itself
			}
			var size int64
			if obj.Size != nil {
				size = *obj.Size
			}
			if err := cb(ObjectMeta{Name: name, Size: size}); err != nil {
				return err
			}
		}
	}
	return nil
}

// List returns the immediate children under the path.
func List(ctx context.Context, sp S3Path) ([]ObjectMeta, error) {
	var out []ObjectMeta
	if err := ListStream(ctx, sp, func(m ObjectMeta) error {
		out = append(out, m)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// ListRecursiveStream lists every object under the path (no delimiter),
// invoking cb with the key relative to the path prefix.
func ListRecursiveStream(ctx context.Context, sp S3Path, cb func(ObjectMeta) error) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	prefix := normalizePrefix(sp.Key)
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket: aws.String(sp.Bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			name := strings.TrimPrefix(*obj.Key, prefix)
			if name == "" || strings.HasSuffix(name, "/") {
				continue
			}
			var size int64
			if obj.Size != nil {
				size = *obj.Size
			}
			if err := cb(ObjectMeta{Name: name, Size: size}); err != nil {
				return err
			}
		}
	}
	return nil
}

// DeletePrefix deletes every object under the path's prefix in batches.
func DeletePrefix(ctx context.Context, sp S3Path) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	prefix := normalizePrefix(sp.Key)
	paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{
		Bucket: aws.String(sp.Bucket),
		Prefix: aws.String(prefix),
	})
	var batch []s3types.ObjectIdentifier
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		_, err := client.DeleteObjects(ctx, &awss3.DeleteObjectsInput{
			Bucket: aws.String(sp.Bucket),
			Delete: &s3types.Delete{Objects: batch, Quiet: aws.Bool(true)},
		})
		batch = batch[:0]
		return err
	}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			batch = append(batch, s3types.ObjectIdentifier{Key: obj.Key})
			if len(batch) >= deleteBatchSize {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
	return flush()
}

// --- Server-side copy ---

// CopyServerSide performs a server-side copy from src to dst within S3. For
// objects up to 5 GiB the single-request CopyObject API is used; larger objects
// use a multipart UploadPartCopy. sizeHint, when > 0, avoids a HeadObject call.
// onProgress, when non-nil, receives (copied, total) updates.
func CopyServerSide(ctx context.Context, src, dst S3Path, concurrency int, sizeHint int64, onProgress func(copied, total int64)) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	size := sizeHint
	if size <= 0 {
		size, err = HeadObject(ctx, src)
		if err != nil {
			return err
		}
	}
	copySource := src.Bucket + "/" + escapeKey(src.Key)
	if size <= s3MaxSingleCopyBytes {
		_, err := client.CopyObject(ctx, &awss3.CopyObjectInput{
			Bucket:     aws.String(dst.Bucket),
			Key:        aws.String(dst.Key),
			CopySource: aws.String(copySource),
		})
		if err != nil {
			return err
		}
		if onProgress != nil {
			onProgress(size, size)
		}
		return nil
	}
	return multipartCopy(ctx, client, src, dst, copySource, size, concurrency, onProgress)
}

func multipartCopy(ctx context.Context, client *awss3.Client, src, dst S3Path, copySource string, size int64, concurrency int, onProgress func(copied, total int64)) error {
	create, err := client.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket: aws.String(dst.Bucket),
		Key:    aws.String(dst.Key),
	})
	if err != nil {
		return err
	}
	uploadID := create.UploadId

	var parts []struct {
		start int64
		end   int64
		num   int32
	}
	var partNum int32 = 1
	for start := int64(0); start < size; start += copyPartSize {
		end := start + copyPartSize - 1
		if end >= size {
			end = size - 1
		}
		parts = append(parts, struct {
			start int64
			end   int64
			num   int32
		}{start, end, partNum})
		partNum++
	}

	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	results := make([]s3types.CompletedPart, len(parts))
	errs := make([]error, len(parts))
	var copied atomic.Int64
	var wg sync.WaitGroup
	for i, p := range parts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, start, end int64, num int32) {
			defer wg.Done()
			defer func() { <-sem }()
			rng := fmt.Sprintf("bytes=%d-%d", start, end)
			out, err := client.UploadPartCopy(ctx, &awss3.UploadPartCopyInput{
				Bucket:          aws.String(dst.Bucket),
				Key:             aws.String(dst.Key),
				UploadId:        uploadID,
				PartNumber:      aws.Int32(num),
				CopySource:      aws.String(copySource),
				CopySourceRange: aws.String(rng),
			})
			if err != nil {
				errs[i] = err
				return
			}
			results[i] = s3types.CompletedPart{
				ETag:       out.CopyPartResult.ETag,
				PartNumber: aws.Int32(num),
			}
			if onProgress != nil {
				total := copied.Add(end - start + 1)
				onProgress(total, size)
			}
		}(i, p.start, p.end, p.num)
	}
	wg.Wait()

	for _, e := range errs {
		if e != nil {
			_, _ = client.AbortMultipartUpload(ctx, &awss3.AbortMultipartUploadInput{
				Bucket:   aws.String(dst.Bucket),
				Key:      aws.String(dst.Key),
				UploadId: uploadID,
			})
			return e
		}
	}
	_, err = client.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
		Bucket:          aws.String(dst.Bucket),
		Key:             aws.String(dst.Key),
		UploadId:        uploadID,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: results},
	})
	return err
}

// escapeKey URL-encodes an object key for use in a CopySource header, keeping
// the path separators intact.
func escapeKey(key string) string {
	segments := strings.Split(key, "/")
	for i, s := range segments {
		segments[i] = pathSegmentEscape(s)
	}
	return strings.Join(segments, "/")
}

// pathSegmentEscape percent-encodes characters that are unsafe in a single
// path segment of a CopySource value.
func pathSegmentEscape(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		if isUnreservedByte(r) {
			b.WriteByte(r)
			continue
		}
		b.WriteByte('%')
		fmt.Fprintf(&b, "%02X", r)
	}
	return b.String()
}

func isUnreservedByte(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '~':
		return true
	}
	return false
}
