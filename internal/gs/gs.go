// Package gs provides a thin wrapper around the Google Cloud Storage client
// that mirrors the surface of the internal/azblob and internal/s3 packages, so
// that bbb can treat Google Cloud Storage as a first-class backend addressed
// via gs://bucket/object paths.
package gs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"cloud.google.com/go/storage"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const (
	// Scheme is the path prefix that identifies Google Cloud Storage paths.
	Scheme = "gs://"

	// downloadChunkSize is the range size used by the parallel downloader.
	downloadChunkSize = 16 * 1024 * 1024

	// deleteConcurrency bounds the number of parallel object deletions
	// performed by DeletePrefix (GCS has no batch delete API).
	deleteConcurrency = 32
)

// GSPath represents a gs:// path (bucket/object).
type GSPath struct {
	Bucket string
	Object string // may be empty or end with '/' for a virtual directory
}

// IsDirLike reports whether the path refers to a bucket root or a virtual
// directory (empty object name or one ending in '/').
func (p GSPath) IsDirLike() bool { return p.Object == "" || strings.HasSuffix(p.Object, "/") }

// WithDir returns a copy of the path whose object name is guaranteed to end
// with '/'.
func (p GSPath) WithDir() GSPath {
	if p.Object == "" || strings.HasSuffix(p.Object, "/") {
		return p
	}
	p.Object += "/"
	return p
}

// Child returns the path of a relative child of this path.
func (p GSPath) Child(rel string) GSPath {
	if p.Object == "" {
		return GSPath{Bucket: p.Bucket, Object: rel}
	}
	// GCS object names are opaque byte strings: path.Clean would collapse
	// "."/".." segments and duplicate slashes, misaddressing objects and
	// breaking round-trips between listing output and subsequent operations.
	return GSPath{Bucket: p.Bucket, Object: strings.TrimSuffix(p.Object, "/") + "/" + rel}
}

// String renders the path back into its gs://bucket/object form.
func (p GSPath) String() string {
	if p.Bucket == "" {
		return Scheme
	}
	if p.Object == "" {
		return Scheme + p.Bucket
	}
	return Scheme + p.Bucket + "/" + p.Object
}

// Parse parses a gs://bucket[/object] path.
func Parse(raw string) (GSPath, error) {
	if !strings.HasPrefix(raw, Scheme) {
		return GSPath{}, fmt.Errorf("not a gs:// path: %s", raw)
	}
	rest := raw[len(Scheme):]
	if rest == "" {
		return GSPath{}, errors.New("expected gs://bucket[/object]")
	}
	parts := strings.SplitN(rest, "/", 2)
	gp := GSPath{Bucket: parts[0]}
	if gp.Bucket == "" {
		return GSPath{}, errors.New("expected gs://bucket[/object]")
	}
	if len(parts) == 2 {
		gp.Object = parts[1]
	}
	return gp, nil
}

// ObjectMeta is minimal object metadata used for listing.
type ObjectMeta struct {
	Name string
	Size int64
}

// --- Client construction and caching ---

var (
	sharedHTTPClient atomic.Pointer[http.Client]

	cachedClient     *storage.Client
	cachedClientOnce sync.Once
	cachedClientErr  error
)

// SetHTTPClient installs a shared *http.Client used when talking to a custom
// endpoint (emulator). Against real Google Cloud Storage the SDK builds its own
// authenticated client on top of http.DefaultTransport, which bbb already
// replaces with the DNS-pinning/logging transport, so the override is only
// needed for unauthenticated endpoints. Passing nil clears the override. It
// must be called before the client is first constructed.
func SetHTTPClient(c *http.Client) {
	sharedHTTPClient.Store(c)
}

func endpoint() string {
	if v := strings.TrimSpace(os.Getenv("BBB_GS_ENDPOINT")); v != "" {
		return v
	}
	// The Google SDK's own emulator variable, honoured for compatibility with
	// existing tooling (e.g. fake-gcs-server setups).
	if v := strings.TrimSpace(os.Getenv("STORAGE_EMULATOR_HOST")); v != "" {
		return v
	}
	return ""
}

// normalizeEndpoint returns the endpoint with a scheme, defaulting to http://
// (emulators are usually plain HTTP), and without a trailing slash.
func normalizeEndpoint(ep string) string {
	if ep == "" {
		return ""
	}
	if !strings.Contains(ep, "://") {
		ep = "http://" + ep
	}
	return strings.TrimRight(ep, "/")
}

// Endpoint returns the configured custom GCS endpoint (BBB_GS_ENDPOINT or
// STORAGE_EMULATOR_HOST), or an empty string when targeting Google Cloud.
func Endpoint() string { return normalizeEndpoint(endpoint()) }

// Project returns the Google Cloud project used for operations that require
// one (currently bucket creation).
func Project() string {
	for _, env := range []string{"BBB_GS_PROJECT", "GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return v
		}
	}
	return ""
}

// getClient returns a process-wide cached GCS client. Credentials are resolved
// from the standard Google sources (GOOGLE_APPLICATION_CREDENTIALS, gcloud
// application default credentials, workload identity). When a custom endpoint
// is configured (BBB_GS_ENDPOINT / STORAGE_EMULATOR_HOST) authentication is
// disabled so emulators such as fake-gcs-server can be used.
func getClient(ctx context.Context) (*storage.Client, error) {
	cachedClientOnce.Do(func() {
		var opts []option.ClientOption
		if ep := Endpoint(); ep != "" {
			// The chosen endpoint drives both the JSON API host and the
			// media (read/write) host inside the SDK.
			opts = append(opts,
				option.WithEndpoint(ep+"/storage/v1/"),
				option.WithoutAuthentication(),
			)
			if c := sharedHTTPClient.Load(); c != nil {
				opts = append(opts, option.WithHTTPClient(c))
			}
		}
		client, err := storage.NewClient(ctx, opts...)
		if err != nil {
			cachedClientErr = err
			return
		}
		cachedClient = client
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
	if errors.Is(err, storage.ErrObjectNotExist) || errors.Is(err, storage.ErrBucketNotExist) {
		return true
	}
	var ae *googleapi.Error
	if errors.As(err, &ae) && ae.Code == http.StatusNotFound {
		return true
	}
	return false
}

// --- Data plane ---

// DownloadStream opens the object for streaming reads.
func DownloadStream(ctx context.Context, gp GSPath) (io.ReadCloser, error) {
	client, err := getClient(ctx)
	if err != nil {
		return nil, err
	}
	r, err := client.Bucket(gp.Bucket).Object(gp.Object).NewReader(ctx)
	if err != nil {
		if isNotFound(err) {
			return nil, notExistError(gp.String())
		}
		return nil, err
	}
	return r, nil
}

// HeadObject returns the size of the object, or an error if it does not exist.
func HeadObject(ctx context.Context, gp GSPath) (int64, error) {
	client, err := getClient(ctx)
	if err != nil {
		return 0, err
	}
	attrs, err := client.Bucket(gp.Bucket).Object(gp.Object).Attrs(ctx)
	if err != nil {
		if isNotFound(err) {
			return 0, notExistError(gp.String())
		}
		return 0, err
	}
	return attrs.Size, nil
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

// upload copies reader into the object, reporting cumulative bytes when
// onProgress is non-nil.
func upload(ctx context.Context, gp GSPath, reader io.Reader, onProgress func(int64)) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	if onProgress != nil {
		var read atomic.Int64
		reader = &progressReader{r: reader, read: &read, onProgress: onProgress}
	}
	w := client.Bucket(gp.Bucket).Object(gp.Object).NewWriter(ctx)
	if _, err := io.Copy(w, reader); err != nil {
		// Abort the upload session so no partial object is committed.
		_ = w.Close()
		return err
	}
	return w.Close()
}

// UploadStream uploads the contents of reader to the object. GCS commits a
// single resumable upload session per object, so concurrency is accepted for
// API symmetry with the other backends but unused.
func UploadStream(ctx context.Context, gp GSPath, reader io.Reader, _ int) error {
	return upload(ctx, gp, reader, nil)
}

// UploadFile uploads a local file to the object, reporting cumulative bytes via
// onProgress.
func UploadFile(ctx context.Context, gp GSPath, file *os.File, _ int, onProgress func(int64)) error {
	return upload(ctx, gp, file, onProgress)
}

// DownloadFile downloads the object into file using parallel ranged reads,
// returning the number of bytes written.
func DownloadFile(ctx context.Context, gp GSPath, file *os.File, concurrency int, onProgress func(int64)) (int64, error) {
	client, err := getClient(ctx)
	if err != nil {
		return 0, err
	}
	if concurrency < 1 {
		concurrency = 1
	}
	obj := client.Bucket(gp.Bucket).Object(gp.Object)
	attrs, err := obj.Attrs(ctx)
	if err != nil {
		if isNotFound(err) {
			return 0, notExistError(gp.String())
		}
		return 0, err
	}
	size := attrs.Size
	if size == 0 {
		if err := file.Truncate(0); err != nil {
			return 0, err
		}
		if onProgress != nil {
			onProgress(0)
		}
		return 0, nil
	}
	// Pin the generation so concurrent ranges cannot mix content from two
	// different versions of the object.
	obj = obj.Generation(attrs.Generation)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var written atomic.Int64
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var firstErrOnce sync.Once
	var firstErr error
	fail := func(err error) {
		firstErrOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for start := int64(0); start < size; start += downloadChunkSize {
		length := int64(downloadChunkSize)
		if start+length > size {
			length = size - start
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(start, length int64) {
			defer wg.Done()
			defer func() { <-sem }()
			r, err := obj.NewRangeReader(ctx, start, length)
			if err != nil {
				fail(err)
				return
			}
			defer func() { _ = r.Close() }()
			buf := make([]byte, 1024*1024)
			off := start
			for {
				n, rerr := r.Read(buf)
				if n > 0 {
					if _, werr := file.WriteAt(buf[:n], off); werr != nil {
						fail(werr)
						return
					}
					off += int64(n)
					total := written.Add(int64(n))
					if onProgress != nil {
						onProgress(total)
					}
				}
				if rerr == io.EOF {
					return
				}
				if rerr != nil {
					fail(rerr)
					return
				}
			}
		}(start, length)
	}
	wg.Wait()
	if firstErr != nil {
		if isNotFound(firstErr) {
			return written.Load(), notExistError(gp.String())
		}
		return written.Load(), firstErr
	}
	return written.Load(), nil
}

// Touch creates an empty object at the path.
func Touch(ctx context.Context, gp GSPath) error {
	if gp.IsDirLike() {
		return fmt.Errorf("cannot touch directory-like path: %s", gp.String())
	}
	return upload(ctx, gp, strings.NewReader(""), nil)
}

// Delete removes a single object.
func Delete(ctx context.Context, gp GSPath) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	if err := client.Bucket(gp.Bucket).Object(gp.Object).Delete(ctx); err != nil {
		if isNotFound(err) {
			return notExistError(gp.String())
		}
		return err
	}
	return nil
}

// MkBucket creates a bucket, ignoring an already-exists error for a bucket we
// can already read.
func MkBucket(ctx context.Context, bucket string) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	project := Project()
	if project == "" {
		if Endpoint() == "" {
			return errors.New("a Google Cloud project is required: set BBB_GS_PROJECT or GOOGLE_CLOUD_PROJECT")
		}
		// Emulators ignore the project, but the API requires a non-empty value.
		project = "bbb"
	}
	if err := client.Bucket(bucket).Create(ctx, project, nil); err != nil {
		var ae *googleapi.Error
		if errors.As(err, &ae) && ae.Code == http.StatusConflict {
			// The bucket name is taken; treat as idempotent success only when
			// the bucket is readable by us (i.e. it is our own bucket).
			if _, aerr := client.Bucket(bucket).Attrs(ctx); aerr == nil {
				return nil
			}
		}
		return err
	}
	return nil
}

// --- Listing ---

func normalizePrefix(name string) string {
	if name == "" || strings.HasSuffix(name, "/") {
		return name
	}
	return name + "/"
}

// ListStream lists the immediate children (objects and virtual directories)
// under the path, invoking cb for each. Directories are reported with a
// trailing '/'.
func ListStream(ctx context.Context, gp GSPath, cb func(ObjectMeta) error) error {
	return listStream(ctx, gp, "/", cb)
}

// ListRecursiveStream lists every object under the path (no delimiter),
// invoking cb with the object name relative to the path prefix.
func ListRecursiveStream(ctx context.Context, gp GSPath, cb func(ObjectMeta) error) error {
	return listStream(ctx, gp, "", func(m ObjectMeta) error {
		if m.Name == "" || strings.HasSuffix(m.Name, "/") {
			return nil
		}
		return cb(m)
	})
}

func listStream(ctx context.Context, gp GSPath, delimiter string, cb func(ObjectMeta) error) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	prefix := normalizePrefix(gp.Object)
	it := client.Bucket(gp.Bucket).Objects(ctx, &storage.Query{
		Prefix:    prefix,
		Delimiter: delimiter,
	})
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return nil
		}
		if err != nil {
			if isNotFound(err) {
				return notExistError(gp.String())
			}
			return err
		}
		if attrs.Prefix != "" {
			name := strings.TrimPrefix(attrs.Prefix, prefix)
			if name == "" {
				continue
			}
			if err := cb(ObjectMeta{Name: name}); err != nil {
				return err
			}
			continue
		}
		name := strings.TrimPrefix(attrs.Name, prefix)
		if name == "" {
			continue // the directory marker itself
		}
		if err := cb(ObjectMeta{Name: name, Size: attrs.Size}); err != nil {
			return err
		}
	}
}

// List returns the immediate children under the path.
func List(ctx context.Context, gp GSPath) ([]ObjectMeta, error) {
	var out []ObjectMeta
	if err := ListStream(ctx, gp, func(m ObjectMeta) error {
		out = append(out, m)
		return nil
	}); err != nil {
		return nil, err
	}
	return out, nil
}

// DeletePrefix deletes every object under the path's prefix.
func DeletePrefix(ctx context.Context, gp GSPath) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	bucket := client.Bucket(gp.Bucket)
	prefix := normalizePrefix(gp.Object)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	it := bucket.Objects(ctx, &storage.Query{Prefix: prefix})

	sem := make(chan struct{}, deleteConcurrency)
	var wg sync.WaitGroup
	var firstErrOnce sync.Once
	var firstErr error
	fail := func(err error) {
		firstErrOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			fail(err)
			break
		}
		name := attrs.Name
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()
			if derr := bucket.Object(name).Delete(ctx); derr != nil && !isNotFound(derr) {
				fail(derr)
			}
		}(name)
	}
	wg.Wait()
	return firstErr
}

// --- Server-side copy ---

// CopyServerSide performs a server-side copy from src to dst within GCS using
// the rewrite API, which handles objects of any size. sizeHint, when > 0,
// avoids an attribute lookup. onProgress, when non-nil, receives
// (copied, total) updates.
func CopyServerSide(ctx context.Context, src, dst GSPath, _ int, sizeHint int64, onProgress func(copied, total int64)) error {
	client, err := getClient(ctx)
	if err != nil {
		return err
	}
	copier := client.Bucket(dst.Bucket).Object(dst.Object).CopierFrom(client.Bucket(src.Bucket).Object(src.Object))
	total := sizeHint
	if onProgress != nil {
		copier.ProgressFunc = func(copied, size uint64) {
			total = int64(size)
			onProgress(int64(copied), int64(size))
		}
	}
	attrs, err := copier.Run(ctx)
	if err != nil {
		if isNotFound(err) {
			return notExistError(src.String())
		}
		return err
	}
	if onProgress != nil {
		if attrs != nil && attrs.Size > 0 {
			total = attrs.Size
		}
		onProgress(total, total)
	}
	return nil
}
