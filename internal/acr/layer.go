package acr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"
	"sync/atomic"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// fileLayer adapts an UploadFile to go-containerregistry's v1.Layer.
//
// Artifact layers are stored verbatim rather than gzipped, so the compressed
// and uncompressed views are the same bytes and Digest equals DiffID. Content
// is streamed from the opener on every read instead of being buffered, which
// matters because bbb routinely pushes multi-gigabyte files.
type fileLayer struct {
	ctx    context.Context
	open   func() (io.ReadCloser, error)
	size   int64
	onRead func(int64)

	once   sync.Once
	digest v1.Hash
	err    error

	// reported is the high-water byte count already surfaced to onRead, so a
	// retried upload does not count the same bytes twice.
	reported atomic.Int64
}

var _ v1.Layer = (*fileLayer)(nil)

// ctxReader aborts a read as soon as the push context is cancelled.
type ctxReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Digest hashes the content once and caches the result. go-containerregistry
// asks for the digest before uploading so it can skip blobs the registry
// already has.
//
// The hash pass reads the whole file, which for bbb is routinely many
// gigabytes and happens before any registry I/O, so it honours the push
// context rather than running to EOF after a cancellation.
func (l *fileLayer) Digest() (v1.Hash, error) {
	l.once.Do(func() {
		reader, err := l.open()
		if err != nil {
			l.err = err
			return
		}
		defer func() {
			_ = reader.Close()
		}()
		var source io.Reader = reader
		if l.ctx != nil {
			source = ctxReader{ctx: l.ctx, reader: reader}
		}
		hasher := sha256.New()
		written, err := io.Copy(hasher, source)
		if err != nil {
			l.err = err
			return
		}
		// Always record what was actually hashed. A declared size that no
		// longer matches would put a length in the descriptor that disagrees
		// with the blob it describes.
		l.size = written
		l.digest = v1.Hash{Algorithm: "sha256", Hex: hex.EncodeToString(hasher.Sum(nil))}
	})
	return l.digest, l.err
}

// DiffID matches Digest because the layer is not compressed.
func (l *fileLayer) DiffID() (v1.Hash, error) {
	return l.Digest()
}

func (l *fileLayer) Compressed() (io.ReadCloser, error) {
	reader, err := l.open()
	if err != nil {
		return nil, err
	}
	if l.onRead == nil {
		return reader, nil
	}
	return &progressReadCloser{ReadCloser: reader, layer: l}, nil
}

func (l *fileLayer) Uncompressed() (io.ReadCloser, error) {
	return l.Compressed()
}

// Size reports the hashed length, so the descriptor always agrees with the
// blob rather than with whatever size was declared at collection time.
func (l *fileLayer) Size() (int64, error) {
	if _, err := l.Digest(); err != nil {
		return 0, err
	}
	return l.size, nil
}

func (l *fileLayer) MediaType() (types.MediaType, error) {
	return layerMediaType, nil
}

// progressReadCloser reports bytes as they are uploaded.
//
// go-containerregistry sets GetBody so a retried request reopens the layer, so
// only progress beyond the layer's high-water mark is reported. Counting every
// physical read would let a retransmission push the total past the artifact's
// real size.
type progressReadCloser struct {
	io.ReadCloser
	layer *fileLayer
	read  int64
}

func (r *progressReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.read += int64(n)
		for {
			previous := r.layer.reported.Load()
			if r.read <= previous {
				break
			}
			if r.layer.reported.CompareAndSwap(previous, r.read) {
				r.layer.onRead(r.read - previous)
				break
			}
		}
	}
	return n, err
}
