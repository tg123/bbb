package acr

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sync"

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
	open   func() (io.ReadCloser, error)
	size   int64
	onRead func(int64)

	once   sync.Once
	digest v1.Hash
	err    error
}

var _ v1.Layer = (*fileLayer)(nil)

// Digest hashes the content once and caches the result. go-containerregistry
// asks for the digest before uploading so it can skip blobs the registry
// already has.
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
		hasher := sha256.New()
		written, err := io.Copy(hasher, reader)
		if err != nil {
			l.err = err
			return
		}
		if l.size < 0 {
			l.size = written
		}
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
	return &progressReadCloser{ReadCloser: reader, onRead: l.onRead}, nil
}

func (l *fileLayer) Uncompressed() (io.ReadCloser, error) {
	return l.Compressed()
}

func (l *fileLayer) Size() (int64, error) {
	if l.size >= 0 {
		return l.size, nil
	}
	if _, err := l.Digest(); err != nil {
		return 0, err
	}
	return l.size, nil
}

func (l *fileLayer) MediaType() (types.MediaType, error) {
	return layerMediaType, nil
}

// progressReadCloser reports bytes as they are uploaded.
type progressReadCloser struct {
	io.ReadCloser
	onRead func(int64)
}

func (r *progressReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.onRead(int64(n))
	}
	return n, err
}
