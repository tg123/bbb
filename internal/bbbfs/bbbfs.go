package bbbfs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tg123/bbb/internal/azblob"
	"github.com/tg123/bbb/internal/hf"
)

// FS provides abstract read/write access for supported backends.
type FS interface {
	Match(path string) bool
	Read(ctx context.Context, path string) (io.ReadCloser, error)
	Write(ctx context.Context, path string, r io.Reader) error
}

var (
	providers       []FS
	providersMu     sync.RWMutex
	azProvider      = azFS{}
	hfProvider      = hfFS{}
	localFSProvider = localFS{}
)

// ErrWriteUnsupported indicates that a backend does not support writes.
var ErrWriteUnsupported = errors.New("bbbfs: write not supported")

func init() {
	// Register order defines resolution priority; localFS is the fallback.
	Register(hfProvider)
	Register(azProvider)
	Register(localFSProvider)
}

// Register adds a filesystem provider.
func Register(provider FS) {
	providersMu.Lock()
	defer providersMu.Unlock()
	providers = append(providers, provider)
}

// Resolve returns the first filesystem provider that matches the path.
func Resolve(path string) FS {
	providersMu.RLock()
	defer providersMu.RUnlock()
	for _, provider := range providers {
		if provider.Match(path) {
			return provider
		}
	}
	return localFSProvider
}

type azFS struct{}

func (azFS) Match(path string) bool {
	return strings.HasPrefix(path, "az://") || azblob.IsBlobURL(path)
}

func (azFS) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	ap, err := azblob.Parse(path)
	if err != nil {
		return nil, err
	}
	return azblob.DownloadStream(ctx, ap)
}

func (azFS) Write(ctx context.Context, path string, r io.Reader) error {
	ap, err := azblob.Parse(path)
	if err != nil {
		return err
	}
	return azblob.UploadStream(ctx, ap, r)
}

type hfFS struct{}

func (hfFS) Match(path string) bool {
	return strings.HasPrefix(path, "hf://")
}

func (hfFS) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	hp, err := hf.Parse(path)
	if err != nil {
		return nil, err
	}
	return hf.DownloadStream(ctx, hp)
}

func (hfFS) Write(ctx context.Context, path string, r io.Reader) error {
	return ErrWriteUnsupported
}

type localFS struct{}

func (localFS) Match(path string) bool {
	return true
}

func (localFS) Read(ctx context.Context, path string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func (localFS) Write(ctx context.Context, path string, r io.Reader) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return writeLocal(path, r)
}

func writeLocal(path string, r io.Reader) (err error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	dstFile, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := dstFile.Close(); err == nil {
			err = closeErr
		}
	}()
	_, err = io.Copy(dstFile, r)
	return err
}
