package bbbfs

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"
)

// FS provides abstract access for supported backends.
type FS interface {
	Match(path string) bool
	Read(ctx context.Context, path string) (io.ReadCloser, error)
	Write(ctx context.Context, path string, r io.Reader) error
	List(ctx context.Context, path string) ([]Entry, error)
	Stat(ctx context.Context, path string) (Entry, error)
}

// Entry is a filesystem entry metadata.
type Entry struct {
	Name    string
	Path    string
	Size    int64
	IsDir   bool
	ModTime time.Time
}

// HFScheme is the scheme prefix for Hugging Face paths.
const HFScheme = "hf://"

// ErrWriteUnsupported indicates that a backend does not support writes.
var ErrWriteUnsupported = errors.New("bbbfs: write not supported")

var (
	providers       []FS
	providersMu     sync.RWMutex
	azProvider      = azFS{}
	hfProvider      = hfFS{}
	localFSProvider = localFS{}
)

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
