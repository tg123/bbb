//go:build !linux

package azblob

import (
	"errors"
	"os"
)

func tryFallocate(f *os.File, size int64) bool        { return false }
func tryFadviseSequential(f *os.File) bool            { return false }
func tryFadviseDontneed(f *os.File) bool              { return false }
func mmapFile(f *os.File, size int64, write bool) ([]byte, error) {
	return nil, errors.New("mmap not supported on this platform")
}
func munmap(b []byte) error      { return nil }
func madviseSequential(b []byte) {}
