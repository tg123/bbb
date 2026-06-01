//go:build !linux

package azblob

import "os"

func tryFallocate(f *os.File, size int64) {}
func tryFadviseSequential(f *os.File)     {}
func tryFadviseDontneed(f *os.File)       {}
