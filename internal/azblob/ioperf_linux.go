//go:build linux

package azblob

import (
	"os"

	"golang.org/x/sys/unix"
)

// tryFallocate preallocates size bytes on the file. Best-effort: silently
// no-ops on filesystems or kernels that reject the syscall. On ext4/xfs
// this collapses extent allocation + journal cost from per-pwrite into a
// single up-front allocation, which strace shows as the dominant kernel
// cost for large parallel downloads.
func tryFallocate(f *os.File, size int64) {
	if size <= 0 {
		return
	}
	_ = unix.Fallocate(int(f.Fd()), 0, 0, size)
}

// tryFadviseSequential hints the kernel to size readahead / writeback for
// sequential access. Cheap and safe: just metadata on the inode.
func tryFadviseSequential(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_SEQUENTIAL)
}

// tryFadviseDontneed asks the kernel to drop cached pages for the file.
// Forces synchronous writeback + eviction; trades latency for cache
// hygiene. Use only when the caller explicitly opts in.
func tryFadviseDontneed(f *os.File) {
	_ = unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
