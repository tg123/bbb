//go:build linux

package azblob

import (
	"os"

	"golang.org/x/sys/unix"
)

// tryFallocate preallocates size bytes on the file. Eliminates per-pwrite
// extent allocation and journal commits on ext4/xfs, which strace shows as
// ~5 ms/pwrite of intrinsic kernel cost on large sparse downloads.
// Returns true if the syscall succeeded.
func tryFallocate(f *os.File, size int64) bool {
	if size <= 0 {
		return false
	}
	return unix.Fallocate(int(f.Fd()), 0, 0, size) == nil
}

// tryFadviseSequential hints the kernel that pages will be accessed in
// order. Triggers aggressive readahead on read and drops pages after they
// pass the read window on either path.
func tryFadviseSequential(f *os.File) bool {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_SEQUENTIAL) == nil
}

// tryFadviseDontneed asks the kernel to drop cached pages for the file.
// Used after closing a large download we won't re-read so we don't evict
// genuinely-hot pages from other workloads on the host.
func tryFadviseDontneed(f *os.File) bool {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED) == nil
}

// mmapFile maps the whole file (must be sized) as a read+write region.
// Returns the mapped byte slice; caller must munmap.
func mmapFile(f *os.File, size int64, write bool) ([]byte, error) {
	prot := unix.PROT_READ
	if write {
		prot |= unix.PROT_WRITE
	}
	return unix.Mmap(int(f.Fd()), 0, int(size), prot, unix.MAP_SHARED)
}

func munmap(b []byte) error { return unix.Munmap(b) }

// madviseSequential hints kernel to readahead aggressively on mmap region.
func madviseSequential(b []byte) {
	_ = unix.Madvise(b, unix.MADV_SEQUENTIAL)
}
