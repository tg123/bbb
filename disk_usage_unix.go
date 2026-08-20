//go:build !windows

package main

import (
	"os"
	"syscall"
)

func fileAllocatedSize(info os.FileInfo) int64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Blocks * 512
	}
	return info.Size()
}
