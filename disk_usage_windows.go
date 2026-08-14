//go:build windows

package main

import "os"

func fileAllocatedSize(info os.FileInfo) int64 {
	return info.Size()
}
