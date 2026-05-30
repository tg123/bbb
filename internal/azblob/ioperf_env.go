package azblob

import "os"

// Experimental high-performance I/O env flags. All default-off; set to
// "1" or "true" to enable. These are intentionally undocumented while we
// benchmark them; winners will be promoted to defaults.
const (
	envDownloadFallocate = "BBB_DOWNLOAD_FALLOCATE"
	envDownloadFadvise   = "BBB_DOWNLOAD_FADVISE"
	envDownloadMmap      = "BBB_DOWNLOAD_MMAP"
	envUploadFadvise     = "BBB_UPLOAD_FADVISE"
	envUploadMmap        = "BBB_UPLOAD_MMAP"
)

func envOn(name string) bool {
	switch os.Getenv(name) {
	case "1", "true", "TRUE", "yes", "on":
		return true
	}
	return false
}
