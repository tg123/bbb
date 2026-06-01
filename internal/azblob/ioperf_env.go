package azblob

import (
	"os"
	"strings"
)

// envDownloadFadviseDontneed lets users opt into POSIX_FADV_DONTNEED on
// the destination file once the download finishes. It forces synchronous
// page eviction and trades wall-clock time for reduced page-cache
// pressure — useful on hosts where another workload owns the cache.
const envDownloadFadviseDontneed = "BBB_DOWNLOAD_FADVISE_DONTNEED"

func envOn(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
