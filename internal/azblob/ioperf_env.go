package azblob

// envDownloadFadviseDontneed lets users opt into POSIX_FADV_DONTNEED on
// the destination file once the download finishes. It forces synchronous
// page eviction and trades wall-clock time for reduced page-cache
// pressure — useful on hosts where another workload owns the cache.
const envDownloadFadviseDontneed = "BBB_DOWNLOAD_FADVISE_DONTNEED"
