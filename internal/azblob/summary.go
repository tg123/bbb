package azblob

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

// SummarizeRecursive counts blobs and bytes under ap. When the root contains
// multiple virtual directories, each directory is scanned independently so
// Azure continuation-token chains can advance in parallel.
func SummarizeRecursive(ctx context.Context, ap AzurePath, scanConcurrency int, onProgress func(count, size int64)) (int64, int64, error) {
	rootPrefix := normalizeRootPrefix(ap.Blob)
	client, err := getAzBlobClient(ctx, ap.Account)
	if err != nil {
		return 0, 0, err
	}
	containerClient := client.ServiceClient().NewContainerClient(ap.Container)
	if scanConcurrency <= 1 {
		return summarizeFlat(ctx, containerClient, ap.Container, rootPrefix, onProgress)
	}

	prefixes, rootCount, rootSize, err := summaryPartitions(ctx, containerClient, ap.Container, rootPrefix)
	if err != nil {
		return 0, 0, err
	}
	if len(prefixes) < 2 {
		return summarizeFlat(ctx, containerClient, ap.Container, rootPrefix, onProgress)
	}

	count, size, partitionCount, err := summarizePrefixSet(
		ctx, prefixes, scanConcurrency, rootCount, rootSize, onProgress,
		func(ctx context.Context, prefix string, progress func(count, size int64)) (int64, int64, error) {
			return summarizeFlat(ctx, containerClient, ap.Container, prefix, progress)
		},
	)
	if err != nil {
		return count, size, err
	}
	if partitionCount == 0 {
		// Azurite versions that support hierarchy listing can still return no
		// results for flat listings scoped to a virtual-directory prefix.
		return summarizeFlat(ctx, containerClient, ap.Container, rootPrefix, func(flatCount, flatSize int64) {
			if onProgress != nil && flatCount >= count && flatSize >= size {
				onProgress(flatCount, flatSize)
			}
		})
	}
	return count, size, nil
}

func summaryPartitions(ctx context.Context, client *container.Client, containerName, rootPrefix string) ([]string, int64, int64, error) {
	opts := &container.ListBlobsHierarchyOptions{}
	if rootPrefix != "" {
		opts.Prefix = &rootPrefix
	}
	pager := client.NewListBlobsHierarchyPager("/", opts)
	seen := make(map[string]struct{})
	var prefixes []string
	var count, size int64
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return nil, 0, 0, summaryListError(err, containerName)
		}
		if resp.Segment == nil {
			break
		}
		for _, prefix := range resp.Segment.BlobPrefixes {
			if prefix == nil || prefix.Name == nil {
				continue
			}
			if _, ok := seen[*prefix.Name]; ok {
				continue
			}
			seen[*prefix.Name] = struct{}{}
			prefixes = append(prefixes, *prefix.Name)
		}
		pageCount, pageSize := summarizeBlobItems(resp.Segment.BlobItems)
		count += pageCount
		size += pageSize
	}
	return prefixes, count, size, nil
}

type prefixSummarizer func(ctx context.Context, prefix string, onProgress func(count, size int64)) (int64, int64, error)

func summarizePrefixSet(
	ctx context.Context,
	prefixes []string,
	concurrency int,
	initialCount, initialSize int64,
	onProgress func(count, size int64),
	summarize prefixSummarizer,
) (int64, int64, int64, error) {
	if concurrency > len(prefixes) {
		concurrency = len(prefixes)
	}
	if concurrency < 1 {
		concurrency = 1
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan string)
	var aggregateMu sync.Mutex
	count := initialCount
	size := initialSize
	var partitionCount int64
	if onProgress != nil && initialCount > 0 {
		onProgress(initialCount, initialSize)
	}
	addProgress := func(countDelta, sizeDelta int64) {
		aggregateMu.Lock()
		defer aggregateMu.Unlock()
		partitionCount += countDelta
		count += countDelta
		size += sizeDelta
		if onProgress != nil {
			onProgress(count, size)
		}
	}
	snapshot := func() (int64, int64, int64) {
		aggregateMu.Lock()
		defer aggregateMu.Unlock()
		return count, size, partitionCount
	}

	var firstErr error
	var errOnce sync.Once
	setErr := func(err error) {
		errOnce.Do(func() {
			firstErr = err
			cancel()
		})
	}

	var workers sync.WaitGroup
	workers.Add(concurrency)
	for range concurrency {
		go func() {
			defer workers.Done()
			for prefix := range jobs {
				var previousCount, previousSize int64
				_, _, err := summarize(workerCtx, prefix, func(prefixCount, prefixSize int64) {
					countDelta := prefixCount - previousCount
					sizeDelta := prefixSize - previousSize
					previousCount = prefixCount
					previousSize = prefixSize
					addProgress(countDelta, sizeDelta)
				})
				if err != nil {
					setErr(err)
					return
				}
			}
		}()
	}

sendLoop:
	for _, prefix := range prefixes {
		select {
		case jobs <- prefix:
		case <-workerCtx.Done():
			break sendLoop
		}
	}
	close(jobs)
	workers.Wait()
	finalCount, finalSize, finalPartitionCount := snapshot()
	if firstErr != nil {
		return finalCount, finalSize, finalPartitionCount, firstErr
	}
	if err := ctx.Err(); err != nil {
		return finalCount, finalSize, finalPartitionCount, err
	}
	return finalCount, finalSize, finalPartitionCount, nil
}

func summarizeFlat(ctx context.Context, client *container.Client, containerName, prefix string, onProgress func(count, size int64)) (int64, int64, error) {
	opts := &azblob.ListBlobsFlatOptions{}
	if prefix != "" {
		opts.Prefix = &prefix
	}
	pager := client.NewListBlobsFlatPager(opts)
	var count, size int64
	for pager.More() {
		resp, err := pager.NextPage(ctx)
		if err != nil {
			return count, size, summaryListError(err, containerName)
		}
		if resp.Segment == nil {
			break
		}
		pageCount, pageSize := summarizeBlobItems(resp.Segment.BlobItems)
		count += pageCount
		size += pageSize
		if onProgress != nil && pageCount > 0 {
			onProgress(count, size)
		}
	}
	return count, size, nil
}

func summarizeBlobItems(items []*container.BlobItem) (int64, int64) {
	var count, size int64
	for _, blob := range items {
		if blob == nil || blob.Name == nil || strings.HasSuffix(*blob.Name, "/") ||
			blob.Properties == nil || blob.Properties.ContentLength == nil {
			continue
		}
		count++
		size += *blob.Properties.ContentLength
	}
	return count, size
}

func summaryListError(err error, containerName string) error {
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) && responseErr.ErrorCode == "ContainerNotFound" {
		return fmt.Errorf("container '%s' not found", containerName)
	}
	return err
}
