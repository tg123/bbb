package bbbfs

import (
	"context"
	"path"
	"path/filepath"
	"strings"
)

// recursiveLister is implemented by backends that support efficient recursive listing.
type recursiveLister interface {
	ListRecursive(ctx context.Context, root string, emit func(Entry) error) error
}

type recursiveSummarizer interface {
	SummarizeRecursive(ctx context.Context, root string, onProgress func(count, size int64)) (RecursiveSummary, error)
}

// RecursiveSummary contains aggregate metadata for a recursive file listing.
type RecursiveSummary struct {
	FileCount int64
	TotalSize int64
}

// SummarizeRecursive returns aggregate file count and size without retaining
// individual entries. Backends may optimize this operation independently.
func SummarizeRecursive(ctx context.Context, root string, onProgress func(count, size int64)) (RecursiveSummary, error) {
	if summarizer, ok := Resolve(root).(recursiveSummarizer); ok {
		return summarizer.SummarizeRecursive(ctx, root, onProgress)
	}
	var summary RecursiveSummary
	for result := range ListRecursive(ctx, root) {
		if result.Err != nil {
			return summary, result.Err
		}
		if result.Entry.Name == "" || result.Entry.IsDir {
			continue
		}
		summary.FileCount++
		summary.TotalSize += result.Entry.Size
		if onProgress != nil && summary.FileCount%4096 == 0 {
			onProgress(summary.FileCount, summary.TotalSize)
		}
	}
	if onProgress != nil {
		onProgress(summary.FileCount, summary.TotalSize)
	}
	return summary, nil
}

// ListRecursive returns a channel that streams all files under the path.
// Entries are emitted as they are discovered; any listing error is sent as a
// ListResult with Err set. The channel is closed when listing completes or
// the context is cancelled. Callers should cancel the context if they stop
// consuming the channel early.
func ListRecursive(ctx context.Context, root string) <-chan ListResult {
	ch := make(chan ListResult, 4096)
	go func() {
		defer close(ch)
		emit := func(e Entry) error {
			select {
			case ch <- ListResult{Entry: e}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		fs := Resolve(root)
		var err error
		if rl, ok := fs.(recursiveLister); ok {
			err = rl.ListRecursive(ctx, root, emit)
		} else {
			isRemote := strings.Contains(root, "://")
			err = listRecursive(ctx, fs, root, root, "", isRemote, emit)
		}
		if err != nil && ctx.Err() == nil {
			select {
			case ch <- ListResult{Err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return ch
}

func listRecursive(ctx context.Context, fs FS, root, current, relPrefix string, isRemote bool, emit func(Entry) error) error {
	entries, err := fs.List(ctx, current)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		childName := strings.TrimSuffix(entry.Name, "/")
		if childName == "" {
			continue
		}
		childPath := entry.Path
		if entry.IsDir && !strings.HasSuffix(childPath, "/") && isRemote {
			childPath += "/"
		}
		childRel := childName
		if relPrefix != "" {
			if isRemote {
				childRel = path.Join(relPrefix, childName)
			} else {
				childRel = filepath.Join(relPrefix, childName)
			}
		}
		if entry.IsDir {
			if err := listRecursive(ctx, fs, root, childPath, childRel, isRemote, emit); err != nil {
				return err
			}
			continue
		}
		stat, err := fs.Stat(ctx, childPath)
		if err != nil {
			return err
		}
		if !isRemote {
			if relPath, relErr := filepath.Rel(root, stat.Path); relErr == nil {
				stat.Name = relPath
			} else {
				stat.Name = childRel
			}
		} else {
			stat.Name = childRel
		}
		stat.Path = childPath
		if err := emit(stat); err != nil {
			return err
		}
	}
	return nil
}
