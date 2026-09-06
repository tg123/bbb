package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/tg123/bbb/internal/acr"
	"github.com/tg123/bbb/internal/bbbfs"
	"github.com/tg123/bbb/internal/gs"
)

func validateLocalCopyNames(root string, names []string) error {
	for _, name := range names {
		if _, err := localCopyPath(root, name); err != nil {
			return err
		}
	}
	// Reuse artifact extraction's case-folded/NFC and file/directory
	// coexistence rules for every remote-to-local download.
	if err := acr.ValidateLocalNames(names); err != nil {
		return fmt.Errorf("unsafe local destination: %w", err)
	}
	return nil
}

// listCopyEntries preflights a remote-to-local expansion before emitting any
// work, so aliases cannot race to overwrite the same local file. Disjoint
// remote destinations keep streaming and preserve their object-store semantics.
func listCopyEntries(ctx context.Context, src, dst string, sourceErr error, exclude func(string) bool, emit func(bbbfs.Entry) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if bbbfs.IsGS(src) && bbbfs.IsGS(dst) {
		source, err := gs.Parse(src)
		if err != nil {
			return err
		}
		destination, err := gs.Parse(dst)
		if err != nil {
			return err
		}
		// Match listing/Child prefix boundaries without cleaning opaque keys.
		// Overlapping trees can overwrite unread sources or feed newly copied
		// objects back into later listing pages.
		sourcePrefix, destinationPrefix := source.WithDir().Object, destination.WithDir().Object
		if source.Bucket == destination.Bucket &&
			(strings.HasPrefix(sourcePrefix, destinationPrefix) || strings.HasPrefix(destinationPrefix, sourcePrefix)) {
			return fmt.Errorf("overlapping GCS source and destination prefixes: %s -> %s", src, dst)
		}
	}
	preflight := bbbfs.IsRemote(src) && !bbbfs.IsRemote(dst)
	var entries []bbbfs.Entry
	var names []string
	found := false
	err := bbbfs.ListRecursiveWithSizeStream(ctx, src, func(entry bbbfs.Entry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir || entry.Name == "" {
			return nil
		}
		found = true
		if exclude != nil && exclude(entry.Name) {
			return nil
		}
		if _, err := copyDestination(src, dst, entry.Name); err != nil {
			return err
		}
		if preflight {
			entries = append(entries, entry)
			names = append(names, entry.Name)
			return nil
		}
		return emit(entry)
	})
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !found && sourceErr != nil {
		return sourceErr
	}
	if preflight {
		if err := validateLocalCopyNames(dst, names); err != nil {
			return err
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := emit(entry); err != nil {
				return err
			}
		}
	}
	return nil
}
