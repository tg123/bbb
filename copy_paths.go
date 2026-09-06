package main

import (
	"context"
	"fmt"

	"github.com/tg123/bbb/internal/acr"
	"github.com/tg123/bbb/internal/bbbfs"
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
// work, so aliases cannot race to overwrite the same local file. Remote
// destinations keep streaming and preserve their object-store semantics.
func listCopyEntries(ctx context.Context, src, dst string, sourceErr error, exclude func(string) bool, emit func(bbbfs.Entry) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
