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

// ListRecursive streams all files under the path via the emit callback, using
// provider-specific recursive listing when available, and falling back to
// List and Stat-based traversal.
func ListRecursive(ctx context.Context, root string, emit func(Entry) error) error {
	fs := Resolve(root)

	if rl, ok := fs.(recursiveLister); ok {
		return rl.ListRecursive(ctx, root, emit)
	}
	isRemote := strings.Contains(root, "://")
	return listRecursive(ctx, fs, root, root, "", isRemote, emit)
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
