package bbbfs

import (
	"context"
	"path"
	"path/filepath"
	"strings"
)

// recursiveLister is implemented by backends that support efficient recursive listing.
type recursiveLister interface {
	ListRecursive(ctx context.Context, root string) ([]Entry, error)
}

// ListRecursive lists all files under the path, using provider-specific recursive
// listing when available, and falling back to List and Stat-based traversal.
func ListRecursive(ctx context.Context, root string) ([]Entry, error) {
	fs := Resolve(root)

	if rl, ok := fs.(recursiveLister); ok {
		return rl.ListRecursive(ctx, root)
	}
	isRemote := strings.Contains(root, "://")
	return listRecursive(ctx, fs, root, root, "", isRemote)
}

func listRecursive(ctx context.Context, fs FS, root, current, relPrefix string, isRemote bool) ([]Entry, error) {
	entries, err := fs.List(ctx, current)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		childName := strings.TrimSuffix(entry.Name, "/")
		if childName == "" {
			continue
		}
		childPath := entry.Path
		if entry.IsDir && !strings.HasSuffix(childPath, "/") && isRemote {
			childPath += "/"
		}
		if !isRemote && !filepath.IsAbs(childPath) {
			childPath = filepath.Join(current, childPath)
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
			childEntries, err := listRecursive(ctx, fs, root, childPath, childRel, isRemote)
			if err != nil {
				return nil, err
			}
			out = append(out, childEntries...)
			continue
		}
		stat, err := fs.Stat(ctx, childPath)
		if err != nil {
			return nil, err
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
		out = append(out, stat)
	}
	return out, nil
}
