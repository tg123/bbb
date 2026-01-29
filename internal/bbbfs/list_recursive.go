package bbbfs

import (
	"context"
	"path"
	"path/filepath"
	"strings"
)

// ListRecursive lists all files under the path using List and Stat metadata.
func ListRecursive(ctx context.Context, root string) ([]Entry, error) {
	fs := Resolve(root)
	isRemote := IsAz(root) || IsHF(root)
	return listRecursive(ctx, fs, root, "", isRemote)
}

func listRecursive(ctx context.Context, fs FS, current, relPrefix string, isRemote bool) ([]Entry, error) {
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
		stat, err := fs.Stat(ctx, childPath)
		if err != nil {
			return nil, err
		}
		if stat.IsDir {
			childEntries, err := listRecursive(ctx, fs, childPath, childRel, isRemote)
			if err != nil {
				return nil, err
			}
			out = append(out, childEntries...)
			continue
		}
		stat.Name = childRel
		stat.Path = childPath
		out = append(out, stat)
	}
	return out, nil
}
