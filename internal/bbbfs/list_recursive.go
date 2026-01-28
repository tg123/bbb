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
	remote := IsAz(root) || IsHF(root)
	return listRecursive(ctx, fs, root, root, "", remote)
}

func listRecursive(ctx context.Context, fs FS, root, current, relPrefix string, remote bool) ([]Entry, error) {
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
		if strings.HasSuffix(entry.Name, "/") && !strings.HasSuffix(childPath, "/") {
			childPath += "/"
		}
		if !remote && !filepath.IsAbs(childPath) {
			childPath = filepath.Join(current, childPath)
		}
		childRel := childName
		if relPrefix != "" {
			if remote {
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
			childEntries, err := listRecursive(ctx, fs, root, childPath, childRel, remote)
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
