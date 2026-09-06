package bbbfs

import (
	"path"
	"sort"
	"strings"
)

// pathBase returns the last path element, ignoring trailing slashes.
func pathBase(name string) string {
	if name == "" {
		return ""
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" {
		return ""
	}
	return path.Base(trimmed)
}

// normalizePrefix cleans a flat-listing prefix: leading slashes are stripped
// and the result is path-cleaned ("" for the root).
func normalizePrefix(prefix string) string {
	for strings.HasPrefix(prefix, "/") {
		prefix = strings.TrimPrefix(prefix, "/")
	}
	if prefix == "" {
		return ""
	}
	prefix = path.Clean(prefix)
	if prefix == "." {
		return ""
	}
	return prefix
}

// filterPrefix returns the prefix in the form used for matching flat file
// names: normalized and, when non-empty, terminated by a slash.
func filterPrefix(prefix string) string {
	prefix = normalizePrefix(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return prefix
}

// filterFilesByPrefix keeps the files under prefix and returns their names
// relative to it. Used by backends (Hugging Face, ACR) that expose a flat
// file list and derive virtual directories from it.
func filterFilesByPrefix(files []string, prefix string) []string {
	prefix = filterPrefix(prefix)
	out := make([]string, 0, len(files))
	for _, file := range files {
		if file == "" {
			continue
		}
		if prefix != "" {
			if !strings.HasPrefix(file, prefix) {
				continue
			}
			file = strings.TrimPrefix(file, prefix)
			if file == "" {
				continue
			}
		}
		out = append(out, file)
	}
	return out
}

// listEntriesByPrefix returns the immediate children of prefix in a flat file
// list; directory entries are suffixed with a slash.
func listEntriesByPrefix(files []string, prefix string) []string {
	seen := map[string]struct{}{}
	for _, file := range filterFilesByPrefix(files, prefix) {
		parts := strings.SplitN(file, "/", 2)
		name := parts[0]
		if name == "" {
			continue
		}
		if len(parts) > 1 {
			name += "/"
		}
		seen[name] = struct{}{}
	}
	entries := make([]string, 0, len(seen))
	for name := range seen {
		entries = append(entries, name)
	}
	sort.Strings(entries)
	return entries
}
