package bbbfs

import (
	"path"
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
