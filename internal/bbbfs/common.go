package bbbfs

import (
	"path"
	"strings"

	"github.com/tg123/bbb/internal/azblob"
)

// IsAz reports whether the path refers to an Azure blob resource.
func IsAz(path string) bool {
	return strings.HasPrefix(path, "az://") || azblob.IsBlobURL(path)
}

// IsHF reports whether the path refers to a Hugging Face resource.
func IsHF(path string) bool {
	return strings.HasPrefix(path, HFScheme)
}

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
