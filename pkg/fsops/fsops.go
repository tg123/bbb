package fsops

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// List lists entries in a directory (non-recursive). If path is empty, '.' is used.
func List(path string) ([]fs.DirEntry, error) {
	if path == "" {
		path = "."
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// Walk collects all files/dirs recursively.
func Walk(root string) ([]string, error) {
	if root == "" {
		root = "."
	}
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// CopyFile copies a single file from src to dst, creating parent dirs.
func CopyFile(src, dst string, overwrite bool) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("source is directory; use CopyTree")
	}
	if !overwrite {
		if _, err := os.Stat(dst); err == nil {
			return errors.New("destination exists")
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	srcF, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcF.Close()
	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer dstF.Close()
	if _, err := io.Copy(dstF, srcF); err != nil {
		return err
	}
	return nil
}

// CopyTree recursively copies a directory tree.
func CopyTree(src, dst string, overwrite bool) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return CopyFile(p, target, overwrite)
	})
}

// RemoveFile removes a file.
func RemoveFile(path string) error { return os.Remove(path) }

// RemoveTree removes a directory tree.
func RemoveTree(path string) error { return os.RemoveAll(path) }
