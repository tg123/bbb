package bbbfs

import "testing"

func TestHFFilterFiles(t *testing.T) {
	files := []string{"dir/file.txt", "dir/sub/file2.txt", "root.txt"}
	got := filterFilesByPrefix(files, "/dir")
	if len(got) != 2 || got[0] != "file.txt" || got[1] != "sub/file2.txt" {
		t.Fatalf("unexpected filtered files: %#v", got)
	}
}

func TestNormalizeHFPrefix(t *testing.T) {
	if got := normalizePrefix("///dir/sub"); got != "dir/sub" {
		t.Fatalf("unexpected normalized prefix: %s", got)
	}
	if got := normalizePrefix("/"); got != "" {
		t.Fatalf("expected empty prefix, got: %s", got)
	}
}

func TestHFListEntries(t *testing.T) {
	files := []string{"dir/file.txt", "dir/sub/file2.txt", "root.txt"}
	got := listEntriesByPrefix(files, "dir")
	expected := []string{"file.txt", "sub/"}
	if len(got) != len(expected) {
		t.Fatalf("unexpected entry count: %#v", got)
	}
	for i, entry := range expected {
		if got[i] != entry {
			t.Fatalf("unexpected entry at %d: %s", i, got[i])
		}
	}
}
