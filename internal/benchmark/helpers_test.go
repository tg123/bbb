package benchmark_test

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://x.blob.core.windows.net/c/b.bin?sv=2024-01-01&sig=SECRET&se=2026", "https://x.blob.core.windows.net/c/b.bin?<redacted>"},
		{"http://example.com/?foo=bar", "http://example.com/?<redacted>"},
		{"https://x.blob.core.windows.net/c/b.bin", "https://x.blob.core.windows.net/c/b.bin"},
		{"/local/path", "/local/path"},
		{"--overwrite=true", "--overwrite=true"},
	}
	for _, c := range cases {
		if got := redactURL(c.in); got != c.want {
			t.Errorf("redactURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactArgsNoLeakSAS(t *testing.T) {
	args := []string{"copy", "/src/file.bin", "https://acct.blob.core.windows.net/c/b?sv=2024&sig=AAAA%2Fsecret", "--overwrite=true"}
	out := redactArgs(args)
	if strings.Contains(out, "sig=") || strings.Contains(out, "secret") {
		t.Fatalf("SAS leaked in redacted args: %q", out)
	}
	if !strings.Contains(out, "?<redacted>") {
		t.Fatalf("expected ?<redacted> marker in %q", out)
	}
}

func TestParsePybbbDefaults(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty falls back to default", "", []string{"python", "-m", "boostedblob"}},
		{"whitespace-only falls back to default", "   \t  ", []string{"python", "-m", "boostedblob"}},
		{"explicit single-word command preserved", "bbb", []string{"bbb"}},
		{"multi-word command preserved", "python3 -m boostedblob", []string{"python3", "-m", "boostedblob"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parsePybbb(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("parsePybbb(%q) = %v, want %v", c.in, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("parsePybbb(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestWriteRandomFileSizeAndMD5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.bin")
	got, err := writeRandomFile(path, 2)
	if err != nil {
		t.Fatalf("writeRandomFile: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() != 2<<20 {
		t.Fatalf("file size = %d, want %d", info.Size(), 2<<20)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	sum := md5.Sum(data)
	if want := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("MD5 mismatch: got %s, file %s", got, want)
	}
}
