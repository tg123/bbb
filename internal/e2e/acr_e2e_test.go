package e2e_test

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

const acrHost = "localhost:5000"

func TestACRPushAndReadArtifact(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}
	if !waitForEndpointReady(acrHost) {
		t.Skipf("OCI registry endpoint %s not reachable", acrHost)
	}

	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sub", "b.txt"), []byte("bravo"), 0o644); err != nil {
		t.Fatal(err)
	}

	artifact := "acr://localhost:5000/bbb/e2e:roundtrip"
	if _, err := runBBB("cp", "-f", source, artifact); err != nil {
		t.Fatalf("push artifact: %v", err)
	}

	files, err := bbbLs(artifact, true)
	if err != nil {
		t.Fatalf("list artifact: %v", err)
	}
	expected := []string{
		artifact + "/a.txt",
		artifact + "/sub/b.txt",
	}
	sort.Strings(files)
	sort.Strings(expected)
	if !slices.Equal(files, expected) {
		t.Fatalf("unexpected artifact files: got %v, want %v", files, expected)
	}

	destination := filepath.Join(t.TempDir(), "download")
	if err := os.MkdirAll(destination, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := runBBB("cp", artifact, destination); err != nil {
		t.Fatalf("download artifact: %v", err)
	}
	for name, expectedContent := range map[string]string{
		"a.txt":                       "alpha",
		filepath.Join("sub", "b.txt"): "bravo",
	} {
		content, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil {
			t.Fatalf("read downloaded %s: %v", name, err)
		}
		if string(content) != expectedContent {
			t.Fatalf("downloaded %s = %q, want %q", name, content, expectedContent)
		}
	}
}
