package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/tg123/bbb/internal/acr"
	"github.com/tg123/bbb/internal/bbbfs"
	"github.com/tg123/bbb/internal/hf"
	"github.com/urfave/cli/v3"
)

func TestIsAzHTTPS(t *testing.T) {
	if !bbbfs.IsAz("https://myacct.blob.core.windows.net/container") {
		t.Fatalf("expected https blob url to be treated as az path")
	}
	if bbbfs.IsAz("https://example.com/file") {
		t.Fatalf("non-blob https url should not be treated as az path")
	}
}

func TestIsAzHTTPEdgeCases(t *testing.T) {
	if !bbbfs.IsAz("http://MYACCT.blob.core.windows.net:8080/container/blob.txt?sv=2021#frag") {
		t.Fatalf("expected blob url with port/query/fragment to be az path")
	}
	if bbbfs.IsAz("http://bad.blob.core.windows.net/") {
		t.Fatalf("url missing container should not be treated as az path")
	}
	if bbbfs.IsAz("ftp://acct.blob.core.windows.net/container") {
		t.Fatalf("non-http scheme should not be treated as az path")
	}
}

func TestIsHF(t *testing.T) {
	if !bbbfs.IsHF("hf://openai/gpt-oss-120b") {
		t.Fatalf("expected hf scheme to be detected")
	}
	if bbbfs.IsHF("https://example.com/model") {
		t.Fatalf("non-hf scheme should not be detected")
	}
}

func TestHFPathParseRepoOnly(t *testing.T) {
	path, err := hf.Parse("hf://owner/repo")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if path.File != "" {
		t.Fatalf("expected empty file, got %s", path.File)
	}
}

func TestHFPathStringPreservesSpaces(t *testing.T) {
	path, err := hf.Parse("hf://owner/repo/a b.txt")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if path.String() != "hf://owner/repo/a b.txt" {
		t.Fatalf("unexpected escaped path: %s", path.String())
	}
}

func TestHFPathDatasetURL(t *testing.T) {
	p, err := hf.Parse("hf://datasets/allenai/tulu-3-sft-mixture/README.md")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if p.Repo != "datasets/allenai/tulu-3-sft-mixture" {
		t.Fatalf("unexpected dataset repo: %s", p.Repo)
	}
	url, err := p.URL()
	if err != nil {
		t.Fatalf("unexpected url error: %v", err)
	}
	expected := "https://huggingface.co/datasets/allenai/tulu-3-sft-mixture/resolve/main/README.md"
	if url != expected {
		t.Fatalf("unexpected dataset url: %s", url)
	}
}

func TestHFPathDatasetDefaults(t *testing.T) {
	p, err := hf.Parse("hf://datasets/allenai/tulu-3-sft-mixture")
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if p.Repo != "datasets/allenai/tulu-3-sft-mixture" {
		t.Fatalf("unexpected dataset repo: %s", p.Repo)
	}
	if p.File != "" {
		t.Fatalf("expected empty file for dataset repo path, got: %s", p.File)
	}
	if p.DefaultFilename() != "tulu-3-sft-mixture" {
		t.Fatalf("unexpected default filename: %s", p.DefaultFilename())
	}
	if _, err := p.URL(); err == nil {
		t.Fatalf("expected url error for dataset repo path")
	}
}

func TestResolveDstPathAzDir(t *testing.T) {
	dst, err := bbbfs.ResolveDstPath("az://acct/container/prefix", "model.bin", true)
	if err != nil {
		t.Fatalf("ResolveDstPath failed: %v", err)
	}
	if dst != "az://acct/container/prefix/model.bin" {
		t.Fatalf("unexpected dst: %s", dst)
	}
}

func TestSyncFilterExclude(t *testing.T) {
	files := []string{"file.txt", "dir/file2.txt", "dir/skip.txt"}
	list := filterExclude(files, func(name string) bool { return strings.Contains(name, "skip") })
	if len(list) != 2 {
		t.Fatalf("unexpected list length: %d", len(list))
	}
}

func TestCmdSyncRejectsHFFilePath(t *testing.T) {
	app := &cli.Command{
		Action: cmdSync,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "dry-run"},
			&cli.BoolFlag{Name: "delete"},
			&cli.StringFlag{Name: "x"},
			&cli.IntFlag{Name: "concurrency", Value: 1},
			&cli.IntFlag{Name: "retry-count"},
			&cli.BoolFlag{Name: "q"},
		},
	}
	err := app.Run(context.Background(), []string{"sync", "hf://owner/repo/file.txt", "az://acct/container"})
	if err == nil {
		t.Fatalf("expected error for hf file path")
	}
}

// A dry run must predict the real outcome, so an invalid destination or a
// missing source has to fail rather than report a successful PUSH.
func TestSyncACRDryRunValidatesTarget(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := cmdSyncPaths(context.Background(), true, false, true, "", 1, 0,
		source, "acr://myreg.azurecr.io/models@sha256:abc")
	if err == nil || !strings.Contains(err.Error(), "must use a tag") {
		t.Fatalf("expected digest destination to be rejected in dry run, got %v", err)
	}

	err = cmdSyncPaths(context.Background(), true, false, true, "", 1, 0,
		filepath.Join(source, "missing"), "acr://myreg.azurecr.io/models:v1")
	if err == nil {
		t.Fatal("expected a missing source to be rejected in dry run")
	}
}

func TestCmdSyncRejectsDeleteWithACRSource(t *testing.T) {
	err := cmdSyncPaths(context.Background(), false, true, true, "", 1, 0,
		"acr://myreg.azurecr.io/models:v1", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "--delete is not supported") {
		t.Fatalf("expected --delete rejection for acr source, got %v", err)
	}
}

// A path inside an artifact is rejected from the path alone. Asking the
// registry whether it is a directory expands the layer holding it, so a source
// sync cannot accept anyway would transfer gigabytes before saying so — and
// the host here does not exist, which is what proves nothing was contacted.
func TestCmdSyncRejectsACRFilePathWithoutContactingTheRegistry(t *testing.T) {
	err := cmdSyncPaths(context.Background(), true, false, true, "", 1, 0,
		"acr://nonexistent-registry.invalid/models:v1/linux/amd64", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "must target an artifact") {
		t.Fatalf("expected a path inside an artifact to be rejected, got %v", err)
	}
}

func TestCPDirectoryCopiesTree(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	srcFile := filepath.Join(srcDir, "sub", "file.txt")
	if err := os.WriteFile(srcFile, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", srcDir, dstDir}); err != nil {
		t.Fatalf("cp failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "sub", "file.txt")); err != nil {
		t.Fatalf("expected copied file: %v", err)
	}
}

// A resumed run must not be blocked by a conflict with a task that already
// completed and will be skipped.
func TestValidateACRTasksIgnoresCompletedTasks(t *testing.T) {
	publish := taskPair{src: "./dir", dst: "acr://myreg.azurecr.io/models:v1"}
	read := taskPair{src: "acr://myreg.azurecr.io/models:v1", dst: "./out"}

	if err := validateACRTasks([]taskPair{publish, read}, nil, nil); err == nil {
		t.Fatal("expected the overlap to be rejected when both tasks are pending")
	}
	completed := map[string]struct{}{
		taskCheckpointKey(publish.src, publish.dst): {},
	}
	if err := validateACRTasks([]taskPair{publish, read}, nil, completed); err != nil {
		t.Fatalf("a completed publisher should not block the reader: %v", err)
	}

	// Duplicate destinations behave the same way.
	other := taskPair{src: "./other", dst: "acr://myreg.azurecr.io/models:v1"}
	if err := validateACRTasks([]taskPair{publish, other}, nil, nil); err == nil {
		t.Fatal("expected duplicate destinations to be rejected")
	}
	if err := validateACRTasks([]taskPair{publish, other}, nil, completed); err != nil {
		t.Fatalf("a completed publisher should not block another: %v", err)
	}
}

// Reading and republishing one artifact in the same run would move the tag
// under the reader, since tasks execute concurrently.
func TestCPRejectsReadAndWriteOfSameArtifact(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	taskfile := filepath.Join(dir, "tasks.txt")
	content := "acr://myreg.azurecr.io/models:v1 " + filepath.Join(dir, "out") + "\n" +
		dir + " acr://myreg.azurecr.io/models:v1\n"
	if err := os.WriteFile(taskfile, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "taskfile"},
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
		},
	}
	err := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile})
	if err == nil || !strings.Contains(err.Error(), "read and publish the same acr:// artifact") {
		t.Fatalf("expected the overlap to be rejected, got %v", err)
	}
}

// An ACR artifact source must expand into one task per file, so a download
// gets the normal per-file concurrency and state tracking.
func TestExpandCPTaskExpandsACRSource(t *testing.T) {
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	artifact := acr.Path{Registry: parsed.Host, Repository: "models", Reference: "v1"}
	uploads := []acr.UploadFile{
		{Name: "a.txt", Size: 5, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("alpha")), nil
		}},
		{Name: "sub/b.txt", Size: 5, Open: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("bravo")), nil
		}},
	}
	if err := acr.Push(context.Background(), artifact, uploads, acr.PushOptions{Overwrite: true}); err != nil {
		t.Fatalf("push artifact: %v", err)
	}

	destination := t.TempDir()
	var expanded []cpTask
	if err := expandCPTask(context.Background(), taskPair{src: artifact.String(), dst: destination},
		func(task cpTask) error {
			expanded = append(expanded, task)
			return nil
		}); err != nil {
		t.Fatalf("expandCPTask failed: %v", err)
	}
	if len(expanded) != 2 {
		t.Fatalf("expected one task per file, got %#v", expanded)
	}
	for _, task := range expanded {
		if !strings.HasPrefix(task.src, "acr://") || task.src == artifact.String() {
			t.Fatalf("expected a per-file source, got %q", task.src)
		}
	}

	// A path naming a single file inside the artifact stays one task.
	single := artifact
	single.File = "a.txt"
	expanded = nil
	if err := expandCPTask(context.Background(), taskPair{src: single.String(), dst: destination},
		func(task cpTask) error {
			expanded = append(expanded, task)
			return nil
		}); err != nil {
		t.Fatalf("expandCPTask failed: %v", err)
	}
	if len(expanded) != 1 || expanded[0].src != single.String() {
		t.Fatalf("expected a single task for a file path, got %#v", expanded)
	}
}

func TestExpandCPTaskKeepsACRArtifactAtomic(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	var expanded []cpTask
	err := expandCPTask(t.Context(), taskPair{
		src: source,
		dst: "acr://registry.example.com/models:v1",
	}, func(task cpTask) error {
		expanded = append(expanded, task)
		return nil
	})
	if err != nil {
		t.Fatalf("expandCPTask failed: %v", err)
	}
	if len(expanded) != 1 || expanded[0].src != source {
		t.Fatalf("expected one artifact-level task, got %#v", expanded)
	}
}

// A symlink inside an artifact source must not be dereferenced, or a link such
// as `secrets -> /etc/passwd` would upload data from outside the source tree.
// Collection only proves a path was a regular file during the walk. Each later
// open must confirm it is still the same file, or a swap after collection would
// be read from wherever the new path points.
func TestArtifactFileOpenDetectsReplacement(t *testing.T) {
	source := t.TempDir()
	target := filepath.Join(source, "a.txt")
	if err := os.WriteFile(target, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, _, cleanup, err := collectLocalArtifactFiles(source, nil)
	if err != nil {
		t.Fatalf("collectLocalArtifactFiles failed: %v", err)
	}
	t.Cleanup(cleanup)
	if len(files) != 1 {
		t.Fatalf("unexpected files: %#v", files)
	}

	// The same file still opens and reads normally.
	reader, err := files[0].Open()
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	content, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil || string(content) != "original" {
		t.Fatalf("content = %q (%v)", content, err)
	}

	// Replacing the path with something that is no longer the same regular
	// file must be caught rather than silently uploaded. A directory is used
	// because it needs no privileges and cannot alias the original, whereas
	// deleting and recreating a file can reuse the inode on Linux.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := files[0].Open(); err == nil || !strings.Contains(err.Error(), "changed while it was being uploaded") {
		t.Fatalf("expected the replacement to be detected, got %v", err)
	}

	// The threat this guards against is a swap for a symlink pointing outside
	// the source tree. The root handle refuses to traverse out of the source,
	// so this fails before the handle comparison is even reached.
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("classified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	reader, err = files[0].Open()
	if err == nil {
		_ = reader.Close()
		t.Fatal("expected the symlink swap to be rejected")
	}
}

// A directory component replaced after the walk must not let a later open
// escape the source tree, which is what the root handle guarantees and a
// path-based walk cannot.
func TestArtifactFileOpenRejectsDirectorySwap(t *testing.T) {
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sub", "a.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "a.txt"), []byte("classified"), 0o644); err != nil {
		t.Fatal(err)
	}

	files, _, cleanup, err := collectLocalArtifactFiles(source, nil)
	if err != nil {
		t.Fatalf("collectLocalArtifactFiles failed: %v", err)
	}
	t.Cleanup(cleanup)
	if len(files) != 1 || files[0].Name != "sub/a.txt" {
		t.Fatalf("unexpected files: %#v", files)
	}

	// Swap the directory itself for a symlink to somewhere else.
	if err := os.RemoveAll(filepath.Join(source, "sub")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "sub")); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	reader, err := files[0].Open()
	if err == nil {
		content, _ := io.ReadAll(reader)
		_ = reader.Close()
		t.Fatalf("expected the directory swap to be rejected, read %q", content)
	}
}

func TestCollectLocalArtifactFilesRejectsSymlink(t *testing.T) {
	source := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("classified"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "ok.txt"), []byte("fine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(source, "secrets")); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	_, _, cleanup, err := collectLocalArtifactFiles(source, nil)
	t.Cleanup(cleanup)
	if err == nil || !strings.Contains(err.Error(), "unsupported source file type") {
		t.Fatalf("expected the symlink to be rejected, got %v", err)
	}
}

// A retry re-uploads only the blobs the registry is still missing, so an
// attempt's own byte total is not comparable with the previous attempt's.
// Progress has to be held per file, or an artifact whose layers advanced on
// different attempts finishes under-counted.
func TestArtifactProgressAcrossRetries(t *testing.T) {
	progress := newArtifactProgress(2)

	// Attempt one uploads a.bin and then fails before b.bin.
	if delta, total := progress.observe("a.bin", 100); delta != 100 || total != 100 {
		t.Fatalf("a.bin = (%d, %d), want (100, 100)", delta, total)
	}

	// Attempt two skips a.bin, whose blob now exists, and uploads b.bin. Its
	// own total never exceeds the first attempt's, but the bytes are real.
	delta, total := progress.observe("b.bin", 100)
	if delta != 100 || total != 200 {
		t.Fatalf("b.bin = (%d, %d), want (100, 200)", delta, total)
	}

	// Re-reading a file already counted adds nothing, so a retransmission
	// cannot push the total past the artifact size.
	if delta, total := progress.observe("a.bin", 40); delta != 0 || total != 200 {
		t.Fatalf("a.bin replay = (%d, %d), want (0, 200)", delta, total)
	}
	if delta, total := progress.observe("a.bin", 100); delta != 0 || total != 200 {
		t.Fatalf("a.bin resend = (%d, %d), want (0, 200)", delta, total)
	}

	// A file that got further than before contributes only the difference.
	if delta, total := progress.observe("b.bin", 150); delta != 50 || total != 250 {
		t.Fatalf("b.bin growth = (%d, %d), want (50, 250)", delta, total)
	}
}

func TestCollectLocalArtifactFiles(t *testing.T) {
	source := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "a.txt"), []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "sub", "b.txt"), []byte("bravo"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, total, cleanup, err := collectLocalArtifactFiles(source, func(name string) bool {
		return name == "a.txt"
	})
	if err != nil {
		t.Fatalf("collectLocalArtifactFiles failed: %v", err)
	}
	t.Cleanup(cleanup)
	if total != 5 || len(files) != 1 || files[0].Name != "sub/b.txt" {
		t.Fatalf("unexpected artifact files: total=%d files=%#v", total, files)
	}
	reader, err := files[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = reader.Close()
	}()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "bravo" {
		t.Fatalf("unexpected file content: %q", content)
	}
}

func TestCmdCPTaskfileStateRecovery(t *testing.T) {
	dir := t.TempDir()
	srcOk := filepath.Join(dir, "ok.txt")
	dstOk := filepath.Join(dir, "out-ok.txt")
	if err := os.WriteFile(srcOk, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(srcOk+" "+dstOk+"\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}

	stateFile := filepath.Join(dir, "tasks.state")
	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("cp failed: %v", err)
	}
	if _, err := os.Stat(dstOk); err != nil {
		t.Fatalf("expected copied file: %v", err)
	}
	if err := os.Remove(srcOk); err != nil {
		t.Fatalf("remove src: %v", err)
	}
	if err := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("cp resume failed: %v", err)
	}
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read statefile: %v", err)
	}
	if strings.TrimSpace(string(stateData)) == "" {
		t.Fatalf("expected non-empty statefile")
	}
}

func TestRunCPTasksFlushesStateBeforeReturningError(t *testing.T) {
	dir := t.TempDir()
	srcOK := filepath.Join(dir, "ok.txt")
	srcMissing := filepath.Join(dir, "missing.txt")
	dstDir := filepath.Join(dir, "dst")
	stateFile := filepath.Join(dir, "tasks.state")
	if err := os.WriteFile(srcOK, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.Mkdir(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}

	err := runCPTasks(context.Background(), []taskPair{
		{src: srcOK, dst: dstDir},
		{src: srcMissing, dst: dstDir},
	}, true, true, 1, 0, stateFile)
	if err == nil {
		t.Fatal("expected copy error")
	}

	stateData, readErr := os.ReadFile(stateFile)
	if readErr != nil {
		t.Fatalf("read statefile: %v", readErr)
	}
	if want := taskStateKey(srcOK, dstDir); !strings.Contains(string(stateData), want) {
		t.Fatalf("statefile does not contain completed copy %q: %q", want, stateData)
	}
}

func TestRunCPTasksReturnsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stateFile := filepath.Join(t.TempDir(), "tasks.state")
	err := runCPTasks(ctx, []taskPair{{src: "unused", dst: "unused"}}, true, true, 1, 0, stateFile)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runCPTasks error = %v, want context.Canceled", err)
	}
}

func TestLoadTaskPairsLongLine(t *testing.T) {
	dir := t.TempDir()
	longSrc := strings.Repeat("a", 70*1024)
	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(longSrc+" dst\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	tasks, err := loadTaskPairs(taskfile)
	if err != nil {
		t.Fatalf("loadTaskPairs failed: %v", err)
	}
	if len(tasks) != 1 || tasks[0].src != longSrc || tasks[0].dst != "dst" {
		t.Fatalf("unexpected parsed tasks: %+v", tasks)
	}
}

func TestLoadTaskPairsRejectsWhitespacePaths(t *testing.T) {
	dir := t.TempDir()
	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte("a b c\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	_, err := loadTaskPairs(taskfile)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if !strings.Contains(err.Error(), "paths with spaces are not supported") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCmdCPTaskfileStateRecoverySkipsFinishedTask(t *testing.T) {
	dir := t.TempDir()
	srcMissing := filepath.Join(dir, "missing.txt")
	srcOK := filepath.Join(dir, "ok.txt")
	dstDir := filepath.Join(dir, "out")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}
	if err := os.WriteFile(srcOK, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(strings.Join([]string{
		srcMissing + " " + dstDir,
		srcOK + " " + dstDir,
		"",
	}, "\n")), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}

	stateFile := filepath.Join(dir, "tasks.state")
	skippedKey := taskStateKey(srcMissing, dstDir)
	if err := os.WriteFile(stateFile, []byte(skippedKey+"\n"), 0o644); err != nil {
		t.Fatalf("write statefile: %v", err)
	}

	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = w
	runErr := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--state", stateFile})
	if err := w.Close(); err != nil {
		t.Fatalf("close write pipe: %v", err)
	}
	os.Stderr = origStderr
	stderrOut, readErr := io.ReadAll(r)
	if err := r.Close(); err != nil {
		t.Fatalf("close read pipe: %v", err)
	}
	if runErr != nil {
		t.Fatalf("cp recovery failed: %v", runErr)
	}
	if readErr != nil {
		t.Fatalf("read stderr: %v", readErr)
	}
	expectedSkipMsg := "cp: skip already copied " + srcMissing + " -> " + dstDir
	if !strings.Contains(string(stderrOut), expectedSkipMsg) {
		t.Fatalf("expected skip message in stderr, got %q", string(stderrOut))
	}
	expectedListingMissing := "cp: listing " + srcMissing + " -> " + dstDir
	if !strings.Contains(string(stderrOut), expectedListingMissing) {
		t.Fatalf("expected listing message for first task in stderr, got %q", string(stderrOut))
	}
	expectedListingOK := "cp: listing " + srcOK + " -> " + dstDir
	if !strings.Contains(string(stderrOut), expectedListingOK) {
		t.Fatalf("expected listing message for second task in stderr, got %q", string(stderrOut))
	}
	if _, err := os.Stat(filepath.Join(dstDir, filepath.Base(srcOK))); err != nil {
		t.Fatalf("expected copied file: %v", err)
	}

	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read statefile: %v", err)
	}
	stateText := string(stateData)
	if !strings.Contains(stateText, skippedKey) {
		t.Fatalf("expected skipped task key in statefile")
	}
	if !strings.Contains(stateText, taskStateKey(srcOK, dstDir)) {
		t.Fatalf("expected completed task key in statefile")
	}
}

func TestCmdCPTaskfileStateRecoveryPartialTask(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write src a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write src b: %v", err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("seed partial dst: %v", err)
	}

	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(srcDir+" "+dstDir+"\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	stateFile := filepath.Join(dir, "tasks.state")

	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "-f", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("cp partial recovery failed: %v", err)
	}
	for _, name := range []string{"a.txt", "b.txt"} {
		if _, err := os.Stat(filepath.Join(dstDir, name)); err != nil {
			t.Fatalf("expected copied file %s: %v", name, err)
		}
	}
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read statefile: %v", err)
	}
	stateText := string(stateData)
	if !strings.Contains(stateText, taskStateKey(filepath.Join(srcDir, "a.txt"), dstDir)) {
		t.Fatalf("expected a.txt task key in statefile")
	}
	if !strings.Contains(stateText, taskStateKey(filepath.Join(srcDir, "b.txt"), dstDir)) {
		t.Fatalf("expected b.txt task key in statefile")
	}
}

func TestCmdCPTaskfileStateRecoveryPartialTaskSkipsFinishedFile(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("new-a"), 0o644); err != nil {
		t.Fatalf("write src a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("new-b"), 0o644); err != nil {
		t.Fatalf("write src b: %v", err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dstDir, "a.txt"), []byte("old-a"), 0o644); err != nil {
		t.Fatalf("seed dst a: %v", err)
	}

	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(srcDir+" "+dstDir+"\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	stateFile := filepath.Join(dir, "tasks.state")
	skippedKey := taskStateKey(filepath.Join(srcDir, "a.txt"), dstDir)
	if err := os.WriteFile(stateFile, []byte(skippedKey+"\n"), 0o644); err != nil {
		t.Fatalf("write statefile: %v", err)
	}

	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "-f", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("cp partial recovery failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "b.txt")); err != nil {
		t.Fatalf("expected copied file b.txt: %v", err)
	}
	dstA, err := os.ReadFile(filepath.Join(dstDir, "a.txt"))
	if err != nil {
		t.Fatalf("read dst a: %v", err)
	}
	if string(dstA) != "old-a" {
		t.Fatalf("expected a.txt to be skipped, got content %q", string(dstA))
	}
}

func TestCmdCPTaskfileStateHumanReadable(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write src a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write src b: %v", err)
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}

	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(srcDir+" "+dstDir+"\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	stateFile := filepath.Join(dir, "tasks.state")

	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "-f", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("cp failed: %v", err)
	}
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read statefile: %v", err)
	}
	stateText := string(stateData)
	// File-level keys should be human-readable src -> dst
	expectedA := filepath.Join(srcDir, "a.txt") + " -> " + dstDir
	expectedB := filepath.Join(srcDir, "b.txt") + " -> " + dstDir
	if !strings.Contains(stateText, expectedA) {
		t.Fatalf("expected human-readable key for a.txt in statefile, got:\n%s", stateText)
	}
	if !strings.Contains(stateText, expectedB) {
		t.Fatalf("expected human-readable key for b.txt in statefile, got:\n%s", stateText)
	}
	// Task checkpoint should be present
	expectedCheckpoint := "TASK\t" + srcDir + " -> " + dstDir
	if !strings.Contains(stateText, expectedCheckpoint) {
		t.Fatalf("expected task checkpoint in statefile, got:\n%s", stateText)
	}
}

func TestCmdCPTaskfileStateCheckpointSkipsExpansion(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	// Source does not exist — if expansion is attempted it would fail or return empty
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}

	taskfile := filepath.Join(dir, "tasks.txt")
	if err := os.WriteFile(taskfile, []byte(srcDir+" "+dstDir+"\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	stateFile := filepath.Join(dir, "tasks.state")
	// Pre-seed task checkpoint
	checkpoint := "TASK\t" + srcDir + " -> " + dstDir + "\n"
	if err := os.WriteFile(stateFile, []byte(checkpoint), 0o644); err != nil {
		t.Fatalf("write statefile: %v", err)
	}

	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = w

	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	runErr := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--state", stateFile})
	if err := w.Close(); err != nil {
		t.Fatalf("close write pipe: %v", err)
	}
	os.Stderr = origStderr
	stderrOut, readErr := io.ReadAll(r)
	if err := r.Close(); err != nil {
		t.Fatalf("close read pipe: %v", err)
	}
	if runErr != nil {
		t.Fatalf("cp failed: %v", runErr)
	}
	if readErr != nil {
		t.Fatalf("read stderr: %v", readErr)
	}
	// Should see the task-level skip message, not a listing message
	if !strings.Contains(string(stderrOut), "cp: skip already completed task") {
		t.Fatalf("expected task checkpoint skip message, got:\n%s", string(stderrOut))
	}
	if strings.Contains(string(stderrOut), "cp: listing") {
		t.Fatalf("expansion should be skipped for checkpointed task, got:\n%s", string(stderrOut))
	}
}

func TestCmdSyncTaskfile(t *testing.T) {
	dir := t.TempDir()
	srcA := filepath.Join(dir, "src-a")
	dstA := filepath.Join(dir, "dst-a")
	srcB := filepath.Join(dir, "src-b")
	dstB := filepath.Join(dir, "dst-b")
	if err := os.MkdirAll(srcA, 0o755); err != nil {
		t.Fatalf("mkdir srcA: %v", err)
	}
	if err := os.MkdirAll(srcB, 0o755); err != nil {
		t.Fatalf("mkdir srcB: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcA, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write srcA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcB, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write srcB: %v", err)
	}

	taskfile := filepath.Join(dir, "sync.tasks")
	content := strings.Join([]string{srcA + " " + dstA, srcB + " " + dstB, ""}, "\n")
	if err := os.WriteFile(taskfile, []byte(content), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}

	app := &cli.Command{
		Action: cmdSync,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "dry-run"},
			&cli.BoolFlag{Name: "delete"},
			&cli.StringFlag{Name: "x"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.BoolFlag{Name: "q"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	if err := app.Run(context.Background(), []string{"sync", "--taskfile", taskfile}); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstA, "a.txt")); err != nil {
		t.Fatalf("expected synced file A: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstB, "b.txt")); err != nil {
		t.Fatalf("expected synced file B: %v", err)
	}
}

func TestCmdSyncTaskfileStateRecovery(t *testing.T) {
	dir := t.TempDir()
	srcA := filepath.Join(dir, "src-a")
	dstA := filepath.Join(dir, "dst-a")
	srcB := filepath.Join(dir, "src-b")
	dstB := filepath.Join(dir, "dst-b")
	if err := os.MkdirAll(srcA, 0o755); err != nil {
		t.Fatalf("mkdir srcA: %v", err)
	}
	if err := os.MkdirAll(srcB, 0o755); err != nil {
		t.Fatalf("mkdir srcB: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcA, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write srcA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcB, "b.txt"), []byte("b"), 0o644); err != nil {
		t.Fatalf("write srcB: %v", err)
	}

	taskfile := filepath.Join(dir, "sync.tasks")
	content := strings.Join([]string{srcA + " " + dstA, srcB + " " + dstB, ""}, "\n")
	if err := os.WriteFile(taskfile, []byte(content), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	stateFile := filepath.Join(dir, "sync.state")

	app := &cli.Command{
		Action: cmdSync,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "dry-run"},
			&cli.BoolFlag{Name: "delete"},
			&cli.StringFlag{Name: "x"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.BoolFlag{Name: "q"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}

	// First run: sync both task pairs
	if err := app.Run(context.Background(), []string{"sync", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("sync failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstA, "a.txt")); err != nil {
		t.Fatalf("expected synced file A: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstB, "b.txt")); err != nil {
		t.Fatalf("expected synced file B: %v", err)
	}
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read statefile: %v", err)
	}
	stateText := string(stateData)
	cpKeyA := taskCheckpointKey(srcA, dstA)
	cpKeyB := taskCheckpointKey(srcB, dstB)
	if !strings.Contains(stateText, cpKeyA) {
		t.Fatalf("expected checkpoint for task A in statefile, got:\n%s", stateText)
	}
	if !strings.Contains(stateText, cpKeyB) {
		t.Fatalf("expected checkpoint for task B in statefile, got:\n%s", stateText)
	}

	// Remove source A so a re-run would fail if it tried to sync it again
	if err := os.RemoveAll(srcA); err != nil {
		t.Fatalf("remove srcA: %v", err)
	}
	// Second run: both tasks are already checkpointed, so should be skipped
	if err := app.Run(context.Background(), []string{"sync", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("sync resume failed: %v", err)
	}
}

func TestCmdSyncTaskfileDryRunNoState(t *testing.T) {
	dir := t.TempDir()
	srcA := filepath.Join(dir, "src-a")
	dstA := filepath.Join(dir, "dst-a")
	if err := os.MkdirAll(srcA, 0o755); err != nil {
		t.Fatalf("mkdir srcA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcA, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatalf("write srcA: %v", err)
	}

	taskfile := filepath.Join(dir, "sync.tasks")
	if err := os.WriteFile(taskfile, []byte(srcA+" "+dstA+"\n"), 0o644); err != nil {
		t.Fatalf("write taskfile: %v", err)
	}
	stateFile := filepath.Join(dir, "sync.state")

	app := &cli.Command{
		Action: cmdSync,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "dry-run"},
			&cli.BoolFlag{Name: "delete"},
			&cli.StringFlag{Name: "x"},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.BoolFlag{Name: "q"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	if err := app.Run(context.Background(), []string{"sync", "--dry-run", "--taskfile", taskfile, "--state", stateFile}); err != nil {
		t.Fatalf("sync dry-run failed: %v", err)
	}
	// State file should not be created in dry-run mode
	if _, err := os.Stat(stateFile); err == nil {
		t.Fatalf("state file should not exist after dry-run")
	}
	// Destination should not be created in dry-run mode
	if _, err := os.Stat(dstA); err == nil {
		t.Fatalf("destination should not exist after dry-run")
	}
}

func TestCmdCPStateNoTaskfile(t *testing.T) {
	dir := t.TempDir()
	srcA := filepath.Join(dir, "a.txt")
	srcB := filepath.Join(dir, "b.txt")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}
	if err := os.WriteFile(srcA, []byte("aaa"), 0o644); err != nil {
		t.Fatalf("write srcA: %v", err)
	}
	if err := os.WriteFile(srcB, []byte("bbb"), 0o644); err != nil {
		t.Fatalf("write srcB: %v", err)
	}

	stateFile := filepath.Join(dir, "cp.state")
	app := &cli.Command{
		Action: cmdCP,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "f"},
			&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	// First run: copy both files
	if err := app.Run(context.Background(), []string{"cp", "--state", stateFile, srcA, srcB, dstDir}); err != nil {
		t.Fatalf("cp run 1 failed: %v", err)
	}
	// Verify files were copied
	if _, err := os.Stat(filepath.Join(dstDir, "a.txt")); err != nil {
		t.Fatalf("a.txt not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "b.txt")); err != nil {
		t.Fatalf("b.txt not copied: %v", err)
	}
	// Verify state file contains both entries
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if !strings.Contains(string(stateData), taskStateKey(srcA, dstDir)) {
		t.Fatalf("state missing srcA entry, got:\n%s", stateData)
	}
	if !strings.Contains(string(stateData), taskStateKey(srcB, dstDir)) {
		t.Fatalf("state missing srcB entry, got:\n%s", stateData)
	}
	// Remove srcA, second run should skip both via state
	if err := os.Remove(srcA); err != nil {
		t.Fatalf("remove srcA: %v", err)
	}
	if err := app.Run(context.Background(), []string{"cp", "--state", stateFile, srcA, srcB, dstDir}); err != nil {
		t.Fatalf("cp run 2 (resume) failed: %v", err)
	}
}

func TestCmdSyncStateNoTaskfile(t *testing.T) {
	dir := t.TempDir()
	srcDir := filepath.Join(dir, "src")
	dstDir := filepath.Join(dir, "dst")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "f.txt"), []byte("data"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	stateFile := filepath.Join(dir, "sync.state")
	app := &cli.Command{
		Action: cmdSync,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "dry-run"},
			&cli.BoolFlag{Name: "delete"},
			&cli.BoolFlag{Name: "q", Aliases: []string{"quiet"}},
			&cli.IntFlag{Name: "concurrency", Value: 2},
			&cli.IntFlag{Name: "retry-count"},
			&cli.StringFlag{Name: "x", Aliases: []string{"exclude"}},
			&cli.StringFlag{Name: "taskfile"},
			&cli.StringFlag{Name: "state"},
		},
	}
	// First run: sync
	if err := app.Run(context.Background(), []string{"sync", "--state", stateFile, srcDir, dstDir}); err != nil {
		t.Fatalf("sync run 1 failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "f.txt")); err != nil {
		t.Fatalf("f.txt not synced: %v", err)
	}
	// State should record the pair
	stateData, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	if !strings.Contains(string(stateData), taskStateKey(srcDir, dstDir)) {
		t.Fatalf("state missing entry, got:\n%s", stateData)
	}
	// Remove source, second run should skip via state
	if err := os.RemoveAll(srcDir); err != nil {
		t.Fatalf("remove src: %v", err)
	}
	if err := app.Run(context.Background(), []string{"sync", "--state", stateFile, srcDir, dstDir}); err != nil {
		t.Fatalf("sync run 2 (resume) failed: %v", err)
	}
}

func TestRunOpPoolProcessesAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	items := []int{1, 2, 3}
	seen := make(map[int]bool, len(items))
	var mu sync.Mutex
	err := runOpPool(ctx, 2, func(pending chan<- int) error {
		for _, item := range items {
			if err := sendOp(ctx, pending, item); err != nil {
				return err
			}
		}
		return nil
	}, func(item int) error {
		mu.Lock()
		seen[item] = true
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatalf("runOpPool failed: %v", err)
	}
	if len(seen) != len(items) {
		t.Fatalf("expected %d items, got %d", len(items), len(seen))
	}
}

func TestRetryOpRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	attempts := 0
	err := retryOp(ctx, 2, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryOp failed: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetryOpFailFast401(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	err := retryOp(ctx, 5, func() error {
		attempts++
		return fmt.Errorf("wrapped: %w", &hf.HTTPStatusError{StatusCode: 401, Status: "401 Unauthorized"})
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt (fail fast), got %d", attempts)
	}
}

func TestRetryOpFailFast403(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	err := retryOp(ctx, 5, func() error {
		attempts++
		return fmt.Errorf("wrapped: %w", &hf.HTTPStatusError{StatusCode: 403, Status: "403 Forbidden"})
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt (fail fast), got %d", attempts)
	}
}

func TestRetryOpFailFast404(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	err := retryOp(ctx, 5, func() error {
		attempts++
		return fmt.Errorf("wrapped: %w", &hf.HTTPStatusError{StatusCode: 404, Status: "404 Not Found"})
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 1 {
		t.Fatalf("expected 1 attempt (fail fast), got %d", attempts)
	}
}

func TestRetryOpRetries500(t *testing.T) {
	ctx := context.Background()
	attempts := 0
	err := retryOp(ctx, 2, func() error {
		attempts++
		return fmt.Errorf("wrapped: %w", &hf.HTTPStatusError{StatusCode: 500, Status: "500 Internal Server Error"})
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts for 500, got %d", attempts)
	}
}

func TestRetryJitterWaitsBetweenAttempts(t *testing.T) {
	t.Setenv("BBB_RETRY_JITTER", "20ms")
	ctx := context.Background()
	attempts := 0
	start := time.Now()
	err := retryOp(ctx, 3, func() error {
		attempts++
		if attempts < 4 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryOp failed: %v", err)
	}
	if attempts != 4 {
		t.Fatalf("expected 4 attempts, got %d", attempts)
	}
	// 3 retries each wait in [0, 20ms); ensure jitter does not hang. The
	// first attempt has no wait.
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("unexpectedly slow with jitter: %v", elapsed)
	}
}

func TestRetryJitterInvalidIgnored(t *testing.T) {
	t.Setenv("BBB_RETRY_JITTER", "not-a-duration")
	if d := retryJitter(); d != 0 {
		t.Fatalf("expected 0 jitter for invalid value, got %v", d)
	}
	t.Setenv("BBB_RETRY_JITTER", "")
	if d := retryJitter(); d != 0 {
		t.Fatalf("expected 0 jitter when unset, got %v", d)
	}
	t.Setenv("BBB_RETRY_JITTER", "250ms")
	if d := retryJitter(); d != 250*time.Millisecond {
		t.Fatalf("expected 250ms jitter, got %v", d)
	}
}

func TestForceS2SEnabled(t *testing.T) {
	t.Setenv("BBB_AZBLOB_FORCE_S2S", "")
	if forceS2SEnabled() {
		t.Fatal("expected force-S2S off by default")
	}
	t.Setenv("BBB_AZBLOB_FORCE_S2S", "1")
	if !forceS2SEnabled() {
		t.Fatal("expected force-S2S on for 1")
	}
	t.Setenv("BBB_AZBLOB_FORCE_S2S", "true")
	if !forceS2SEnabled() {
		t.Fatal("expected force-S2S on for true")
	}
	t.Setenv("BBB_AZBLOB_FORCE_S2S", "0")
	if forceS2SEnabled() {
		t.Fatal("expected force-S2S off for 0")
	}
}

func TestSleepJitterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepJitter(ctx, time.Hour); err == nil {
		t.Fatal("expected context error when canceled")
	}
	if err := sleepJitter(context.Background(), 0); err != nil {
		t.Fatalf("expected no error for zero jitter, got %v", err)
	}
}

func TestRunOpPoolWithRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	items := []int{1, 2, 3}
	attempts := make(map[int]int, len(items))
	var mu sync.Mutex
	err := runOpPoolWithRetry(ctx, 2, 1, func(pending chan<- int) error {
		for _, item := range items {
			if err := sendOp(ctx, pending, item); err != nil {
				return err
			}
		}
		return nil
	}, func(item int) error {
		mu.Lock()
		attempts[item]++
		count := attempts[item]
		mu.Unlock()
		if count == 1 {
			return errors.New("retry")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("runOpPoolWithRetry failed: %v", err)
	}
	for _, item := range items {
		if attempts[item] != 2 {
			t.Fatalf("expected item %d to retry once, got %d attempts", item, attempts[item])
		}
	}
}

func TestFormatProgressBarIncludesSpeed(t *testing.T) {
	line := formatProgressBar("cp", 5, 10, 10, 2.5*1024*1024, true, false, 30*time.Second)
	if line != "cp [=====     ]  50% (5/10, 2.5 MB/s) 30s" {
		t.Fatalf("unexpected progress bar output: %s", line)
	}
}

func TestFormatCountingBar(t *testing.T) {
	line := formatCountingBar("Counting", 3, 1536, 5, 200*time.Millisecond, false)
	if line != "Counting [  >  ] 3 files (1.5 KiB) 0s" {
		t.Fatalf("unexpected counting bar output: %s", line)
	}

	line = formatCountingBar("Counting", 1, 512, 5, 2*time.Second, true)
	if line != "Counting [=====] 1 file (512 B) 2s" {
		t.Fatalf("unexpected completed counting bar output: %s", line)
	}
}

func TestFormatProgressBarClampsDoneToTotal(t *testing.T) {
	line := formatProgressBar("cp", 7, 5, 10, 1*1024*1024, true, false, 5*time.Second)
	if line != "cp [==========] 100% (5/5, 1.0 MB/s) 5s" {
		t.Fatalf("unexpected clamped output: %s", line)
	}
}

func TestLLRSummaryOnly(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("abc"), 0o644); err != nil {
		t.Fatalf("write a.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b.txt"), []byte("12345"), 0o644); err != nil {
		t.Fatalf("write b.txt: %v", err)
	}

	app := &cli.Command{
		Action: func(ctx context.Context, c *cli.Command) error {
			return runListTree(ctx, c, true)
		},
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "summary", Aliases: []string{"s"}},
			&cli.BoolFlag{Name: "machine"},
			&cli.BoolFlag{Name: "relative"},
			&cli.IntFlag{Name: "concurrency", Value: 1},
		},
	}

	output := captureStdout(t, func() error {
		return app.Run(context.Background(), []string{"llr", "-s", "--concurrency", "4", root})
	})
	if output != "Listed 2 files summing to 8 B (8 bytes)\n" {
		t.Fatalf("unexpected summary output: %q", output)
	}

	output = captureStdout(t, func() error {
		return app.Run(context.Background(), []string{"llr", "--summary", "--machine", root})
	})
	if output != "2\t8\n" {
		t.Fatalf("unexpected machine summary output: %q", output)
	}
}

func TestDUSummaryIsRecursive(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a"), []byte("abc"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b"), []byte("12345"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}
	app := &cli.Command{
		Action: cmdDU,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "summarize", Aliases: []string{"s"}},
			&cli.BoolFlag{Name: "machine"},
			&cli.IntFlag{Name: "concurrency", Value: 1},
		},
	}
	output := captureStdout(t, func() error {
		return app.Run(context.Background(), []string{"du", "-s", root})
	})
	if output != "Listed 2 files summing to 8 B (8 bytes)\n" {
		t.Fatalf("unexpected du summary output: %q", output)
	}

	output = captureStdout(t, func() error {
		return app.Run(context.Background(), []string{"du", "--machine", "-s", root})
	})
	if output != "2\t8\n" {
		t.Fatalf("unexpected machine du summary output: %q", output)
	}
}

func TestDUDefaultPrintsDirectoriesPostOrder(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "a"), []byte("abc"), 0o644); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sub, "b"), []byte("12345"), 0o644); err != nil {
		t.Fatalf("write b: %v", err)
	}
	app := &cli.Command{
		Action: cmdDU,
		Flags: []cli.Flag{
			&cli.BoolFlag{Name: "summarize", Aliases: []string{"s"}},
			&cli.BoolFlag{Name: "machine"},
			&cli.IntFlag{Name: "concurrency", Value: 1},
		},
	}
	output := captureStdout(t, func() error {
		return app.Run(context.Background(), []string{"du", root})
	})
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 2 || !strings.HasSuffix(lines[0], "\t"+sub) || !strings.HasSuffix(lines[1], "\t"+root) {
		t.Fatalf("unexpected du output: %q", output)
	}

	output = captureStdout(t, func() error {
		return app.Run(context.Background(), []string{"du", "--machine", "-s", root})
	})
	if output != "2\t8\n" {
		t.Fatalf("unexpected machine du output: %q", output)
	}
}

func TestFormatDiskUsageSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0"},
		{8, "8B"},
		{4 * 1024, "4.0K"},
		{16 * 1024, "16K"},
		{3992 * 1024, "3.9M"},
	}
	for _, test := range tests {
		if got := formatDiskUsageSize(test.bytes); got != test.want {
			t.Errorf("formatDiskUsageSize(%d) = %q, want %q", test.bytes, got, test.want)
		}
	}
}

func captureStdout(t *testing.T, run func() error) string {
	t.Helper()
	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	runErr := run()
	closeErr := w.Close()
	os.Stdout = original
	output, readErr := io.ReadAll(r)
	_ = r.Close()
	if runErr != nil {
		t.Fatalf("command failed: %v", runErr)
	}
	if closeErr != nil {
		t.Fatalf("close stdout: %v", closeErr)
	}
	if readErr != nil {
		t.Fatalf("read stdout: %v", readErr)
	}
	return string(output)
}

func TestFormatProgressBarNormalizesWidth(t *testing.T) {
	line := formatProgressBar("cp", 1, 5, 0, 1*1024*1024, true, false, 10*time.Second)
	if line != "cp [ ]  20% (1/5, 1.0 MB/s) 10s" {
		t.Fatalf("unexpected normalized width output: %s", line)
	}
}

func TestFormatProgressBarNormalizesNegativeSpeed(t *testing.T) {
	line := formatProgressBar("cp", 1, 5, 10, -2, true, false, 0)
	if line != "cp [==        ]  20% (1/5, 0 B/s) 0s" {
		t.Fatalf("unexpected normalized speed output: %s", line)
	}
}

func TestFormatProgressBarUsesGBSpeedForLargeValues(t *testing.T) {
	line := formatProgressBar("cp", 5, 10, 10, 1.5*1024*1024*1024, true, false, 2*time.Minute+15*time.Second)
	if line != "cp [=====     ]  50% (5/10, 1.5 GB/s) 2m15s" {
		t.Fatalf("unexpected GB speed output: %s", line)
	}
}

func TestFormatProgressBarWithoutSpeed(t *testing.T) {
	line := formatProgressBar("sync", 3, 10, 10, 10*1024*1024, false, false, 45*time.Second)
	if line != "sync [===       ]  30% (3/10) 45s" {
		t.Fatalf("unexpected output without speed: %s", line)
	}
}

func TestFormatProgressBarByteSized(t *testing.T) {
	line := formatProgressBar("file.dat", 50*1024*1024, 100*1024*1024, 10, 5*1024*1024, true, true, 10*time.Second)
	if line != "file.dat [=====     ]  50% (50.0 MiB/100.0 MiB, 5.0 MB/s) 10s" {
		t.Fatalf("unexpected byte-sized output: %s", line)
	}
}

func TestFormatProgressBarByteSizedNoSpeed(t *testing.T) {
	line := formatProgressBar("file.dat", 50*1024*1024, 100*1024*1024, 10, 0, false, true, 1*time.Hour+5*time.Minute+30*time.Second)
	if line != "file.dat [=====     ]  50% (50.0 MiB/100.0 MiB) 1h05m30s" {
		t.Fatalf("unexpected byte-sized no speed output: %s", line)
	}
}

func TestFormatElapsed(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0s"},
		{5 * time.Second, "5s"},
		{59 * time.Second, "59s"},
		{1 * time.Minute, "1m00s"},
		{2*time.Minute + 15*time.Second, "2m15s"},
		{1 * time.Hour, "1h00m00s"},
		{1*time.Hour + 5*time.Minute + 30*time.Second, "1h05m30s"},
		{25*time.Hour + 59*time.Minute + 59*time.Second, "25h59m59s"},
		// sub-second is truncated
		{5*time.Second + 500*time.Millisecond, "5s"},
	}
	for _, tt := range tests {
		got := formatElapsed(tt.d)
		if got != tt.want {
			t.Errorf("formatElapsed(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestHFSplitWildcard(t *testing.T) {
	tests := []struct {
		input      string
		parentPath string
		pattern    string
	}{
		{"hf://owner/repo", "hf://owner/repo", ""},
		{"hf://owner/repo/*.bin", "hf://owner/repo/", "*.bin"},
		{"hf://owner/repo/dir/*.bin", "hf://owner/repo/dir/", "*.bin"},
	}
	for _, tc := range tests {
		parentPath, pattern := splitWildcard(tc.input)
		if parentPath != tc.parentPath || pattern != tc.pattern {
			t.Fatalf("unexpected split for %s: %s %s", tc.input, parentPath, pattern)
		}
	}
}

func TestSplitWildcardGlobChars(t *testing.T) {
	tests := []struct {
		input      string
		parentPath string
		pattern    string
	}{
		// * wildcard
		{"az://account/container/blob*", "az://account/container/", "blob*"},
		{"az://account/container/dir/*.txt", "az://account/container/dir/", "*.txt"},
		// ? wildcard
		{"az://account/container/test?.txt", "az://account/container/", "test?.txt"},
		{"az://account/container/dir/test?.txt", "az://account/container/dir/", "test?.txt"},
		// [ character class
		{"az://account/container/test[0-9].txt", "az://account/container/", "test[0-9].txt"},
		{"az://account/container/dir/test[0-9].txt", "az://account/container/dir/", "test[0-9].txt"},
		// no wildcard
		{"az://account/container/blob", "az://account/container/blob", ""},
		// wildcard in scheme authority
		{"az://account*", "az://account*", "*"},
	}
	for _, tc := range tests {
		parentPath, pattern := splitWildcard(tc.input)
		if parentPath != tc.parentPath || pattern != tc.pattern {
			t.Errorf("splitWildcard(%q) = (%q, %q), want (%q, %q)", tc.input, parentPath, pattern, tc.parentPath, tc.pattern)
		}
	}
}

func TestWriteStreamToLocal(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "nested", "file.txt")
	content := "stream data"
	if err := bbbfs.Resolve(dst).Write(context.Background(), dst, strings.NewReader(content)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if string(data) != content {
		t.Fatalf("unexpected content: %s", data)
	}
}

func TestProgressWriterReportsByteCount(t *testing.T) {
	var got int
	pw := &progressWriter{onWrite: func(n int) { got += n }}
	n, err := pw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("write returned error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write returned %d, want 5", n)
	}
	if got != 5 {
		t.Fatalf("onWrite saw %d bytes, want 5", got)
	}
}

func TestProgressWriterNilCallback(t *testing.T) {
	pw := &progressWriter{}
	n, err := pw.Write([]byte("data"))
	if err != nil {
		t.Fatalf("write returned error: %v", err)
	}
	if n != 4 {
		t.Fatalf("Write returned %d, want 4", n)
	}
}

// TestProgressWriterTeeReaderAccumulates verifies the streaming-copy pattern
// added for remote↔local cp: piping a reader through io.TeeReader into a
// progressWriter must report exactly the total number of bytes streamed,
// matching the size of the data copied to the destination.
func TestProgressWriterTeeReaderAccumulates(t *testing.T) {
	content := strings.Repeat("abcdefgh", 10000) // 80000 bytes
	var streamCopied atomic.Int64
	var lastReported atomic.Int64
	var reported atomic.Int64
	pr := io.TeeReader(strings.NewReader(content), &progressWriter{
		onWrite: func(n int) {
			copied := streamCopied.Add(int64(n))
			// Mirror the CAS-guarded incremental reporting used in cmdCPPaths.
			for {
				prev := lastReported.Load()
				if copied <= prev {
					break
				}
				if lastReported.CompareAndSwap(prev, copied) {
					reported.Add(copied - prev)
					break
				}
			}
		},
	})
	var dst strings.Builder
	written, err := io.Copy(&dst, pr)
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}
	if written != int64(len(content)) {
		t.Fatalf("copied %d bytes, want %d", written, len(content))
	}
	if dst.String() != content {
		t.Fatalf("destination content mismatch")
	}
	if streamCopied.Load() != int64(len(content)) {
		t.Fatalf("streamCopied = %d, want %d", streamCopied.Load(), len(content))
	}
	if reported.Load() != int64(len(content)) {
		t.Fatalf("reported bytes = %d, want %d", reported.Load(), len(content))
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		bytes int64
		want  string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1073741824, "1.0 GiB"},
		{1099511627776, "1.0 TiB"},
		{-1, "0 B"},
		// boundary: just below 1 MiB must stay in KiB, not round up
		{1048575, "1023.9 KiB"},
		// large value beyond float64 exact integer range
		{1<<53 + 1, "8192.0 TiB"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%d", tt.bytes), func(t *testing.T) {
			got := formatSize(tt.bytes)
			if got != tt.want {
				t.Errorf("formatSize(%d) = %q, want %q", tt.bytes, got, tt.want)
			}
		})
	}
}

func TestDNSLoggingDialContextPassesThrough(t *testing.T) {
	var dialedNetwork, dialedAddr string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialedNetwork = network
		dialedAddr = addr
		return nil, errors.New("fake")
	}
	dial := dnsLoggingDialContext(baseDial, net.DefaultResolver)
	_, _ = dial(context.Background(), "tcp", "example.com:443")
	if dialedNetwork != "tcp" || dialedAddr != "example.com:443" {
		t.Fatalf("expected baseDial to receive original addr, got %s %s", dialedNetwork, dialedAddr)
	}
}

func TestDNSLoggingDialContextLogsOnDebug(t *testing.T) {
	orig := slog.Default()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	dial := dnsLoggingDialContext(baseDial, net.DefaultResolver)
	_, _ = dial(context.Background(), "tcp", "localhost:80")
	if !strings.Contains(buf.String(), "DNS lookup") {
		t.Fatalf("expected DNS lookup log at debug level, got: %s", buf.String())
	}
}

func TestDNSLoggingDialContextSilentOnInfo(t *testing.T) {
	orig := slog.Default()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	dial := dnsLoggingDialContext(baseDial, net.DefaultResolver)
	_, _ = dial(context.Background(), "tcp", "localhost:80")
	if buf.Len() != 0 {
		t.Fatalf("expected no log at info level, got: %s", buf.String())
	}
}

func TestDNSLoggingDialContextBadAddr(t *testing.T) {
	var called bool
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return nil, errors.New("fake")
	}
	// Enable debug logging so the SplitHostPort error path is exercised.
	orig := slog.Default()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	dial := dnsLoggingDialContext(baseDial, net.DefaultResolver)
	_, _ = dial(context.Background(), "tcp", "no-port")
	if !called {
		t.Fatal("expected baseDial to be called on bad addr")
	}
	// SplitHostPort fails, so no DNS lookup should be attempted.
	if strings.Contains(buf.String(), "DNS") {
		t.Fatalf("expected no DNS log on bad addr, got: %s", buf.String())
	}
}

func TestDNSLoggingDialContextResolverError(t *testing.T) {
	orig := slog.Default()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	dial := dnsLoggingDialContext(baseDial, net.DefaultResolver)
	// Use a hostname that won't resolve
	_, _ = dial(context.Background(), "tcp", "this-host-does-not-exist-xyzzy.invalid:443")
	if !strings.Contains(buf.String(), "DNS lookup error") {
		t.Fatalf("expected DNS lookup error log, got: %s", buf.String())
	}
}

// --------------- dnsCachingDialContext tests ---------------

// fakeLookup returns a lookupHostFunc that returns the given addresses and
// counts how many times it was called.
func fakeLookup(addrs []string, err error) (lookupHostFunc, *int) {
	count := 0
	return func(ctx context.Context, host string) ([]string, error) {
		count++
		return addrs, err
	}, &count
}

func TestDNSCachingDialContextPassesThrough(t *testing.T) {
	var dialedAddr string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if dialedAddr != "10.0.0.1:80" {
		t.Fatalf("expected dialed address to be resolved IP, got %s", dialedAddr)
	}
}

func TestDNSCachingDialContextIPPassthrough(t *testing.T) {
	var dialedAddr string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("fake")
	}
	lookup, count := fakeLookup(nil, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "1.2.3.4:443")
	if dialedAddr != "1.2.3.4:443" {
		t.Fatalf("expected IP address to pass through unchanged, got %s", dialedAddr)
	}
	if *count != 0 {
		t.Fatalf("expected no lookup for IP literal, got %d", *count)
	}
}

func TestDNSCachingDialContextBadAddr(t *testing.T) {
	var called bool
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		called = true
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup(nil, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "no-port")
	if !called {
		t.Fatal("expected baseDial to be called on bad addr")
	}
}

func TestDNSCachingDialContextCachesResult(t *testing.T) {
	lookup, count := fakeLookup([]string{"10.0.0.1"}, nil)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)

	// First call – cache miss, lookup should be called.
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if *count != 1 {
		t.Fatalf("expected exactly 1 lookup on first call, got %d", *count)
	}

	// Second call – should hit cache, no additional lookup.
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if *count != 1 {
		t.Fatalf("expected lookup count to stay 1 after cache hit, got %d", *count)
	}
}

func TestDNSCachingDialContextTTLExpiry(t *testing.T) {
	lookup, count := fakeLookup([]string{"10.0.0.1"}, nil)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	// Use a very short TTL so it expires immediately.
	dial := newCachingDialContext(baseDial, lookup, 1*time.Nanosecond, false)

	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if *count != 1 {
		t.Fatalf("expected 1 lookup on first call, got %d", *count)
	}

	// Wait for TTL to expire.
	time.Sleep(1 * time.Millisecond)

	// Second call – cache should have expired, triggering a new lookup.
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if *count != 2 {
		t.Fatalf("expected 2 lookups after TTL expiry, got %d", *count)
	}
}

func TestDNSCachingDialContextTriesAllAddrs(t *testing.T) {
	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	want := []string{"10.0.0.1:80", "10.0.0.2:80", "10.0.0.3:80"}
	if len(tried) != len(want) {
		t.Fatalf("expected %d dial attempts, got %d: %v", len(want), len(tried), tried)
	}
	for i, w := range want {
		if tried[i] != w {
			t.Fatalf("dial attempt %d: expected %s, got %s", i, w, tried[i])
		}
	}
}

func TestDNSCachingDialContextStopsOnSuccess(t *testing.T) {
	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		if addr == "10.0.0.2:80" {
			// Simulate a successful connection for the second address.
			return nil, nil
		}
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	want := []string{"10.0.0.1:80", "10.0.0.2:80"}
	if len(tried) != len(want) {
		t.Fatalf("expected %d dial attempts (stop on success), got %d: %v", len(want), len(tried), tried)
	}
}

func TestDNSCachingDialContextResolverError(t *testing.T) {
	var dialedAddr string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialedAddr = addr
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup(nil, errors.New("no such host"))
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "bad.invalid:443")
	if dialedAddr != "bad.invalid:443" {
		t.Fatalf("expected original address on resolver error, got %s", dialedAddr)
	}
}

func TestDNSCachingDialContextLogsDNSLookupOnMiss(t *testing.T) {
	orig := slog.Default()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)
	_, _ = dial(context.Background(), "tcp", "example.com:80")

	out := buf.String()
	if !strings.Contains(out, `msg="DNS lookup"`) {
		t.Fatalf("expected 'DNS lookup' log on cache miss, got: %s", out)
	}
	if !strings.Contains(out, "host=example.com") {
		t.Fatalf("expected host=example.com in DNS lookup log, got: %s", out)
	}
}

func TestDNSCachingDialContextNoDNSLookupOnHit(t *testing.T) {
	orig := slog.Default()
	var buf strings.Builder
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
	defer slog.SetDefault(orig)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, false)

	// First call – populates cache.
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	buf.Reset()

	// Second call – should be a cache hit, no "DNS lookup" log.
	_, _ = dial(context.Background(), "tcp", "example.com:80")

	out := buf.String()
	if strings.Contains(out, `msg="DNS lookup"`) {
		t.Fatalf("expected no 'DNS lookup' log on cache hit, got: %s", out)
	}
	if !strings.Contains(out, `msg="DNS cache hit"`) {
		t.Fatalf("expected 'DNS cache hit' log, got: %s", out)
	}
}

func TestDNSCachingDialContextUnlimitedTTL(t *testing.T) {
	lookup, count := fakeLookup([]string{"10.0.0.1"}, nil)

	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("fake")
	}
	// TTL 0 means unlimited – entries never expire.
	dial := newCachingDialContext(baseDial, lookup, 0, false)

	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if *count != 1 {
		t.Fatalf("expected 1 lookup on first call, got %d", *count)
	}

	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if *count != 1 {
		t.Fatalf("expected lookup count to stay 1 with unlimited TTL, got %d", *count)
	}
}

// --------------- DNS pin tests ---------------

func TestDNSPinUsesFirstAddress(t *testing.T) {
	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		// First address is unreachable, second succeeds.
		if addr == "10.0.0.2:80" {
			return nil, nil
		}
		return nil, errors.New("unreachable")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, true)
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	// With pin=true, addresses are tried in order until one succeeds.
	want := []string{"10.0.0.1:80", "10.0.0.2:80"}
	if len(tried) != len(want) {
		t.Fatalf("expected %d dial attempts with pin, got %d: %v", len(want), len(tried), tried)
	}
	for i, w := range want {
		if tried[i] != w {
			t.Fatalf("dial attempt %d: expected %s, got %s", i, w, tried[i])
		}
	}
}

func TestDNSPinFirstAddressReachable(t *testing.T) {
	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		// First address succeeds immediately.
		if addr == "10.0.0.1:80" {
			return nil, nil
		}
		return nil, errors.New("unreachable")
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, true)
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	// Only the first address should be tried since it succeeded.
	if len(tried) != 1 || tried[0] != "10.0.0.1:80" {
		t.Fatalf("expected only 10.0.0.1:80 tried, got %v", tried)
	}
}

func TestDNSPinSingleAddress(t *testing.T) {
	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		return nil, nil // success
	}
	lookup, _ := fakeLookup([]string{"10.0.0.1"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, true)
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	if len(tried) != 1 || tried[0] != "10.0.0.1:80" {
		t.Fatalf("expected single address 10.0.0.1:80, got %v", tried)
	}
}

func TestDNSPinCacheReturnsSameIP(t *testing.T) {
	var tried []string
	baseDial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		tried = append(tried, addr)
		return nil, nil // all succeed
	}
	lookup, count := fakeLookup([]string{"10.0.0.1", "10.0.0.2"}, nil)
	dial := newCachingDialContext(baseDial, lookup, 5*time.Minute, true)

	// First call – resolves and pins to first reachable.
	_, _ = dial(context.Background(), "tcp", "example.com:80")
	// Second call – should use cached pinned address.
	_, _ = dial(context.Background(), "tcp", "example.com:80")

	if *count != 1 {
		t.Fatalf("expected 1 lookup (cached), got %d", *count)
	}
	if len(tried) != 2 {
		t.Fatalf("expected 2 dial attempts total, got %d", len(tried))
	}
	for i, addr := range tried {
		if addr != "10.0.0.1:80" {
			t.Fatalf("dial attempt %d: expected pinned 10.0.0.1:80, got %s", i, addr)
		}
	}
}

// --------------- custom DNS server tests ---------------

func TestParseDNSServers(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"8.8.8.8", []string{"8.8.8.8:53"}},
		{"8.8.8.8:5353", []string{"8.8.8.8:5353"}},
		{" 8.8.8.8 , 1.1.1.1:5353 ", []string{"8.8.8.8:53", "1.1.1.1:5353"}},
		{"::1", []string{"[::1]:53"}},
		{"[2001:db8::1]:5353", []string{"[2001:db8::1]:5353"}},
		{"8.8.8.8,,1.1.1.1", []string{"8.8.8.8:53", "1.1.1.1:53"}},
		{"8.8.8.8 : 53", []string{"8.8.8.8:53"}},
		{"[2001:db8::1]", []string{"[2001:db8::1]:53"}},
	}

	for _, tc := range cases {
		got, err := parseDNSServers(tc.raw)
		if err != nil {
			t.Fatalf("parseDNSServers(%q) returned error: %v", tc.raw, err)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("parseDNSServers(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestParseDNSServersInvalid(t *testing.T) {
	for _, raw := range []string{"", "  ", ",", "dns.example.com", "8.8.8.8:notaport", "8.8.8.8:99999", "not an ip"} {
		if got, err := parseDNSServers(raw); err == nil {
			t.Fatalf("parseDNSServers(%q) expected error, got %v", raw, got)
		}
	}
}

func TestNewDNSServerResolverTriesAllServers(t *testing.T) {
	var mu sync.Mutex
	dialed := map[string]bool{}

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		dialed[addr] = true
		mu.Unlock()
		return nil, errors.New("dial refused")
	}

	r := newDNSServerResolver([]string{"10.0.0.1:53", "10.0.0.2:5353"}, dial)
	if _, err := r.LookupHost(context.Background(), "example.com."); err == nil {
		t.Fatal("expected lookup error when every DNS server is unreachable")
	}

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"10.0.0.1:53", "10.0.0.2:5353"} {
		if !dialed[want] {
			t.Fatalf("expected DNS server %s to be dialled, dialled: %v", want, dialed)
		}
	}
}

// startTestDNSServer starts a minimal UDP DNS server that answers every A
// query with the given IPv4 address, and returns its address.
func startTestDNSServer(t *testing.T, ip net.IP) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp, ok := buildDNSResponse(buf[:n], ip)
			if !ok {
				continue
			}
			_, _ = pc.WriteTo(resp, from)
		}
	}()

	return pc.LocalAddr().String()
}

// buildDNSResponse builds a response for a single-question DNS query. A
// records are answered with ip; every other question type gets an empty
// (NOERROR) answer.
func buildDNSResponse(query []byte, ip net.IP) ([]byte, bool) {
	if len(query) < 12 {
		return nil, false
	}

	// Walk the QNAME label sequence to find the end of the question.
	i := 12
	for i < len(query) && query[i] != 0 {
		i += int(query[i]) + 1
	}
	if i >= len(query) || i+5 > len(query) {
		return nil, false
	}
	qEnd := i + 5 // terminating zero + QTYPE + QCLASS
	qtype := int(query[i+1])<<8 | int(query[i+2])

	resp := make([]byte, 0, 64)
	resp = append(resp, query[0], query[1]) // ID
	resp = append(resp, 0x81, 0x80)         // QR + RD + RA, NOERROR
	resp = append(resp, 0x00, 0x01)         // QDCOUNT
	if qtype == 1 {                         // A
		resp = append(resp, 0x00, 0x01) // ANCOUNT
	} else {
		resp = append(resp, 0x00, 0x00)
	}
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT, ARCOUNT
	resp = append(resp, query[12:qEnd]...)      // question section

	if qtype == 1 {
		v4 := ip.To4()
		if v4 == nil {
			return nil, false
		}
		resp = append(resp, 0xc0, 0x0c) // name pointer to question
		resp = append(resp, 0x00, 0x01) // TYPE A
		resp = append(resp, 0x00, 0x01) // CLASS IN
		resp = append(resp, 0x00, 0x00, 0x00, 0x3c)
		resp = append(resp, 0x00, 0x04) // RDLENGTH
		resp = append(resp, v4...)
	}

	return resp, true
}

func TestNewDNSServerResolverResolvesViaConfiguredServer(t *testing.T) {
	addr := startTestDNSServer(t, net.IPv4(203, 0, 113, 7))

	servers, err := parseDNSServers(addr)
	if err != nil {
		t.Fatalf("parseDNSServers(%q): %v", addr, err)
	}

	r := newDNSServerResolver(servers, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(ctx, "bbb-dns-test.invalid.")
	if err != nil {
		t.Fatalf("LookupHost via custom DNS server failed: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "203.0.113.7" {
		t.Fatalf("expected [203.0.113.7] from custom DNS server, got %v", addrs)
	}
}

func TestProgressBarAbortDoesNotMarkComplete(t *testing.T) {
	p := &progressBar{}
	p.total.Store(1000)
	p.done.Store(400)
	p.lastTotal.Store(progressUninitialized)

	p.Abort()

	if !p.finished.Load() {
		t.Fatal("expected Abort to mark the bar finished")
	}
	// Abort must not render the bar as completed (done left as-is, not total).
	if got := p.done.Load(); got != 400 {
		t.Fatalf("expected done to stay 400 after Abort, got %d", got)
	}
	// A subsequent Finish must be a no-op and must not resurrect the bar to 100%.
	p.Finish()
	if got := p.done.Load(); got != 400 {
		t.Fatalf("expected done to remain 400 after Finish following Abort, got %d", got)
	}
}
