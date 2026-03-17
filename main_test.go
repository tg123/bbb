package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tg123/bbb/internal/hf"
	"github.com/urfave/cli/v3"
)

func TestIsAzHTTPS(t *testing.T) {
	if !isAz("https://myacct.blob.core.windows.net/container") {
		t.Fatalf("expected https blob url to be treated as az path")
	}
	if isAz("https://example.com/file") {
		t.Fatalf("non-blob https url should not be treated as az path")
	}
}

func TestIsAzHTTPEdgeCases(t *testing.T) {
	if !isAz("http://MYACCT.blob.core.windows.net:8080/container/blob.txt?sv=2021#frag") {
		t.Fatalf("expected blob url with port/query/fragment to be az path")
	}
	if isAz("http://bad.blob.core.windows.net/") {
		t.Fatalf("url missing container should not be treated as az path")
	}
	if isAz("ftp://acct.blob.core.windows.net/container") {
		t.Fatalf("non-http scheme should not be treated as az path")
	}
}

func TestIsHF(t *testing.T) {
	if !isHF("hf://openai/gpt-oss-120b") {
		t.Fatalf("expected hf scheme to be detected")
	}
	if isHF("https://example.com/model") {
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
	dst, err := resolveDstPath("az://acct/container/prefix", true, "model.bin", true)
	if err != nil {
		t.Fatalf("resolveDstPath failed: %v", err)
	}
	if dst != "az://acct/container/prefix/model.bin" {
		t.Fatalf("unexpected dst: %s", dst)
	}
}

func TestSyncHFFiles(t *testing.T) {
	files := []string{"file.txt", "dir/file2.txt", "dir/skip.txt"}
	list := syncHFFilesFromList(files, func(name string) bool { return strings.Contains(name, "skip") })
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
			&cli.StringFlag{Name: "taskfile-state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--taskfile-state", stateFile}); err != nil {
		t.Fatalf("cp failed: %v", err)
	}
	if _, err := os.Stat(dstOk); err != nil {
		t.Fatalf("expected copied file: %v", err)
	}
	if err := os.Remove(srcOk); err != nil {
		t.Fatalf("remove src: %v", err)
	}
	if err := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--taskfile-state", stateFile}); err != nil {
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
			&cli.StringFlag{Name: "taskfile-state"},
		},
	}
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stderr: %v", err)
	}
	os.Stderr = w
	runErr := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--taskfile-state", stateFile})
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
			&cli.StringFlag{Name: "taskfile-state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "-f", "--taskfile", taskfile, "--taskfile-state", stateFile}); err != nil {
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
			&cli.StringFlag{Name: "taskfile-state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "-f", "--taskfile", taskfile, "--taskfile-state", stateFile}); err != nil {
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
			&cli.StringFlag{Name: "taskfile-state"},
		},
	}
	if err := app.Run(context.Background(), []string{"cp", "-f", "--taskfile", taskfile, "--taskfile-state", stateFile}); err != nil {
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
			&cli.StringFlag{Name: "taskfile-state"},
		},
	}
	runErr := app.Run(context.Background(), []string{"cp", "--taskfile", taskfile, "--taskfile-state", stateFile})
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
	line := formatProgressBar("cp", 5, 10, 10, 2.5*1024*1024, true)
	if line != "cp [=====     ]  50% (5/10, 2.5 MB/s)" {
		t.Fatalf("unexpected progress bar output: %s", line)
	}
}

func TestFormatProgressBarClampsDoneToTotal(t *testing.T) {
	line := formatProgressBar("cp", 7, 5, 10, 1*1024*1024, true)
	if line != "cp [==========] 100% (5/5, 1.0 MB/s)" {
		t.Fatalf("unexpected clamped output: %s", line)
	}
}

func TestFormatProgressBarNormalizesWidth(t *testing.T) {
	line := formatProgressBar("cp", 1, 5, 0, 1*1024*1024, true)
	if line != "cp [ ]  20% (1/5, 1.0 MB/s)" {
		t.Fatalf("unexpected normalized width output: %s", line)
	}
}

func TestFormatProgressBarNormalizesNegativeSpeed(t *testing.T) {
	line := formatProgressBar("cp", 1, 5, 10, -2, true)
	if line != "cp [==        ]  20% (1/5, 0.0 MB/s)" {
		t.Fatalf("unexpected normalized speed output: %s", line)
	}
}

func TestFormatProgressBarUsesGBSpeedForLargeValues(t *testing.T) {
	line := formatProgressBar("cp", 5, 10, 10, 1.5*1024*1024*1024, true)
	if line != "cp [=====     ]  50% (5/10, 1.5 GB/s)" {
		t.Fatalf("unexpected GB speed output: %s", line)
	}
}

func TestFormatProgressBarWithoutSpeed(t *testing.T) {
	line := formatProgressBar("sync", 3, 10, 10, 10*1024*1024, false)
	if line != "sync [===       ]  30% (3/10)" {
		t.Fatalf("unexpected output without speed: %s", line)
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

func TestWriteStreamToFile(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "nested", "file.txt")
	content := "stream data"
	if err := writeStreamToFile(dst, strings.NewReader(content), 0o644); err != nil {
		t.Fatalf("writeStreamToFile failed: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if string(data) != content {
		t.Fatalf("unexpected content: %s", data)
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
