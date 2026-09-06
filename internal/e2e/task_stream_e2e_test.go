package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type taskStreamProcess struct {
	stdin  io.WriteCloser
	done   chan struct{}
	output bytes.Buffer
	err    error
}

func startTaskStream(t *testing.T, command, dir string) *taskStreamProcess {
	t.Helper()
	bin := os.Getenv("BBB_TEST_BIN_PATH")
	if bin == "" {
		bin = "bbb"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*waitTimeout)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, bin, command, "--taskfile", "-", "--concurrency", "2", "--retry-count", "0", "-q")
	cmd.Dir = dir
	cmd.WaitDelay = time.Second
	stream := &taskStreamProcess{done: make(chan struct{})}
	// os/exec serializes writes when stdout and stderr share the same writer.
	cmd.Stdout = &stream.output
	cmd.Stderr = &stream.output
	var err error
	stream.stdin, err = cmd.StdinPipe()
	if err != nil {
		t.Fatalf("open task stream: %v", err)
	}
	t.Cleanup(func() { _ = stream.stdin.Close() })
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", command, err)
	}
	go func() {
		stream.err = cmd.Wait()
		close(stream.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-stream.done
		if t.Failed() {
			t.Logf("bbb output:\n%s", stream.output.String())
		}
	})
	return stream
}

func (s *taskStreamProcess) wait(t *testing.T) error {
	t.Helper()
	select {
	case <-s.done:
		return s.err
	case <-time.After(waitTimeout):
		t.Fatal("bbb did not exit before the deadline")
		return nil
	}
}

func (s *taskStreamProcess) waitForFile(t *testing.T, path, want string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(waitTimeout)
	defer timer.Stop()
	for {
		content, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("read copied file: %v", err)
		}
		if err == nil && string(content) == want {
			return
		}
		select {
		case <-s.done:
			t.Fatalf("bbb exited before copying %s: %v", path, s.err)
		case <-timer.C:
			t.Fatalf("file %s was not copied while stdin remained open", path)
		case <-ticker.C:
		}
	}
}

func TestTaskfileStreamCopiesBeforeEOF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}
	for _, command := range []string{"cp", "sync"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			stream := startTaskStream(t, command, dir)
			for i := 1; i <= 2; i++ {
				src := fmt.Sprintf("source-%d", i)
				dst := fmt.Sprintf("destination-%d", i)
				want := fmt.Sprintf("streamed task %d\n", i)
				if err := os.Mkdir(filepath.Join(dir, src), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, src, "payload.txt"), []byte(want), 0o644); err != nil {
					t.Fatal(err)
				}
				// Send the next pair only after the previous copy completes,
				// keeping stdin open throughout both transfers.
				if _, err := fmt.Fprintln(stream.stdin, src, dst); err != nil {
					t.Fatalf("write task %d: %v", i, err)
				}
				stream.waitForFile(t, filepath.Join(dir, dst, "payload.txt"), want)
				select {
				case <-stream.done:
					t.Fatalf("bbb exited before EOF: %v", stream.err)
				default:
				}
			}
			if err := stream.stdin.Close(); err != nil {
				t.Fatalf("close stdin: %v", err)
			}
			if err := stream.wait(t); err != nil {
				t.Fatalf("%s failed after EOF: %v", command, err)
			}
		})
	}
}

func TestTaskfileStreamFailureBeforeEOF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}
	for _, command := range []string{"cp", "sync"} {
		t.Run(command, func(t *testing.T) {
			stream := startTaskStream(t, command, t.TempDir())
			if _, err := fmt.Fprintln(stream.stdin, "missing-source destination"); err != nil {
				t.Fatalf("write failing task: %v", err)
			}
			// Do not close stdin: an error must not wait for another pair or EOF.
			if err := stream.wait(t); err == nil {
				t.Fatal("bbb succeeded despite a missing source")
			}
			if !strings.Contains(stream.output.String(), "missing-source") {
				t.Fatalf("expected missing-source error, got:\n%s", stream.output.String())
			}
		})
	}
}
