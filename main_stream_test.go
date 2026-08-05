//go:build unix

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestStreamTaskPairsEmitsBeforeEOF(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "tasks.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unsupported: %v", err)
	}

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			return
		}
		defer func() {
			_ = w.Close()
		}()
		_, _ = w.WriteString("src1 dst1\n")
		// Hold the pipe open; the first pair must be emitted before EOF.
		time.Sleep(200 * time.Millisecond)
		_, _ = w.WriteString("src2 dst2\n")
	}()

	first := make(chan taskPair, 1)
	var got []taskPair
	errCh := make(chan error, 1)
	go func() {
		errCh <- streamTaskPairs(fifo, func(task taskPair) error {
			select {
			case first <- task:
			default:
			}
			got = append(got, task)
			return nil
		})
	}()

	select {
	case task := <-first:
		if task.src != "src1" || task.dst != "dst1" {
			t.Fatalf("unexpected first task: %+v", task)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first streamed task pair")
	}
	select {
	case <-writerDone:
		t.Fatal("first task pair was only emitted after the writer finished")
	default:
	}

	if err := <-errCh; err != nil {
		t.Fatalf("streamTaskPairs failed: %v", err)
	}
	<-writerDone
	if len(got) != 2 || got[1].src != "src2" {
		t.Fatalf("unexpected streamed tasks: %+v", got)
	}
}
