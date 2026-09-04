//go:build unix

package main

import (
	"fmt"
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
	writerErr := make(chan error, 1)
	continueWriter := make(chan struct{})
	defer func() {
		select {
		case <-continueWriter:
		default:
			close(continueWriter)
		}
	}()
	go func() {
		defer close(writerDone)
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			writerErr <- fmt.Errorf("open FIFO writer: %w", err)
			return
		}
		defer func() {
			_ = w.Close()
		}()
		if _, err := w.WriteString("src1 dst1\n"); err != nil {
			writerErr <- fmt.Errorf("write first task: %w", err)
			return
		}
		// Hold the pipe open; the first pair must be emitted before EOF.
		<-continueWriter
		if _, err := w.WriteString("src2 dst2\n"); err != nil {
			writerErr <- fmt.Errorf("write second task: %w", err)
		}
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
	case err := <-writerErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first streamed task pair")
	}
	select {
	case <-writerDone:
		t.Fatal("first task pair was only emitted after the writer finished")
	default:
	}
	close(continueWriter)

	if err := <-errCh; err != nil {
		t.Fatalf("streamTaskPairs failed: %v", err)
	}
	<-writerDone
	select {
	case err := <-writerErr:
		t.Fatal(err)
	default:
	}
	if len(got) != 2 || got[1].src != "src2" {
		t.Fatalf("unexpected streamed tasks: %+v", got)
	}
}
