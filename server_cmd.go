package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/tg123/bbb/internal/server"
	"github.com/urfave/cli/v3"
)

// cliRunner performs the actual data movement for server mode by reusing the
// regular bbb cp implementation.
type cliRunner struct{}

func (cliRunner) Expand(ctx context.Context, src, dst string, emit func(server.FileTask) error) error {
	return expandCPTask(ctx, taskPair{src: src, dst: dst}, func(task cpTask) error {
		return emit(server.FileTask{Src: task.src, Dst: task.dst, Size: task.size})
	})
}

func (cliRunner) Copy(ctx context.Context, src, dst string, opts server.CopyOptions, onBytes func(int64)) error {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	return cmdCPPaths(ctx, opts.Overwrite, true, concurrency, opts.RetryCount, []string{src}, dst, 0, false, onBytes)
}

func defaultWorkerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "bbb"
	}
	return host + "-" + uuid.NewString()[:8]
}

func cmdServer(ctx context.Context, c *cli.Command) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	workers := c.Int("workers")
	if workers < 0 {
		return fmt.Errorf("server: --workers must not be negative")
	}
	workerID := c.String("worker-id")
	if workerID == "" {
		workerID = defaultWorkerID()
	}

	if leader := c.String("leader"); leader != "" {
		return runFollower(ctx, c, leader, workerID, workers)
	}
	return runLeader(ctx, c, workerID, workers)
}

func runFollower(ctx context.Context, c *cli.Command, leader, workerID string, workers int) error {
	if workers == 0 {
		return fmt.Errorf("server: follower mode requires --workers > 0")
	}
	lease := c.Duration("lease")
	slog.Info("bbb server: starting follower", "leader", leader, "worker", workerID, "workers", workers)

	pool := server.NewPool(server.NewClient(leader, c.String("token")), cliRunner{}, server.PoolOptions{
		WorkerID:          workerID,
		Mode:              server.ModeFollower,
		Version:           version(),
		Slots:             workers,
		PollInterval:      c.Duration("poll-interval"),
		ProgressInterval:  lease / 3,
		HeartbeatInterval: lease / 3,
	})
	if err := pool.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func runLeader(ctx context.Context, c *cli.Command, workerID string, workers int) error {
	store, err := server.OpenStore(c.String("db"))
	if err != nil {
		return err
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			slog.Warn("bbb server: close database failed", "error", cerr)
		}
	}()

	listen := c.String("listen")
	srv := server.New(store, cliRunner{}, server.Options{
		Token:         c.String("token"),
		Workers:       workers,
		Concurrency:   c.Int("concurrency"),
		LeaseDuration: c.Duration("lease"),
		PollInterval:  c.Duration("poll-interval"),
		WorkerID:      workerID,
		Version:       version(),
	})

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		slog.Info("bbb server: listening", "addr", listen, "db", c.String("db"), "workers", workers)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
			return
		}
		serveErr <- nil
	}()

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = srv.Run(runCtx)
	}()

	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-serveErr:
	}

	cancel()
	<-runDone

	shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("bbb server: shutdown failed", "error", err)
	}
	return runErr
}
