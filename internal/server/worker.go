package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// TaskSource hands leased tasks to a worker pool and collects their progress.
// The leader talks to the local store, followers talk to the leader over REST.
type TaskSource interface {
	Claim(ctx context.Context, workerID string, limit int) ([]Lease, error)
	Progress(ctx context.Context, workerID string, taskID int64, copiedBytes int64) (abort bool, err error)
	Complete(ctx context.Context, workerID string, taskID int64, state string, copiedBytes int64, taskErr string) error
	Heartbeat(ctx context.Context, worker Worker) error
}

// PoolOptions configures a worker pool.
type PoolOptions struct {
	WorkerID          string
	Mode              string
	Addr              string
	Version           string
	Slots             int
	PollInterval      time.Duration
	ProgressInterval  time.Duration
	HeartbeatInterval time.Duration
}

func (o *PoolOptions) setDefaults() {
	if o.Slots <= 0 {
		o.Slots = 1
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.ProgressInterval <= 0 {
		o.ProgressInterval = 5 * time.Second
	}
	if o.HeartbeatInterval <= 0 {
		o.HeartbeatInterval = 5 * time.Second
	}
	if o.Mode == "" {
		o.Mode = ModeFollower
	}
}

// Pool claims tasks from a TaskSource and executes them with a Runner.
type Pool struct {
	source TaskSource
	runner Runner
	opts   PoolOptions
}

// NewPool creates a worker pool.
func NewPool(source TaskSource, runner Runner, opts PoolOptions) *Pool {
	opts.setDefaults()
	return &Pool{source: source, runner: runner, opts: opts}
}

// Run claims and executes tasks until ctx is cancelled.
func (p *Pool) Run(ctx context.Context) error {
	var (
		wg       sync.WaitGroup
		inflight atomic.Int64
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.heartbeatLoop(ctx)
	}()

	for {
		if ctx.Err() != nil {
			break
		}
		free := p.opts.Slots - int(inflight.Load())
		var leases []Lease
		if free > 0 {
			var err error
			leases, err = p.source.Claim(ctx, p.opts.WorkerID, free)
			if err != nil && ctx.Err() == nil {
				slog.Warn("bbb server: claim tasks failed", "error", err)
			}
		}
		if len(leases) == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(p.opts.PollInterval):
			}
			continue
		}
		for _, lease := range leases {
			inflight.Add(1)
			wg.Add(1)
			go func(lease Lease) {
				defer wg.Done()
				defer inflight.Add(-1)
				p.execute(ctx, lease)
			}(lease)
		}
	}

	wg.Wait()
	return ctx.Err()
}

func (p *Pool) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(p.opts.HeartbeatInterval)
	defer ticker.Stop()
	for {
		if err := p.source.Heartbeat(ctx, Worker{
			ID:       p.opts.WorkerID,
			Mode:     p.opts.Mode,
			Addr:     p.opts.Addr,
			Version:  p.opts.Version,
			Capacity: p.opts.Slots,
		}); err != nil && ctx.Err() == nil {
			slog.Warn("bbb server: worker heartbeat failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (p *Pool) execute(ctx context.Context, lease Lease) {
	taskCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		copied    atomic.Int64
		aborted   atomic.Bool
		reporting sync.WaitGroup
	)

	reporting.Add(1)
	go func() {
		defer reporting.Done()
		ticker := time.NewTicker(p.opts.ProgressInterval)
		defer ticker.Stop()
		for {
			select {
			case <-taskCtx.Done():
				return
			case <-ticker.C:
			}
			abort, err := p.source.Progress(context.WithoutCancel(taskCtx), p.opts.WorkerID, lease.Task.ID, copied.Load())
			if err != nil {
				slog.Warn("bbb server: task progress failed", "task", lease.Task.ID, "error", err)
				continue
			}
			if abort {
				aborted.Store(true)
				cancel()
				return
			}
		}
	}()

	err := p.runner.Copy(taskCtx, lease.Task.Src, lease.Task.Dst, CopyOptions{
		Overwrite:   lease.Overwrite,
		Concurrency: lease.Concurrency,
		RetryCount:  lease.RetryCount,
	}, func(delta int64) {
		copied.Add(delta)
	})

	cancel()
	reporting.Wait()

	// The parent context is only cancelled on shutdown; leave the task running
	// so its lease expires and another worker picks it up.
	if ctx.Err() != nil && !aborted.Load() {
		return
	}

	state := TaskSucceeded
	taskErr := ""
	switch {
	case aborted.Load():
		state = TaskCancelled
		taskErr = "cancelled"
	case err != nil:
		state = TaskFailed
		taskErr = err.Error()
		if errors.Is(err, context.Canceled) {
			taskErr = "cancelled"
		}
	}

	completeCtx, completeCancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer completeCancel()
	if err := p.source.Complete(completeCtx, p.opts.WorkerID, lease.Task.ID, state, copied.Load(), taskErr); err != nil {
		slog.Warn("bbb server: task completion failed", "task", lease.Task.ID, "error", err)
	}
}

// StoreSource is a TaskSource backed directly by the leader store.
type StoreSource struct {
	Store *Store
	Lease time.Duration
}

// Claim implements TaskSource.
func (s *StoreSource) Claim(ctx context.Context, workerID string, limit int) ([]Lease, error) {
	return s.Store.ClaimTasks(ctx, workerID, limit, s.Lease)
}

// Progress implements TaskSource.
func (s *StoreSource) Progress(ctx context.Context, workerID string, taskID int64, copiedBytes int64) (bool, error) {
	return s.Store.TaskProgress(ctx, workerID, taskID, copiedBytes, s.Lease)
}

// Complete implements TaskSource.
func (s *StoreSource) Complete(ctx context.Context, workerID string, taskID int64, state string, copiedBytes int64, taskErr string) error {
	return s.Store.CompleteTask(ctx, workerID, taskID, state, copiedBytes, taskErr)
}

// Heartbeat implements TaskSource.
func (s *StoreSource) Heartbeat(ctx context.Context, worker Worker) error {
	return s.Store.UpsertWorker(ctx, worker)
}
