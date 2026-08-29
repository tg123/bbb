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

	for ctx.Err() == nil {
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
		ticker := time.NewTicker(p.progressInterval(lease))
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

	// Keep retrying inside the lease window: once the lease expires the task
	// belongs to another worker and this report is rejected anyway.
	completeWait := maxCompleteWait
	if !lease.Expires.IsZero() {
		if remaining := time.Until(lease.Expires); remaining < completeWait {
			completeWait = remaining
		}
	}
	if completeWait < time.Second {
		completeWait = time.Second
	}
	completeCtx, completeCancel := context.WithTimeout(context.WithoutCancel(ctx), completeWait)
	defer completeCancel()
	if err := p.completeWithRetry(completeCtx, lease, state, copied.Load(), taskErr); err != nil {
		slog.Warn("bbb server: task completion failed", "task", lease.Task.ID, "error", err)
	}
}

// minProgressInterval bounds how often a worker reports progress, so a short or
// already-expired lease cannot turn into a tight request loop.
const minProgressInterval = 100 * time.Millisecond

// maxCompleteWait bounds how long a worker keeps retrying a completion report.
const maxCompleteWait = 30 * time.Second

// progressInterval derives the reporting cadence from the lease the leader
// actually granted. The leader owns the lease duration, so deriving the cadence
// from a worker-local setting lets the lease expire mid-copy: the task is then
// requeued and copied a second time concurrently. The worker-local interval is
// still honoured as an upper bound. Clock skew only makes the computed remaining
// time shorter or longer, which at worst costs extra progress calls.
func (p *Pool) progressInterval(lease Lease) time.Duration {
	interval := p.opts.ProgressInterval
	if lease.Expires.IsZero() {
		return interval
	}
	if remaining := time.Until(lease.Expires); remaining/3 < interval {
		interval = remaining / 3
	}
	if interval < minProgressInterval {
		interval = minProgressInterval
	}
	return interval
}

// completeWithRetry reports a terminal task state, retrying transient failures.
// Dropping this report leaves the task leased until it expires and is copied a
// second time; with overwrite=false that retry usually fails because the first
// copy already created the destination, failing a job that actually succeeded.
// Reporting a terminal state is idempotent, so retrying is safe.
func (p *Pool) completeWithRetry(ctx context.Context, lease Lease, state string, copied int64, taskErr string) error {
	backoff := 100 * time.Millisecond
	for attempt := 1; ; attempt++ {
		err := p.source.Complete(ctx, p.opts.WorkerID, lease.Task.ID, state, copied, taskErr)
		if err == nil || ctx.Err() != nil {
			return err
		}
		slog.Warn("bbb server: task completion failed, retrying",
			"task", lease.Task.ID, "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(backoff):
		}
		if backoff < 2*time.Second {
			backoff *= 2
		}
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
