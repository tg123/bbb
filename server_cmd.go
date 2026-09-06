package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/tg123/bbb/internal/bbbfs"
	"github.com/tg123/bbb/internal/server"
	"github.com/urfave/cli/v3"
)

// cliRunner performs the actual data movement for server mode by reusing the
// regular bbb cp implementation.
type cliRunner struct{}

func (cliRunner) Expand(ctx context.Context, src, dst string, emit func(server.FileTask) error) error {
	bbbfs.RegisterAzAccountRolesForCopy(src, dst)
	if err := bbbfs.PreAuthenticateAz(ctx, src, dst); err != nil {
		return err
	}
	return expandCPTask(ctx, taskPair{src: src, dst: dst}, func(task cpTask) error {
		return emit(server.FileTask{Src: task.src, Dst: task.dst, Size: task.size})
	})
}

func (cliRunner) Copy(ctx context.Context, src, dst string, opts server.CopyOptions, onBytes func(int64)) error {
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	// Followers never run Expand, so tag the credential roles here too;
	// otherwise an untagged destination account authenticates with the source
	// role's credentials.
	bbbfs.RegisterAzAccountRolesForCopy(src, dst)
	if err := bbbfs.PreAuthenticateAz(ctx, src, dst); err != nil {
		return err
	}
	// Retries belong to the persisted task layer, which re-queues a failed task
	// up to the job's retry_count. Retrying inside this call as well would
	// multiply the attempts per file and re-count the bytes already reported by
	// the failed attempt.
	return cmdCPPaths(ctx, opts.Overwrite, true, concurrency, 0, []string{src}, dst, 0, false, onBytes)
}

func cmdCPAction(ctx context.Context, c *cli.Command) error {
	if strings.TrimSpace(c.Root().String("server")) != "" {
		return cmdServerCP(ctx, c)
	}
	return cmdCP(ctx, c)
}

func remoteServerClient(c *cli.Command, command string) (*server.Client, error) {
	baseURL := strings.TrimSpace(c.Root().String("server"))
	if baseURL == "" {
		return nil, fmt.Errorf("%s: --server is required", command)
	}
	return server.NewClient(baseURL, c.Root().String("server-token")), nil
}

func cmdServerCP(ctx context.Context, c *cli.Command) error {
	if stateFile := c.String("state"); stateFile != "" || c.Root().String("state") != "" {
		return errors.New("cp: --state is not supported with --server")
	}
	tasks, err := cpTaskPairs(c)
	if err != nil {
		return err
	}
	client, err := remoteServerClient(c, "cp")
	if err != nil {
		return err
	}
	concurrency := 0
	if c.IsSet("concurrency") {
		concurrency = c.Int("concurrency")
	}
	for _, task := range tasks {
		job, err := client.CreateJob(ctx, server.CreateJobRequest{
			Src:         task.src,
			Dst:         task.dst,
			Overwrite:   c.Bool("f"),
			Concurrency: concurrency,
			RetryCount:  c.Int("retry-count"),
		})
		if err != nil {
			return fmt.Errorf("cp: submit %s -> %s: %w", task.src, task.dst, err)
		}
		fmt.Println(job.ID)
	}
	return nil
}

func serverJobCommand() *cli.Command {
	return &cli.Command{
		Name:      "job",
		Usage:     "Manage copy jobs on --server",
		UsageText: "bbb --server URL job <list|get|tasks|cancel|delete>",
		Commands: []*cli.Command{
			{
				Name:  "list",
				Usage: "List jobs",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "state", Usage: "Filter by job `state`"},
					&cli.IntFlag{Name: "limit", Usage: "Maximum jobs to return", Value: 100},
				},
				Action: cmdJobList,
			},
			{
				Name:      "get",
				Usage:     "Get a job",
				UsageText: "bbb --server URL job get ID",
				Action:    cmdJobGet,
			},
			{
				Name:      "tasks",
				Usage:     "List a job's file tasks",
				UsageText: "bbb --server URL job tasks [--state STATE] [--limit N] [--offset N] ID",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "state", Usage: "Filter by task `state`"},
					&cli.IntFlag{Name: "limit", Usage: "Maximum tasks to return", Value: 100},
					&cli.IntFlag{Name: "offset", Usage: "Number of tasks to skip"},
				},
				Action: cmdJobTasks,
			},
			{
				Name:      "cancel",
				Usage:     "Cancel a job",
				UsageText: "bbb --server URL job cancel ID",
				Action:    cmdJobCancel,
			},
			{
				Name:      "delete",
				Usage:     "Delete a terminal job and its tasks",
				UsageText: "bbb --server URL job delete ID",
				Action:    cmdJobDelete,
			},
		},
	}
}

func writeCommandJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func requireJobID(c *cli.Command, command string) (string, error) {
	if c.Args().Len() != 1 {
		return "", fmt.Errorf("job %s: need exactly one job ID", command)
	}
	return c.Args().Get(0), nil
}

func cmdJobList(ctx context.Context, c *cli.Command) error {
	if c.Args().Len() != 0 {
		return errors.New("job list: does not accept positional arguments")
	}
	client, err := remoteServerClient(c, "job list")
	if err != nil {
		return err
	}
	jobs, err := client.ListJobs(ctx, c.String("state"), c.Int("limit"))
	if err != nil {
		return err
	}
	return writeCommandJSON(jobs)
}

func cmdJobGet(ctx context.Context, c *cli.Command) error {
	id, err := requireJobID(c, "get")
	if err != nil {
		return err
	}
	client, err := remoteServerClient(c, "job get")
	if err != nil {
		return err
	}
	job, err := client.GetJob(ctx, id)
	if err != nil {
		return err
	}
	return writeCommandJSON(job)
}

func cmdJobTasks(ctx context.Context, c *cli.Command) error {
	id, err := requireJobID(c, "tasks")
	if err != nil {
		return err
	}
	client, err := remoteServerClient(c, "job tasks")
	if err != nil {
		return err
	}
	tasks, err := client.ListTasks(ctx, id, c.String("state"), c.Int("limit"), c.Int("offset"))
	if err != nil {
		return err
	}
	return writeCommandJSON(tasks)
}

func cmdJobCancel(ctx context.Context, c *cli.Command) error {
	id, err := requireJobID(c, "cancel")
	if err != nil {
		return err
	}
	client, err := remoteServerClient(c, "job cancel")
	if err != nil {
		return err
	}
	job, err := client.CancelJob(ctx, id)
	if err != nil {
		return err
	}
	return writeCommandJSON(job)
}

func cmdJobDelete(ctx context.Context, c *cli.Command) error {
	id, err := requireJobID(c, "delete")
	if err != nil {
		return err
	}
	client, err := remoteServerClient(c, "job delete")
	if err != nil {
		return err
	}
	return client.DeleteJob(ctx, id)
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

	// Surface a scheduler failure instead of leaving a process that still
	// answers /healthz but no longer expands, leases or reconciles anything.
	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- srv.Run(runCtx)
	}()

	var (
		runErr    error
		runExited bool
	)
	select {
	case <-ctx.Done():
	case runErr = <-serveErr:
	case runErr = <-runErrCh:
		runExited = true
	}

	cancel()
	if !runExited {
		if err := <-runErrCh; runErr == nil {
			runErr = err
		}
	}
	if errors.Is(runErr, context.Canceled) {
		runErr = nil
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer shutdownCancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		slog.Warn("bbb server: shutdown failed", "error", err)
	}
	return runErr
}
