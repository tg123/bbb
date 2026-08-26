package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu      sync.Mutex
	files   []FileTask
	copied  map[string]string
	block   chan struct{}
	failOn  map[string]error
	expandE error
}

func newFakeRunner(files ...FileTask) *fakeRunner {
	return &fakeRunner{files: files, copied: map[string]string{}, failOn: map[string]error{}}
}

func (r *fakeRunner) Expand(_ context.Context, _, _ string, emit func(FileTask) error) error {
	if r.expandE != nil {
		return r.expandE
	}
	for _, file := range r.files {
		if err := emit(file); err != nil {
			return err
		}
	}
	return nil
}

func (r *fakeRunner) Copy(ctx context.Context, src, dst string, _ CopyOptions, onBytes func(int64)) error {
	r.mu.Lock()
	block := r.block
	err := r.failOn[src]
	r.mu.Unlock()

	if err != nil {
		return err
	}
	onBytes(10)
	if block != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-block:
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.copied[src] = dst
	return nil
}

func (r *fakeRunner) copiedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.copied)
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := OpenStore(filepath.Join(t.TempDir(), "bbb.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func newTestServer(t *testing.T, runner Runner, opts Options) (*Server, *httptest.Server) {
	t.Helper()
	store := newTestStore(t)
	if opts.LeaseDuration == 0 {
		opts.LeaseDuration = 3 * time.Second
	}
	if opts.PollInterval == 0 {
		opts.PollInterval = 10 * time.Millisecond
	}
	srv := New(store, runner, opts)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return srv, httpSrv
}

func createJob(t *testing.T, base, token string, req CreateJobRequest) Job {
	t.Helper()
	var job Job
	api := NewClient(base, token)
	if err := api.do(context.Background(), http.MethodPost, "/api/v1/jobs", req, &job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	return job
}

func getJob(t *testing.T, base, token, id string) Job {
	t.Helper()
	var job Job
	if err := NewClient(base, token).do(context.Background(), http.MethodGet, "/api/v1/jobs/"+id, nil, &job); err != nil {
		t.Fatalf("get job: %v", err)
	}
	return job
}

func waitForJob(t *testing.T, base, token, id string, want string) Job {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var job Job
	for time.Now().Before(deadline) {
		job = getJob(t, base, token, id)
		if job.State == want {
			return job
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("job %s state = %s, want %s", id, job.State, want)
	return job
}

func TestJobLifecycleWithLeaderWorker(t *testing.T) {
	runner := newFakeRunner(
		FileTask{Src: "az://acct/src/a", Dst: "az://acct/dst/a", Size: 10},
		FileTask{Src: "az://acct/src/b", Dst: "az://acct/dst/b", Size: 10},
	)
	_, httpSrv := newTestServer(t, runner, Options{Workers: 2})

	job := createJob(t, httpSrv.URL, "", CreateJobRequest{
		Src: "az://acct/src", Dst: "az://acct/dst", Overwrite: true,
	})
	if job.State != JobPending {
		t.Fatalf("new job state = %s", job.State)
	}

	done := waitForJob(t, httpSrv.URL, "", job.ID, JobSucceeded)
	if done.TotalTasks != 2 || done.DoneTasks != 2 {
		t.Fatalf("job counters = %+v", done)
	}
	if done.CopiedBytes != 20 || done.TotalBytes != 20 {
		t.Fatalf("job bytes = %d/%d", done.CopiedBytes, done.TotalBytes)
	}
	if runner.copiedCount() != 2 {
		t.Fatalf("copied %d files", runner.copiedCount())
	}

	var tasks struct {
		Tasks []Task `json:"tasks"`
	}
	if err := NewClient(httpSrv.URL, "").do(context.Background(), http.MethodGet, "/api/v1/jobs/"+job.ID+"/tasks", nil, &tasks); err != nil {
		t.Fatalf("list tasks: %v", err)
	}
	if len(tasks.Tasks) != 2 {
		t.Fatalf("tasks = %d", len(tasks.Tasks))
	}
	for _, task := range tasks.Tasks {
		if task.State != TaskSucceeded {
			t.Fatalf("task %d state = %s", task.ID, task.State)
		}
	}
}

func TestJobFailurePropagates(t *testing.T) {
	runner := newFakeRunner(
		FileTask{Src: "az://acct/src/a", Dst: "az://acct/dst/a", Size: 10},
	)
	runner.failOn["az://acct/src/a"] = context.DeadlineExceeded
	_, httpSrv := newTestServer(t, runner, Options{Workers: 1})

	job := createJob(t, httpSrv.URL, "", CreateJobRequest{Src: "az://acct/src", Dst: "az://acct/dst"})
	done := waitForJob(t, httpSrv.URL, "", job.ID, JobFailed)
	if done.FailedTasks != 1 || done.Error == "" {
		t.Fatalf("job = %+v", done)
	}
}

func TestCancelRunningJob(t *testing.T) {
	runner := newFakeRunner(
		FileTask{Src: "az://acct/src/a", Dst: "az://acct/dst/a", Size: 10},
		FileTask{Src: "az://acct/src/b", Dst: "az://acct/dst/b", Size: 10},
	)
	runner.block = make(chan struct{})
	_, httpSrv := newTestServer(t, runner, Options{Workers: 1, LeaseDuration: 300 * time.Millisecond})

	job := createJob(t, httpSrv.URL, "", CreateJobRequest{Src: "az://acct/src", Dst: "az://acct/dst"})
	waitForJob(t, httpSrv.URL, "", job.ID, JobRunning)

	var cancelled Job
	if err := NewClient(httpSrv.URL, "").do(context.Background(), http.MethodPost, "/api/v1/jobs/"+job.ID+"/cancel", nil, &cancelled); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if !cancelled.CancelRequested {
		t.Fatal("cancel_requested not set")
	}

	waitForJob(t, httpSrv.URL, "", job.ID, JobCancelled)
	close(runner.block)

	// terminal jobs can be deleted
	if err := NewClient(httpSrv.URL, "").do(context.Background(), http.MethodDelete, "/api/v1/jobs/"+job.ID, nil, nil); err != nil {
		t.Fatalf("delete job: %v", err)
	}
	if err := NewClient(httpSrv.URL, "").do(context.Background(), http.MethodGet, "/api/v1/jobs/"+job.ID, nil, &cancelled); err == nil {
		t.Fatal("expected 404 after delete")
	}
}

func TestCancelPendingJob(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	if _, err := store.CreateJob(ctx, Job{ID: "pending", Src: "src", Dst: "dst"}); err != nil {
		t.Fatalf("create job: %v", err)
	}

	job, err := store.CancelJob(ctx, "pending")
	if err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	if job.State != JobCancelled || !job.CancelRequested || job.FinishedAt == nil {
		t.Fatalf("cancelled job = %+v", job)
	}
	if _, ok, err := store.NextJobToExpand(ctx); err != nil || ok {
		t.Fatalf("cancelled job selected for expansion: ok=%v err=%v", ok, err)
	}
}

func TestFollowerCopiesTasks(t *testing.T) {
	runner := newFakeRunner(
		FileTask{Src: "az://acct/src/a", Dst: "az://acct/dst/a", Size: 10},
		FileTask{Src: "az://acct/src/b", Dst: "az://acct/dst/b", Size: 10},
	)
	// leader schedules only, all copying happens on the follower
	_, httpSrv := newTestServer(t, runner, Options{Workers: 0, Token: "secret"})

	followerRunner := newFakeRunner()
	pool := NewPool(NewClient(httpSrv.URL, "secret"), followerRunner, PoolOptions{
		WorkerID:          "follower-1",
		Mode:              ModeFollower,
		Slots:             2,
		PollInterval:      10 * time.Millisecond,
		ProgressInterval:  50 * time.Millisecond,
		HeartbeatInterval: 50 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = pool.Run(ctx) }()

	job := createJob(t, httpSrv.URL, "secret", CreateJobRequest{Src: "az://acct/src", Dst: "az://acct/dst"})
	waitForJob(t, httpSrv.URL, "secret", job.ID, JobSucceeded)

	if followerRunner.copiedCount() != 2 {
		t.Fatalf("follower copied %d files", followerRunner.copiedCount())
	}
	if runner.copiedCount() != 0 {
		t.Fatalf("leader copied %d files, want 0", runner.copiedCount())
	}

	var workers struct {
		Workers []Worker `json:"workers"`
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := NewClient(httpSrv.URL, "secret").do(ctx, http.MethodGet, "/api/v1/workers", nil, &workers); err != nil {
			t.Fatalf("list workers: %v", err)
		}
		if len(workers.Workers) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(workers.Workers) != 1 || workers.Workers[0].ID != "follower-1" {
		t.Fatalf("workers = %+v", workers.Workers)
	}
}

func TestAuthRequired(t *testing.T) {
	_, httpSrv := newTestServer(t, newFakeRunner(), Options{Token: "secret"})

	if err := NewClient(httpSrv.URL, "").do(context.Background(), http.MethodGet, "/api/v1/jobs", nil, nil); err == nil {
		t.Fatal("expected unauthorized error")
	}
	if err := NewClient(httpSrv.URL, "wrong").do(context.Background(), http.MethodGet, "/api/v1/jobs", nil, nil); err == nil {
		t.Fatal("expected unauthorized error for wrong token")
	}
	if err := NewClient(httpSrv.URL, "").do(context.Background(), http.MethodGet, "/healthz", nil, nil); err != nil {
		t.Fatalf("healthz should not require auth: %v", err)
	}
	if err := NewClient(httpSrv.URL, "secret").do(context.Background(), http.MethodGet, "/api/v1/jobs", nil, nil); err != nil {
		t.Fatalf("authorized request failed: %v", err)
	}
}

func TestExpiredLeaseIsRequeued(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	job, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst", RetryCount: 5})
	if err != nil {
		t.Fatalf("create job: %v", err)
	}
	if _, _, err := store.NextJobToExpand(ctx); err != nil {
		t.Fatalf("next job: %v", err)
	}
	if err := store.AddTasks(ctx, job.ID, []Task{{Src: "az://a/src/f", Dst: "az://a/dst/f", Size: 5}}); err != nil {
		t.Fatalf("add tasks: %v", err)
	}
	if err := store.FinishExpansion(ctx, job.ID, nil); err != nil {
		t.Fatalf("finish expansion: %v", err)
	}

	leases, err := store.ClaimTasks(ctx, "w1", 10, -time.Second) // already expired lease
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim: %v %d", err, len(leases))
	}

	requeued, err := store.RequeueExpiredLeases(ctx)
	if err != nil || requeued != 1 {
		t.Fatalf("requeue = %d, %v", requeued, err)
	}

	// the worker that lost its lease must be told to abort
	abort, err := store.TaskProgress(ctx, "w1", leases[0].Task.ID, 1, time.Minute)
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if !abort {
		t.Fatal("expected abort after losing the lease")
	}

	leases, err = store.ClaimTasks(ctx, "w2", 10, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("re-claim: %v %d", err, len(leases))
	}
	if leases[0].Task.Attempts != 2 {
		t.Fatalf("attempts = %d", leases[0].Task.Attempts)
	}
}

func TestFailedTaskIsRetried(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst", RetryCount: 1}); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if _, _, err := store.NextJobToExpand(ctx); err != nil {
		t.Fatalf("next job: %v", err)
	}
	if err := store.AddTasks(ctx, "job1", []Task{{Src: "az://a/src/f", Dst: "az://a/dst/f"}}); err != nil {
		t.Fatalf("add tasks: %v", err)
	}
	if err := store.FinishExpansion(ctx, "job1", nil); err != nil {
		t.Fatalf("finish expansion: %v", err)
	}

	leases, err := store.ClaimTasks(ctx, "w1", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim: %v", err)
	}
	if err := store.CompleteTask(ctx, "w1", leases[0].Task.ID, TaskFailed, 0, "boom"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// first failure is retried
	leases, err = store.ClaimTasks(ctx, "w1", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("retry claim: %v %d", err, len(leases))
	}
	if err := store.CompleteTask(ctx, "w1", leases[0].Task.ID, TaskFailed, 0, "boom"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// retries exhausted, task stays failed and the job fails
	leases, err = store.ClaimTasks(ctx, "w1", 1, time.Minute)
	if err != nil || len(leases) != 0 {
		t.Fatalf("unexpected extra claim: %v %d", err, len(leases))
	}
	if err := store.ReconcileJobs(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	job, err := store.GetJob(ctx, "job1")
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.State != JobFailed || job.Error != "boom" {
		t.Fatalf("job = %+v", job)
	}
}
