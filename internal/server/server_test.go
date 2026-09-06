package server

import (
	"context"
	"errors"
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

func TestExpiredLeaseOfCancelledJobIsNotRequeued(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst"}); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if _, _, err := store.NextJobToExpand(ctx); err != nil {
		t.Fatalf("next job: %v", err)
	}
	if err := store.AddTasks(ctx, "job1", []Task{{Src: "az://a/src/f", Dst: "az://a/dst/f", Size: 5}}); err != nil {
		t.Fatalf("add tasks: %v", err)
	}
	if err := store.FinishExpansion(ctx, "job1", nil); err != nil {
		t.Fatalf("finish expansion: %v", err)
	}

	// a worker leases the task with an already expired lease, then dies
	if leases, err := store.ClaimTasks(ctx, "w1", 10, -time.Second); err != nil || len(leases) != 1 {
		t.Fatalf("claim: %v %d", err, len(leases))
	}
	if _, err := store.CancelJob(ctx, "job1"); err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	if _, err := store.RequeueExpiredLeases(ctx); err != nil {
		t.Fatalf("requeue: %v", err)
	}

	tasks, err := store.ListTasks(ctx, "job1", "", 10, 0)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("list tasks: %v %d", err, len(tasks))
	}
	// requeueing as pending would strand the job: claims skip cancelled jobs
	if tasks[0].State != TaskCancelled {
		t.Fatalf("task state = %s, want %s", tasks[0].State, TaskCancelled)
	}
	if err := store.ReconcileJobs(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	job, err := store.GetJob(ctx, "job1")
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.State != JobCancelled {
		t.Fatalf("job state = %s, want %s", job.State, JobCancelled)
	}
}

func TestFailedTaskAfterCancelIsNotRequeued(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst", RetryCount: 5}); err != nil {
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
		t.Fatalf("claim: %v %d", err, len(leases))
	}

	// the job is cancelled while the worker is still finishing with an error
	if _, err := store.CancelJob(ctx, "job1"); err != nil {
		t.Fatalf("cancel job: %v", err)
	}
	if err := store.CompleteTask(ctx, "w1", leases[0].Task.ID, TaskFailed, 0, "boom"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	tasks, err := store.ListTasks(ctx, "job1", "", 10, 0)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("list tasks: %v %d", err, len(tasks))
	}
	if tasks[0].State != TaskCancelled {
		t.Fatalf("task state = %s, want %s", tasks[0].State, TaskCancelled)
	}
	if err := store.ReconcileJobs(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	job, err := store.GetJob(ctx, "job1")
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.State != JobCancelled {
		t.Fatalf("job state = %s, want %s", job.State, JobCancelled)
	}
}

func TestAddTasksTotalsCountOnlyInsertedRows(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst"}); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if _, _, err := store.NextJobToExpand(ctx); err != nil {
		t.Fatalf("next job: %v", err)
	}
	if err := store.AddTasks(ctx, "job1", []Task{
		{Src: "az://a/src/f1", Dst: "az://a/dst/f1", Size: 10},
		{Src: "az://a/src/f2", Dst: "az://a/dst/f2", Size: 20},
	}); err != nil {
		t.Fatalf("add tasks: %v", err)
	}
	job, err := store.GetJob(ctx, "job1")
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.TotalTasks != 2 || job.TotalBytes != 30 {
		t.Fatalf("after first batch: %d tasks, %d bytes", job.TotalTasks, job.TotalBytes)
	}

	// re-emitting a known file (expansion is idempotent) must not double count
	if err := store.AddTasks(ctx, "job1", []Task{
		{Src: "az://a/src/f2", Dst: "az://a/dst/f2", Size: 20},
		{Src: "az://a/src/f3", Dst: "az://a/dst/f3", Size: 5},
	}); err != nil {
		t.Fatalf("add tasks: %v", err)
	}
	job, err = store.GetJob(ctx, "job1")
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.TotalTasks != 3 || job.TotalBytes != 35 {
		t.Fatalf("after second batch: %d tasks, %d bytes", job.TotalTasks, job.TotalBytes)
	}
}

func TestProgressIntervalFollowsLeaderLease(t *testing.T) {
	pool := NewPool(nil, nil, PoolOptions{ProgressInterval: 20 * time.Second})

	// without a lease expiry the worker-local interval is used
	if got := pool.progressInterval(Lease{}); got != 20*time.Second {
		t.Fatalf("no expiry: got %s", got)
	}
	// a shorter leader lease must win, otherwise the lease expires mid copy
	got := pool.progressInterval(Lease{Expires: time.Now().Add(3 * time.Second)})
	if got > 1100*time.Millisecond || got < 500*time.Millisecond {
		t.Fatalf("short lease: got %s, want about 1s", got)
	}
	// an expired or skewed lease must not turn into a tight loop
	if got := pool.progressInterval(Lease{Expires: time.Now().Add(-time.Minute)}); got != minProgressInterval {
		t.Fatalf("expired lease: got %s", got)
	}
}

// flakySource fails the first failures Complete calls, then succeeds.
type flakySource struct {
	failures int
	calls    int
}

func (f *flakySource) Claim(context.Context, string, int) ([]Lease, error) { return nil, nil }

func (f *flakySource) Progress(context.Context, string, int64, int64) (bool, error) {
	return false, nil
}

func (f *flakySource) Complete(_ context.Context, _ string, _ int64, _ string, _ int64, _ string) error {
	f.calls++
	if f.calls <= f.failures {
		return errors.New("transient")
	}
	return nil
}

func (f *flakySource) Heartbeat(context.Context, Worker) error { return nil }

func TestCompleteIsRetriedAfterTransientFailure(t *testing.T) {
	source := &flakySource{failures: 2}
	pool := NewPool(source, newFakeRunner(), PoolOptions{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.completeWithRetry(ctx, Lease{Task: Task{ID: 1}}, TaskSucceeded, 10, ""); err != nil {
		t.Fatalf("complete: %v", err)
	}
	// losing the report would leave the task leased and copy the file twice
	if source.calls != 3 {
		t.Fatalf("Complete called %d times, want 3", source.calls)
	}
}

func TestCrashRequeueIsCappedByRetryCount(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// retry_count 1 => one crash is retried, the second exhausts the budget
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

	// first worker claims and crashes (lease already expired)
	if leases, err := store.ClaimTasks(ctx, "w1", 1, -time.Second); err != nil || len(leases) != 1 {
		t.Fatalf("claim: %v %d", err, len(leases))
	}
	requeued, err := store.RequeueExpiredLeases(ctx)
	if err != nil || requeued != 1 {
		t.Fatalf("first requeue = %d, %v", requeued, err)
	}

	// second worker claims and crashes as well, exhausting the budget
	if leases, err := store.ClaimTasks(ctx, "w2", 1, -time.Second); err != nil || len(leases) != 1 {
		t.Fatalf("re-claim: %v %d", err, len(leases))
	}
	requeued, err = store.RequeueExpiredLeases(ctx)
	if err != nil {
		t.Fatalf("second requeue: %v", err)
	}
	// handing the task out again would crash a third worker, and so on forever
	if requeued != 0 {
		t.Fatalf("second requeue = %d, want 0", requeued)
	}

	tasks, err := store.ListTasks(ctx, "job1", "", 10, 0)
	if err != nil || len(tasks) != 1 {
		t.Fatalf("list tasks: %v %d", err, len(tasks))
	}
	if tasks[0].State != TaskFailed || tasks[0].Error != "lease expired" {
		t.Fatalf("task = %+v", tasks[0])
	}
	if leases, err := store.ClaimTasks(ctx, "w3", 1, time.Minute); err != nil || len(leases) != 0 {
		t.Fatalf("exhausted task was claimed again: %v %d", err, len(leases))
	}
	if err := store.ReconcileJobs(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	job, err := store.GetJob(ctx, "job1")
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.State != JobFailed {
		t.Fatalf("job state = %s, want %s", job.State, JobFailed)
	}
}

func TestRetryAfterCrashMayOverwritePartialOutput(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// the job itself did not ask for --overwrite
	if _, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst", RetryCount: 3}); err != nil {
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

	leases, err := store.ClaimTasks(ctx, "w1", 1, -time.Second)
	if err != nil || len(leases) != 1 {
		t.Fatalf("claim: %v %d", err, len(leases))
	}
	if leases[0].Overwrite {
		t.Fatal("first attempt must honour the job's overwrite setting")
	}

	// the worker dies mid copy, leaving partial data at the destination
	if _, err := store.RequeueExpiredLeases(ctx); err != nil {
		t.Fatalf("requeue: %v", err)
	}
	leases, err = store.ClaimTasks(ctx, "w2", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("re-claim: %v %d", err, len(leases))
	}
	// without this the retry fails forever: the destination already exists
	if !leases[0].Overwrite {
		t.Fatal("retry after a crash must be allowed to overwrite its own partial output")
	}
}

func TestRetryAfterFailureWithoutCopiedBytesKeepsOverwriteOff(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	if _, err := store.CreateJob(ctx, Job{ID: "job1", Src: "az://a/src", Dst: "az://a/dst", RetryCount: 3}); err != nil {
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
		t.Fatalf("claim: %v %d", err, len(leases))
	}
	// an overwrite=false job whose destination already exists fails before
	// copying anything, so pre-existing data must stay protected on retry
	if err := store.CompleteTask(ctx, "w1", leases[0].Task.ID, TaskFailed, 0, "cp: destination exists"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	leases, err = store.ClaimTasks(ctx, "w1", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("retry claim: %v %d", err, len(leases))
	}
	if leases[0].Overwrite {
		t.Fatal("retry must not clobber a pre-existing destination")
	}

	// a failure reported after bytes were copied does force an overwrite
	if err := store.CompleteTask(ctx, "w1", leases[0].Task.ID, TaskFailed, 512, "connection reset"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	leases, err = store.ClaimTasks(ctx, "w1", 1, time.Minute)
	if err != nil || len(leases) != 1 {
		t.Fatalf("retry claim: %v %d", err, len(leases))
	}
	if !leases[0].Overwrite {
		t.Fatal("retry after a partial write must be allowed to overwrite")
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
