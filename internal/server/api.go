package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Options configures the leader server.
type Options struct {
	// Token, when set, is the bearer token required by every API call.
	Token string
	// Workers is the number of tasks the leader itself copies concurrently.
	// Zero disables the built-in worker so the leader only schedules.
	Workers int
	// Concurrency is the default per file concurrency used when a job does not
	// request one.
	Concurrency int
	// LeaseDuration is how long a task lease is valid without progress report.
	LeaseDuration time.Duration
	// PollInterval is how often the scheduler loops run.
	PollInterval time.Duration
	// WorkerTTL is how long a worker is listed after its last heartbeat.
	WorkerTTL time.Duration
	// WorkerID identifies the leader's built-in worker.
	WorkerID string
	// Version is reported by the leader worker and /healthz.
	Version string
}

func (o *Options) setDefaults() {
	if o.LeaseDuration <= 0 {
		o.LeaseDuration = 60 * time.Second
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.WorkerTTL <= 0 {
		o.WorkerTTL = 5 * time.Minute
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 1
	}
	if o.WorkerID == "" {
		o.WorkerID = "leader"
	}
}

// Server is the bbb leader: it owns the database, exposes the REST API and
// schedules tasks to the cluster workers.
type Server struct {
	store  *Store
	runner Runner
	opts   Options
}

// New creates a leader server on top of store.
func New(store *Store, runner Runner, opts Options) *Server {
	opts.setDefaults()
	return &Server{store: store, runner: runner, opts: opts}
}

// Store exposes the underlying store.
func (s *Server) Store() *Store { return s.store }

func newID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Run starts the background schedulers and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.store.ResetExpandingJobs(ctx); err != nil {
		return err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.schedulerLoop(ctx)
	}()

	if s.opts.Workers > 0 {
		pool := NewPool(&StoreSource{Store: s.store, Lease: s.opts.LeaseDuration}, s.runner, PoolOptions{
			WorkerID:          s.opts.WorkerID,
			Mode:              ModeLeader,
			Version:           s.opts.Version,
			Slots:             s.opts.Workers,
			PollInterval:      s.opts.PollInterval,
			ProgressInterval:  s.opts.LeaseDuration / 3,
			HeartbeatInterval: s.opts.LeaseDuration / 3,
		})
		_ = pool.Run(ctx)
	}

	<-done
	return ctx.Err()
}

func (s *Server) schedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(s.opts.PollInterval)
	defer ticker.Stop()
	for {
		s.scheduleOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) scheduleOnce(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	for {
		job, ok, err := s.store.NextJobToExpand(ctx)
		if err != nil {
			slog.Warn("bbb server: pick job failed", "error", err)
			break
		}
		if !ok {
			break
		}
		s.expandJob(ctx, job)
	}
	if _, err := s.store.RequeueExpiredLeases(ctx); err != nil {
		slog.Warn("bbb server: requeue expired leases failed", "error", err)
	}
	if err := s.store.ReconcileJobs(ctx); err != nil {
		slog.Warn("bbb server: reconcile jobs failed", "error", err)
	}
	if err := s.store.PruneWorkers(ctx, 24*time.Hour); err != nil {
		slog.Warn("bbb server: prune workers failed", "error", err)
	}
}

var errJobCancelled = errors.New("job cancelled")

const expandBatchSize = 500

func (s *Server) expandJob(ctx context.Context, job Job) {
	slog.Info("bbb server: expanding job", "job", job.ID, "src", job.Src, "dst", job.Dst)

	batch := make([]Task, 0, expandBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := s.store.AddTasks(ctx, job.ID, batch); err != nil {
			return err
		}
		batch = batch[:0]
		current, err := s.store.GetJob(ctx, job.ID)
		if err != nil {
			return err
		}
		if current.CancelRequested {
			return errJobCancelled
		}
		return nil
	}

	err := s.runner.Expand(ctx, job.Src, job.Dst, func(file FileTask) error {
		batch = append(batch, Task{Src: file.Src, Dst: file.Dst, Size: file.Size})
		if len(batch) >= expandBatchSize {
			return flush()
		}
		return nil
	})
	if err == nil {
		err = flush()
	}

	cancelled := errors.Is(err, errJobCancelled)
	if cancelled || errors.Is(err, context.Canceled) {
		err = nil
	}
	if ferr := s.store.FinishExpansion(ctx, job.ID, err); ferr != nil {
		slog.Warn("bbb server: finish expansion failed", "job", job.ID, "error", ferr)
	}
	if cancelled {
		if _, cerr := s.store.CancelJob(ctx, job.ID); cerr != nil {
			slog.Warn("bbb server: cancel job failed", "job", job.ID, "error", cerr)
		}
	}
}

// Handler returns the REST API handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": s.opts.Version})
	})

	mux.HandleFunc("POST /api/v1/jobs", s.handleCreateJob)
	mux.HandleFunc("GET /api/v1/jobs", s.handleListJobs)
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.handleGetJob)
	mux.HandleFunc("DELETE /api/v1/jobs/{id}", s.handleDeleteJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", s.handleCancelJob)
	mux.HandleFunc("GET /api/v1/jobs/{id}/tasks", s.handleListTasks)
	mux.HandleFunc("GET /api/v1/workers", s.handleListWorkers)

	// cluster endpoints used by followers
	mux.HandleFunc("POST /api/v1/cluster/claim", s.handleClaim)
	mux.HandleFunc("POST /api/v1/cluster/tasks/{id}/progress", s.handleTaskProgress)
	mux.HandleFunc("POST /api/v1/cluster/tasks/{id}/complete", s.handleTaskComplete)
	mux.HandleFunc("POST /api/v1/cluster/workers/heartbeat", s.handleWorkerHeartbeat)

	return s.withAuth(mux)
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Token == "" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.opts.Token)) != 1 {
			writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.Debug("bbb server: write response failed", "error", err)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

const maxRequestBody = 1 << 20

func decodeJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid request body: %w", err))
		return false
	}
	return true
}

// CreateJobRequest is the body of POST /api/v1/jobs.
type CreateJobRequest struct {
	Src         string `json:"src"`
	Dst         string `json:"dst"`
	Overwrite   bool   `json:"overwrite,omitempty"`
	Concurrency int    `json:"concurrency,omitempty"`
	RetryCount  int    `json:"retry_count,omitempty"`
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req CreateJobRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Src = strings.TrimSpace(req.Src)
	req.Dst = strings.TrimSpace(req.Dst)
	if req.Src == "" || req.Dst == "" {
		writeError(w, http.StatusBadRequest, errors.New("src and dst are required"))
		return
	}
	if req.Concurrency < 0 || req.RetryCount < 0 {
		writeError(w, http.StatusBadRequest, errors.New("concurrency and retry_count must not be negative"))
		return
	}
	if req.Concurrency == 0 {
		req.Concurrency = s.opts.Concurrency
	}

	id, err := newID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	job, err := s.store.CreateJob(r.Context(), Job{
		ID:          id,
		Src:         req.Src,
		Dst:         req.Dst,
		Overwrite:   req.Overwrite,
		Concurrency: req.Concurrency,
		RetryCount:  req.RetryCount,
	})
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	jobs, err := s.store.ListJobs(r.Context(), r.URL.Query().Get("state"), limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.GetJob(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteJob(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeError(w, http.StatusConflict, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	job, err := s.store.CancelJob(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) handleListTasks(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	if _, err := s.store.GetJob(r.Context(), r.PathValue("id")); err != nil {
		writeStoreError(w, err)
		return
	}
	tasks, err := s.store.ListTasks(r.Context(), r.PathValue("id"), query.Get("state"), limit, offset)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (s *Server) handleListWorkers(w http.ResponseWriter, r *http.Request) {
	workers, err := s.store.ListWorkers(r.Context(), s.opts.WorkerTTL)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"workers": workers})
}

// ClaimRequest is the body of POST /api/v1/cluster/claim.
type ClaimRequest struct {
	WorkerID string `json:"worker_id"`
	Limit    int    `json:"limit"`
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	var req ClaimRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.WorkerID == "" {
		writeError(w, http.StatusBadRequest, errors.New("worker_id is required"))
		return
	}
	leases, err := s.store.ClaimTasks(r.Context(), req.WorkerID, req.Limit, s.opts.LeaseDuration)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if leases == nil {
		leases = []Lease{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"leases": leases})
}

// ProgressRequest is the body of POST /api/v1/cluster/tasks/{id}/progress.
type ProgressRequest struct {
	WorkerID    string `json:"worker_id"`
	CopiedBytes int64  `json:"copied_bytes"`
}

func (s *Server) handleTaskProgress(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid task id"))
		return
	}
	var req ProgressRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	abort, err := s.store.TaskProgress(r.Context(), req.WorkerID, taskID, req.CopiedBytes, s.opts.LeaseDuration)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"abort": abort})
}

// CompleteRequest is the body of POST /api/v1/cluster/tasks/{id}/complete.
type CompleteRequest struct {
	WorkerID    string `json:"worker_id"`
	State       string `json:"state"`
	CopiedBytes int64  `json:"copied_bytes"`
	Error       string `json:"error,omitempty"`
}

func (s *Server) handleTaskComplete(w http.ResponseWriter, r *http.Request) {
	taskID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid task id"))
		return
	}
	var req CompleteRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	switch req.State {
	case TaskSucceeded, TaskFailed, TaskCancelled:
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid task state %q", req.State))
		return
	}
	if err := s.store.CompleteTask(r.Context(), req.WorkerID, taskID, req.State, req.CopiedBytes, req.Error); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleWorkerHeartbeat(w http.ResponseWriter, r *http.Request) {
	var worker Worker
	if !decodeJSON(w, r, &worker) {
		return
	}
	if worker.ID == "" {
		writeError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if worker.Mode != ModeLeader {
		worker.Mode = ModeFollower
	}
	if err := s.store.UpsertWorker(r.Context(), worker); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
