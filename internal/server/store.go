package server

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // sqlite driver (pure go, no cgo)
)

//go:embed schema.sql
var schemaSQL string

// ErrNotFound is returned when a job or task does not exist.
var ErrNotFound = errors.New("not found")

// Store persists jobs, tasks and cluster workers in a SQLite database.
type Store struct {
	db *sql.DB
}

// OpenStore opens (and creates when missing) the server database at path.
// Use ":memory:" for an ephemeral database.
func OpenStore(path string) (*Store, error) {
	dsn := path
	if path != ":memory:" {
		dsn = path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// SQLite allows a single writer only; serializing access keeps the
	// scheduler simple and avoids SQLITE_BUSY retries.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying database.
func (s *Store) Close() error {
	return s.db.Close()
}

func unixMilli(t time.Time) int64 {
	return t.UTC().UnixMilli()
}

func fromUnixMilli(ms int64) time.Time {
	return time.UnixMilli(ms).UTC()
}

func fromNullMilli(ms sql.NullInt64) *time.Time {
	if !ms.Valid {
		return nil
	}
	t := fromUnixMilli(ms.Int64)
	return &t
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateJob inserts a new pending job.
func (s *Store) CreateJob(ctx context.Context, job Job) (Job, error) {
	now := time.Now().UTC()
	job.State = JobPending
	job.CreatedAt = now
	job.UpdatedAt = now
	_, err := s.db.ExecContext(ctx, `
INSERT INTO jobs (id, src, dst, state, overwrite, concurrency, retry_count, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		job.ID, job.Src, job.Dst, job.State, boolToInt(job.Overwrite), job.Concurrency, job.RetryCount,
		unixMilli(now), unixMilli(now))
	if err != nil {
		return Job{}, err
	}
	return job, nil
}

const jobColumns = `id, src, dst, state, overwrite, concurrency, retry_count, cancel_requested,
total_tasks, done_tasks, failed_tasks, total_bytes, copied_bytes, error, created_at, updated_at, started_at, finished_at`

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var (
		job               Job
		overwrite, cancel int
		created, updated  int64
		started, finished sql.NullInt64
	)
	err := row.Scan(&job.ID, &job.Src, &job.Dst, &job.State, &overwrite, &job.Concurrency, &job.RetryCount,
		&cancel, &job.TotalTasks, &job.DoneTasks, &job.FailedTasks, &job.TotalBytes, &job.CopiedBytes,
		&job.Error, &created, &updated, &started, &finished)
	if err != nil {
		return Job{}, err
	}
	job.Overwrite = overwrite != 0
	job.CancelRequested = cancel != 0
	job.CreatedAt = fromUnixMilli(created)
	job.UpdatedAt = fromUnixMilli(updated)
	job.StartedAt = fromNullMilli(started)
	job.FinishedAt = fromNullMilli(finished)
	return job, nil
}

// GetJob returns a single job by id.
func (s *Store) GetJob(ctx context.Context, id string) (Job, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id)
	job, err := scanJob(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return job, err
}

// ListJobs returns jobs, newest first, optionally filtered by state.
func (s *Store) ListJobs(ctx context.Context, state string, limit int) ([]Job, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `SELECT ` + jobColumns + ` FROM jobs`
	args := []any{}
	if state != "" {
		query += ` WHERE state = ?`
		args = append(args, state)
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	jobs := []Job{}
	for rows.Next() {
		job, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

// DeleteJob removes a job and its tasks. Only terminal jobs can be deleted.
func (s *Store) DeleteJob(ctx context.Context, id string) error {
	job, err := s.GetJob(ctx, id)
	if err != nil {
		return err
	}
	if !JobDone(job.State) {
		return fmt.Errorf("job %s is %s, cancel it first", id, job.State)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM tasks WHERE job_id = ?`, id); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM jobs WHERE id = ?`, id)
	return err
}

// CancelJob requests cancellation of a job. Pending tasks are cancelled
// immediately, running tasks are stopped by their worker on the next progress
// report.
func (s *Store) CancelJob(ctx context.Context, id string) (Job, error) {
	now := unixMilli(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var state string
	if err := tx.QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, id).Scan(&state); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Job{}, ErrNotFound
		}
		return Job{}, err
	}
	if !JobDone(state) {
		if _, err := tx.ExecContext(ctx, `UPDATE tasks SET state = ?, updated_at = ? WHERE job_id = ? AND state = ?`,
			TaskCancelled, now, id, TaskPending); err != nil {
			return Job{}, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET cancel_requested = 1, updated_at = ? WHERE id = ?`, now, id); err != nil {
			return Job{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Job{}, err
	}
	return s.GetJob(ctx, id)
}

const taskColumns = `id, job_id, src, dst, size, state, attempts, copied_bytes, worker_id, error, created_at, updated_at`

func scanTask(row interface{ Scan(...any) error }) (Task, error) {
	var (
		task             Task
		created, updated int64
	)
	err := row.Scan(&task.ID, &task.JobID, &task.Src, &task.Dst, &task.Size, &task.State, &task.Attempts,
		&task.CopiedBytes, &task.WorkerID, &task.Error, &created, &updated)
	if err != nil {
		return Task{}, err
	}
	task.CreatedAt = fromUnixMilli(created)
	task.UpdatedAt = fromUnixMilli(updated)
	return task, nil
}

// ListTasks returns tasks of a job, optionally filtered by state.
func (s *Store) ListTasks(ctx context.Context, jobID, state string, limit, offset int) ([]Task, error) {
	if limit <= 0 || limit > 10000 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	query := `SELECT ` + taskColumns + ` FROM tasks WHERE job_id = ?`
	args := []any{jobID}
	if state != "" {
		query += ` AND state = ?`
		args = append(args, state)
	}
	query += ` ORDER BY id LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	tasks := []Task{}
	for rows.Next() {
		task, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	return tasks, rows.Err()
}

// NextJobToExpand atomically moves one pending job into the expanding state and
// returns it. ok is false when there is nothing to expand.
func (s *Store) NextJobToExpand(ctx context.Context) (job Job, ok bool, err error) {
	now := unixMilli(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	var id string
	err = tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE state = ? ORDER BY created_at LIMIT 1`, JobPending).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, nil
	}
	if err != nil {
		return Job{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state = ?, started_at = COALESCE(started_at, ?), updated_at = ? WHERE id = ?`,
		JobExpanding, now, now, id); err != nil {
		return Job{}, false, err
	}
	row := tx.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs WHERE id = ?`, id)
	job, err = scanJob(row)
	if err != nil {
		return Job{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, false, err
	}
	return job, true, nil
}

// AddTasks appends file level tasks to a job. Duplicated (job, src, dst)
// triples are ignored so expansion is idempotent.
func (s *Store) AddTasks(ctx context.Context, jobID string, tasks []Task) error {
	if len(tasks) == 0 {
		return nil
	}
	now := unixMilli(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO tasks (job_id, src, dst, size, state, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (job_id, src, dst) DO NOTHING`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, task := range tasks {
		if _, err := stmt.ExecContext(ctx, jobID, task.Src, task.Dst, task.Size, TaskPending, now, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE jobs SET total_tasks = (SELECT COUNT(*) FROM tasks WHERE job_id = ?),
                total_bytes = (SELECT COALESCE(SUM(size), 0) FROM tasks WHERE job_id = ?),
                updated_at = ?
WHERE id = ?`, jobID, jobID, now, jobID); err != nil {
		return err
	}
	return tx.Commit()
}

// FinishExpansion moves a job out of the expanding state. When expandErr is not
// nil the job is failed, otherwise it starts running (or completes right away
// when it contains no file).
func (s *Store) FinishExpansion(ctx context.Context, jobID string, expandErr error) error {
	now := unixMilli(time.Now())
	if expandErr != nil {
		_, err := s.db.ExecContext(ctx, `
UPDATE jobs SET state = ?, error = ?, finished_at = ?, updated_at = ? WHERE id = ? AND state = ?`,
			JobFailed, expandErr.Error(), now, now, jobID, JobExpanding)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ? WHERE id = ? AND state = ?`,
		JobRunning, now, jobID, JobExpanding)
	return err
}

// ResetExpandingJobs re-queues jobs left in the expanding state by a previous
// leader process.
func (s *Store) ResetExpandingJobs(ctx context.Context) error {
	now := unixMilli(time.Now())
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET state = ?, updated_at = ? WHERE state = ?`, JobPending, now, JobExpanding)
	return err
}

// ClaimTasks leases up to max pending tasks to a worker.
func (s *Store) ClaimTasks(ctx context.Context, workerID string, limit int, lease time.Duration) ([]Lease, error) {
	if limit <= 0 {
		return nil, nil
	}
	now := time.Now().UTC()
	expire := now.Add(lease)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
SELECT t.id FROM tasks t JOIN jobs j ON j.id = t.job_id
WHERE t.state = ? AND j.state = ? AND j.cancel_requested = 0
ORDER BY t.id LIMIT ?`, TaskPending, JobRunning, limit)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()

	leases := make([]Lease, 0, len(ids))
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `
UPDATE tasks SET state = ?, worker_id = ?, lease_expire = ?, attempts = attempts + 1, copied_bytes = 0, updated_at = ?
WHERE id = ? AND state = ?`, TaskRunning, workerID, unixMilli(expire), unixMilli(now), id, TaskPending); err != nil {
			return nil, err
		}
		row := tx.QueryRowContext(ctx, `SELECT `+taskColumns+` FROM tasks WHERE id = ?`, id)
		task, err := scanTask(row)
		if err != nil {
			return nil, err
		}
		var (
			overwrite   int
			concurrency int
			retryCount  int
		)
		if err := tx.QueryRowContext(ctx, `SELECT overwrite, concurrency, retry_count FROM jobs WHERE id = ?`, task.JobID).
			Scan(&overwrite, &concurrency, &retryCount); err != nil {
			return nil, err
		}
		leases = append(leases, Lease{
			Task:        task,
			Overwrite:   overwrite != 0,
			Concurrency: concurrency,
			RetryCount:  retryCount,
			Expires:     expire,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return leases, nil
}

// TaskProgress records progress of a running task, extends its lease and
// reports whether the task should be aborted (job cancelled or lease lost).
func (s *Store) TaskProgress(ctx context.Context, workerID string, taskID int64, copiedBytes int64, lease time.Duration) (abort bool, err error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `
UPDATE tasks SET copied_bytes = ?, lease_expire = ?, updated_at = ?
WHERE id = ? AND worker_id = ? AND state = ?`,
		copiedBytes, unixMilli(now.Add(lease)), unixMilli(now), taskID, workerID, TaskRunning)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if affected == 0 {
		// lease lost (expired and re-queued, or task cancelled)
		return true, nil
	}
	var cancel int
	if err := s.db.QueryRowContext(ctx, `
SELECT j.cancel_requested FROM jobs j JOIN tasks t ON t.job_id = j.id WHERE t.id = ?`, taskID).Scan(&cancel); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return false, err
	}
	return cancel != 0, nil
}

// CompleteTask records the final state of a leased task. Failed tasks are
// re-queued while attempts are left.
func (s *Store) CompleteTask(ctx context.Context, workerID string, taskID int64, state string, copiedBytes int64, taskErr string) error {
	now := unixMilli(time.Now())
	if state == TaskFailed {
		var (
			attempts   int
			retryCount int
		)
		err := s.db.QueryRowContext(ctx, `
SELECT t.attempts, j.retry_count FROM tasks t JOIN jobs j ON j.id = t.job_id WHERE t.id = ?`, taskID).Scan(&attempts, &retryCount)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if attempts <= retryCount {
			_, err := s.db.ExecContext(ctx, `
UPDATE tasks SET state = ?, worker_id = '', lease_expire = 0, copied_bytes = 0, error = ?, updated_at = ?
WHERE id = ? AND worker_id = ? AND state = ?`, TaskPending, taskErr, now, taskID, workerID, TaskRunning)
			return err
		}
	}
	_, err := s.db.ExecContext(ctx, `
UPDATE tasks SET state = ?, copied_bytes = ?, error = ?, lease_expire = 0, updated_at = ?
WHERE id = ? AND worker_id = ? AND state = ?`, state, copiedBytes, taskErr, now, taskID, workerID, TaskRunning)
	return err
}

// RequeueExpiredLeases returns tasks whose worker stopped reporting back to the
// pending pool so another worker can pick them up.
func (s *Store) RequeueExpiredLeases(ctx context.Context) (int64, error) {
	now := unixMilli(time.Now())
	res, err := s.db.ExecContext(ctx, `
UPDATE tasks SET state = ?, worker_id = '', lease_expire = 0, copied_bytes = 0,
                 error = 'lease expired', updated_at = ?
WHERE state = ? AND lease_expire < ?`, TaskPending, now, TaskRunning, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ReconcileJobs refreshes job counters and finalizes jobs whose tasks are all
// done.
func (s *Store) ReconcileJobs(ctx context.Context) error {
	now := unixMilli(time.Now())
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
UPDATE jobs SET
  done_tasks = (SELECT COUNT(*) FROM tasks WHERE job_id = jobs.id AND state = '`+TaskSucceeded+`'),
  failed_tasks = (SELECT COUNT(*) FROM tasks WHERE job_id = jobs.id AND state = '`+TaskFailed+`'),
  copied_bytes = (SELECT COALESCE(SUM(copied_bytes), 0) FROM tasks WHERE job_id = jobs.id),
  updated_at = ?
WHERE state IN ('`+JobRunning+`', '`+JobExpanding+`')`, now); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
UPDATE jobs SET state = CASE
    WHEN cancel_requested = 1 THEN '`+JobCancelled+`'
    WHEN failed_tasks > 0 THEN '`+JobFailed+`'
    ELSE '`+JobSucceeded+`' END,
  error = CASE WHEN cancel_requested = 0 AND failed_tasks > 0
    THEN COALESCE((SELECT error FROM tasks WHERE job_id = jobs.id AND state = '`+TaskFailed+`' AND error != '' LIMIT 1), 'copy failed')
    ELSE error END,
  finished_at = ?, updated_at = ?
WHERE state = '`+JobRunning+`'
  AND NOT EXISTS (SELECT 1 FROM tasks WHERE job_id = jobs.id AND state IN ('`+TaskPending+`', '`+TaskRunning+`'))`,
		now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// UpsertWorker records a worker heartbeat.
func (s *Store) UpsertWorker(ctx context.Context, worker Worker) error {
	now := unixMilli(time.Now())
	_, err := s.db.ExecContext(ctx, `
INSERT INTO workers (id, mode, addr, version, capacity, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET mode = excluded.mode, addr = excluded.addr, version = excluded.version,
                               capacity = excluded.capacity, last_seen = excluded.last_seen`,
		worker.ID, worker.Mode, worker.Addr, worker.Version, worker.Capacity, now, now)
	return err
}

// ListWorkers returns cluster members seen within maxAge.
func (s *Store) ListWorkers(ctx context.Context, maxAge time.Duration) ([]Worker, error) {
	cutoff := unixMilli(time.Now().Add(-maxAge))
	rows, err := s.db.QueryContext(ctx, `
SELECT id, mode, addr, version, capacity, first_seen, last_seen FROM workers WHERE last_seen >= ? ORDER BY id`, cutoff)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	workers := []Worker{}
	for rows.Next() {
		var (
			worker              Worker
			firstSeen, lastSeen int64
		)
		if err := rows.Scan(&worker.ID, &worker.Mode, &worker.Addr, &worker.Version, &worker.Capacity, &firstSeen, &lastSeen); err != nil {
			return nil, err
		}
		worker.FirstSeen = fromUnixMilli(firstSeen)
		worker.LastSeen = fromUnixMilli(lastSeen)
		workers = append(workers, worker)
	}
	return workers, rows.Err()
}

// PruneWorkers deletes workers not seen within maxAge.
func (s *Store) PruneWorkers(ctx context.Context, maxAge time.Duration) error {
	cutoff := unixMilli(time.Now().Add(-maxAge))
	_, err := s.db.ExecContext(ctx, `DELETE FROM workers WHERE last_seen < ?`, cutoff)
	return err
}

// SchemaVersion returns the schema version stored in the meta table.
func (s *Store) SchemaVersion(ctx context.Context) (string, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = 'schema_version'`).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return strings.TrimSpace(value), err
}
