// Package server implements bbb server mode: a REST API to submit, track and
// manage copy jobs, backed by a SQLite database, plus a follower mode which
// turns several bbb processes into a distributed copying cluster.
package server

import "time"

// Job states.
const (
	JobPending   = "pending"
	JobExpanding = "expanding"
	JobRunning   = "running"
	JobSucceeded = "succeeded"
	JobFailed    = "failed"
	JobCancelled = "cancelled"
)

// Task states.
const (
	TaskPending   = "pending"
	TaskRunning   = "running"
	TaskSucceeded = "succeeded"
	TaskFailed    = "failed"
	TaskCancelled = "cancelled"
)

// Worker modes.
const (
	ModeLeader   = "leader"
	ModeFollower = "follower"
)

// JobDone reports whether a job state is terminal.
func JobDone(state string) bool {
	switch state {
	case JobSucceeded, JobFailed, JobCancelled:
		return true
	}
	return false
}

// Job is a user submitted copy request.
type Job struct {
	ID              string     `json:"id"`
	Src             string     `json:"src"`
	Dst             string     `json:"dst"`
	State           string     `json:"state"`
	Overwrite       bool       `json:"overwrite"`
	Concurrency     int        `json:"concurrency"`
	RetryCount      int        `json:"retry_count"`
	CancelRequested bool       `json:"cancel_requested"`
	TotalTasks      int64      `json:"total_tasks"`
	DoneTasks       int64      `json:"done_tasks"`
	FailedTasks     int64      `json:"failed_tasks"`
	TotalBytes      int64      `json:"total_bytes"`
	CopiedBytes     int64      `json:"copied_bytes"`
	Error           string     `json:"error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
}

// Task is a single file copy belonging to a job.
type Task struct {
	ID          int64     `json:"id"`
	JobID       string    `json:"job_id"`
	Src         string    `json:"src"`
	Dst         string    `json:"dst"`
	Size        int64     `json:"size"`
	State       string    `json:"state"`
	Attempts    int       `json:"attempts"`
	CopiedBytes int64     `json:"copied_bytes"`
	WorkerID    string    `json:"worker_id,omitempty"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Lease is a task handed to a worker together with the job options needed to
// execute it.
type Lease struct {
	Task        Task      `json:"task"`
	Overwrite   bool      `json:"overwrite"`
	Concurrency int       `json:"concurrency"`
	RetryCount  int       `json:"retry_count"`
	Expires     time.Time `json:"lease_expires_at"`
}

// Worker is a member of the copying cluster.
type Worker struct {
	ID        string    `json:"id"`
	Mode      string    `json:"mode"`
	Addr      string    `json:"addr,omitempty"`
	Version   string    `json:"version,omitempty"`
	Capacity  int       `json:"capacity"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
