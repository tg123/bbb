package server

import "context"

// FileTask is a single file copy discovered while expanding a job.
type FileTask struct {
	Src  string
	Dst  string
	Size int64
}

// CopyOptions carries the per job copy settings to the runner.
type CopyOptions struct {
	Overwrite   bool
	Concurrency int
	RetryCount  int
}

// Runner performs the actual filesystem work. It is injected by the caller so
// that the server package stays independent from the CLI implementation.
type Runner interface {
	// Expand enumerates the files of a job source, calling emit for each file
	// to copy. Returning an error from emit stops the expansion.
	Expand(ctx context.Context, src, dst string, emit func(FileTask) error) error
	// Copy copies a single file, reporting copied bytes deltas via onBytes.
	Copy(ctx context.Context, src, dst string, opts CopyOptions, onBytes func(int64)) error
}
