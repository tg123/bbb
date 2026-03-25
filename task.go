package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/tg123/bbb/internal/bbbfs"
)

type taskPair struct {
	src string
	dst string
}

const maxTaskfileLineSize = 4 * 1024 * 1024

func parseTaskPairLine(line string, lineNo int) (taskPair, error) {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		return taskPair{}, fmt.Errorf("taskfile: line %d: expected exactly two whitespace-separated fields `src dst` (paths with spaces are not supported)", lineNo)
	}
	return taskPair{src: parts[0], dst: parts[1]}, nil
}

func loadTaskPairs(taskfile string) ([]taskPair, error) {
	var (
		reader io.Reader
		file   *os.File
		err    error
	)
	if taskfile == "-" {
		reader = os.Stdin
	} else {
		file, err = os.Open(taskfile)
		if err != nil {
			return nil, err
		}
		defer func() {
			_ = file.Close()
		}()
		reader = file
	}

	var tasks []taskPair
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxTaskfileLineSize)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		task, err := parseTaskPairLine(line, lineNo)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, task)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return tasks, nil
}

func loadTaskState(path string) (fileState map[string]struct{}, taskCheckpoints map[string]struct{}, err error) {
	fileState = map[string]struct{}{}
	taskCheckpoints = map[string]struct{}{}
	if path == "" {
		return fileState, taskCheckpoints, nil
	}

	file, ferr := os.Open(path)
	if ferr != nil {
		if os.IsNotExist(ferr) {
			return fileState, taskCheckpoints, nil
		}
		return nil, nil, ferr
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxTaskfileLineSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, taskCheckpointPrefix) {
			taskCheckpoints[line] = struct{}{}
		} else {
			fileState[line] = struct{}{}
		}
	}
	if serr := scanner.Err(); serr != nil {
		return nil, nil, serr
	}
	return fileState, taskCheckpoints, nil
}

type taskStateAppender struct {
	mu   sync.Mutex
	file *os.File
}

func newTaskStateAppender(path string) (*taskStateAppender, error) {
	if path == "" {
		return &taskStateAppender{}, nil
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &taskStateAppender{file: file}, nil
}

func (a *taskStateAppender) append(taskKey string) error {
	if a.file == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.file.WriteString(taskKey + "\n"); err != nil {
		return a.closeOnError(err)
	}

	return nil
}

func (a *taskStateAppender) appendCheckpoint(taskKey string) error {
	if a.file == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.file.WriteString(taskKey + "\n"); err != nil {
		return a.closeOnError(err)
	}

	if err := a.file.Sync(); err != nil {
		return a.closeOnError(err)
	}

	return nil
}

func (a *taskStateAppender) closeOnError(err error) error {
	if a.file == nil {
		return err
	}
	if cerr := a.file.Close(); cerr != nil {
		a.file = nil
		return errors.Join(err, cerr)
	}
	a.file = nil
	return err
}

func (a *taskStateAppender) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	if serr := a.file.Sync(); serr != nil {
		_ = a.file.Close()
		a.file = nil
		return serr
	}
	err := a.file.Close()
	a.file = nil
	return err
}

const taskCheckpointPrefix = "TASK\t"

func taskStateKey(src, dst string) string {
	return src + " -> " + dst
}

func taskCheckpointKey(src, dst string) string {
	return taskCheckpointPrefix + src + " -> " + dst
}

type taskTracker struct {
	remaining atomic.Int64
	key       string // task checkpoint key
}

type cpTask struct {
	src     string
	dst     string
	key     string
	size    int64       // known size from listing; 0 = unknown
	tracker *taskTracker // nil when no task-level checkpoint tracking
}

// expandCPTask streams file-level copy tasks for a taskfile pair via the emit
// callback. When the source is directory-like it expands recursively and calls
// emit for each discovered file; for file-like sources it emits a single task.
// Returning a non-nil error from emit stops expansion early.
func expandCPTask(ctx context.Context, task taskPair, emit func(cpTask) error) error {
	// Check if source is a single file (not a directory)
	if bbbfs.IsHF(task.src) || bbbfs.IsAz(task.src) {
		dirLike, err := bbbfs.IsDirLike(ctx, task.src)
		if err != nil {
			return err
		}
		if !dirLike {
			return emit(cpTask{src: task.src, dst: task.dst, key: taskStateKey(task.src, task.dst)})
		}
	} else {
		if info, err := os.Stat(task.src); err != nil || !info.IsDir() {
			return emit(cpTask{src: task.src, dst: task.dst, key: taskStateKey(task.src, task.dst)})
		}
	}

	for result := range bbbfs.ListRecursive(ctx, task.src) {
		if result.Err != nil {
			return result.Err
		}
		entry := result.Entry
		if entry.IsDir {
			continue
		}
		dstPath := bbbfs.ChildPath(task.dst, filepath.ToSlash(entry.Name))
		if err := emit(cpTask{
			src:  entry.Path,
			dst:  dstPath,
			key:  taskStateKey(entry.Path, task.dst),
			size: entry.Size,
		}); err != nil {
			return err
		}
	}
	return nil
}
