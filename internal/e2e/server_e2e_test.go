package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tg123/bbb/internal/server"
)

type serverProcess struct {
	cancel context.CancelFunc
	done   chan struct{}
	output bytes.Buffer

	mu  sync.Mutex
	err error
}

func startServerProcess(t *testing.T, bin string, args ...string) *serverProcess {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = os.Environ()

	process := &serverProcess{cancel: cancel, done: make(chan struct{})}
	cmd.Stdout = &process.output
	cmd.Stderr = &process.output
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start %s %v: %v", bin, args, err)
	}
	go func() {
		err := cmd.Wait()
		process.mu.Lock()
		process.err = err
		process.mu.Unlock()
		close(process.done)
	}()

	t.Cleanup(func() {
		process.stop()
	})
	return process
}

func (p *serverProcess) stop() {
	p.cancel()
	<-p.done
}

func (p *serverProcess) result() (string, error) {
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.output.String(), p.err
}

func reserveTCPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve server address: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release server address: %v", err)
	}
	return addr
}

func waitForServerHealth(t *testing.T, process *serverProcess, baseURL string) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	client := &http.Client{Timeout: 250 * time.Millisecond}
	for time.Now().Before(deadline) {
		select {
		case <-process.done:
			output, err := process.result()
			t.Fatalf("leader exited before becoming healthy: %v\n%s", err, output)
		default:
		}

		resp, err := client.Get(baseURL + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	process.stop()
	output, err := process.result()
	t.Fatalf("leader did not become healthy: %v\n%s", err, output)
}

func serverRequest(ctx context.Context, method, url, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		message, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: status %d: %s", method, url, resp.StatusCode, message)
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(output)
}

func runServerCLI(bin string, args ...string) ([]byte, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = os.Environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %v: %w\n%s", bin, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

func waitForFollower(t *testing.T, leaderURL, token string, process *serverProcess) {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-process.done:
			output, err := process.result()
			t.Fatalf("follower exited before registering: %v\n%s", err, output)
		default:
		}

		var response struct {
			Workers []server.Worker `json:"workers"`
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := serverRequest(ctx, http.MethodGet, leaderURL+"/api/v1/workers", token, nil, &response)
		cancel()
		if err == nil && len(response.Workers) == 1 &&
			response.Workers[0].ID == "e2e-follower" &&
			response.Workers[0].Mode == server.ModeFollower &&
			response.Workers[0].Capacity == 1 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	process.stop()
	output, err := process.result()
	t.Fatalf("follower did not register: %v\n%s", err, output)
}

func waitForServerJob(t *testing.T, leaderURL, token, jobID string, leader, follower *serverProcess) server.Job {
	t.Helper()
	deadline := time.Now().Add(waitTimeout)
	var job server.Job
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := serverRequest(ctx, http.MethodGet, leaderURL+"/api/v1/jobs/"+jobID, token, nil, &job)
		cancel()
		if err != nil {
			t.Fatalf("get server job: %v", err)
		}
		if server.JobDone(job.State) {
			return job
		}
		time.Sleep(50 * time.Millisecond)
	}

	follower.stop()
	leader.stop()
	leaderOutput, leaderErr := leader.result()
	followerOutput, followerErr := follower.result()
	t.Fatalf(
		"job %s did not finish (last state %q)\nleader: %v\n%s\nfollower: %v\n%s",
		jobID, job.State, leaderErr, leaderOutput, followerErr, followerOutput,
	)
	return server.Job{}
}

func TestServerLeaderFollower(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e tests in short mode")
	}

	bin := os.Getenv("BBB_TEST_BIN_PATH")
	if bin == "" {
		bin = "bbb"
	}
	resolvedBin, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("bbb test binary not found: %v", err)
	}

	root := t.TempDir()
	src := filepath.Join(root, "src")
	dst := filepath.Join(root, "dst")
	if err := os.MkdirAll(filepath.Join(src, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"first.txt":                           "copied by follower",
		filepath.Join("nested", "second.txt"): "one leader, one worker",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	addr := reserveTCPAddress(t)
	leaderURL := "http://" + addr
	token := "e2e-server-token"
	leader := startServerProcess(
		t,
		resolvedBin,
		"server",
		"--listen", addr,
		"--db", filepath.Join(root, "server.db"),
		"--workers", "0",
		"--token", token,
		"--poll-interval", "20ms",
		"--lease", "3s",
	)
	waitForServerHealth(t, leader, leaderURL)

	follower := startServerProcess(
		t,
		resolvedBin,
		"server",
		"--leader", leaderURL,
		"--worker-id", "e2e-follower",
		"--workers", "1",
		"--token", token,
		"--poll-interval", "20ms",
		"--lease", "3s",
	)
	waitForFollower(t, leaderURL, token, follower)

	output, err := runServerCLI(
		resolvedBin,
		"--server", leaderURL,
		"--server-token", token,
		"cp", src, dst,
	)
	if err != nil {
		t.Fatalf("submit server job: %v", err)
	}
	jobID := strings.TrimSpace(string(output))
	if jobID == "" || strings.ContainsAny(jobID, " \t\r\n") {
		t.Fatalf("invalid submitted job ID %q", jobID)
	}

	job := waitForServerJob(t, leaderURL, token, jobID, leader, follower)
	if job.State != server.JobSucceeded || job.TotalTasks != int64(len(files)) || job.DoneTasks != int64(len(files)) {
		t.Fatalf("unexpected completed job: %+v", job)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("read copied file %s: %v", name, err)
		}
		if string(got) != want {
			t.Fatalf("copied file %s = %q, want %q", name, got, want)
		}
	}

	output, err = runServerCLI(
		resolvedBin,
		"--server", leaderURL,
		"--server-token", token,
		"job", "get", jobID,
	)
	if err != nil {
		t.Fatal(err)
	}
	var fetched server.Job
	if err := json.Unmarshal(output, &fetched); err != nil {
		t.Fatalf("decode job get output: %v\n%s", err, output)
	}
	if fetched.ID != jobID || fetched.State != server.JobSucceeded {
		t.Fatalf("job get = %+v", fetched)
	}

	output, err = runServerCLI(
		resolvedBin,
		"--server", leaderURL,
		"--server-token", token,
		"job", "list", "--state", server.JobSucceeded,
	)
	if err != nil {
		t.Fatal(err)
	}
	var jobs []server.Job
	if err := json.Unmarshal(output, &jobs); err != nil {
		t.Fatalf("decode job list output: %v\n%s", err, output)
	}
	if !slices.ContainsFunc(jobs, func(candidate server.Job) bool { return candidate.ID == jobID }) {
		t.Fatalf("job list does not contain %s: %+v", jobID, jobs)
	}

	output, err = runServerCLI(
		resolvedBin,
		"--server", leaderURL,
		"--server-token", token,
		"job", "tasks", "--state", server.TaskSucceeded, jobID,
	)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []server.Task
	if err := json.Unmarshal(output, &tasks); err != nil {
		t.Fatalf("decode job tasks output: %v\n%s", err, output)
	}
	if len(tasks) != len(files) {
		t.Fatalf("job tasks = %+v", tasks)
	}

	follower.stop()
	output, err = runServerCLI(
		resolvedBin,
		"--server", leaderURL,
		"--server-token", token,
		"cp", filepath.Join(src, "first.txt"), filepath.Join(dst, "cancelled.txt"),
	)
	if err != nil {
		t.Fatalf("submit job to cancel: %v", err)
	}
	cancelJobID := strings.TrimSpace(string(output))

	output, err = runServerCLI(
		resolvedBin,
		"--server", leaderURL,
		"--server-token", token,
		"job", "cancel", cancelJobID,
	)
	if err != nil {
		t.Fatal(err)
	}
	var cancelled server.Job
	if err := json.Unmarshal(output, &cancelled); err != nil {
		t.Fatalf("decode job cancel output: %v\n%s", err, output)
	}
	if !cancelled.CancelRequested {
		t.Fatalf("job cancel = %+v", cancelled)
	}
	cancelled = waitForServerJob(t, leaderURL, token, cancelJobID, leader, follower)
	if cancelled.State != server.JobCancelled {
		t.Fatalf("cancelled job = %+v", cancelled)
	}

	for _, id := range []string{jobID, cancelJobID} {
		if _, err := runServerCLI(
			resolvedBin,
			"--server", leaderURL,
			"--server-token", token,
			"job", "delete", id,
		); err != nil {
			t.Fatalf("delete job %s: %v", id, err)
		}
	}
}
