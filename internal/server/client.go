package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to a bbb leader over the REST API. It implements TaskSource so
// a follower process can join the copying cluster.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient creates a leader API client.
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= http.StatusBadRequest {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		var apiErr struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(payload, &apiErr) == nil && apiErr.Error != "" {
			return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, apiErr.Error)
		}
		return fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// CreateJob submits a copy job.
func (c *Client) CreateJob(ctx context.Context, req CreateJobRequest) (Job, error) {
	var job Job
	err := c.do(ctx, http.MethodPost, "/api/v1/jobs", req, &job)
	return job, err
}

// ListJobs returns jobs, optionally filtered by state.
func (c *Client) ListJobs(ctx context.Context, state string, limit int) ([]Job, error) {
	query := url.Values{}
	if state != "" {
		query.Set("state", state)
	}
	if limit > 0 {
		query.Set("limit", fmt.Sprint(limit))
	}
	path := "/api/v1/jobs"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out struct {
		Jobs []Job `json:"jobs"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if out.Jobs == nil {
		out.Jobs = []Job{}
	}
	return out.Jobs, nil
}

// GetJob returns one job by ID.
func (c *Client) GetJob(ctx context.Context, id string) (Job, error) {
	var job Job
	err := c.do(ctx, http.MethodGet, "/api/v1/jobs/"+url.PathEscape(id), nil, &job)
	return job, err
}

// ListTasks returns a job's file tasks, optionally filtered by state.
func (c *Client) ListTasks(ctx context.Context, jobID, state string, limit, offset int) ([]Task, error) {
	query := url.Values{}
	if state != "" {
		query.Set("state", state)
	}
	if limit > 0 {
		query.Set("limit", fmt.Sprint(limit))
	}
	if offset > 0 {
		query.Set("offset", fmt.Sprint(offset))
	}
	path := "/api/v1/jobs/" + url.PathEscape(jobID) + "/tasks"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out struct {
		Tasks []Task `json:"tasks"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if out.Tasks == nil {
		out.Tasks = []Task{}
	}
	return out.Tasks, nil
}

// CancelJob requests cancellation and returns the updated job.
func (c *Client) CancelJob(ctx context.Context, id string) (Job, error) {
	var job Job
	err := c.do(ctx, http.MethodPost, "/api/v1/jobs/"+url.PathEscape(id)+"/cancel", nil, &job)
	return job, err
}

// DeleteJob deletes a terminal job and its tasks.
func (c *Client) DeleteJob(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/jobs/"+url.PathEscape(id), nil, nil)
}

// Claim implements TaskSource.
func (c *Client) Claim(ctx context.Context, workerID string, limit int) ([]Lease, error) {
	var out struct {
		Leases []Lease `json:"leases"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/cluster/claim", ClaimRequest{WorkerID: workerID, Limit: limit}, &out); err != nil {
		return nil, err
	}
	return out.Leases, nil
}

// Progress implements TaskSource.
func (c *Client) Progress(ctx context.Context, workerID string, taskID int64, copiedBytes int64) (bool, error) {
	var out struct {
		Abort bool `json:"abort"`
	}
	path := fmt.Sprintf("/api/v1/cluster/tasks/%d/progress", taskID)
	if err := c.do(ctx, http.MethodPost, path, ProgressRequest{WorkerID: workerID, CopiedBytes: copiedBytes}, &out); err != nil {
		return false, err
	}
	return out.Abort, nil
}

// Complete implements TaskSource.
func (c *Client) Complete(ctx context.Context, workerID string, taskID int64, state string, copiedBytes int64, taskErr string) error {
	path := fmt.Sprintf("/api/v1/cluster/tasks/%d/complete", taskID)
	return c.do(ctx, http.MethodPost, path, CompleteRequest{
		WorkerID:    workerID,
		State:       state,
		CopiedBytes: copiedBytes,
		Error:       taskErr,
	}, nil)
}

// Heartbeat implements TaskSource.
func (c *Client) Heartbeat(ctx context.Context, worker Worker) error {
	return c.do(ctx, http.MethodPost, "/api/v1/cluster/workers/heartbeat", map[string]any{
		"id":       worker.ID,
		"mode":     worker.Mode,
		"addr":     worker.Addr,
		"version":  worker.Version,
		"capacity": worker.Capacity,
	}, nil)
}
