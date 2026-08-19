package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
