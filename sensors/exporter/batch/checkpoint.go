package batch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

type CheckpointResult struct {
	Scope           string `json:"scope"`
	ResourceVersion string `json:"resource_version"`
	CommittedAt     string `json:"committed_at"`
	Revision        uint64 `json:"checkpoint_revision"`
}

// GetCheckpoint uses the same verified workload mTLS client as batch delivery.
// A 404 means no accessible checkpoint; it does not grant authority for a scope.
func (c *Client) GetCheckpoint(ctx context.Context, scope string) (*CheckpointResult, error) {
	if !validText(scope) {
		return nil, errors.New("invalid checkpoint scope")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+"/internal/lifecycle/checkpoints?"+url.Values{"scope": {scope}}.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{resp.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	var result CheckpointResult
	if len(raw) > MaxBytes || strictDecode(raw, &result) != nil || result.Scope != scope || !validText(result.ResourceVersion) || result.Revision == 0 || result.Revision > maxSequence {
		return nil, &ProtocolError{errors.New("invalid server checkpoint")}
	}
	if _, err = time.Parse(time.RFC3339Nano, result.CommittedAt); err != nil {
		return nil, &ProtocolError{errors.New("invalid checkpoint commit time")}
	}
	return &result, nil
}
