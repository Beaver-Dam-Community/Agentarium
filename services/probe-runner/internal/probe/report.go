package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Report paths (COMMON internal API table). The agent-exec runner reaches only the
// gateway, which relays to control-health with the verified SAN and serial;
// the agent-adapters runner calls control-health directly (TASK-06 allow table).
const (
	RelayPath  = "/v1/runtime/probe-reports"
	DirectPath = "/internal/control-health/probe-results"
)

// Result is the COMMON POST /internal/control-health/probe-results body for
// a node answer probe. scope/scope_id are omitted: control-health resolves
// them to node/<node_uid> for these kinds.
type Result struct {
	ProbeKind    string    `json:"probe_kind"`
	NodeUID      string    `json:"node_uid"`
	BootID       string    `json:"boot_id"`
	StimulusAt   time.Time `json:"stimulus_at"`
	Outcome      string    `json:"outcome"`
	EvidenceRefs []string  `json:"evidence_refs"`
}

// StimulusRef is the runner's own reference to a stimulus. control-health
// keeps it next to the kernel events it found, as context only.
// SPEC-QUESTION: COMMON fixes no evidence_refs form for runner references.
func StimulusRef(kind string, at time.Time) string {
	return "probe_stimulus:" + kind + ":" + at.UTC().Format(time.RFC3339Nano)
}

// Sender posts results to one origin and path.
type Sender struct {
	URL    string // https origin
	Path   string // RelayPath or DirectPath
	Client *http.Client
}

// Send posts r and returns the HTTP status (0 when no answer arrived).
func (s Sender) Send(ctx context.Context, r Result) (int, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL+s.Path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return res.StatusCode, err
	}
	if res.StatusCode != http.StatusCreated {
		return res.StatusCode, fmt.Errorf("probe report HTTP %d: %s", res.StatusCode, bytes.TrimSpace(raw))
	}
	var ack struct {
		ProbeResultID string `json:"probe_result_id"`
	}
	if json.Unmarshal(raw, &ack) != nil || ack.ProbeResultID == "" {
		return res.StatusCode, errors.New("probe report: invalid acknowledgement")
	}
	return res.StatusCode, nil
}
