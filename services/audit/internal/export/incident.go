package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// IncidentReporter records a verification failure as TASK-07 3.2.1 requires:
// first an export_verification_failed AuditEvent through the audit writer,
// then an audit_integrity hold through the TASK-10 hold API. The source epoch
// is new per process and the sequence starts at 1 within it.
type IncidentReporter struct {
	WriterURL, HoldURL string
	Writer, Holds      *http.Client
	SourceID, Version  string
	mu                 sync.Mutex
	epoch              string
	sequence           int64
}

// Incident is the durable result of one report.
type Incident struct {
	EventID     string `json:"event_id"`
	HoldID      string `json:"hold_id"`
	FailureCode string `json:"failure_code"`
	ManifestSeq int64  `json:"manifest_seq"`
}

func (r *IncidentReporter) next() (string, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.epoch == "" {
		r.epoch = uuid.NewString()
	}
	r.sequence++
	return r.epoch, r.sequence
}

func postJSON(ctx context.Context, client *http.Client, url string, body []byte, want ...int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("invalid response")
	}
	for _, code := range want {
		if resp.StatusCode == code {
			return raw, nil
		}
	}
	return nil, errors.New("request not accepted: HTTP " + strconv.Itoa(resp.StatusCode))
}

// Report stores the incident event and requests the hold. Any failure is
// returned; callers must not treat a partly reported incident as reported.
func (r *IncidentReporter) Report(ctx context.Context, chain string, manifestSeq int64, code, objectKey string) (Incident, error) {
	inc := Incident{FailureCode: code, ManifestSeq: manifestSeq}
	if r.Writer == nil || r.Holds == nil || r.WriterURL == "" || r.HoldURL == "" || r.SourceID == "" || r.Version == "" {
		return inc, errors.New("incident reporting not configured")
	}
	epoch, sequence := r.next()
	payload := map[string]any{"chain_id": chain, "manifest_seq": manifestSeq, "failure_code": code}
	if objectKey != "" {
		payload["object_key"] = objectKey
	}
	safe := map[string]json.RawMessage{}
	for k, v := range payload {
		b, err := json.Marshal(v)
		if err != nil {
			return inc, err
		}
		safe[k] = b
	}
	event := map[string]any{
		"event_id": uuid.NewString(), "event_type": "export_verification_failed", "tenant": "*",
		"source_id": r.SourceID, "source_version": r.Version, "source_epoch": epoch, "source_sequence": sequence,
		"source_time": time.Now().UTC().Format(time.RFC3339Nano), "schema_version": 1,
		"authenticated_actor": nil, "workload_id": nil, "session_id": nil, "action_id": nil, "request_id": nil, "attempt_id": nil,
		"policy_bundle_id": nil, "policy_epoch": nil, "catalog_digest": nil, "catalog_version": nil,
		"evidence_refs": []string{}, "safe_payload": safe,
	}
	unsigned, err := json.Marshal(event)
	if err != nil {
		return inc, err
	}
	if event["payload_digest"], err = canonical.PayloadDigest(unsigned); err != nil {
		return inc, err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return inc, err
	}
	body, err := postJSON(ctx, r.Writer, r.WriterURL+"/internal/audit/events", raw, 201, 200)
	if err != nil {
		return inc, errors.Join(errors.New("incident event not stored"), err)
	}
	var ack struct {
		EventID string `json:"event_id"`
		Result  string `json:"result"`
	}
	if json.Unmarshal(body, &ack) != nil || ack.EventID != event["event_id"] || (ack.Result != "created" && ack.Result != "duplicate") {
		return inc, errors.New("invalid incident event acknowledgement")
	}
	inc.EventID = ack.EventID
	hold, err := json.Marshal(map[string]any{"scope": "global", "scope_id": "*", "reason": "audit_integrity", "evidence_refs": []string{"audit_event:" + inc.EventID}})
	if err != nil {
		return inc, err
	}
	body, err = postJSON(ctx, r.Holds, r.HoldURL+"/internal/holds", hold, 200)
	if err != nil {
		return inc, errors.Join(errors.New("audit_integrity hold not accepted"), err)
	}
	var h struct {
		ID       string `json:"hold_id"`
		Decision string `json:"decision"`
	}
	if json.Unmarshal(body, &h) != nil || !validUUID(h.ID) || (h.Decision != "created" && h.Decision != "existing") {
		return inc, errors.New("invalid audit_integrity hold acknowledgement")
	}
	inc.HoldID = h.ID
	return inc, nil
}
