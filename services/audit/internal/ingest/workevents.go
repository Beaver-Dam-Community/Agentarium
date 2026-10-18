package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// Runtime work events (TASK-07 work readiness check and multi-session audit,
// COMMON `POST /v1/runtime/work-events` row). TASK-15 reports agent_work_* through
// the TASK-04 gateway relay; the gateway is the only caller of this internal
// path. The writer builds the AuditEvent itself: source, tenant, session,
// workload and the readiness-check evidence come from the gateway's
// authenticated context and the TASK-10 check it read, never from the
// runtime body. The runtime only supplies the event ID, type, version, time
// and the IDs it reports, which must equal the check's.
//
// SPEC-QUESTION: COMMON names the public route and its owner (TASK-07) but
// no internal path or body. This handler defines
// POST /internal/audit/work-events with the body WorkEventRequest; the spec
// change is proposed separately.

// WorkEventsPath is the internal route the gateway relays to.
const WorkEventsPath = "/internal/audit/work-events"

// PeerIdentityHeader is the verified runtime SAN the gateway forwards
// (COMMON header X-Agentarium-Peer-Identity). It is trusted only on a
// connection from the configured gateway SAN.
const PeerIdentityHeader = "X-Agentarium-Peer-Identity"

// RuntimeNamespace is the execution-area Namespace (COMMON Namespace table).
const RuntimeNamespace = "agent-exec"

// WorkEventTypes are the only accepted types (COMMON registry agent_work_*).
// A runtime cannot report work_readiness_* or any other event here.
var WorkEventTypes = map[string]bool{
	"agent_work_start_requested": true,
	"agent_work_started":         true,
	"agent_work_paused":          true,
	"agent_work_finished":        true,
}

// WorkEventRequest is the internal body. Every key is required and the body
// must be in the exact shape below (nullable keys present, outcome/reason
// omitted when absent).
type WorkEventRequest struct {
	Context WorkEventContext `json:"context"`
	Check   WorkEventCheck   `json:"check"`
	Event   WorkEvent        `json:"event"`
}

// WorkEventContext is the gateway-authenticated session (TASK-04 3.1).
type WorkEventContext struct {
	SessionID          string  `json:"session_id"`
	Tenant             string  `json:"tenant"`
	WorkloadID         string  `json:"workload_id"`
	AuthenticatedActor *string `json:"authenticated_actor"`
}

// WorkEventCheck is the TASK-10 WorkReadinessCheck the gateway read for this
// caller and session. state is checked but not stored: it is the only field
// that a later read can still change for a determined check (ready reports
// its expiry by time, not by a stored transition).
type WorkEventCheck struct {
	CheckID             string          `json:"check_id"`
	WorkRunID           string          `json:"work_run_id"`
	SessionID           string          `json:"session_id"`
	WorkloadID          string          `json:"workload_id"`
	CallerIdentity      string          `json:"caller_identity"`
	RuntimeProcessEpoch string          `json:"runtime_process_epoch"`
	WorkerInstanceID    string          `json:"worker_instance_id"`
	WorkerBindingID     string          `json:"worker_binding_id"`
	RootExecID          *string         `json:"root_exec_id"`
	InstanceBinding     json.RawMessage `json:"instance_binding"`
	SensorGeneration    *int64          `json:"sensor_generation"`
	PolicyEpoch         *int64          `json:"policy_epoch"`
	State               string          `json:"state"`
	AuditEventRef       string          `json:"audit_event_ref"`
}

// WorkEvent is the runtime's public body, relayed unchanged in content.
type WorkEvent struct {
	EventID       string           `json:"event_id"`
	EventType     string           `json:"event_type"`
	SourceVersion string           `json:"source_version"`
	SourceTime    string           `json:"source_time"`
	SafePayload   WorkEventPayload `json:"safe_payload"`
}

// WorkEventPayload is the runtime-reported part of the registry payload. The
// session_id of the registry row is added by the writer from the context.
type WorkEventPayload struct {
	WorkRunID           string  `json:"work_run_id"`
	CheckID             string  `json:"check_id"`
	RuntimeProcessEpoch string  `json:"runtime_process_epoch"`
	WorkerInstanceID    string  `json:"worker_instance_id"`
	WorkerBindingID     string  `json:"worker_binding_id"`
	Outcome             *string `json:"outcome,omitempty"`
	Reason              *string `json:"reason,omitempty"`
}

// WorkEventsHandler serves WorkEventsPath. GatewaySAN is the exact service
// SAN of the TASK-04 gateway; every other peer is 403.
type WorkEventsHandler struct {
	GatewaySAN string
	Store      Store
}

var (
	errBinding = errors.New("work event does not match the readiness check")
	errPending = errors.New("readiness check is not determined")
)

func (h WorkEventsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != WorkEventsPath || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	requestID := uuid.NewString()
	san, err := peerSAN(r.TLS)
	if err != nil {
		writeError(w, 401, requestID, "AUTH_REQUIRED")
		return
	}
	if h.GatewaySAN == "" || san != h.GatewaySAN {
		writeError(w, 403, requestID, "")
		return
	}
	peers := r.Header.Values(PeerIdentityHeader)
	if len(peers) != 1 {
		writeError(w, 403, requestID, "")
		return
	}
	source, workload, ok := RuntimeSource(peers[0])
	if !ok {
		writeError(w, 403, requestID, "")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, canonical.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, 413, requestID, "BODY_TOO_LARGE")
		} else {
			writeError(w, 422, requestID, "SCHEMA_INVALID")
		}
		return
	}
	req, err := DecodeWorkEvent(raw)
	if err != nil {
		writeError(w, 422, requestID, "SCHEMA_INVALID")
		return
	}
	event, eventRaw, err := BuildWorkEvent(req, peers[0], source, workload)
	switch {
	case errors.Is(err, errBinding):
		writeError(w, 403, requestID, "WORK_READINESS_BINDING_MISMATCH")
		return
	case errors.Is(err, errPending):
		// SPEC-QUESTION: no code names an undetermined check here; it is
		// not ready, so the readiness 503 code is used and the runtime
		// retries the same event.
		writeError(w, 503, requestID, "WORK_READINESS_EXPIRED")
		return
	case err != nil:
		writeError(w, 422, requestID, "SCHEMA_INVALID")
		return
	}
	ack, err := h.Store.Append(r.Context(), event, eventRaw)
	writeAck(w, requestID, event, ack, err)
}

// writeAck answers a Store.Append result exactly like Handler (TASK-07 chapter 4:
// 201 created, 200 duplicate, 409 EVENT_ID_CONFLICT; body
// {event_id, result, received_at}).
func writeAck(w http.ResponseWriter, requestID string, event Event, ack Ack, err error) {
	if err != nil {
		switch {
		case errors.Is(err, ErrForbidden):
			writeError(w, 403, requestID, "")
		case errors.Is(err, ErrSchema):
			writeError(w, 422, requestID, "SCHEMA_INVALID")
		default:
			writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		}
		return
	}
	status := 200
	switch ack.Result {
	case "created":
		status = 201
	case "duplicate":
	case "conflict":
		writeError(w, 409, requestID, "EVENT_ID_CONFLICT")
		return
	default:
		writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	if ack.EventID != event.EventID || ack.ReceivedAt.IsZero() {
		writeError(w, 503, requestID, "STATE_STORE_UNAVAILABLE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ack)
}

// RuntimeSource maps a forwarded runtime workload SAN
// (spiffe://agentarium.internal/ns/agent-exec/sa/<ksa>[/pod/<uid>]) to its
// audit source_id, the workload's service SAN without the Pod segment, and
// workload_id "<ns>/<ksa>". Replicas of one runtime KSA share one source, so
// producer_event_grants need no row per Pod.
// SPEC-QUESTION: the specs register no source_id for TASK-15 runtimes.
func RuntimeSource(san string) (source, workload string, ok bool) {
	rest, found := strings.CutPrefix(san, "spiffe://agentarium.internal/ns/")
	if !found {
		return "", "", false
	}
	p := strings.Split(rest, "/")
	if !(len(p) == 3 || len(p) == 5) || p[0] != RuntimeNamespace || p[1] != "sa" || p[2] == "" ||
		(len(p) == 5 && (p[3] != "pod" || p[4] == "")) {
		return "", "", false
	}
	for _, s := range p {
		if strings.ContainsAny(s, "?#%@ ") {
			return "", "", false
		}
	}
	return "spiffe://agentarium.internal/ns/" + p[0] + "/sa/" + p[2], p[0] + "/" + p[2], true
}

// DecodeWorkEvent parses the internal body strictly: COMMON strict JSON, the
// TASK-07 limits, no unknown or case-variant keys, and the exact shape (the
// body must re-encode to the same canonical JSON).
func DecodeWorkEvent(raw []byte) (WorkEventRequest, error) {
	var req WorkEventRequest
	if len(raw) > canonical.MaxBodyBytes {
		return req, errors.New("body too large")
	}
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return req, err
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return req, err
	}
	if err := limits(value); err != nil {
		return req, err
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		return req, err
	}
	if d.More() {
		return req, errors.New("trailing data")
	}
	if len(req.Check.InstanceBinding) == 0 {
		return req, errors.New("missing instance_binding")
	}
	again, err := json.Marshal(req)
	if err != nil {
		return req, err
	}
	want, err := canonical.JCS(raw)
	if err != nil {
		return req, err
	}
	got, err := canonical.JCS(again)
	if err != nil {
		return req, err
	}
	if !bytes.Equal(want, got) {
		return req, errors.New("body is not in the exact shape")
	}
	ib := bytes.TrimSpace(req.Check.InstanceBinding)
	if !bytes.Equal(ib, []byte("null")) && (len(ib) == 0 || ib[0] != '{') {
		return req, errors.New("instance_binding must be an object or null")
	}
	return req, nil
}

// BuildWorkEvent validates req against the forwarded caller and returns the
// signed AuditEvent. Field assignment (SPEC-QUESTION, proposed in the spec
// change):
//
//	source_id           runtime workload service SAN (RuntimeSource)
//	source_version      runtime-reported event.source_version
//	source_epoch        check.runtime_process_epoch (a new value per runtime start)
//	source_sequence     null (the runtime keeps no durable sequence)
//	tenant, session_id, workload_id, authenticated_actor   gateway context
//	policy_epoch        check.policy_epoch
//	evidence_refs       [check.audit_event_ref]
//	safe_payload        registry fields + caller_identity, root_exec_id,
//	                    instance_binding, sensor_generation, outcome?, reason?
//
// The result is deterministic for the same request and check, so a retry is
// a duplicate, not a conflict.
func BuildWorkEvent(req WorkEventRequest, peer, source, workload string) (Event, []byte, error) {
	ctx, chk, ev := req.Context, req.Check, req.Event
	if !WorkEventTypes[ev.EventType] {
		return Event{}, nil, errors.New("event_type is not agent_work_*")
	}
	for _, id := range []string{ev.EventID, ctx.SessionID, chk.CheckID, chk.WorkRunID, chk.SessionID} {
		if !validUUID(id) {
			return Event{}, nil, errors.New("invalid id")
		}
	}
	for _, s := range []string{ev.SourceVersion, ctx.Tenant, ctx.WorkloadID, chk.WorkloadID, chk.CallerIdentity,
		chk.RuntimeProcessEpoch, chk.WorkerInstanceID, chk.WorkerBindingID} {
		if s == "" {
			return Event{}, nil, errors.New("missing field")
		}
	}
	if strings.Contains(chk.RuntimeProcessEpoch, "/") {
		return Event{}, nil, errors.New("invalid epoch")
	}
	if ctx.AuthenticatedActor != nil && *ctx.AuthenticatedActor == "" {
		return Event{}, nil, errors.New("empty actor")
	}
	for _, s := range []*string{ev.SafePayload.Outcome, ev.SafePayload.Reason} {
		if s != nil && *s == "" {
			return Event{}, nil, errors.New("empty outcome or reason")
		}
	}
	if !validUUID(chk.AuditEventRef) {
		return Event{}, nil, errors.New("invalid audit_event_ref")
	}
	if _, err := time.Parse(time.RFC3339Nano, ev.SourceTime); err != nil {
		return Event{}, nil, errors.New("invalid source time")
	}
	switch chk.State {
	case "ready", "blocked", "expired":
	case "pending":
		return Event{}, nil, errPending
	default:
		return Event{}, nil, errors.New("invalid check state")
	}
	p := ev.SafePayload
	if peer != chk.CallerIdentity || workload != ctx.WorkloadID || workload != chk.WorkloadID ||
		ctx.SessionID != chk.SessionID || p.CheckID != chk.CheckID || p.WorkRunID != chk.WorkRunID ||
		p.RuntimeProcessEpoch != chk.RuntimeProcessEpoch || p.WorkerInstanceID != chk.WorkerInstanceID ||
		p.WorkerBindingID != chk.WorkerBindingID {
		return Event{}, nil, errBinding
	}
	str := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	ptr := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	payload := map[string]json.RawMessage{
		"work_run_id":           str(chk.WorkRunID),
		"session_id":            str(ctx.SessionID),
		"check_id":              str(chk.CheckID),
		"runtime_process_epoch": str(chk.RuntimeProcessEpoch),
		"worker_instance_id":    str(chk.WorkerInstanceID),
		"worker_binding_id":     str(chk.WorkerBindingID),
		"caller_identity":       str(chk.CallerIdentity),
		"root_exec_id":          ptr(chk.RootExecID),
		"instance_binding":      bytes.TrimSpace(chk.InstanceBinding),
		"sensor_generation":     ptr(chk.SensorGeneration),
	}
	if p.Outcome != nil {
		payload["outcome"] = str(*p.Outcome)
	}
	if p.Reason != nil {
		payload["reason"] = str(*p.Reason)
	}
	sessionID, workloadID := ctx.SessionID, ctx.WorkloadID
	e := Event{
		EventID: ev.EventID, EventType: ev.EventType, Tenant: ctx.Tenant,
		SourceID: source, SourceVersion: ev.SourceVersion, SourceEpoch: chk.RuntimeProcessEpoch,
		SourceTime: ev.SourceTime, SchemaVersion: 1, AuthenticatedActor: ctx.AuthenticatedActor,
		WorkloadID: &workloadID, SessionID: &sessionID, PolicyEpoch: chk.PolicyEpoch,
		EvidenceRefs: []json.RawMessage{str(chk.AuditEventRef)}, SafePayload: payload,
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return Event{}, nil, err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return Event{}, nil, err
	}
	e.PayloadDigest = digest
	if raw, err = json.Marshal(e); err != nil {
		return Event{}, nil, err
	}
	// The same validation as a producer-submitted AuditEvent.
	checked, err := Decode(raw)
	if err != nil {
		return Event{}, nil, fmt.Errorf("built event invalid: %w", err)
	}
	return checked, raw, nil
}
