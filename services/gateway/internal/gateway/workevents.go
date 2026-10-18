package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// POST /v1/runtime/work-events (COMMON internal API table: TASK-04 relay, owner
// TASK-07; via the gateway for the TASK-04 work-start gate). The runtime reports
// agent_work_* with its workload mTLS and claimed session token. The gateway:
//
//  1. authenticates certificate + token (runtimeSession);
//  2. parses the public body strictly (workEventBody: no session_id, no
//     producer, tenant or readiness field — the session comes from the token);
//  3. reads the referenced WorkReadinessCheck from control-health with the
//     caller's SAN and requires it to be this caller's, session's and
//     workload's, with the same work_run_id, runtime_process_epoch,
//     worker_instance_id and worker_binding_id (403
//     WORK_READINESS_BINDING_MISMATCH otherwise);
//  4. forwards {context, check, event} to audit-writer
//     POST /internal/audit/work-events with the verified SAN in
//     X-Agentarium-Peer-Identity, and returns the TASK-07 ack unchanged
//     (201/200 {event_id, result, received_at}, 409 EVENT_ID_CONFLICT).
//
// The relay grants nothing: it never reads holds and no event it relays is a
// readiness pass (COMMON: a readiness pass cannot be self-issued). The check state is
// not required to be ready, so a late report still links the original check
// (COMMON 1336); audit-writer refuses a still-pending check.
//
// SPEC-QUESTION: COMMON names no internal path or body for this relay; the
// TASK-07 side defines POST /internal/audit/work-events (proposed in the
// spec change).
const internalWorkEvents = "/internal/audit/work-events"

// workEventBody is the public request. Only the event's own identity, type,
// version, time and the IDs the runtime reports.
type workEventBody struct {
	EventID       string           `json:"event_id"`
	EventType     string           `json:"event_type"`
	SourceVersion string           `json:"source_version"`
	SourceTime    string           `json:"source_time"`
	SafePayload   workEventPayload `json:"safe_payload"`
}

type workEventPayload struct {
	WorkRunID           string  `json:"work_run_id"`
	CheckID             string  `json:"check_id"`
	RuntimeProcessEpoch string  `json:"runtime_process_epoch"`
	WorkerInstanceID    string  `json:"worker_instance_id"`
	WorkerBindingID     string  `json:"worker_binding_id"`
	Outcome             *string `json:"outcome,omitempty"`
	Reason              *string `json:"reason,omitempty"`
}

// workEventCheck is the part of the control-health WorkReadinessCheck the
// audit record links. Every field is fixed once the check is determined.
type workEventCheck struct {
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

type workEventContext struct {
	SessionID          string  `json:"session_id"`
	Tenant             string  `json:"tenant"`
	WorkloadID         string  `json:"workload_id"`
	AuthenticatedActor *string `json:"authenticated_actor"`
}

// workEventRelay is the internal audit-writer body.
type workEventRelay struct {
	Context workEventContext `json:"context"`
	Check   workEventCheck   `json:"check"`
	Event   workEventBody    `json:"event"`
}

// decodeWorkEvent parses the public body: COMMON strict JSON, no unknown or
// case-variant key (the body must re-encode to the same canonical JSON), and
// a canonical check_id.
func decodeWorkEvent(body []byte) (workEventBody, error) {
	var ev workEventBody
	if err := canonical.CheckStrictJSON(body); err != nil {
		return ev, schemaInvalid
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&ev); err != nil {
		return ev, schemaInvalid
	}
	again, err := json.Marshal(ev)
	if err != nil {
		return ev, schemaInvalid
	}
	want, err1 := canonical.JCS(body)
	got, err2 := canonical.JCS(again)
	if err1 != nil || err2 != nil || !bytes.Equal(want, got) {
		return ev, schemaInvalid
	}
	if !canonicalUUID(ev.EventID) || !canonicalUUID(ev.SafePayload.CheckID) || !canonicalUUID(ev.SafePayload.WorkRunID) {
		return ev, schemaInvalid
	}
	return ev, nil
}

func (rl *Relay) workEvent(w http.ResponseWriter, r *http.Request) {
	if !noQuery(w, r) {
		return
	}
	c, ok := rl.runtimeSession(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, maxHealthRelayBody)
	if !ok {
		return
	}
	ev, err := decodeWorkEvent(body)
	if err != nil {
		rl.fail(w, err)
		return
	}
	status, out, retry, ok := rl.owned(w, r, internalChecks+"/"+url.PathEscape(ev.SafePayload.CheckID), c, readinessMismatch)
	if !ok {
		return
	}
	if status != http.StatusOK {
		// 404: no such check for this caller; the event cannot be linked.
		copyAnswer(w, status, out, retry)
		return
	}
	var chk workEventCheck
	if err := json.Unmarshal(out, &chk); err != nil {
		rl.fail(w, healthUnavailable)
		return
	}
	if len(chk.InstanceBinding) == 0 {
		chk.InstanceBinding = json.RawMessage("null")
	}
	p := ev.SafePayload
	if chk.CheckID != p.CheckID || chk.CallerIdentity != c.SAN || chk.WorkloadID != c.WorkloadID ||
		chk.SessionID != c.SessionID || chk.WorkRunID != p.WorkRunID || chk.RuntimeProcessEpoch != p.RuntimeProcessEpoch ||
		chk.WorkerInstanceID != p.WorkerInstanceID || chk.WorkerBindingID != p.WorkerBindingID {
		writeError(w, readinessMismatch)
		return
	}
	var actor *string
	if c.AuthenticatedActor != "" {
		a := c.AuthenticatedActor
		actor = &a
	}
	fwd, err := json.Marshal(workEventRelay{
		Context: workEventContext{SessionID: c.SessionID, Tenant: c.Tenant, WorkloadID: c.WorkloadID, AuthenticatedActor: actor},
		Check:   chk,
		Event:   ev,
	})
	if err != nil {
		rl.fail(w, err)
		return
	}
	rl.relay(w, r, toAudit, http.MethodPost, internalWorkEvents, fwd, c.SAN, "", "", "")
}
