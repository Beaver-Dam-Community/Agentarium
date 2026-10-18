package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// TASK-10 3.5a/3.5b: session worker registration, independent worker
// observation and work-readiness checks (COMMON agent work start contract).

// PeerIdentityHeader carries the runtime SAN the gateway verified (COMMON
// header table). control-health trusts it only on a connection whose client
// certificate is a registered gateway principal.
const PeerIdentityHeader = "X-Agentarium-Peer-Identity"

// PeerSessionHeader carries the session_id the gateway verified from the
// runtime session token on session-worker and work-readiness relays. The
// gateway strips any client-sent copy and sets this to the verified value, so
// control-health trusts it only on a gateway connection (TASK-04, COMMON
// header table, review #228/#229).
const PeerSessionHeader = "X-Agentarium-Peer-Session"

// PeerSerialHeader carries the hex leaf serial of the certificate the
// gateway verified on a relayed probe report (COMMON probe-reports row).
const PeerSerialHeader = "X-Agentarium-Peer-Certificate-Serial"

// COMMON time limits: work_readiness.challenge_timeout_seconds and
// maximum_result_age_seconds (TASK-16 environment lock initial values).
const (
	ChallengeTimeout = 15 * time.Second
	MaxResultAge     = 3 * time.Second
)

// Reason codes (COMMON enum table WorkReadinessCheck/SessionProcessBinding, error code table).
const (
	CodePodNotReady          = "POD_OBSERVATION_NOT_READY"
	CodeWorkerNotReady       = "WORKER_OBSERVATION_NOT_READY"
	CodeWorkerMismatch       = "WORKER_BINDING_MISMATCH"
	CodeWorkerExited         = "WORKER_EXITED"
	CodeWorkerIsolation      = "WORKER_ISOLATION_NOT_READY"
	CodeRegistrationConflict = "WORKER_REGISTRATION_CONFLICT"
	CodeReadinessExpired     = "WORK_READINESS_EXPIRED"
	CodeReadinessMismatch    = "WORK_READINESS_BINDING_MISMATCH"
	CodeHealthUnavailable    = "CONTROL_HEALTH_UNAVAILABLE"
	CodeHoldActive           = "HOLD_ACTIVE"
	CodeSessionBinding       = "SESSION_BINDING_INVALID"
	CodeEventIDConflict      = "EVENT_ID_CONFLICT"
)

// CodedError is a failure with an HTTP status and one COMMON reason code.
type CodedError struct {
	Status int
	Code   string
}

func (e *CodedError) Error() string { return e.Code }

func Coded(status int, code string) error { return &CodedError{Status: status, Code: code} }

// WorkerBackend is the store side of the work-readiness API. gateway is the
// verified relay connection, callerSAN the runtime SAN it forwarded, and
// session the session_id the gateway verified from the session token
// (compared to the target worker/check, review #228/#229).
type WorkerBackend interface {
	RegisterWorker(ctx context.Context, gateway Peer, callerSAN, session string, r WorkerRegistration) (WorkerBinding, error)
	GetWorker(ctx context.Context, gateway Peer, callerSAN, session, id string) (WorkerBinding, error)
	CloseWorker(ctx context.Context, gateway Peer, callerSAN, session, id string, r WorkerClose) (WorkerBinding, error)
	ReportWorkerObservation(ctx context.Context, sensor Peer, r WorkerObservationResult) (EvidenceAck, error)
	RequestReadiness(ctx context.Context, gateway Peer, callerSAN, session string, r ReadinessRequest) (ReadinessCheck, error)
	GetReadiness(ctx context.Context, gateway Peer, callerSAN, session, id string) (ReadinessCheck, error)
	ReportPodObservation(ctx context.Context, sensor Peer, r PodObservationResult) (EvidenceAck, error)
}

// ProcessHint is a supervisor-reported process location: local PID, PID
// namespace inode and /proc/<pid>/stat start ticks (COMMON
// SessionProcessBinding hints). Never authority or observation evidence.
// SPEC-QUESTION: the field names inside the hint are not specified.
type ProcessHint struct {
	LocalPID   int64 `json:"local_pid"`
	PIDNSInode int64 `json:"pid_ns_inode"`
	StartTicks int64 `json:"start_ticks"`
}

func (h ProcessHint) valid() bool { return h.LocalPID > 0 && h.PIDNSInode > 0 && h.StartTicks > 0 }

// NodeProcessIdentity is the node witness for one live process: the
// supervisor's local hint values resolved to a host PID.
type NodeProcessIdentity struct {
	ProcessHint
	HostPID int64 `json:"host_pid"`
}

// InstanceBinding is fixed by the server from lifecycle records (COMMON
// WorkReadinessCheck.instance_binding).
type InstanceBinding struct {
	ClusterUID          string  `json:"cluster_uid"`
	PodUID              string  `json:"pod_uid"`
	NodeUID             string  `json:"node_uid"`
	BootID              string  `json:"boot_id"`
	ContainerID         string  `json:"container_id"`
	RestartInstance     int64   `json:"restart_instance"`
	CgroupInode         int64   `json:"cgroup_inode"`
	ImageManifestDigest *string `json:"image_manifest_digest"`
}

// SameLocation compares every field except the image digest, which the
// lifecycle intervals do not carry (see store).
func (b InstanceBinding) SameLocation(o InstanceBinding) bool {
	return b.ClusterUID == o.ClusterUID && b.PodUID == o.PodUID && b.NodeUID == o.NodeUID && b.BootID == o.BootID &&
		b.ContainerID == o.ContainerID && b.RestartInstance == o.RestartInstance && b.CgroupInode == o.CgroupInode
}

// WorkerRegistration is the validated request passed to the store. SessionID
// comes from the gateway-authenticated peer-session header, never the wire body.
type WorkerRegistration struct {
	SessionID              string          `json:"session_id"`
	WorkerInstanceID       string          `json:"worker_instance_id"`
	RuntimeProcessEpoch    string          `json:"runtime_process_epoch"`
	SupervisorProcessHint  ProcessHint     `json:"supervisor_process_hint"`
	WorkerProcessHint      ProcessHint     `json:"worker_process_hint"`
	IsolationProfileDigest string          `json:"isolation_profile_digest"`
	ControlsReport         json.RawMessage `json:"controls_report"`
}

type WorkerClose struct {
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// WorkerObservationResult is the node-sensors witness (COMMON
// worker-observation-results row).
type WorkerObservationResult struct {
	WorkerBindingID    string              `json:"worker_binding_id"`
	ChallengeID        string              `json:"challenge_id"`
	InstanceBinding    InstanceBinding     `json:"instance_binding"`
	SupervisorIdentity NodeProcessIdentity `json:"supervisor_identity"`
	WorkerIdentity     NodeProcessIdentity `json:"worker_identity"`
	RootExecID         string              `json:"root_exec_id"`
	ExecEventRef       string              `json:"exec_event_ref"`
	WorkerAlive        bool                `json:"worker_alive"`
	ObservedControls   json.RawMessage     `json:"observed_controls"`
	SensorGeneration   int64               `json:"sensor_generation"`
	ReportedAt         time.Time           `json:"reported_at"`
	EvidenceRefs       []string            `json:"evidence_refs"`
}

// PodObservationResult is the node answer to a work-readiness challenge
// (COMMON pod-observation-results row).
type PodObservationResult struct {
	CheckID            string          `json:"check_id"`
	ChallengeID        string          `json:"challenge_id"`
	InstanceBinding    InstanceBinding `json:"instance_binding"`
	SensorGeneration   int64           `json:"sensor_generation"`
	RuleHash           string          `json:"rule_hash"`
	FilterIncluded     bool            `json:"filter_included"`
	WALFsyncReady      bool            `json:"wal_fsync_ready"`
	WorkerBindingID    *string         `json:"worker_binding_id"`
	RootExecID         *string         `json:"root_exec_id"`
	WorkerAlive        *bool           `json:"worker_alive"`
	WorkerEvidenceRefs []string        `json:"worker_evidence_refs"`
	ReportedAt         time.Time       `json:"reported_at"`
	EvidenceRefs       []string        `json:"evidence_refs"`
}

// ReadinessRequest is the internal POST .../work-readiness/checks body
// (COMMON 1331 plus the forwarded session_id, see WorkerRegistration).
type ReadinessRequest struct {
	SessionID           string `json:"session_id"`
	WorkRunID           string `json:"work_run_id"`
	RuntimeProcessEpoch string `json:"runtime_process_epoch"`
	Checkpoint          string `json:"checkpoint"`
	WorkerInstanceID    string `json:"worker_instance_id"`
	WorkerBindingID     string `json:"worker_binding_id"`
}

// WorkerBinding is the caller-visible SessionProcessBinding: no process
// hints, controls report or host PID.
type WorkerBinding struct {
	WorkerBindingID     string           `json:"worker_binding_id"`
	WorkerInstanceID    string           `json:"worker_instance_id"`
	SessionID           string           `json:"session_id"`
	WorkloadID          string           `json:"workload_id"`
	CallerIdentity      string           `json:"caller_identity"`
	RuntimeProcessEpoch string           `json:"runtime_process_epoch"`
	InstanceBinding     *InstanceBinding `json:"instance_binding"`
	RootExecID          *string          `json:"root_exec_id"`
	SensorGeneration    *int64           `json:"sensor_generation"`
	State               string           `json:"state"`
	RegisteredAt        time.Time        `json:"registered_at"`
	ObservedAt          *time.Time       `json:"observed_at"`
	EndedAt             *time.Time       `json:"ended_at"`
	ReasonCodes         []string         `json:"reason_codes"`
	EvidenceRefs        []string         `json:"evidence_refs"`
	AuditEventRef       string           `json:"audit_event_ref"`
}

// ReadinessCheck is COMMON WorkReadinessCheck plus remaining_valid_ms.
type ReadinessCheck struct {
	CheckID               string           `json:"check_id"`
	WorkRunID             string           `json:"work_run_id"`
	Checkpoint            string           `json:"checkpoint"`
	SessionID             string           `json:"session_id"`
	WorkloadID            string           `json:"workload_id"`
	CallerIdentity        string           `json:"caller_identity"`
	RuntimeProcessEpoch   string           `json:"runtime_process_epoch"`
	WorkerInstanceID      string           `json:"worker_instance_id"`
	WorkerBindingID       string           `json:"worker_binding_id"`
	RootExecID            *string          `json:"root_exec_id"`
	WorkerEvidenceRefs    []string         `json:"worker_evidence_refs"`
	InstanceBinding       *InstanceBinding `json:"instance_binding"`
	SensorGeneration      *int64           `json:"sensor_generation"`
	RuleHash              *string          `json:"rule_hash"`
	PolicyEpoch           *int64           `json:"policy_epoch"`
	ChallengeID           *string          `json:"challenge_id"`
	ChallengeEvidenceRefs []string         `json:"challenge_evidence_refs"`
	State                 string           `json:"state"`
	ReasonCodes           []string         `json:"reason_codes"`
	CreatedAt             time.Time        `json:"created_at"`
	CheckedAt             *time.Time       `json:"checked_at"`
	ExpiresAt             *time.Time       `json:"expires_at"`
	AuditEventRef         string           `json:"audit_event_ref"`
	RemainingValidMS      int64            `json:"remaining_valid_ms"`
}

type EvidenceAck struct {
	EvidenceID string    `json:"evidence_id"`
	Result     string    `json:"result"` // created | existing
	ReceivedAt time.Time `json:"received_at"`
}

// WorkerObservationChallenge and ReadinessChallenge are the elements of the
// node-scope health GET arrays (TASK-10 chapter 4).
type WorkerObservationChallenge struct {
	WorkerBindingID          string          `json:"worker_binding_id"`
	ChallengeID              string          `json:"challenge_id"`
	InstanceBinding          InstanceBinding `json:"instance_binding"`
	SupervisorProcessHint    ProcessHint     `json:"supervisor_process_hint"`
	WorkerProcessHint        ProcessHint     `json:"worker_process_hint"`
	IsolationProfileDigest   string          `json:"isolation_profile_digest"`
	ExpectedSensorGeneration int64           `json:"expected_sensor_generation"`
	RuleHash                 *string         `json:"rule_hash"`
	Deadline                 time.Time       `json:"deadline"`
}
type ReadinessChallenge struct {
	CheckID                  string          `json:"check_id"`
	ChallengeID              string          `json:"challenge_id"`
	InstanceBinding          InstanceBinding `json:"instance_binding"`
	ExpectedSensorGeneration int64           `json:"expected_sensor_generation"`
	RuleHash                 *string         `json:"rule_hash"`
	WorkerBindingID          string          `json:"worker_binding_id"`
	RootExecID               string          `json:"root_exec_id"`
	Deadline                 time.Time       `json:"deadline"`
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// RuntimeSAN parses an execution Pod SAN
// spiffe://agentarium.internal/ns/agent-exec/sa/<ksa>/pod/<pod_uid> (COMMON service PKI).
func RuntimeSAN(san string) (namespace, ksa, podUID string, ok bool) {
	rest, found := strings.CutPrefix(san, "spiffe://agentarium.internal/ns/")
	if !found || len(san) > 1024 {
		return "", "", "", false
	}
	p := strings.Split(rest, "/")
	if len(p) != 5 || p[0] != "agent-exec" || p[1] != "sa" || p[2] == "" || p[3] != "pod" || !canonicalUUID(p[4]) {
		return "", "", "", false
	}
	return p[0], p[2], p[4], true
}

// decodeStrict applies the request pre-check, rejects unknown fields and
// requires every listed key to be present and not null.
func decodeStrict(raw []byte, v any, required ...string) error {
	if len(raw) > canonical.MaxBodyBytes || canonical.CheckStrictJSON(raw) != nil {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return ErrInvalid
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return ErrInvalid
	}
	for _, k := range required {
		if val, ok := keys[k]; !ok || bytes.Equal(val, []byte("null")) {
			return ErrInvalid
		}
	}
	return nil
}

func isObject(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) > 1 && t[0] == '{'
}

func workerRefs(refs []string, nonEmpty bool) bool {
	if refs == nil || (nonEmpty && len(refs) == 0) || len(refs) > 64 {
		return false
	}
	for _, r := range refs {
		if r == "" || len(r) > 1024 {
			return false
		}
	}
	return true
}

func validBinding(b InstanceBinding) bool {
	if !canonicalUUID(b.ClusterUID) || !canonicalUUID(b.PodUID) || !canonicalUUID(b.NodeUID) || b.BootID == "" || len(b.BootID) > 256 ||
		b.ContainerID == "" || len(b.ContainerID) > 256 || b.RestartInstance < 0 || b.CgroupInode <= 0 {
		return false
	}
	return b.ImageManifestDigest == nil || (*b.ImageManifestDigest != "" && len(*b.ImageManifestDigest) <= 256)
}

func DecodeWorkerRegistration(raw []byte) (WorkerRegistration, error) {
	var r WorkerRegistration
	if err := decodeStrict(raw, &r, "session_id", "worker_instance_id", "runtime_process_epoch", "supervisor_process_hint", "worker_process_hint", "isolation_profile_digest", "controls_report"); err != nil {
		return r, err
	}
	if !canonicalUUID(r.SessionID) || !canonicalUUID(r.WorkerInstanceID) || !canonicalUUID(r.RuntimeProcessEpoch) ||
		!r.SupervisorProcessHint.valid() || !r.WorkerProcessHint.valid() || r.SupervisorProcessHint == r.WorkerProcessHint ||
		!hex64.MatchString(r.IsolationProfileDigest) || !isObject(r.ControlsReport) {
		return r, ErrInvalid
	}
	return r, nil
}

func DecodeWorkerClose(raw []byte) (WorkerClose, error) {
	var r WorkerClose
	if err := decodeStrict(raw, &r, "reason", "evidence_refs"); err != nil {
		return r, err
	}
	if r.Reason == "" || len(r.Reason) > 256 || !workerRefs(r.EvidenceRefs, false) {
		return r, ErrInvalid
	}
	return r, nil
}

func DecodeWorkerObservation(raw []byte) (WorkerObservationResult, error) {
	var r WorkerObservationResult
	if err := decodeStrict(raw, &r, "worker_binding_id", "challenge_id", "instance_binding", "supervisor_identity", "worker_identity", "root_exec_id", "exec_event_ref", "worker_alive", "observed_controls", "sensor_generation", "reported_at", "evidence_refs"); err != nil {
		return r, err
	}
	if !canonicalUUID(r.WorkerBindingID) || !canonicalUUID(r.ChallengeID) || !validBinding(r.InstanceBinding) ||
		!r.SupervisorIdentity.valid() || r.SupervisorIdentity.HostPID <= 0 || !r.WorkerIdentity.valid() || r.WorkerIdentity.HostPID <= 0 ||
		r.RootExecID == "" || len(r.RootExecID) > 512 || !canonicalUUID(r.ExecEventRef) || !isObject(r.ObservedControls) ||
		r.SensorGeneration < 1 || r.ReportedAt.IsZero() || !workerRefs(r.EvidenceRefs, true) {
		return r, ErrInvalid
	}
	return r, nil
}

func DecodePodObservation(raw []byte) (PodObservationResult, error) {
	var r PodObservationResult
	if err := decodeStrict(raw, &r, "check_id", "challenge_id", "instance_binding", "sensor_generation", "rule_hash", "filter_included", "wal_fsync_ready", "worker_evidence_refs", "reported_at", "evidence_refs"); err != nil {
		return r, err
	}
	if !canonicalUUID(r.CheckID) || !canonicalUUID(r.ChallengeID) || !validBinding(r.InstanceBinding) || r.SensorGeneration < 1 ||
		!hex64.MatchString(r.RuleHash) || r.ReportedAt.IsZero() || !workerRefs(r.EvidenceRefs, true) || !workerRefs(r.WorkerEvidenceRefs, false) ||
		(r.WorkerBindingID != nil && !canonicalUUID(*r.WorkerBindingID)) || (r.RootExecID != nil && (*r.RootExecID == "" || len(*r.RootExecID) > 512)) {
		return r, ErrInvalid
	}
	return r, nil
}

func DecodeReadinessRequest(raw []byte) (ReadinessRequest, error) {
	var r ReadinessRequest
	if err := decodeStrict(raw, &r, "session_id", "work_run_id", "runtime_process_epoch", "checkpoint", "worker_instance_id", "worker_binding_id"); err != nil {
		return r, err
	}
	if !canonicalUUID(r.SessionID) || !canonicalUUID(r.WorkRunID) || !canonicalUUID(r.RuntimeProcessEpoch) ||
		!canonicalUUID(r.WorkerInstanceID) || !canonicalUUID(r.WorkerBindingID) ||
		(r.Checkpoint != "start" && r.Checkpoint != "resume" && r.Checkpoint != "control_step") {
		return r, ErrInvalid
	}
	return r, nil
}

// bindPeerSession builds the internal decoder input after the gateway's
// identity and canonical session header have been checked. The public body
// cannot choose or override the authenticated session.
func bindPeerSession(raw []byte, session string) ([]byte, error) {
	if !canonicalUUID(session) || canonical.CheckStrictJSON(raw) != nil {
		return nil, ErrInvalid
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, ErrInvalid
	}
	for key := range body {
		if strings.EqualFold(key, "session_id") {
			return nil, ErrInvalid
		}
	}
	body["session_id"], _ = json.Marshal(session)
	return json.Marshal(body)
}

// forwardedCaller returns the runtime SAN the gateway forwarded. Exactly one
// header value that is an execution Pod SAN; anything else is 422.
func forwardedCaller(r *http.Request) (string, bool) {
	values := r.Header.Values(PeerIdentityHeader)
	if len(values) != 1 {
		return "", false
	}
	if _, _, _, ok := RuntimeSAN(values[0]); !ok {
		return "", false
	}
	return values[0], true
}

// forwardedSession returns the gateway-verified session_id from the peer
// session header. Exactly one well-formed value is required on the relayed
// worker and readiness routes; anything else is rejected by the caller.
func forwardedSession(r *http.Request) (string, bool) {
	values := r.Header.Values(PeerSessionHeader)
	if len(values) != 1 || !canonicalUUID(values[0]) {
		return "", false
	}
	return values[0], true
}

// serveWorkers routes the work-readiness API. It reports false when the
// path is not one of its routes.
func (h Handler) serveWorkers(w http.ResponseWriter, r *http.Request, id string, peer Peer) bool {
	const workers = "/internal/control-health/session-workers"
	const checks = "/internal/control-health/work-readiness/checks"
	path := r.URL.Path
	route := ""
	var ref string
	switch {
	case r.Method == "POST" && path == workers:
		route = "register"
	case r.Method == "GET" && strings.HasPrefix(path, workers+"/"):
		route, ref = "get_worker", strings.TrimPrefix(path, workers+"/")
	case r.Method == "POST" && strings.HasPrefix(path, workers+"/") && strings.HasSuffix(path, ":close"):
		route, ref = "close", strings.TrimSuffix(strings.TrimPrefix(path, workers+"/"), ":close")
	case r.Method == "POST" && path == "/internal/control-health/worker-observation-results":
		route = "worker_result"
	case r.Method == "POST" && path == checks:
		route = "check"
	case r.Method == "GET" && strings.HasPrefix(path, checks+"/"):
		route, ref = "get_check", strings.TrimPrefix(path, checks+"/")
	case r.Method == "POST" && path == "/internal/control-health/pod-observation-results":
		route = "pod_result"
	default:
		return false
	}
	if h.Workers == nil {
		writeError(w, 503, id, CodeHealthUnavailable)
		return true
	}
	if r.URL.RawQuery != "" || (ref != "" && !canonicalUUID(ref)) || (route == "get_worker" && strings.Contains(ref, "/")) {
		writeError(w, 422, id, "SCHEMA_INVALID")
		return true
	}
	var caller string
	var session string
	switch route {
	case "register", "get_worker", "close", "check", "get_check":
		var ok bool
		if caller, ok = forwardedCaller(r); !ok {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return true
		}
		// The gateway forwards the verified session_id on these relays; the
		// store compares it to the target worker/check so one session cannot
		// reach another session's worker on the same Pod (review #228/#229).
		if session, ok = forwardedSession(r); !ok {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return true
		}
	default:
		// node-sensors report as themselves; a forwarded identity or session
		// is never accepted on these routes.
		if len(r.Header.Values(PeerIdentityHeader)) != 0 || len(r.Header.Values(PeerSessionHeader)) != 0 {
			writeError(w, 403, id, "")
			return true
		}
	}
	var raw []byte
	if r.Method == "POST" {
		var ok bool
		if raw, ok = readBody(w, r, id); !ok {
			return true
		}
	}
	if route == "register" || route == "check" {
		var err error
		raw, err = bindPeerSession(raw, session)
		if err != nil {
			writeError(w, 422, id, "SCHEMA_INVALID")
			return true
		}
	}
	ctx := r.Context()
	var result any
	var err error
	status := http.StatusOK
	switch route {
	case "register":
		var req WorkerRegistration
		if req, err = DecodeWorkerRegistration(raw); err == nil {
			result, err = h.Workers.RegisterWorker(ctx, peer, caller, session, req)
			status = http.StatusAccepted
		}
	case "get_worker":
		result, err = h.Workers.GetWorker(ctx, peer, caller, session, ref)
	case "close":
		var req WorkerClose
		if req, err = DecodeWorkerClose(raw); err == nil {
			result, err = h.Workers.CloseWorker(ctx, peer, caller, session, ref, req)
		}
	case "worker_result":
		var req WorkerObservationResult
		if req, err = DecodeWorkerObservation(raw); err == nil {
			var ack EvidenceAck
			ack, err = h.Workers.ReportWorkerObservation(ctx, peer, req)
			result, status = ack, ackStatus(ack)
		}
	case "check":
		var req ReadinessRequest
		if req, err = DecodeReadinessRequest(raw); err == nil {
			result, err = h.Workers.RequestReadiness(ctx, peer, caller, session, req)
			status = http.StatusAccepted
		}
	case "get_check":
		result, err = h.Workers.GetReadiness(ctx, peer, caller, session, ref)
	case "pod_result":
		var req PodObservationResult
		if req, err = DecodePodObservation(raw); err == nil {
			var ack EvidenceAck
			ack, err = h.Workers.ReportPodObservation(ctx, peer, req)
			result, status = ack, ackStatus(ack)
		}
	}
	if err != nil {
		var coded *CodedError
		switch {
		case errors.As(err, &coded):
			writeError(w, coded.Status, id, coded.Code)
		case errors.Is(err, ErrInvalid):
			writeError(w, 422, id, "SCHEMA_INVALID")
		case errors.Is(err, ErrForbidden):
			writeError(w, 403, id, "")
		case errors.Is(err, ErrNotFound):
			writeError(w, 404, id, "RESOURCE_NOT_FOUND")
		case errors.Is(err, ErrConflict):
			writeError(w, 409, id, "")
		default:
			writeError(w, 503, id, CodeHealthUnavailable)
		}
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
	return true
}

func ackStatus(a EvidenceAck) int {
	if a.Result == "existing" {
		return http.StatusOK
	}
	return http.StatusCreated
}
