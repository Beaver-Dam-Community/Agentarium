package healthreport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// Wire shapes of the TASK-10 chapter 4 node-scope health snapshot challenges and the
// two node result APIs (COMMON API table; services/control-health/internal/
// health/workers.go is the server side). Field names follow that server.

type ProcessHint struct {
	LocalPID   int64 `json:"local_pid"`
	PIDNSInode int64 `json:"pid_ns_inode"`
	StartTicks int64 `json:"start_ticks"`
}

type NodeProcessIdentity struct {
	ProcessHint
	HostPID int64 `json:"host_pid"`
}

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

type WorkerChallenge struct {
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

// Challenges are the node-sensors-only lists of a node-scope snapshot.
type Challenges struct {
	Worker    []WorkerChallenge
	Readiness []ReadinessChallenge
}

type WorkerResult struct {
	WorkerBindingID    string              `json:"worker_binding_id"`
	ChallengeID        string              `json:"challenge_id"`
	InstanceBinding    InstanceBinding     `json:"instance_binding"`
	SupervisorIdentity NodeProcessIdentity `json:"supervisor_identity"`
	WorkerIdentity     NodeProcessIdentity `json:"worker_identity"`
	RootExecID         string              `json:"root_exec_id"`
	ExecEventRef       string              `json:"exec_event_ref"`
	WorkerAlive        bool                `json:"worker_alive"`
	ObservedControls   map[string]any      `json:"observed_controls"`
	SensorGeneration   int64               `json:"sensor_generation"`
	ReportedAt         time.Time           `json:"reported_at"`
	EvidenceRefs       []string            `json:"evidence_refs"`
}

type PodResult struct {
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

// EvidenceAck is the durable acknowledgement: 201 created or 200 existing
// (an identical replay of the same nonce).
type EvidenceAck struct {
	EvidenceID string    `json:"evidence_id"`
	Result     string    `json:"result"`
	ReceivedAt time.Time `json:"received_at"`
}

// StatusError carries the control-health error reason codes so the responder
// can tell a retryable "not committed yet" from a final rejection.
type StatusError struct {
	Status int
	Codes  []string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("health HTTP status %d %v", e.Status, e.Codes)
}

// Has reports whether the rejection carries code.
func (e *StatusError) Has(code string) bool {
	for _, c := range e.Codes {
		if c == code {
			return true
		}
	}
	return false
}

func (c *Client) call(ctx context.Context, method, path string, input any, ok func(int) bool, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.origin+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(req)
	if err != nil {
		return errors.New("health transport failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("invalid health response size")
	}
	if !ok(response.StatusCode) {
		var problem struct {
			RequestID   string   `json:"request_id"`
			ReasonCodes []string `json:"reason_codes"`
		}
		_ = json.Unmarshal(raw, &problem)
		return &StatusError{Status: response.StatusCode, Codes: problem.ReasonCodes}
	}
	if canonical.CheckJSONForJCS(raw) != nil {
		return errors.New("invalid health response JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid health response JSON")
	}
	return nil
}

// Challenges reads this node's pending nonces from the node-scope snapshot
// (TASK-10 chapter 4). Control-health binds node/boot to the caller certificate; the
// response must still name the requested node.
func (c *Client) Challenges(ctx context.Context, nodeUID string) (Challenges, error) {
	var snapshot struct {
		Scope             string             `json:"scope"`
		ScopeID           string             `json:"scope_id"`
		EvaluatedAt       json.RawMessage    `json:"evaluated_at"`
		State             json.RawMessage    `json:"state"`
		Leases            json.RawMessage    `json:"leases"`
		MissingComponents json.RawMessage    `json:"missing_components"`
		OpenHolds         json.RawMessage    `json:"open_holds"`
		Probes            json.RawMessage    `json:"probes"`
		OpenGaps          json.RawMessage    `json:"open_gaps"`
		BundleAck         json.RawMessage    `json:"bundle_ack"`
		StartupCapture    json.RawMessage    `json:"startup_capture"`
		Readiness         *[]json.RawMessage `json:"pending_work_readiness_challenges"`
		Worker            *[]json.RawMessage `json:"pending_worker_observation_challenges"`
	}
	q := url.Values{"scope": {"node"}, "scope_id": {nodeUID}}
	if err := c.call(ctx, http.MethodGet, "/internal/control-health?"+q.Encode(), nil, func(s int) bool { return s == http.StatusOK }, &snapshot); err != nil {
		return Challenges{}, err
	}
	if snapshot.Scope != "node" || snapshot.ScopeID != nodeUID || snapshot.Readiness == nil || snapshot.Worker == nil {
		return Challenges{}, errors.New("invalid health snapshot")
	}
	out := Challenges{Worker: []WorkerChallenge{}, Readiness: []ReadinessChallenge{}}
	for _, raw := range *snapshot.Worker {
		var ch WorkerChallenge
		if strict(raw, &ch) != nil || !canonicalID(ch.ChallengeID) || !canonicalID(ch.WorkerBindingID) || ch.Deadline.IsZero() {
			return Challenges{}, errors.New("invalid worker observation challenge")
		}
		out.Worker = append(out.Worker, ch)
	}
	for _, raw := range *snapshot.Readiness {
		var ch ReadinessChallenge
		if strict(raw, &ch) != nil || !canonicalID(ch.ChallengeID) || !canonicalID(ch.CheckID) || ch.Deadline.IsZero() {
			return Challenges{}, errors.New("invalid work readiness challenge")
		}
		out.Readiness = append(out.Readiness, ch)
	}
	return out, nil
}

func (c *Client) ReportWorker(ctx context.Context, r WorkerResult) (EvidenceAck, error) {
	return c.report(ctx, "/internal/control-health/worker-observation-results", r)
}

func (c *Client) ReportPod(ctx context.Context, r PodResult) (EvidenceAck, error) {
	return c.report(ctx, "/internal/control-health/pod-observation-results", r)
}

func (c *Client) report(ctx context.Context, path string, input any) (EvidenceAck, error) {
	var ack EvidenceAck
	status := 0
	err := c.call(ctx, http.MethodPost, path, input, func(s int) bool { status = s; return s == http.StatusCreated || s == http.StatusOK }, &ack)
	if err != nil {
		return EvidenceAck{}, err
	}
	if !canonicalID(ack.EvidenceID) || ack.ReceivedAt.IsZero() || !(status == http.StatusCreated && ack.Result == "created" || status == http.StatusOK && ack.Result == "existing") {
		return EvidenceAck{}, errors.New("invalid evidence acknowledgement")
	}
	return ack, nil
}

func strict(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid JSON")
	}
	return nil
}

func canonicalID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u != uuid.Nil && u.String() == s
}
