// Package gwclient is the runtime's only network client: every call goes to
// the policy gateway on 8443 (TASK-06: the execution Pod's sole egress).
// Certificate bootstrap is sent without a client certificate; every other
// call presents the runtime workload certificate, and session-scoped calls
// add the claimed session token (COMMON internal API table, TASK-04 relay row).
//
// The client verifies the gateway's chain, serverAuth EKU and exact URI SAN,
// and uses no redirects, keep-alive or HTTP/2 (COMMON implementation defaults).
package gwclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Timeout is the external call timeout (COMMON external timeout 10 s).
const Timeout = 10 * time.Second

const maxResponse = 1 << 20

// Header names (COMMON, TASK-04 work start gate).
const (
	WorkRunHeader        = "X-Agentarium-Work-Run-Id"
	ReadinessCheckHeader = "X-Agentarium-Work-Readiness-Check-Id"
)

// DefaultGatewaySAN is the TASK-04 gateway service identity (COMMON service PKI).
const DefaultGatewaySAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

// APIError is a non-2xx gateway answer (COMMON error envelope).
type APIError struct {
	Status      int
	ReasonCodes []string
	ActionID    string
	DecisionID  string
	RetryAfter  time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gateway HTTP %d %v", e.Status, e.ReasonCodes)
}

// Code returns the first reason code or "".
func (e *APIError) Code() string {
	if len(e.ReasonCodes) == 0 {
		return ""
	}
	return e.ReasonCodes[0]
}

// Client talks to one gateway origin.
type Client struct {
	base      string
	mtls      *http.Client
	bootstrap *http.Client
}

// New builds a client for baseURL (https origin). clientCert supplies the
// current workload certificate for every call except bootstrap.
func New(baseURL string, roots *x509.CertPool, gatewaySAN string,
	clientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("gwclient: gateway URL must be an https origin: %q", baseURL)
	}
	if roots == nil || gatewaySAN == "" || clientCert == nil {
		return nil, errors.New("gwclient: trust bundle, gateway SAN and client certificate source are required")
	}
	mk := func(cc func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) *http.Client {
		cfg := &tls.Config{
			MinVersion:           tls.VersionTLS13,
			GetClientCertificate: cc,
			InsecureSkipVerify:   true, // replaced by VerifyConnection: URI SAN identity, no DNS name
			VerifyConnection: func(cs tls.ConnectionState) error {
				return VerifyServer(cs.PeerCertificates, roots, gatewaySAN, time.Now())
			},
		}
		return &http.Client{
			Timeout: Timeout,
			Transport: &http.Transport{
				TLSClientConfig:   cfg,
				DisableKeepAlives: true,
				ForceAttemptHTTP2: false,
				TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
				Proxy:             nil,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	none := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	return &Client{base: strings.TrimSuffix(baseURL, "/"), mtls: mk(clientCert), bootstrap: mk(none)}, nil
}

// VerifyServer accepts the gateway only when its leaf chains to roots with
// serverAuth, lists serverAuth itself, is not a CA and has exactly one URI
// SAN equal to want and no other SAN.
func VerifyServer(chain []*x509.Certificate, roots *x509.CertPool, want string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("gwclient: gateway presented no certificate")
	}
	leaf := chain[0]
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("gwclient: verify gateway chain: %w", err)
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) || leaf.IsCA {
		return errors.New("gwclient: gateway certificate is not a serverAuth leaf")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != want || len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return fmt.Errorf("gwclient: gateway SAN is not %s", want)
	}
	return nil
}

// call sends one request. body nil sends no body; token adds Authorization.
func (c *Client) call(ctx context.Context, hc *http.Client, method, path string, body any, token string, hdr map[string]string, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return 0, err
	}
	if len(raw) > maxResponse {
		return 0, errors.New("gwclient: response too large")
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		e := &APIError{Status: res.StatusCode}
		var env struct {
			ReasonCodes []string `json:"reason_codes"`
			ActionID    string   `json:"action_id"`
			DecisionID  string   `json:"decision_id"`
		}
		if json.Unmarshal(raw, &env) == nil {
			e.ReasonCodes, e.ActionID, e.DecisionID = env.ReasonCodes, env.ActionID, env.DecisionID
		}
		if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
		return res.StatusCode, e
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return res.StatusCode, fmt.Errorf("gwclient: %s %s: invalid response: %w", method, path, err)
		}
	}
	return res.StatusCode, nil
}

// ---- identity relays (TASK-03 3.3) -------------------------------------------

type CertRequest struct {
	CSR   string `json:"csr"`
	Token string `json:"token"`
}

type CertResponse struct {
	Certificate      string    `json:"certificate"`
	CertificateChain []string  `json:"certificate_chain"`
	Serial           string    `json:"serial"`
	ExpiresAt        time.Time `json:"expires_at"`
}

// Bootstrap is POST /internal/workload-certificates without a client
// certificate (COMMON Workload certificate bootstrap wire format).
func (c *Client) Bootstrap(ctx context.Context, r CertRequest) (CertResponse, error) {
	var out CertResponse
	_, err := c.call(ctx, c.bootstrap, http.MethodPost, "/internal/workload-certificates", r, "", nil, &out)
	return out, err
}

type Assignment struct {
	SessionID      string    `json:"session_id"`
	ClaimCode      string    `json:"claim_code"`
	ClaimExpiresAt time.Time `json:"claim_expires_at"`
	TaskStatement  string    `json:"task_statement"`
}

func (c *Client) Assignments(ctx context.Context) ([]Assignment, error) {
	var out struct {
		Assignments []Assignment `json:"assignments"`
	}
	_, err := c.call(ctx, c.mtls, http.MethodGet, "/v1/runtime/assignments", nil, "", nil, &out)
	return out.Assignments, err
}

type SessionToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c *Client) Claim(ctx context.Context, sessionID, code string) (SessionToken, error) {
	var out SessionToken
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/sessions/"+url.PathEscape(sessionID)+":claim",
		map[string]string{"claim_code": code}, "", nil, &out)
	return out, err
}

func (c *Client) Refresh(ctx context.Context, sessionID, token string) (SessionToken, error) {
	var out SessionToken
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/sessions/"+url.PathEscape(sessionID)+":refresh",
		struct{}{}, token, nil, &out)
	return out, err
}

// ---- control-health relays (TASK-10, #228 bodies without session_id) ---------

// WorkerRegistration is POST /v1/runtime/session-workers.
type WorkerRegistration struct {
	WorkerInstanceID       string          `json:"worker_instance_id"`
	RuntimeProcessEpoch    string          `json:"runtime_process_epoch"`
	SupervisorProcessHint  any             `json:"supervisor_process_hint"`
	WorkerProcessHint      any             `json:"worker_process_hint"`
	IsolationProfileDigest string          `json:"isolation_profile_digest"`
	ControlsReport         json.RawMessage `json:"controls_report"`
}

// WorkerBinding is the caller-visible SessionProcessBinding (fields the
// runtime reads).
type WorkerBinding struct {
	WorkerBindingID     string   `json:"worker_binding_id"`
	WorkerInstanceID    string   `json:"worker_instance_id"`
	SessionID           string   `json:"session_id"`
	RuntimeProcessEpoch string   `json:"runtime_process_epoch"`
	RootExecID          *string  `json:"root_exec_id"`
	State               string   `json:"state"`
	ReasonCodes         []string `json:"reason_codes"`
}

func (c *Client) RegisterWorker(ctx context.Context, token string, r WorkerRegistration) (WorkerBinding, error) {
	var out WorkerBinding
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/runtime/session-workers", r, token, nil, &out)
	return out, err
}

func (c *Client) GetWorker(ctx context.Context, token, id string) (WorkerBinding, error) {
	var out WorkerBinding
	_, err := c.call(ctx, c.mtls, http.MethodGet, "/v1/runtime/session-workers/"+url.PathEscape(id), nil, token, nil, &out)
	return out, err
}

type WorkerClose struct {
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs"`
}

func (c *Client) CloseWorker(ctx context.Context, token, id string, r WorkerClose) (WorkerBinding, error) {
	var out WorkerBinding
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/runtime/session-workers/"+url.PathEscape(id)+":close", r, token, nil, &out)
	return out, err
}

// ReadinessRequest is POST /v1/runtime/work-readiness/checks (COMMON 1331).
type ReadinessRequest struct {
	WorkRunID           string `json:"work_run_id"`
	RuntimeProcessEpoch string `json:"runtime_process_epoch"`
	Checkpoint          string `json:"checkpoint"`
	WorkerInstanceID    string `json:"worker_instance_id"`
	WorkerBindingID     string `json:"worker_binding_id"`
}

// ReadinessCheck is the WorkReadinessCheck fields the runtime reads.
type ReadinessCheck struct {
	CheckID          string   `json:"check_id"`
	WorkRunID        string   `json:"work_run_id"`
	Checkpoint       string   `json:"checkpoint"`
	SessionID        string   `json:"session_id"`
	WorkerInstanceID string   `json:"worker_instance_id"`
	WorkerBindingID  string   `json:"worker_binding_id"`
	RootExecID       *string  `json:"root_exec_id"`
	State            string   `json:"state"`
	ReasonCodes      []string `json:"reason_codes"`
	RemainingValidMS int64    `json:"remaining_valid_ms"`
}

func (c *Client) RequestCheck(ctx context.Context, token string, r ReadinessRequest) (ReadinessCheck, error) {
	var out ReadinessCheck
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/runtime/work-readiness/checks", r, token, nil, &out)
	return out, err
}

func (c *Client) GetCheck(ctx context.Context, token, id string) (ReadinessCheck, error) {
	var out ReadinessCheck
	_, err := c.call(ctx, c.mtls, http.MethodGet, "/v1/runtime/work-readiness/checks/"+url.PathEscape(id), nil, token, nil, &out)
	return out, err
}

// ---- audit relay (TASK-07 via TASK-04) ----------------------------------------

// WorkEvent is the agent_work_* report body (#234 follow-up, gateway
// relay and TASK-07 POST /internal/audit/work-events). The runtime sends only
// what it knows: the event ID, type, its version, time and the IDs it
// reports. session_id, tenant, source_id, source_epoch, received_at and
// payload_digest are server-derived (session from the token, source from the
// verified SAN, epoch from the check); sending session_id is 422.
// SPEC-QUESTION: COMMON 1335 says "registered agent_work_* AuditEvent" but defines
// no runtime body; this shape is proposed in the spec change.
type WorkEvent struct {
	EventID       string           `json:"event_id"`
	EventType     string           `json:"event_type"`
	SourceVersion string           `json:"source_version"`
	SourceTime    time.Time        `json:"source_time"`
	SafePayload   WorkEventPayload `json:"safe_payload"`
}

type WorkEventPayload struct {
	WorkRunID           string  `json:"work_run_id"`
	CheckID             string  `json:"check_id"`
	RuntimeProcessEpoch string  `json:"runtime_process_epoch"`
	WorkerInstanceID    string  `json:"worker_instance_id"`
	WorkerBindingID     string  `json:"worker_binding_id"`
	Outcome             *string `json:"outcome,omitempty"`
	Reason              *string `json:"reason,omitempty"`
}

// WorkEventAck is the TASK-07 event ack (TASK-07 chapter 4: {event_id, result,
// received_at}; 201 created, 200 duplicate).
type WorkEventAck struct {
	EventID    string    `json:"event_id"`
	Result     string    `json:"result"`
	ReceivedAt time.Time `json:"received_at"`
}

// ReportWorkEvent is POST /v1/runtime/work-events. Only a committed TASK-07
// ack for this event counts: 201 created or 200 duplicate (a retry of the
// same event) with the same event_id and a received_at. Anything else,
// including another 2xx, is an error: the start intent is not acknowledged.
func (c *Client) ReportWorkEvent(ctx context.Context, token string, ev WorkEvent) (WorkEventAck, error) {
	var ack WorkEventAck
	status, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/runtime/work-events", ev, token, nil, &ack)
	if err != nil {
		return ack, err
	}
	want := map[int]string{http.StatusCreated: "created", http.StatusOK: "duplicate"}[status]
	if want == "" || ack.Result != want || ack.EventID != ev.EventID || ack.ReceivedAt.IsZero() {
		return ack, fmt.Errorf("gwclient: work event %s: HTTP %d is not a TASK-07 ack", ev.EventID, status)
	}
	return ack, nil
}

// ---- actions (TASK-04 chapter 4) ------------------------------------------------

// ClientAction is the COMMON ClientAction.
type ClientAction struct {
	SessionID        string          `json:"session_id"`
	OperationID      string          `json:"operation_id"`
	RequestedTarget  json.RawMessage `json:"requested_target"`
	Arguments        json.RawMessage `json:"arguments"`
	ClientRequestKey string          `json:"client_request_key"`
}

// ActionResponse is the 202 body of POST /v1/actions and :reevaluate.
type ActionResponse struct {
	RequestID        string   `json:"request_id"`
	ActionID         string   `json:"action_id"`
	DecisionID       string   `json:"decision_id"`
	Verdict          string   `json:"verdict"`
	ExecutionAllowed bool     `json:"execution_allowed"`
	ReasonCodes      []string `json:"reason_codes"`
}

// Readiness is the pair of runtime headers.
type Readiness struct {
	WorkRunID string
	CheckID   string
}

func (r Readiness) headers() map[string]string {
	return map[string]string{WorkRunHeader: r.WorkRunID, ReadinessCheckHeader: r.CheckID}
}

func (c *Client) SubmitAction(ctx context.Context, token string, a ClientAction, ref Readiness) (ActionResponse, error) {
	var out ActionResponse
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/actions", a, token, ref.headers(), &out)
	return out, err
}

func (c *Client) Reevaluate(ctx context.Context, token, actionID, digest string, ref Readiness) (ActionResponse, error) {
	var out ActionResponse
	_, err := c.call(ctx, c.mtls, http.MethodPost, "/v1/actions/"+url.PathEscape(actionID)+":reevaluate",
		map[string]string{"expected_action_digest": digest}, token, ref.headers(), &out)
	return out, err
}

// ActionView is GET /v1/actions/{action_id}.
type ActionView struct {
	ActionID       string   `json:"action_id"`
	ActionDigest   *string  `json:"action_digest"`
	DecisionID     string   `json:"decision_id"`
	Verdict        string   `json:"verdict"`
	ReasonCodes    []string `json:"reason_codes"`
	ExecutionState string   `json:"execution_state"`
}

func (c *Client) GetAction(ctx context.Context, token, id string) (ActionView, error) {
	var out ActionView
	_, err := c.call(ctx, c.mtls, http.MethodGet, "/v1/actions/"+url.PathEscape(id), nil, token, nil, &out)
	return out, err
}

// ActionResult is GET /v1/actions/{action_id}/result: 200 ActionResult or
// 202 with the current execution_state.
type ActionResult struct {
	ActionID       string          `json:"action_id"`
	ExecutionState string          `json:"execution_state"`
	EvidenceLevel  string          `json:"evidence_level,omitempty"`
	ResultBody     json.RawMessage `json:"result_body,omitempty"`
	Truncated      bool            `json:"truncated"`
	ReasonCodes    []string        `json:"reason_codes"`
	Final          bool            `json:"-"`
}

func (c *Client) GetResult(ctx context.Context, token, id string) (ActionResult, error) {
	var out ActionResult
	status, err := c.call(ctx, c.mtls, http.MethodGet, "/v1/actions/"+url.PathEscape(id)+"/result", nil, token, nil, &out)
	out.Final = err == nil && status == http.StatusOK
	return out, err
}
