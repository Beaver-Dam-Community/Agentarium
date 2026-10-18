package execute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// ReserveRequest is the POST /internal/dispatch/reservations body (COMMON
// API implementation contract).
type ReserveRequest struct {
	DecisionID     string `json:"decision_id"`
	ActionID       string `json:"action_id"`
	RequestID      string `json:"request_id"`
	ActionDigest   string `json:"action_digest"`
	WireBodyDigest string `json:"wire_body_digest"`
	PolicyEpoch    int64  `json:"policy_epoch"`
	CatalogDigest  string `json:"catalog_digest"`
}

// Permit is the COMMON DispatchPermit.
type Permit struct {
	PermitID       string     `json:"permit_id"`
	DecisionID     string     `json:"decision_id"`
	ActionID       string     `json:"action_id"`
	RequestID      string     `json:"request_id"`
	AttemptID      string     `json:"attempt_id"`
	ReservationID  string     `json:"reservation_id"`
	AdapterID      string     `json:"adapter_id"`
	ActionDigest   string     `json:"action_digest"`
	WireBodyDigest string     `json:"wire_body_digest"`
	PolicyEpoch    int64      `json:"policy_epoch"`
	CatalogDigest  string     `json:"catalog_digest"`
	ExpiresAt      time.Time  `json:"expires_at"`
	ClaimedAt      *time.Time `json:"claimed_at"`
}

// CheckRequest is the POST /internal/dispatch/permits/{permit_id}/check body.
type CheckRequest struct {
	AttemptID      string `json:"attempt_id"`
	ActionDigest   string `json:"action_digest"`
	PolicyEpoch    int64  `json:"policy_epoch"`
	WireBodyDigest string `json:"wire_body_digest"`
}

// CheckResult is the claim answer; only execution_allowed=true permits the send.
type CheckResult struct {
	ExecutionAllowed bool `json:"execution_allowed"`
}

// OutcomeRequest is the POST /internal/dispatch/attempts/{attempt_id}/outcome
// body: transition, AdapterObservation, reason_codes. A released transition
// carries no observation (no socket existed); every other one always does
// (TASK-05 3.4).
//
// SPEC-QUESTION: COMMON names the field "AdapterObservation" without a JSON
// key. "observation" is used, as the coordinator implementation does.
type OutcomeRequest struct {
	Transition  string                 `json:"transition"`
	Observation *transport.Observation `json:"observation"`
	ReasonCodes []string               `json:"reason_codes"`
}

// Coordinator is the TASK-03 dispatch coordinator API.
type Coordinator interface {
	Reserve(ctx context.Context, req ReserveRequest) (Permit, error)
	Check(ctx context.Context, permitID string, req CheckRequest) (CheckResult, error)
	Outcome(ctx context.Context, attemptID string, req OutcomeRequest) error
}

// RemoteError is a definitive coordinator or broker answer: an HTTP status
// with the COMMON error body. Any other error is ambiguous (the request may
// or may not have been applied).
type RemoteError struct {
	Status      int
	ReasonCodes []string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("remote %d %v", e.Status, e.ReasonCodes)
}

// definitive reports whether err is a definitive refusal (4xx). 5xx answers
// may come from a transaction whose COMMIT outcome the server reported as an
// error, so they are treated like transport errors for state decisions.
func definitive(err error) (*RemoteError, bool) {
	var re *RemoteError
	if errors.As(err, &re) && re.Status >= 400 && re.Status < 500 {
		return re, true
	}
	return nil, false
}

var reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// HTTPCoordinator calls the coordinator over mTLS.
type HTTPCoordinator struct {
	BaseURL string // https://coordinator.agent-control.svc:8443
	Client  *http.Client
}

const maxInternalResponse = 64 << 10

func (c *HTTPCoordinator) Reserve(ctx context.Context, req ReserveRequest) (Permit, error) {
	var p Permit
	err := postJSON(ctx, c.Client, c.BaseURL+"/internal/dispatch/reservations", req, &p)
	return p, err
}

func (c *HTTPCoordinator) Check(ctx context.Context, permitID string, req CheckRequest) (CheckResult, error) {
	if !reUUID.MatchString(permitID) {
		return CheckResult{}, fmt.Errorf("coordinator: bad permit_id %q", permitID)
	}
	var r CheckResult
	err := postJSON(ctx, c.Client, c.BaseURL+"/internal/dispatch/permits/"+url.PathEscape(permitID)+"/check", req, &r)
	return r, err
}

func (c *HTTPCoordinator) Outcome(ctx context.Context, attemptID string, req OutcomeRequest) error {
	if !reUUID.MatchString(attemptID) {
		return fmt.Errorf("coordinator: bad attempt_id %q", attemptID)
	}
	return postJSON(ctx, c.Client, c.BaseURL+"/internal/dispatch/attempts/"+url.PathEscape(attemptID)+"/outcome", req, nil)
}

// postJSON posts body and decodes a 2xx answer into out (when not nil). A
// non-2xx answer becomes *RemoteError with the reason_codes of the COMMON
// error body.
func postJSON(ctx context.Context, client *http.Client, u string, body, out any) error {
	if client == nil {
		return ErrUnwired
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxInternalResponse+1))
	if err != nil {
		return err
	}
	if len(raw) > maxInternalResponse {
		return fmt.Errorf("%s: response larger than %d bytes", u, maxInternalResponse)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var eb struct {
			ReasonCodes []string `json:"reason_codes"`
		}
		_ = json.Unmarshal(raw, &eb)
		return &RemoteError{Status: resp.StatusCode, ReasonCodes: eb.ReasonCodes}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%s: decode %d answer: %w", u, resp.StatusCode, err)
	}
	return nil
}

// HTTPBroker is the TASK-06 POST /internal/credentials:resolve client.
type HTTPBroker struct {
	BaseURL string
	Client  *http.Client
}

func (b *HTTPBroker) Resolve(ctx context.Context, attemptID, adapterID, binding string) (Credential, error) {
	var out struct {
		SecretVersion string    `json:"secret_version"`
		HeaderName    string    `json:"header_name"`
		HeaderValue   string    `json:"header_value"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	in := map[string]string{"attempt_id": attemptID, "adapter_id": adapterID, "credential_binding": binding}
	if err := postJSON(ctx, b.Client, b.BaseURL+"/internal/credentials:resolve", in, &out); err != nil {
		return Credential{}, err
	}
	if out.SecretVersion == "" || out.HeaderName == "" || out.HeaderValue == "" || out.ExpiresAt.IsZero() {
		return Credential{}, errors.New("broker: incomplete credential answer")
	}
	if http.CanonicalHeaderKey(out.HeaderName) == "" || !validHeaderName(out.HeaderName) {
		return Credential{}, fmt.Errorf("broker: invalid header_name %s", strconv.Quote(out.HeaderName))
	}
	return Credential{SecretVersion: out.SecretVersion, HeaderName: out.HeaderName, HeaderValue: out.HeaderValue, ExpiresAt: out.ExpiresAt}, nil
}

var reHeaderName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

func validHeaderName(s string) bool { return reHeaderName.MatchString(s) }
