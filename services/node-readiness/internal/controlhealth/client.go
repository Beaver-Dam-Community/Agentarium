package controlhealth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const maxResponseBytes = 1 << 20

// NodeHealth is the TASK-10 chapter 4 response of
// GET /internal/control-health?scope=node&scope_id=<node_uid>.
// Only the fields node-readiness consumes are typed; unknown fields are ignored.
type NodeHealth struct {
	Scope             string        `json:"scope"`
	ScopeID           string        `json:"scope_id"`
	EvaluatedAt       time.Time     `json:"evaluated_at"`
	State             string        `json:"state"`
	Leases            []LeaseStatus `json:"leases"`
	MissingComponents []string      `json:"missing_components"`
	OpenHolds         []Hold        `json:"open_holds"`
	Probes            []Probe       `json:"probes"`
	StartupCapture    *string       `json:"startup_capture"`
}

type LeaseStatus struct {
	Component        string    `json:"component"`
	SourceID         string    `json:"source_id"`
	ObservedState    string    `json:"observed_state"`
	LeaseUntil       time.Time `json:"lease_until"`
	ActiveVersion    *string   `json:"active_version"`
	SensorGeneration *int64    `json:"sensor_generation"`
	// BootID is not in the TASK-10 chapter 4 example; if the server includes it
	// (health.control_health_leases has boot_id), readiness requires a match.
	BootID *string `json:"boot_id"`
}

type Hold struct {
	HoldID         string    `json:"hold_id"`
	Scope          string    `json:"scope"`
	ScopeID        string    `json:"scope_id"`
	Reason         string    `json:"reason"`
	OwnerComponent string    `json:"owner_component"`
	CreatedAt      time.Time `json:"created_at"`
}

type Probe struct {
	ProbeKind         string     `json:"probe_kind"`
	LastJudgedAt      *time.Time `json:"last_judged_at"`
	LastResult        string     `json:"last_result"`
	ConsecutivePasses int        `json:"consecutive_passes"`
	// BootID: same optional binding as LeaseStatus.BootID (health.probe_results has boot_id).
	BootID *string `json:"boot_id"`
}

// requiredNodeHealthKeys must be present in the response; absence is treated
// as an invalid response rather than as an empty value.
var requiredNodeHealthKeys = []string{
	"scope", "scope_id", "evaluated_at", "state", "leases",
	"missing_components", "open_holds", "probes", "startup_capture",
}

// Lease is the ControlHealthLease body (COMMON "audit, observability and health").
// Optional fields are sent as explicit null.
type Lease struct {
	SourceID             string    `json:"source_id"`
	Component            string    `json:"component"`
	Scope                string    `json:"scope"`
	ScopeID              string    `json:"scope_id"`
	ActiveVersion        *string   `json:"active_version"`
	ActiveBundleRevision *string   `json:"active_bundle_revision"`
	LoadedArtifactDigest *string   `json:"loaded_artifact_digest"`
	CanonicalVersion     *string   `json:"canonical_version"`
	SensorGeneration     *int64    `json:"sensor_generation"`
	LeaseUntil           time.Time `json:"lease_until"`
	ObservedState        string    `json:"observed_state"`
	ReportedAt           time.Time `json:"reported_at"`
}

// LeaseAck is the TASK-10 chapter 4 response {lease_until, scope_state}.
type LeaseAck struct {
	LeaseUntil time.Time `json:"lease_until"`
	ScopeState string    `json:"scope_state"`
}

// APIError carries a non-2xx response; ReasonCodes come from the COMMON error body.
type APIError struct {
	StatusCode  int
	ReasonCodes []string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("controlhealth: HTTP %d %v", e.StatusCode, e.ReasonCodes)
}

type Client struct {
	base *url.URL
	http *http.Client
}

// NewHTTPClient follows the COMMON defaults: no redirects, no keep-alive, no HTTP/2.
func NewHTTPClient(tlsConfig *tls.Config, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func NewClient(baseURL string, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("controlhealth: parse base URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("controlhealth: base URL must be https://host[:port]")
	}
	return &Client{base: u, http: httpClient}, nil
}

// NodeHealth queries the node scope for one node UID.
func (c *Client) NodeHealth(ctx context.Context, nodeUID string) (*NodeHealth, error) {
	u := c.base.JoinPath("/internal/control-health")
	q := url.Values{}
	q.Set("scope", "node")
	q.Set("scope_id", nodeUID)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}

	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("controlhealth: decode response: %w", err)
	}
	for _, k := range requiredNodeHealthKeys {
		if _, ok := keys[k]; !ok {
			return nil, fmt.Errorf("controlhealth: response missing %q", k)
		}
	}
	var h NodeHealth
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, fmt.Errorf("controlhealth: decode response: %w", err)
	}
	if h.Scope != "node" || h.ScopeID != nodeUID {
		return nil, fmt.Errorf("controlhealth: response scope %s/%s does not match node/%s", h.Scope, h.ScopeID, nodeUID)
	}
	return &h, nil
}

// ReportLease posts a ControlHealthLease.
func (c *Client) ReportLease(ctx context.Context, l Lease) (*LeaseAck, error) {
	payload, err := json.Marshal(l)
	if err != nil {
		return nil, err
	}
	u := c.base.JoinPath("/internal/control-health/leases")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var ack LeaseAck
	if err := json.Unmarshal(body, &ack); err != nil {
		return nil, fmt.Errorf("controlhealth: decode lease ack: %w", err)
	}
	return &ack, nil
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("controlhealth: response body too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		var eb struct {
			ReasonCodes []string `json:"reason_codes"`
		}
		if json.Unmarshal(body, &eb) == nil {
			apiErr.ReasonCodes = eb.ReasonCodes
		}
		return nil, apiErr
	}
	return body, nil
}
