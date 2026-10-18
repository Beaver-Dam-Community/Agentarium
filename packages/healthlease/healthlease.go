// Package healthlease reports a component's ControlHealthLease to TASK-10
// control-health (COMMON ControlHealthLease, POST
// /internal/control-health/leases): every HeartbeatInterval, with lease_until
// = reported_at + LeaseTTL (TASK-10 health_contract). It is shared by the
// coordinator (TASK-03 3.2 sweeper, component = coordinator), the gateway
// (TASK-04 3.5 lease reporting) and the adapters (TASK-05 lease obligations), which report
// one source_id per replica.
package healthlease

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
)

// health_contract values (TASK-10 3.2, COMMON error, status and health defaults).
const (
	HeartbeatInterval = 5 * time.Second
	LeaseTTL          = 15 * time.Second
	callTimeout       = 4 * time.Second
	maxAckBytes       = 1 << 20
)

// Observed states (COMMON ControlHealthLease.observed_state).
const (
	Healthy   = "healthy"
	Degraded  = "degraded"
	Unhealthy = "unhealthy"
)

// Lease is the ControlHealthLease wire body. details is not sent: COMMON
// defines it only for netpol-collector and control-health rejects it for
// every other component.
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

// State is what a component reports in one heartbeat: its observed state and
// active versions. Source, component and scope are fixed in Reporter.
type State struct {
	ObservedState        string
	ActiveVersion        *string
	ActiveBundleRevision *string
	LoadedArtifactDigest *string
	CanonicalVersion     *string
}

// Reporter sends one lease per heartbeat. Client must be the component's
// mTLS client that accepts only the control-health service certificate.
type Reporter struct {
	URL                 string // https origin of control-health
	Client              *http.Client
	SourceID, Component string
	Scope, ScopeID      string
	// State is read once per report, with the report's context.
	State func(context.Context) State
	Now   func() time.Time
}

// ValidOrigin reports whether u is an https://host[:port] origin.
func ValidOrigin(u string) bool {
	p, err := url.Parse(u)
	return err == nil && p.Scheme == "https" && p.Host != "" && p.User == nil && (p.Path == "" || p.Path == "/") &&
		p.RawQuery == "" && !p.ForceQuery && p.Fragment == ""
}

// Validate reports whether r has every field Report needs and a valid URL,
// so that a command can refuse to start without them.
func (r Reporter) Validate() error {
	if r.Client == nil || r.State == nil || r.SourceID == "" || r.Component == "" || r.Scope == "" || r.ScopeID == "" {
		return errors.New("healthlease: reporter is not configured")
	}
	if !ValidOrigin(r.URL) {
		return errors.New("healthlease: control-health URL must be an https origin")
	}
	return nil
}

// Report sends one lease and checks the 200 ack. The call is bounded by
// callTimeout, so that a slow control-health cannot stall the caller's loop
// past the heartbeat interval.
func (r Reporter) Report(ctx context.Context) error {
	if err := r.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}
	st := r.State(ctx)
	if st.ObservedState != Healthy && st.ObservedState != Degraded && st.ObservedState != Unhealthy {
		return fmt.Errorf("healthlease: invalid observed_state %q", st.ObservedState)
	}
	at := now().UTC().Truncate(time.Millisecond)
	raw, err := json.Marshal(Lease{
		SourceID: r.SourceID, Component: r.Component, Scope: r.Scope, ScopeID: r.ScopeID,
		ActiveVersion: st.ActiveVersion, ActiveBundleRevision: st.ActiveBundleRevision,
		LoadedArtifactDigest: st.LoadedArtifactDigest, CanonicalVersion: st.CanonicalVersion,
		LeaseUntil: at.Add(LeaseTTL), ObservedState: st.ObservedState, ReportedAt: at,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, trimSlash(r.URL)+"/internal/control-health/leases", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxAckBytes+1))
	if err != nil || len(body) > maxAckBytes {
		return errors.New("healthlease: invalid control-health response")
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("healthlease: lease not accepted: HTTP %d", res.StatusCode)
	}
	var ack struct {
		LeaseUntil time.Time `json:"lease_until"`
		ScopeState string    `json:"scope_state"`
	}
	if json.Unmarshal(body, &ack) != nil || ack.LeaseUntil.IsZero() {
		return errors.New("healthlease: invalid lease ack")
	}
	return nil
}

// Run reports immediately and then every HeartbeatInterval until ctx ends.
// onError gets every failed report; a missed heartbeat only lets the lease
// expire, which fails closed at its readers.
func (r Reporter) Run(ctx context.Context, onError func(error)) {
	t := time.NewTicker(HeartbeatInterval)
	defer t.Stop()
	for {
		err := r.Report(ctx)
		if err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func trimSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}
