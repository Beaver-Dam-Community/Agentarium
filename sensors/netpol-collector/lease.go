package netpolcollector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Details is the netpol-collector lease details object (COMMON
// ControlHealthLease.details, TASK-10 3.7, PR #170).
type Details struct {
	SourceEpoch         string  `json:"source_epoch"`
	FileOffset          int64   `json:"file_offset"`
	AckedThrough        uint64  `json:"acked_through"`
	CaughtUpAt          *string `json:"caught_up_at,omitempty"`
	SchemaRejectedCount uint64  `json:"schema_rejected_count"`
}

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
	Details              Details   `json:"details"`
	LeaseUntil           time.Time `json:"lease_until"`
	ObservedState        string    `json:"observed_state"`
	ReportedAt           time.Time `json:"reported_at"`
}

// NewLease builds the 5-second node-scope lease with a 15-second TTL.
func NewLease(nodeUID, version string, healthy bool, d Details, now time.Time) Lease {
	state := "unhealthy"
	if healthy {
		state = "healthy"
	}
	// Lease source_id is netpol-node/<node_uid>, the same as the gap source (#170).
	return Lease{SourceID: "netpol-node/" + nodeUID, Component: "netpol-collector", Scope: "node", ScopeID: nodeUID, ActiveVersion: &version, Details: d, LeaseUntil: now.UTC().Add(15 * time.Second), ObservedState: state, ReportedAt: now.UTC()}
}

// ReportLease posts one lease and validates the acknowledgement.
func ReportLease(ctx context.Context, client *http.Client, origin string, l Lease) error {
	raw, err := json.Marshal(l)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/internal/control-health/leases", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("health transport failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil || canonical.CheckJSONForJCS(body) != nil {
		return errors.New("invalid lease acknowledgement")
	}
	var ack struct {
		LeaseUntil time.Time `json:"lease_until"`
		ScopeState string    `json:"scope_state"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if d.Decode(&ack) != nil || !ack.LeaseUntil.After(l.ReportedAt) || ack.LeaseUntil.After(l.LeaseUntil) {
		return errors.New("invalid lease acknowledgement")
	}
	return nil
}
