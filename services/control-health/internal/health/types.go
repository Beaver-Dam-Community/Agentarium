package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

var ErrForbidden = errors.New("caller scope denied")
var ErrInvalid = errors.New("invalid lease")

// ErrConflict means the request conflicts with stored state: a reused identity
// with different content (409), or a hold that is already released or whose
// release preconditions (current probes, leases, boot) are not met, so it stays open.
var ErrConflict = errors.New("conflict with stored state")

// ErrNotFound means the referenced hold does not exist (404 RESOURCE_NOT_FOUND).
var ErrNotFound = errors.New("resource not found")

// Peer is a verified caller. PodUID is set for a Pod-bound SAN
// (.../ns/<ns>/sa/<ksa>/pod/<uid>, TASK-03 3.3.1 probe and runtime profile);
// such a caller is accepted only as a probe runner (ProbeRunnerSAN).
type Peer struct{ SAN, Serial, PodUID string }

// ProbeRelay is the reporter identity a gateway forwards on a relayed probe
// report (TASK-10 3.2 "relayed reporter identity"): every received value of
// X-Agentarium-Peer-Identity and X-Agentarium-Peer-Certificate-Serial. The
// store uses it only when the TLS peer is the registered gateway principal
// and ignores it on every other connection.
type ProbeRelay struct{ SAN, Serial []string }
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
type LeaseStatus struct {
	Lease
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
	BootID            *string    `json:"boot_id"`
}
type Gap struct {
	GapID   string    `json:"gap_id"`
	Stage   string    `json:"stage"`
	StartAt time.Time `json:"start_at"`
}
type Snapshot struct {
	Scope                              string            `json:"scope"`
	ScopeID                            string            `json:"scope_id"`
	EvaluatedAt                        time.Time         `json:"evaluated_at"`
	State                              string            `json:"state"`
	Leases                             []LeaseStatus     `json:"leases"`
	MissingComponents                  []string          `json:"missing_components"`
	OpenHolds                          []Hold            `json:"open_holds"`
	Probes                             []Probe           `json:"probes"`
	OpenGaps                           []Gap             `json:"open_gaps"`
	BundleAck                          json.RawMessage   `json:"bundle_ack"`
	StartupCapture                     *string           `json:"startup_capture"`
	PendingWorkReadinessChallenges     []json.RawMessage `json:"pending_work_readiness_challenges"`
	PendingWorkerObservationChallenges []json.RawMessage `json:"pending_worker_observation_challenges"`
}
type LeaseAck struct {
	LeaseUntil time.Time `json:"lease_until"`
	ScopeState string    `json:"scope_state"`
}

func DecodeLease(raw []byte) (Lease, error) {
	var l Lease
	if len(raw) > canonical.MaxBodyBytes {
		return l, ErrInvalid
	}
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return l, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil {
		return l, ErrInvalid
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys)
	encoded, _ := json.Marshal(Lease{})
	var allowed map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &allowed)
	for k := range keys {
		if _, ok := allowed[k]; !ok {
			return l, ErrInvalid
		}
	}
	for _, k := range []string{"source_id", "component", "scope", "scope_id", "lease_until", "observed_state", "reported_at"} {
		if v, ok := keys[k]; !ok || bytes.Equal(v, []byte("null")) {
			return l, ErrInvalid
		}
	}
	if l.SourceID == "" || len(l.SourceID) > 16384 || !ValidComponent(l.Component) || !ValidScope(l.Scope) || !ValidObservedState(l.ObservedState) || !ValidScopeID(l.Scope, l.ScopeID) || l.Scope != ExpiryScope(l.Component) || l.ReportedAt.IsZero() || l.LeaseUntil.IsZero() {
		return l, ErrInvalid
	}
	if l.SensorGeneration != nil && *l.SensorGeneration < 1 {
		return l, ErrInvalid
	}
	for _, s := range []*string{l.ActiveVersion, l.ActiveBundleRevision, l.LoadedArtifactDigest, l.CanonicalVersion} {
		if s != nil && len(*s) > 16384 {
			return l, ErrInvalid
		}
	}
	if l.LoadedArtifactDigest != nil {
		if len(*l.LoadedArtifactDigest) != 64 {
			return l, ErrInvalid
		}
		for _, c := range *l.LoadedArtifactDigest {
			if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
				return l, ErrInvalid
			}
		}
	}
	return l, nil
}
func ValidScopeID(scope, id string) bool {
	if id == "" || len(id) > 16384 {
		return false
	}
	if scope == "global" {
		return id == GlobalScopeID
	}
	if scope == "node" || scope == "session" {
		u, err := uuid.Parse(id)
		return err == nil && u.String() == id
	}
	return ValidScope(scope)
}

// Expiry never extends a caller's lease or lets a future clock create extra TTL.
func Expiry(l Lease, now time.Time) (time.Time, error) {
	if l.ReportedAt.After(now.Add(MaxClockSkew)) || l.ReportedAt.Before(now.Add(-MaxIngestionLag-MaxClockSkew)) || !l.LeaseUntil.After(now) || l.LeaseUntil.After(l.ReportedAt.Add(LeaseTTL)) {
		return time.Time{}, ErrInvalid
	}
	until := l.LeaseUntil
	if max := now.Add(LeaseTTL); until.After(max) {
		until = max
	}
	return until, nil
}
func Evaluate(s *Snapshot, guardedProfile bool) {
	required := []string{}
	switch s.Scope {
	case "global":
		required = append(required, RequiredGlobal...)
		if guardedProfile {
			required = append(required, RequiredPerGuardedProf...)
		}
	case "node":
		required = append(required, RequiredPerNode...)
		if s.StartupCapture != nil && *s.StartupCapture == StartupGuarded {
			required = append(required, RequiredPerGuardedNode...)
		}
	case "workload":
		required = append(required, RequiredPerAdapter...)
	case "target":
		required = append(required, RequiredPerTarget...)
	}
	s.MissingComponents = []string{}
	s.State = StateHealthy
	for _, component := range required {
		found := false
		for _, l := range s.Leases {
			if l.Component == component && l.LeaseUntil.After(s.EvaluatedAt) && l.ObservedState != StateUnhealthy {
				found = true
			}
		}
		if !found {
			s.MissingComponents = append(s.MissingComponents, component)
		}
	}
	if len(s.MissingComponents) > 0 || len(s.OpenHolds) > 0 {
		s.State = StateUnhealthy
		return
	}
	for _, l := range s.Leases {
		if l.Component == ComponentNetpol || !l.LeaseUntil.After(s.EvaluatedAt) {
			continue
		}
		if l.ObservedState == StateUnhealthy {
			s.State = StateUnhealthy
			return
		}
		if l.ObservedState == StateDegraded {
			s.State = StateDegraded
		}
	}
}
