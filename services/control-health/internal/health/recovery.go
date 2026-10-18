package health

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// ConsoleBFFSAN is the identity service console BFF (COMMON console path). Its
// actor/role headers are trusted only on a verified connection with this SAN.
const ConsoleBFFSAN = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"

// NodeProbeKinds are the TASK-10 3.2 answer probes judged per node/boot. Node
// readiness and node-scope automatic release require all of them.
var NodeProbeKinds = []string{"process", "tcp", "file"}

// RequiredConsecutivePasses is the TASK-10 3.2 "probe passes twice in a row" rule.
const RequiredConsecutivePasses = 2

// ProbeSpacing is the allowed spacing between two consecutive counted passes
// of a kind: its probe interval within the 2s clock skew (answer probes 60s,
// TASK-08 receipt probes 5s). Passes closer together are one stimulus window,
// so a burst of reports cannot satisfy recovery. max is also the recency
// bound of the newest cited pass.
func ProbeSpacing(kind string) (min, max time.Duration) {
	if kind == "receipt" {
		return 3 * time.Second, 7 * time.Second
	}
	return 58 * time.Second, 62 * time.Second
}

// MaxProbeSpacing is the answer probe bound (60s interval + 2s skew).
const MaxProbeSpacing = 62 * time.Second

// MaxStimulusAge bounds a reported stimulus_at: the runner judges at t+25s
// (TASK-10 3.2), so a stimulus older than 40s is not a fresh report.
const MaxStimulusAge = 40 * time.Second

// MaxApprovalAge bounds operator approval freshness.
const MaxApprovalAge = 300 * time.Second

// AttestedOwners are the reasons released by the owner's own verification
// flow without probe results (#159): TASK-14 activation, 3.5 reconciliation and
// the TASK-07 DB write/read probe.
var AttestedOwners = map[string]string{"policy_activation": "releaser", "start_unknown": ComponentStartCoord, "db_unavailable": "audit-db"}

// ProbeReporter is the single component that owns a probe kind in a scope
// (COMMON probe-results callers, #159). Other components cannot report it.
func ProbeReporter(kind, scope string) string {
	switch {
	case slices.Contains(NodeProbeKinds, kind) && scope == "node":
		return ProbeRunnerKSA
	case kind == "export" && (scope == "global" || scope == "node"):
		return "audit-export"
	case kind == "receipt" && scope == "target":
		return ComponentDestination
	}
	return ""
}

// ProbeRunnerKSA is the TASK-10 probe runner KSA and component name; its
// Pods run in agent-exec (reporting through the gateway relay) and
// agent-adapters (reporting directly).
const ProbeRunnerKSA = "probe-runner"

// ProbeRunnerSAN parses a probe runner Pod SAN
// spiffe://agentarium.internal/ns/<agent-exec|agent-adapters>/sa/probe-runner/pod/<uid>
// and returns its namespace, Pod UID and the service SAN without the Pod suffix, the
// key of its health.component_principals row (one row per KSA, while every
// Pod has its own SAN).
func ProbeRunnerSAN(san string) (namespace, podUID, principal string, ok bool) {
	rest, found := strings.CutPrefix(san, "spiffe://agentarium.internal/ns/")
	if !found || len(san) > 1024 {
		return "", "", "", false
	}
	p := strings.Split(rest, "/")
	if len(p) != 5 || (p[0] != "agent-exec" && p[0] != "agent-adapters") || p[1] != "sa" || p[2] != ProbeRunnerKSA || p[3] != "pod" || !canonicalUUID(p[4]) {
		return "", "", "", false
	}
	return p[0], p[4], "spiffe://agentarium.internal/ns/" + p[0] + "/sa/" + ProbeRunnerKSA, true
}

// ReleaseProbeKinds are the probe kinds whose verified passes release a
// transient hold. export_lag/db_unavailable need one export pass (TASK-10
// release table "probe passed"); the others need two consecutive passes.
func ReleaseProbeKinds(scope, reason string) (kinds []string, single bool) {
	switch {
	case reason == "export_lag":
		return []string{"export"}, true
	case scope == "node":
		return NodeProbeKinds, false
	case scope == "target":
		return []string{"receipt"}, false
	}
	return nil, false
}

// SecurityReasons are released only with operator approval (TASK-10 3.2).
var SecurityReasons = []string{"control_drift", "bypass_detected", "sensor_tampering", "alignment_mismatch", "audit_integrity", "risk_event", "operator_stop"}

// AutoReleasable lists transient reasons per scope whose owner may release
// them with verified probes. Workload/session holds and the remaining
// transient reasons (start_unknown, policy_activation, global lease_expired)
// have no probe rule here and stay held.
func AutoReleasable(scope, reason string) bool {
	switch scope {
	case "node":
		return slices.Contains([]string{"probe_failed", "lease_expired", "sensor_degraded", "export_lag"}, reason)
	case "global":
		return reason == "export_lag"
	case "target":
		return reason == "probe_failed"
	}
	return false
}

// ProbeReport is the COMMON POST /internal/control-health/probe-results body.
type ProbeReport struct {
	ProbeKind    string     `json:"probe_kind"`
	Scope        *string    `json:"scope,omitempty"`
	ScopeID      *string    `json:"scope_id,omitempty"`
	NodeUID      *string    `json:"node_uid,omitempty"`
	BootID       *string    `json:"boot_id,omitempty"`
	StimulusAt   *time.Time `json:"stimulus_at,omitempty"`
	Outcome      string     `json:"outcome"`
	EvidenceRefs []string   `json:"evidence_refs"`
}

type ProbeAck struct {
	ProbeResultID string `json:"probe_result_id"`
}

type OperatorApproval struct {
	AuthenticatedActor string    `json:"authenticated_actor"`
	ApprovedAt         time.Time `json:"approved_at"`
	ConsoleRequestID   string    `json:"console_request_id"`
}

// ReleaseRequest is the TASK-10 3.2 release body.
type ReleaseRequest struct {
	Justification    string            `json:"justification"`
	EvidenceRefs     []string          `json:"evidence_refs"`
	ProbeResultIDs   []string          `json:"probe_result_ids,omitempty"`
	OperatorApproval *OperatorApproval `json:"operator_approval,omitempty"`
}

// ConsoleContext carries BFF headers; the store trusts them only for ConsoleBFFSAN.
type ConsoleContext struct {
	Actor string
	Roles []string
}

type ReleaseAck struct {
	HoldID     string    `json:"hold_id"`
	ReleasedAt time.Time `json:"released_at"`
	ReleaseRef string    `json:"release_ref"`
}

func strictFields(raw []byte, v any, allowed, required []string) error {
	if len(raw) > canonical.MaxBodyBytes || canonical.CheckStrictJSON(raw) != nil {
		return ErrInvalid
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return ErrInvalid
	}
	for k, v := range keys {
		if !slices.Contains(allowed, k) {
			return ErrInvalid
		}
		if slices.Contains(required, k) && bytes.Equal(v, []byte("null")) {
			return ErrInvalid
		}
	}
	for _, k := range required {
		if _, ok := keys[k]; !ok {
			return ErrInvalid
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(v) != nil {
		return ErrInvalid
	}
	return nil
}

func validRefs(refs []string) bool {
	if refs == nil || len(refs) > 256 {
		return false
	}
	for _, ref := range refs {
		if ref == "" || len(ref) > 16384 {
			return false
		}
	}
	return true
}

func canonicalUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// DecodeProbeReport accepts the COMMON wire and enforces the per-kind scope
// and field combination (#159). It returns the resolved scope and scope_id.
func DecodeProbeReport(raw []byte) (ProbeReport, error) {
	var p ProbeReport
	if err := strictFields(raw, &p, []string{"probe_kind", "scope", "scope_id", "node_uid", "boot_id", "stimulus_at", "outcome", "evidence_refs"}, []string{"probe_kind", "outcome", "evidence_refs"}); err != nil {
		return p, err
	}
	if !slices.Contains([]string{"pass", "fail", "unknown"}, p.Outcome) || !validRefs(p.EvidenceRefs) {
		return p, ErrInvalid
	}
	if (p.Scope == nil) != (p.ScopeID == nil) || (p.BootID != nil && p.NodeUID == nil) {
		return p, ErrInvalid
	}
	if p.NodeUID != nil && !canonicalUUID(*p.NodeUID) || p.BootID != nil && (*p.BootID == "" || len(*p.BootID) > 256) {
		return p, ErrInvalid
	}
	answer := slices.Contains(NodeProbeKinds, p.ProbeKind)
	// Answer probes are bound to a node boot; the exporter cannot know a boot.
	if answer && (p.NodeUID == nil || p.BootID == nil) || !answer && p.BootID != nil {
		return p, ErrInvalid
	}
	if p.Scope == nil && answer {
		scope, id := "node", *p.NodeUID
		p.Scope, p.ScopeID = &scope, &id
	}
	if p.Scope == nil || !ValidScopeID(*p.Scope, *p.ScopeID) || ProbeReporter(p.ProbeKind, *p.Scope) == "" {
		return p, ErrInvalid
	}
	if (*p.Scope == "node") != (p.NodeUID != nil) || (p.NodeUID != nil && *p.ScopeID != *p.NodeUID) {
		return p, ErrInvalid
	}
	// stimulus_at belongs to answer probes and is required for their passes:
	// the server finds the kernel evidence of that stimulus window (#179).
	if p.StimulusAt != nil && !answer || answer && p.Outcome == "pass" && p.StimulusAt == nil {
		return p, ErrInvalid
	}
	// A pass without evidence references cannot support release.
	if p.Outcome == "pass" && len(p.EvidenceRefs) == 0 {
		return p, ErrInvalid
	}
	return p, nil
}

// DecodeReleaseRequest requires exactly one of probe_result_ids (owner
// automatic release) or operator_approval (security release).
func DecodeReleaseRequest(raw []byte) (ReleaseRequest, error) {
	var r ReleaseRequest
	if err := strictFields(raw, &r, []string{"justification", "evidence_refs", "probe_result_ids", "operator_approval"}, []string{"justification", "evidence_refs"}); err != nil {
		return r, err
	}
	if strings.TrimSpace(r.Justification) == "" || len(r.Justification) > 4096 || !validRefs(r.EvidenceRefs) {
		return r, ErrInvalid
	}
	// At most one of probe_result_ids / operator_approval; neither is the
	// owner-attested release, which needs evidence.
	if r.ProbeResultIDs != nil && r.OperatorApproval != nil || r.ProbeResultIDs == nil && r.OperatorApproval == nil && len(r.EvidenceRefs) == 0 {
		return r, ErrInvalid
	}
	if r.ProbeResultIDs != nil {
		if len(r.ProbeResultIDs) == 0 || len(r.ProbeResultIDs) > 64 {
			return r, ErrInvalid
		}
		seen := map[string]bool{}
		for _, id := range r.ProbeResultIDs {
			if !canonicalUUID(id) || seen[id] {
				return r, ErrInvalid
			}
			seen[id] = true
		}
	}
	if a := r.OperatorApproval; a != nil {
		if a.AuthenticatedActor == "" || len(a.AuthenticatedActor) > 512 || strings.ContainsAny(a.AuthenticatedActor, " \t\r\n") || a.ConsoleRequestID == "" || len(a.ConsoleRequestID) > 256 || strings.ContainsAny(a.ConsoleRequestID, " \t\r\n:") || a.ApprovedAt.IsZero() {
			return r, ErrInvalid
		}
	}
	return r, nil
}

// ConsoleRoles parses the BFF comma-separated role header.
func ConsoleRoles(header string) []string {
	roles := []string{}
	for _, r := range strings.Split(header, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

// ProbeRun is one stored probe result as seen by the pure release verifier.
// JudgedAt is the server-assigned judged time. StimulusAt is set only for
// answer probe passes, where the server bounded it to [now-40s, now+2s] and
// consumed kernel events back it.
type ProbeRun struct {
	ID         string
	Kind       string
	Result     string
	JudgedAt   time.Time
	StimulusAt time.Time
}

// spacing is the distance between two consecutive counted passes: stimulus
// times for answer probes (a runner waiting for kernel ingest retries with the
// same stimulus_at, so judged_at drifts), judged times otherwise (#179).
func spacing(newer, older ProbeRun) time.Duration {
	if !newer.StimulusAt.IsZero() && !older.StimulusAt.IsZero() {
		return newer.StimulusAt.Sub(older.StimulusAt)
	}
	return newer.JudgedAt.Sub(older.JudgedAt)
}

// VerifiedPasses returns, per probe kind, the latest run of consecutive
// passes judged after since. rows must be ordered newest judged first per
// kind; consecutiveness follows that order. A pass closer than the kind's
// minimum spacing to the previously counted pass is the same stimulus window
// and is skipped; a non-pass or a spacing above the maximum ends the run.
func VerifiedPasses(rows []ProbeRun, since time.Time) map[string][]ProbeRun {
	byKind := map[string][]ProbeRun{}
	stopped := map[string]bool{}
	for _, r := range rows {
		if stopped[r.Kind] {
			continue
		}
		run := byKind[r.Kind]
		if r.Result != "pass" || !r.JudgedAt.After(since) {
			stopped[r.Kind] = true
			continue
		}
		if len(run) > 0 {
			gap := spacing(run[len(run)-1], r)
			min, max := ProbeSpacing(r.Kind)
			if gap < min {
				continue
			}
			if gap > max {
				stopped[r.Kind] = true
				continue
			}
		}
		byKind[r.Kind] = append(run, r)
	}
	return byKind
}

// Recent reports whether a pass is within its kind's interval of now, so a
// pass recorded while the lease was expired or long ago never releases.
func Recent(r ProbeRun, now time.Time) bool {
	_, max := ProbeSpacing(r.Kind)
	return !r.JudgedAt.After(now.Add(MaxClockSkew)) && now.Sub(r.JudgedAt) <= max
}

// LatestPass returns the newest result of kind judged after since when it is
// a pass; any newer fail/unknown blocks single-pass release.
func LatestPass(rows []ProbeRun, kind string, since time.Time) (ProbeRun, bool) {
	for _, r := range rows {
		if r.Kind != kind || !r.JudgedAt.After(since) {
			continue
		}
		return r, r.Result == "pass"
	}
	return ProbeRun{}, false
}

// ProbesSatisfy reports whether every kind has at least two consecutive
// verified passes whose newest pass is recent, and, when cited is non-nil,
// whether cited contains exactly the two latest counted passes of every kind.
func ProbesSatisfy(passes map[string][]ProbeRun, kinds, cited []string, now time.Time) bool {
	if len(kinds) == 0 {
		return false
	}
	want := []string{}
	for _, kind := range kinds {
		run := passes[kind]
		if len(run) < RequiredConsecutivePasses {
			return false
		}
		// Recency is per kind (#159): a fresh pass of one kind never stands in
		// for an old pass of another, and passes recorded while a lease was
		// expired or long ago never release a hold.
		if !Recent(run[0], now) {
			return false
		}
		for _, r := range run[:RequiredConsecutivePasses] {
			want = append(want, r.ID)
		}
	}
	if cited == nil {
		return true
	}
	if len(cited) != len(want) {
		return false
	}
	for _, id := range want {
		if !slices.Contains(cited, id) {
			return false
		}
	}
	return true
}
