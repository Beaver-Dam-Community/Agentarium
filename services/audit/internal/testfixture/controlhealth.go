package testfixture

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ControlHealth is a contract-enforcing stand-in for the TASK-10 control-health
// API surfaces TASK-07 calls. It is not the TASK-10 implementation. It enforces:
//
//   - COMMON ControlHealthLease wire and the caller/component binding
//     (audit-writer -> audit-db, audit-exporter -> audit-export);
//   - POST /internal/holds {scope, scope_id, reason, evidence_refs}, where
//     export_lag may come only from audit-exporter and audit_integrity only
//     from audit-verifier at global scope; other callers get 403 rejected;
//     an open (scope, scope_id, reason) returns decision=existing;
//   - POST /internal/control-health/probe-results in the COMMON wire
//     {probe_kind, scope?, scope_id?, node_uid?, boot_id?, outcome,
//     evidence_refs}; export probes need audit-exporter, a scope matching the
//     hold scopes, node_uid exactly for node scope, and evidence for pass;
//   - POST /internal/holds/{hold_id}/release in the TASK-10 §3.2 form
//     {justification, evidence_refs, probe_result_ids?, operator_approval?}:
//     automatic release by the owning component requires passing probe
//     results of the same scope reported after the hold; the server builds
//     release_ref = auto:<component>:<probe_result_id>. Exactly as #159: an
//     unknown hold is 404; a repeated request whose release_ref equals the
//     stored one gets the stored 200; any other request for a released hold
//     and insufficient evidence are 409 with empty reason_codes; owner or
//     operator verification failure is 403; both optional fields is 422.
//     Security reasons (audit_integrity) need operator approval;
//   - GET /internal/holds?owner_component= (#177): the caller's SAN must map to
//     that component, which must have releasable reasons; only its own open
//     holds with a releasable reason are listed.
type ControlHealth struct {
	URL    string
	mu     sync.Mutex
	leases []Lease
	holds  map[string]*Hold
	probes map[string]Probe
	// Rejected counts requests refused by the contract checks.
	Rejected     int
	listCalls    int
	failListings int
	releaseCalls map[string]int
	refuse       map[string]bool
}

// RefuseEvidence makes release of an open hold answer 409 (insufficient
// evidence), as #159 does when the cited probe does not satisfy the server.
func (f *ControlHealth) RefuseEvidence(id string, on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse == nil {
		f.refuse = map[string]bool{}
	}
	f.refuse[id] = on
}

type Lease struct {
	Caller        string
	Component     string
	ObservedState string
}

type Hold struct {
	ID, Scope, ScopeID, Reason, Owner string
	EvidenceRefs                      []string
	CreatedAt                         time.Time
	ReleasedAt                        *time.Time
	ReleaseRef                        string
	Justification                     string
}

type Probe struct {
	ID, Caller, Kind, Scope, ScopeID, NodeUID, Outcome string
	EvidenceRefs                                       []string
	At                                                 time.Time
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var componentSAN = map[string]string{"audit-db": WriterSAN, "audit-export": ExporterSAN}

// releasable mirrors component_principals.releasable_hold_reasons.
var releasable = map[string][]string{"audit-export": {"export_lag"}, "audit-db": {"db_unavailable"}}

func NewControlHealth(t *testing.T, p *PKI) *ControlHealth {
	t.Helper()
	cert, _, _ := p.Issue(t, "control-health", ControlHealthSAN, false, x509.ExtKeyUsageServerAuth)
	f := &ControlHealth{holds: map[string]*Hold{}, probes: map[string]Probe{}, releaseCalls: map[string]int{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: p.Roots}
	server.StartTLS()
	t.Cleanup(server.Close)
	f.URL = server.URL
	return f
}

func strictDecode(r *http.Request, v any) bool {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(v) == nil && !d.More()
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *ControlHealth) reject(w http.ResponseWriter, code int, reason string) {
	f.mu.Lock()
	f.Rejected++
	f.mu.Unlock()
	reply(w, code, map[string]any{"reason_codes": []string{reason}})
}

func (f *ControlHealth) serve(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 {
		f.reject(w, 401, "AUTH_REQUIRED")
		return
	}
	caller := r.TLS.PeerCertificates[0].URIs[0].String()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/internal/control-health/leases":
		f.lease(w, r, caller)
	case r.Method == http.MethodGet && r.URL.Path == "/internal/holds":
		f.list(w, r, caller)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/holds":
		f.hold(w, r, caller)
	case r.Method == http.MethodPost && r.URL.Path == "/internal/control-health/probe-results":
		f.probe(w, r, caller)
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/internal/holds/") && strings.HasSuffix(r.URL.Path, "/release"):
		f.release(w, r, caller, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/internal/holds/"), "/release"))
	default:
		f.reject(w, 404, "RESOURCE_NOT_FOUND")
	}
}

func (f *ControlHealth) lease(w http.ResponseWriter, r *http.Request, caller string) {
	var l struct {
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
	if !strictDecode(r, &l) || l.SourceID == "" || l.Scope != "global" || l.ScopeID != "*" || l.LeaseUntil.IsZero() || (l.ObservedState != "healthy" && l.ObservedState != "degraded" && l.ObservedState != "unhealthy") {
		f.reject(w, 422, "SCHEMA_INVALID")
		return
	}
	if componentSAN[l.Component] != caller {
		f.reject(w, 403, "HOLD_REQUEST_DENIED")
		return
	}
	f.mu.Lock()
	f.leases = append(f.leases, Lease{Caller: caller, Component: l.Component, ObservedState: l.ObservedState})
	f.mu.Unlock()
	reply(w, 200, map[string]any{"lease_until": l.LeaseUntil, "scope_state": l.ObservedState})
}

func validScope(scope, id string) bool {
	switch scope {
	case "global":
		return id == "*"
	case "node":
		return uuidPattern.MatchString(id)
	case "workload", "target", "session":
		return id != ""
	}
	return false
}

func (f *ControlHealth) hold(w http.ResponseWriter, r *http.Request, caller string) {
	var req struct {
		Scope           string           `json:"scope"`
		ScopeID         string           `json:"scope_id"`
		Reason          string           `json:"reason"`
		EvidenceRefs    []string         `json:"evidence_refs"`
		OperatorRequest *json.RawMessage `json:"operator_request"`
	}
	if !strictDecode(r, &req) || !validScope(req.Scope, req.ScopeID) || req.EvidenceRefs == nil || req.OperatorRequest != nil {
		f.reject(w, 422, "SCHEMA_INVALID")
		return
	}
	owner := ""
	switch {
	case req.Reason == "export_lag" && caller == ExporterSAN && (req.Scope == "global" || req.Scope == "node"):
		owner = "audit-export"
	case req.Reason == "audit_integrity" && caller == VerifierSAN && req.Scope == "global" && len(req.EvidenceRefs) > 0:
		owner = "control-health" // security reason: operator approval releases it
	default:
		f.mu.Lock()
		f.Rejected++
		f.mu.Unlock()
		reply(w, 403, map[string]any{"hold_id": nil, "decision": "rejected", "reason_codes": []string{"HOLD_REQUEST_DENIED"}})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.holds {
		if h.ReleasedAt == nil && h.Scope == req.Scope && h.ScopeID == req.ScopeID && h.Reason == req.Reason {
			reply(w, 200, map[string]any{"hold_id": h.ID, "decision": "existing", "reason_codes": []string{}})
			return
		}
	}
	h := &Hold{ID: uuid.NewString(), Scope: req.Scope, ScopeID: req.ScopeID, Reason: req.Reason, Owner: owner, EvidenceRefs: req.EvidenceRefs, CreatedAt: time.Now()}
	f.holds[h.ID] = h
	reply(w, 200, map[string]any{"hold_id": h.ID, "decision": "created", "reason_codes": []string{}})
}

func (f *ControlHealth) probe(w http.ResponseWriter, r *http.Request, caller string) {
	var req struct {
		ProbeKind    string   `json:"probe_kind"`
		Scope        *string  `json:"scope"`
		ScopeID      *string  `json:"scope_id"`
		NodeUID      *string  `json:"node_uid"`
		BootID       *string  `json:"boot_id"`
		Outcome      string   `json:"outcome"`
		EvidenceRefs []string `json:"evidence_refs"`
	}
	if !strictDecode(r, &req) || req.EvidenceRefs == nil || (req.Outcome != "pass" && req.Outcome != "fail" && req.Outcome != "unknown") {
		f.reject(w, 422, "SCHEMA_INVALID")
		return
	}
	switch req.ProbeKind {
	case "export":
		if caller != ExporterSAN {
			f.reject(w, 403, "HOLD_REQUEST_DENIED")
			return
		}
		if req.Scope == nil || req.ScopeID == nil || !validScope(*req.Scope, *req.ScopeID) || (*req.Scope != "global" && *req.Scope != "node") ||
			(*req.Scope == "node") != (req.NodeUID != nil) || (req.NodeUID != nil && *req.NodeUID != *req.ScopeID) || req.BootID != nil ||
			(req.Outcome == "pass" && len(req.EvidenceRefs) == 0) {
			f.reject(w, 422, "SCHEMA_INVALID")
			return
		}
	case "process", "tcp", "file", "receipt":
		f.reject(w, 403, "HOLD_REQUEST_DENIED") // not a TASK-07 probe
		return
	default:
		f.reject(w, 422, "SCHEMA_INVALID")
		return
	}
	p := Probe{ID: uuid.NewString(), Caller: caller, Kind: req.ProbeKind, Scope: *req.Scope, ScopeID: *req.ScopeID, Outcome: req.Outcome, EvidenceRefs: req.EvidenceRefs, At: time.Now()}
	if req.NodeUID != nil {
		p.NodeUID = *req.NodeUID
	}
	f.mu.Lock()
	f.probes[p.ID] = p
	f.mu.Unlock()
	reply(w, 200, map[string]any{"probe_result_id": p.ID})
}

func (f *ControlHealth) release(w http.ResponseWriter, r *http.Request, caller, id string) {
	var req struct {
		Justification    string           `json:"justification"`
		EvidenceRefs     []string         `json:"evidence_refs"`
		ProbeResultIDs   []string         `json:"probe_result_ids"`
		OperatorApproval *json.RawMessage `json:"operator_approval"`
	}
	requestID := uuid.NewString()
	fail := func(code int, reason string) {
		f.Rejected++
		codes := []string{}
		if reason != "" {
			codes = append(codes, reason)
		}
		reply(w, code, map[string]any{"request_id": requestID, "reason_codes": codes})
	}
	if !strictDecode(r, &req) || req.Justification == "" || req.EvidenceRefs == nil || (req.ProbeResultIDs != nil && req.OperatorApproval != nil) {
		f.mu.Lock()
		fail(422, "SCHEMA_INVALID") // #159: both optional fields together is 422
		f.mu.Unlock()
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls[id]++
	h, ok := f.holds[id]
	if !ok {
		fail(404, "RESOURCE_NOT_FOUND")
		return
	}
	// Owner/operator verification failures are 403 (#159). Security reasons
	// need the console operator path, which this fake does not serve.
	if h.Reason != "export_lag" || h.Owner != "audit-export" || caller != componentSAN[h.Owner] || req.OperatorApproval != nil {
		fail(403, "")
		return
	}
	wouldBe := ""
	if len(req.ProbeResultIDs) > 0 {
		wouldBe = "auto:" + h.Owner + ":" + req.ProbeResultIDs[0]
	}
	if h.ReleasedAt != nil {
		// #159: a repeated request yielding the stored release_ref gets the
		// stored response; any other request for a released hold is 409.
		if wouldBe != "" && wouldBe == h.ReleaseRef {
			reply(w, 200, map[string]any{"hold_id": h.ID, "released_at": *h.ReleasedAt, "release_ref": h.ReleaseRef})
			return
		}
		fail(409, "")
		return
	}
	// Insufficient evidence (no probe results, or not a passing export probe
	// of the same scope judged after the hold) is 409, not 403 (#159).
	if len(req.ProbeResultIDs) == 0 || f.refuse[h.ID] {
		fail(409, "")
		return
	}
	for _, pid := range req.ProbeResultIDs {
		p, ok := f.probes[pid]
		if !ok || p.Kind != "export" || p.Outcome != "pass" || p.Caller != caller || p.Scope != h.Scope || p.ScopeID != h.ScopeID || p.At.Before(h.CreatedAt) {
			fail(409, "")
			return
		}
	}
	now := time.Now().UTC()
	h.ReleasedAt, h.ReleaseRef, h.Justification = &now, wouldBe, req.Justification
	reply(w, 200, map[string]any{"hold_id": h.ID, "released_at": now, "release_ref": h.ReleaseRef})
}

// Snapshot returns copies of the recorded leases, holds and probe results.
func (f *ControlHealth) Snapshot() ([]Lease, []Hold, []Probe) {
	f.mu.Lock()
	defer f.mu.Unlock()
	leases := append([]Lease(nil), f.leases...)
	var holds []Hold
	for _, h := range f.holds {
		holds = append(holds, *h)
	}
	var probes []Probe
	for _, p := range f.probes {
		probes = append(probes, p)
	}
	return leases, holds, probes
}

// HealthyLeases counts healthy reports for a component.
func (f *ControlHealth) HealthyLeases(component string) int {
	leases, _, _ := f.Snapshot()
	n := 0
	for _, l := range leases {
		if l.Component == component && l.ObservedState == "healthy" {
			n++
		}
	}
	return n
}

func (f *ControlHealth) list(w http.ResponseWriter, r *http.Request, caller string) {
	f.mu.Lock()
	f.listCalls++
	if f.failListings > 0 {
		f.failListings--
		f.mu.Unlock()
		reply(w, 503, map[string]any{"reason_codes": []string{"DEPENDENCY_UNAVAILABLE"}})
		return
	}
	f.mu.Unlock()
	q := r.URL.Query()
	component := q.Get("owner_component")
	if component == "" || len(q) != 1 {
		f.reject(w, 422, "SCHEMA_INVALID")
		return
	}
	if componentSAN[component] != caller || len(releasable[component]) == 0 {
		f.mu.Lock()
		f.Rejected++
		f.mu.Unlock()
		reply(w, 403, map[string]any{"reason_codes": []string{"HOLD_REQUEST_DENIED"}})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []map[string]any{}
	for _, h := range f.holds {
		if h.ReleasedAt != nil || h.Owner != component {
			continue
		}
		for _, reason := range releasable[component] {
			if h.Reason == reason {
				out = append(out, map[string]any{"hold_id": h.ID, "scope": h.Scope, "scope_id": h.ScopeID, "reason": h.Reason, "owner_component": h.Owner, "created_at": h.CreatedAt})
			}
		}
	}
	reply(w, 200, map[string]any{"holds": out})
}

// SeedHold stores an open hold as if another request created it earlier.
func (f *ControlHealth) SeedHold(scope, scopeID, reason, owner string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	h := &Hold{ID: uuid.NewString(), Scope: scope, ScopeID: scopeID, Reason: reason, Owner: owner, EvidenceRefs: []string{}, CreatedAt: time.Now()}
	f.holds[h.ID] = h
	return h.ID
}

// FailListings makes the next n owned-hold listings return 503.
func (f *ControlHealth) FailListings(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failListings = n
}

// ListCalls counts owned-hold listing requests.
func (f *ControlHealth) ListCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

// ReleaseCalls counts release requests for a hold.
func (f *ControlHealth) ReleaseCalls(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.releaseCalls[id]
}

// HoldByID returns a copy of one hold.
func (f *ControlHealth) HoldByID(id string) (Hold, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.holds[id]
	if !ok {
		return Hold{}, false
	}
	return *h, true
}
