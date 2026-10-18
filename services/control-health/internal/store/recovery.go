package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// controlHealthSAN requests and owns the holds this controller decides.
const controlHealthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"

// Every writer takes the node advisory lock before hold rows, then node rows:
// node-lock -> holds -> node_boot_generation.
func (s *Store) beginNodeWrite(ctx context.Context) (pgx.Tx, *healthdb.Queries, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, nil, err
	}
	q := healthdb.New(tx)
	if err := q.SetNodeBootstrapLockTimeout(ctx); err != nil {
		rollback(tx)
		return nil, nil, err
	}
	return tx, q, nil
}

// targetBound reports whether the installation maps this SAN to the target;
// certificates carry no target identity (same rule as target leases).
func (s *Store) targetBound(san, target string) bool {
	for _, b := range s.Config.Sources {
		if b.SAN == san && b.ScopeID == target {
			return true
		}
	}
	return false
}

// ReportProbe stores a COMMON probe-results report from the single component
// that owns its kind and scope. A failed node answer probe becomes a
// control-health-owned probe_failed node hold in the same transaction; a pass
// may let control-health release its own transient node holds.
func (s *Store) ReportProbe(ctx context.Context, peer health.Peer, relay health.ProbeRelay, p health.ProbeReport) (health.ProbeAck, error) {
	var ack health.ProbeAck
	scope, scopeID := *p.Scope, *p.ScopeID
	tx, q, err := s.beginNodeWrite(ctx)
	if err != nil {
		return ack, err
	}
	defer rollback(tx)
	reporter, principal, err := probeReporter(ctx, q, peer, relay)
	if err != nil {
		return ack, err
	}
	peer = reporter
	if principal.Component != health.ProbeReporter(p.ProbeKind, scope) || !slices.Contains(principal.AllowedScopes, scope) {
		return ack, health.ErrForbidden
	}
	cert, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN})
	if errors.Is(err, pgx.ErrNoRows) {
		return ack, health.ErrForbidden
	}
	if err != nil {
		return ack, err
	}
	// The issued record of a Pod SAN names the same Pod.
	if peer.PodUID != "" && (!cert.PodUid.Valid || uuid.UUID(cert.PodUid.Bytes).String() != peer.PodUID) {
		return ack, health.ErrForbidden
	}
	params := healthdb.InsertProbeResultParams{Scope: scope, ScopeID: scopeID, ProbeKind: p.ProbeKind, Result: p.Outcome}
	var current healthdb.HealthNodeBootGeneration
	switch scope {
	case "node":
		var node pgtype.UUID
		if err := node.Scan(scopeID); err != nil {
			return ack, health.ErrInvalid
		}
		if p.ProbeKind == "export" {
			// The central audit exporter reports a node's export backlog; it has
			// no node-bound certificate and no boot (#163).
			params.NodeUid = node
			break
		}
		// The certificate binds the reporter to one node (and boot when issued
		// with one); it cannot report another node's probe.
		if cert.NodeUid != node || (cert.BootID.Valid && cert.BootID.String != *p.BootID) {
			return ack, health.ErrForbidden
		}
		if err := q.LockNodeBootstrap(ctx, scopeID); err != nil {
			return ack, err
		}
		current, err = currentNode(ctx, q, node)
		if errors.Is(err, pgx.ErrNoRows) {
			return ack, health.ErrConflict
		}
		if err != nil {
			return ack, err
		}
		if current.BootID != *p.BootID {
			return ack, health.ErrForbidden
		}
		params.NodeUid, params.BootID = node, pgtype.Text{String: current.BootID, Valid: true}
		if slices.Contains(health.NodeProbeKinds, p.ProbeKind) {
			// The answer probe runs in the reporter's own Pod, so its certified
			// namespace is the observed namespace.
			if cert.Namespace != "agent-exec" && cert.Namespace != "agent-adapters" {
				return ack, health.ErrForbidden
			}
			params.Namespace = pgtype.Text{String: cert.Namespace, Valid: true}
		}
	case "target":
		if !s.targetBound(peer.SAN, scopeID) {
			return ack, health.ErrForbidden
		}
	}
	stored := p.EvidenceRefs
	var consumed []string
	if p.Outcome == "pass" && slices.Contains(health.NodeProbeKinds, p.ProbeKind) {
		clock, err := q.Clock(ctx)
		if err != nil {
			return ack, err
		}
		found, err := findAnswerEvidence(ctx, q, cert, current, p.ProbeKind, *p.StimulusAt, clock.Time)
		if err != nil {
			return ack, err
		}
		// Server-found kernel evidence first; the runner's refs stay as context.
		stored, consumed = append(slices.Clone(found), p.EvidenceRefs...), found
		params.StimulusAt = pgtype.Timestamptz{Time: *p.StimulusAt, Valid: true}
	}
	refs, err := json.Marshal(stored)
	if err != nil {
		return ack, err
	}
	params.EvidenceRefs = refs
	row, err := q.InsertProbeResult(ctx, params)
	if err != nil {
		return ack, err
	}
	probeID := uuid.UUID(row.ProbeResultID.Bytes).String()
	// Each kernel event backs at most one pass: a report reusing evidence an
	// earlier probe result consumed is rejected (unique kernel_event_id).
	for _, ref := range consumed {
		id, _ := uuid.Parse(strings.TrimPrefix(ref, "kernel_event:"))
		n, err := q.ConsumeProbeEvidence(ctx, healthdb.ConsumeProbeEvidenceParams{KernelEventID: pgtype.UUID{Bytes: id, Valid: true}, ProbeResultID: row.ProbeResultID})
		if err != nil {
			return ack, err
		}
		if n != 1 {
			return ack, health.ErrConflict
		}
	}
	if scope == "node" && slices.Contains(health.NodeProbeKinds, p.ProbeKind) {
		switch p.Outcome {
		case "fail":
			hold, err := q.ProbeFailedHold(ctx, healthdb.ProbeFailedHoldParams{ScopeID: scopeID, RequestedBy: controlHealthSAN})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return ack, err
			}
			if err == nil {
				if err := s.auditEvidence(ctx, q, "execution_held", map[string]any{"hold_id": uuid.UUID(hold.Bytes).String(), "scope": "node", "scope_id": scopeID, "reason": "probe_failed", "owner_component": health.OwnerComponent}, row.JudgedAt.Time, []string{probeID}); err != nil {
					return ack, err
				}
			}
			if err := setNodeState(ctx, q, current, "held"); err != nil {
				return ack, err
			}
		case "pass":
			if err := s.recoverNode(ctx, q, current, row.JudgedAt.Time); err != nil {
				return ack, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return health.ProbeAck{ProbeResultID: probeID}, nil
}

// probeReporter resolves who reported a probe result (TASK-10 3.2 "relayed
// reporter identity", COMMON probe-reports row).
//
//   - On a connection whose certificate is the registered gateway principal
//     with a current issued certificate, the reporter is the forwarded SAN and
//     serial. Both headers must be present exactly once (else 403), and the SAN
//     must be an agent-exec probe runner Pod SAN: the gateway relays only that
//     caller. The issued record is checked by the caller (Certificate:
//     exact serial and SAN, not revoked, not expired, enabled workload).
//   - On every other connection the two headers are ignored and the reporter
//     is the TLS peer.
//
// A Pod-bound reporter must be a probe runner (agent-exec relayed,
// agent-adapters direct). Its component_principals row is keyed by the KSA's
// service SAN, because every Pod has its own SAN.
func probeReporter(ctx context.Context, q *healthdb.Queries, peer health.Peer, relay health.ProbeRelay) (health.Peer, healthdb.HealthComponentPrincipal, error) {
	var none healthdb.HealthComponentPrincipal
	reporter, relayed := peer, false
	if peer.PodUID == "" {
		principal, err := q.Principal(ctx, peer.SAN)
		if errors.Is(err, pgx.ErrNoRows) {
			return peer, none, health.ErrForbidden
		}
		if err != nil {
			return peer, none, err
		}
		if principal.Component != "gateway" {
			return peer, principal, nil
		}
		if err := requireGateway(ctx, q, peer); err != nil {
			return peer, none, err
		}
		if len(relay.SAN) != 1 || len(relay.Serial) != 1 || relay.Serial[0] == "" || len(relay.Serial[0]) > 128 {
			return peer, none, health.ErrForbidden
		}
		reporter, relayed = health.Peer{SAN: relay.SAN[0], Serial: relay.Serial[0]}, true
	}
	ns, podUID, principalSAN, ok := health.ProbeRunnerSAN(reporter.SAN)
	if !ok || relayed != (ns == "agent-exec") {
		return peer, none, health.ErrForbidden
	}
	reporter.PodUID = podUID
	principal, err := q.Principal(ctx, principalSAN)
	if errors.Is(err, pgx.ErrNoRows) {
		return peer, none, health.ErrForbidden
	}
	if err != nil {
		return peer, none, err
	}
	if principal.Component != health.ProbeRunnerKSA {
		return peer, none, health.ErrForbidden
	}
	return reporter, principal, nil
}

const errnoEACCES = 13

// findAnswerEvidence looks up the stimulus window [t-2s, t+10s] of the
// runner's own Pod containers through the TASK-07 definer function and
// requires the full 3.2 probe table (#179). The runner cannot know sensor
// event IDs, so its refs are never trusted as evidence.
func findAnswerEvidence(ctx context.Context, q *healthdb.Queries, cert healthdb.CertificateRow, current healthdb.HealthNodeBootGeneration, kind string, stimulus, now time.Time) ([]string, error) {
	if stimulus.Before(now.Add(-health.MaxStimulusAge)) || stimulus.After(now.Add(health.MaxClockSkew)) || !cert.PodUid.Valid {
		return nil, health.ErrConflict
	}
	containers, err := q.PodContainers(ctx, healthdb.PodContainersParams{PodUid: cert.PodUid, NodeUid: current.NodeUid, BootID: current.BootID, At: pgtype.Timestamptz{Time: stimulus, Valid: true}})
	if err != nil {
		return nil, err
	}
	if len(containers) == 0 || len(containers) > 16 {
		return nil, health.ErrConflict
	}
	rows, err := q.ProbeEvidence(ctx, healthdb.ProbeEvidenceParams{NodeUid: current.NodeUid, BootID: current.BootID, ContainerIds: containers,
		FromTime: pgtype.Timestamptz{Time: stimulus.Add(-2 * time.Second), Valid: true}, ToTime: pgtype.Timestamptz{Time: stimulus.Add(10 * time.Second), Valid: true}})
	if err != nil {
		return nil, err
	}
	// Events an earlier pass consumed never count again, so replaying a
	// stimulus window or re-citing old events cannot make a second pass.
	ids := make([]pgtype.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.SourceEventID)
	}
	used, err := q.ConsumedProbeEvidence(ctx, ids)
	if err != nil {
		return nil, err
	}
	consumed := map[[16]byte]bool{}
	for _, u := range used {
		consumed[u.Bytes] = true
	}
	refs := []string{}
	has := map[string]bool{}
	tuples := map[string]map[int16]bool{}
	for _, r := range rows {
		if consumed[r.SourceEventID.Bytes] {
			continue
		}
		id := "kernel_event:" + uuid.UUID(r.SourceEventID.Bytes).String()
		tuple := fmt.Sprintf("%s:%d>%s:%d", r.Saddr, r.Sport, r.Daddr, r.Dport)
		used := false
		switch r.EventType {
		case "process_exec", "process_exit":
			used = kind == "process"
			has[r.EventType] = has[r.EventType] || used
		case "tcp_connect":
			if used = kind == "tcp"; used {
				if tuples[tuple] == nil {
					tuples[tuple] = map[int16]bool{}
				}
			}
		case "tcp_state":
			if t, ok := tuples[tuple]; ok && kind == "tcp" {
				t[r.TcpNewState], used = true, true
			}
		case "file_open":
			if used = kind == "file" && r.ReturnValue == 0; used {
				has["file_open_ok"] = true
			}
		case "openat":
			if kind != "file" {
				break
			}
			switch {
			case r.ReturnValue == -errnoEACCES || r.ReturnValue == errnoEACCES:
				has["openat_denied"], used = true, true
			case r.ReturnValue != math.MinInt64 && r.ReturnValue >= 0:
				// Only an explicit non-negative return counts; a missing value
				// never satisfies the allowed-open requirement.
				has["openat_ok"], used = true, true
			}
		}
		if used {
			refs = append(refs, id)
		}
	}
	ok := false
	switch kind {
	case "process":
		ok = has["process_exec"] && has["process_exit"]
	case "tcp":
		for _, states := range tuples {
			ok = ok || states[1] && states[7]
		}
	case "file":
		ok = has["file_open_ok"] && has["openat_ok"] && has["openat_denied"]
	}
	if !ok {
		return nil, health.ErrConflict
	}
	return refs, nil
}

func setNodeState(ctx context.Context, q *healthdb.Queries, current healthdb.HealthNodeBootGeneration, state string) error {
	if current.State == state {
		return nil
	}
	var changed int64
	var err error
	if state == "ready" {
		// Conditional in SQL: never ready while an unreleased node hold exists.
		changed, err = q.SetNodeReady(ctx, healthdb.SetNodeReadyParams{NodeUid: current.NodeUid, BootID: current.BootID})
		if err == nil && changed == 0 {
			return nil
		}
	} else {
		changed, err = q.SetNodeState(ctx, healthdb.SetNodeStateParams{State: state, NodeUid: current.NodeUid, BootID: current.BootID})
	}
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("current node boot changed")
	}
	return nil
}

// nodeLeasesValid requires every required node component to have a live,
// not-unhealthy lease on the current boot (heartbeat resumption is necessary
// but never sufficient for release).
func (s *Store) nodeLeasesValid(ctx context.Context, q *healthdb.Queries, current healthdb.HealthNodeBootGeneration, now time.Time) (bool, error) {
	leases, err := q.ScopeLeases(ctx, healthdb.ScopeLeasesParams{Scope: "node", ScopeID: uuid.UUID(current.NodeUid.Bytes).String()})
	if err != nil {
		return false, err
	}
	required := slices.Clone(health.RequiredPerNode)
	if current.StartupCapture == health.StartupGuarded {
		required = append(required, health.RequiredPerGuardedNode...)
	}
	for _, component := range required {
		ok := false
		for _, l := range leases {
			if l.Component == component && l.BootID.Valid && l.BootID.String == current.BootID && l.LeaseUntil.Time.After(now) && l.ObservedState != health.StateUnhealthy {
				if component == "node-sensors" && (!l.SensorGeneration.Valid || l.SensorGeneration.Int64 != current.SensorGeneration) {
					continue
				}
				ok = true
			}
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// componentLeaseValid requires a live, not-unhealthy lease of the owner in a
// global/target scope (lag normalization or target evidence resumption).
func componentLeaseValid(ctx context.Context, q *healthdb.Queries, scope, id, component string, now time.Time) (bool, error) {
	leases, err := q.ScopeLeases(ctx, healthdb.ScopeLeasesParams{Scope: scope, ScopeID: id})
	if err != nil {
		return false, err
	}
	for _, l := range leases {
		if l.Component == component && l.LeaseUntil.Time.After(now) && l.ObservedState != health.StateUnhealthy {
			return true, nil
		}
	}
	return false, nil
}

func toRuns(rows []healthdb.HealthProbeResult) []health.ProbeRun {
	runs := make([]health.ProbeRun, 0, len(rows))
	for _, r := range rows {
		// Order, consecutiveness and recency use the server judged_at. Answer
		// probe spacing uses stimulus_at, which ReportProbe bounded to server
		// time and backed with consumed kernel events.
		run := health.ProbeRun{ID: uuid.UUID(r.ProbeResultID.Bytes).String(), Kind: r.ProbeKind, Result: r.Result, JudgedAt: r.JudgedAt.Time}
		if r.StimulusAt.Valid && r.Result == "pass" && slices.Contains(health.NodeProbeKinds, r.ProbeKind) {
			run.StimulusAt = r.StimulusAt.Time
		}
		runs = append(runs, run)
	}
	return runs
}

func nodeRuns(ctx context.Context, q *healthdb.Queries, current healthdb.HealthNodeBootGeneration) ([]health.ProbeRun, error) {
	rows, err := q.NodeProbes(ctx, healthdb.NodeProbesParams{NodeUid: current.NodeUid, BootID: pgtype.Text{String: current.BootID, Valid: true}})
	if err != nil {
		return nil, err
	}
	return toRuns(rows), nil
}

// citedPasses lists the two newest counted passes of each kind and the newest
// of them, which becomes the auto release_ref suffix.
func citedPasses(passes map[string][]health.ProbeRun, kinds []string) ([]string, string) {
	ids := []string{}
	var newest health.ProbeRun
	for _, kind := range kinds {
		for _, r := range passes[kind][:health.RequiredConsecutivePasses] {
			ids = append(ids, r.ID)
			if r.JudgedAt.After(newest.JudgedAt) {
				newest = r
			}
		}
	}
	return ids, newest.ID
}

// newestCited is the latest-judged probe among the cited IDs (the auto
// release_ref suffix). Unknown IDs yield the first cited ID, which can never
// match a stored release_ref and fails verification.
func newestCited(runs []health.ProbeRun, cited []string) string {
	var best health.ProbeRun
	for _, r := range runs {
		if slices.Contains(cited, r.ID) && (best.ID == "" || r.JudgedAt.After(best.JudgedAt)) {
			best = r
		}
	}
	if best.ID == "" && len(cited) > 0 {
		return cited[0]
	}
	return best.ID
}

// recoverNode releases control-health's own transient node holds once leases
// are live and each probe kind passed twice consecutively after the hold was
// created, then moves the boot to ready only when no node hold remains.
// The caller holds the node advisory lock.
func (s *Store) recoverNode(ctx context.Context, q *healthdb.Queries, current healthdb.HealthNodeBootGeneration, now time.Time) error {
	id := uuid.UUID(current.NodeUid.Bytes).String()
	leasesOK, err := s.nodeLeasesValid(ctx, q, current, now)
	if err != nil {
		return err
	}
	runs, err := nodeRuns(ctx, q, current)
	if err != nil {
		return err
	}
	holds, err := q.ScopeHolds(ctx, healthdb.ScopeHoldsParams{Scope: "node", ScopeID: id})
	if err != nil {
		return err
	}
	for _, h := range holds {
		passes := health.VerifiedPasses(runs, h.CreatedAt.Time)
		auto := h.OwnerComponent == health.OwnerComponent && (h.Reason == "probe_failed" || h.Reason == "lease_expired")
		if !auto || !leasesOK || !health.ProbesSatisfy(passes, health.NodeProbeKinds, nil, now) {
			continue
		}
		locked, err := q.LockHold(ctx, h.HoldID)
		if err != nil {
			return err
		}
		if locked.ReleasedAt.Valid {
			continue
		}
		cited, newest := citedPasses(passes, health.NodeProbeKinds)
		if _, err := s.release(ctx, q, locked, "auto:"+health.OwnerComponent+":"+newest, controlHealthSAN, "leases live and recent consecutive probe passes after "+locked.Reason, cited, now); err != nil {
			return err
		}
	}
	return s.afterNodeRelease(ctx, q, current, now, leasesOK, runs)
}

// afterNodeRelease keeps the boot held while any node hold remains; otherwise
// it is ready only with live leases and verified probes, else preparing.
func (s *Store) afterNodeRelease(ctx context.Context, q *healthdb.Queries, current healthdb.HealthNodeBootGeneration, now time.Time, leasesOK bool, runs []health.ProbeRun) error {
	holds, err := q.ScopeHolds(ctx, healthdb.ScopeHoldsParams{Scope: "node", ScopeID: uuid.UUID(current.NodeUid.Bytes).String()})
	if err != nil {
		return err
	}
	switch {
	case len(holds) > 0:
		return setNodeState(ctx, q, current, "held")
	case leasesOK && health.ProbesSatisfy(health.VerifiedPasses(runs, time.Time{}), health.NodeProbeKinds, nil, now):
		return setNodeState(ctx, q, current, "ready")
	case current.State == "held":
		return setNodeState(ctx, q, current, "preparing")
	}
	return nil
}

func (s *Store) release(ctx context.Context, q *healthdb.Queries, h healthdb.HealthHold, ref, releasedBy, justification string, refs []string, now time.Time) (time.Time, error) {
	at, err := q.ReleaseHold(ctx, healthdb.ReleaseHoldParams{ReleaseRef: ref, HoldID: h.HoldID})
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, health.ErrConflict
	}
	if err != nil {
		return time.Time{}, err
	}
	if err := s.auditEvidence(ctx, q, "hold_released", map[string]any{"hold_id": uuid.UUID(h.HoldID.Bytes).String(), "release_ref": ref, "released_by": releasedBy, "justification": justification}, now, refs); err != nil {
		return time.Time{}, err
	}
	return at.Time, nil
}

// Recover periodically re-evaluates control-health-owned transient node holds,
// so a lease that resumes after the last passing probe still recovers when a
// recent probe confirms it. Each node commits in its own transaction, so one
// node's failure does not stop the others.
func (s *Store) Recover(ctx context.Context) error {
	holds, err := healthdb.New(s.Pool).OpenAutoNodeHolds(ctx)
	if err != nil {
		return err
	}
	nodes := []string{}
	for _, h := range holds {
		if !slices.Contains(nodes, h.ScopeID) {
			nodes = append(nodes, h.ScopeID)
		}
	}
	slices.Sort(nodes)
	var errs error
	for _, id := range nodes {
		errs = errors.Join(errs, s.recoverOne(ctx, id))
	}
	return errs
}

func (s *Store) recoverOne(ctx context.Context, id string) error {
	var node pgtype.UUID
	if err := node.Scan(id); err != nil {
		return err
	}
	tx, q, err := s.beginNodeWrite(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := q.LockNodeBootstrap(ctx, id); err != nil {
		return err
	}
	current, err := currentNode(ctx, q, node)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, pgx.ErrTooManyRows) {
		return nil // no single authoritative boot: keep the hold
	}
	if err != nil {
		return err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return err
	}
	if err := s.recoverNode(ctx, q, current, clock.Time); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var nodeLocalComponents = []string{"node-sensors", "lifecycle-recorder", "runtime-guard", "probe-runner"}

// lockHoldNode takes the node advisory lock before any hold row lock.
func lockHoldNode(ctx context.Context, q *healthdb.Queries, hid pgtype.UUID) error {
	scope, err := q.HoldScope(ctx, hid)
	if errors.Is(err, pgx.ErrNoRows) {
		return health.ErrNotFound
	}
	if err != nil {
		return err
	}
	if scope.Scope == "node" {
		return q.LockNodeBootstrap(ctx, scope.ScopeID)
	}
	return nil
}

// ReleaseHold implements POST /internal/holds/{hold_id}/release. Owners release
// transient holds only with server-rechecked probe_result_ids; security reasons
// require the console BFF's operator approval. release_ref is server-generated.
func (s *Store) ReleaseHold(ctx context.Context, peer health.Peer, holdID string, r health.ReleaseRequest, console health.ConsoleContext) (health.ReleaseAck, error) {
	var ack health.ReleaseAck
	tx, q, err := s.beginNodeWrite(ctx)
	if err != nil {
		return ack, err
	}
	defer rollback(tx)
	cert, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN})
	if errors.Is(err, pgx.ErrNoRows) {
		return ack, health.ErrForbidden
	}
	if err != nil {
		return ack, err
	}
	var hid pgtype.UUID
	if err := hid.Scan(holdID); err != nil {
		return ack, health.ErrInvalid
	}
	if err := lockHoldNode(ctx, q, hid); err != nil {
		return ack, err
	}
	hold, err := q.LockHold(ctx, hid)
	if errors.Is(err, pgx.ErrNoRows) {
		return ack, health.ErrNotFound
	}
	if err != nil {
		return ack, err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return ack, err
	}
	now := clock.Time
	security := slices.Contains(health.SecurityReasons, hold.Reason)
	var current *healthdb.HealthNodeBootGeneration
	if hold.Scope == "node" {
		var node pgtype.UUID
		_ = node.Scan(hold.ScopeID)
		row, err := currentNode(ctx, q, node)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ack, err
		}
		if err == nil {
			current = &row
		}
	}
	var ref, releasedBy string
	var refs []string
	stored := func() (health.ReleaseAck, error) {
		// A repeated request that would produce the stored release_ref gets the
		// stored response back (the client may have lost the first answer).
		if hold.ReleaseRef.Valid && hold.ReleaseRef.String == ref {
			return health.ReleaseAck{HoldID: holdID, ReleasedAt: hold.ReleasedAt.Time, ReleaseRef: ref}, nil
		}
		return ack, health.ErrConflict
	}
	switch {
	case r.OperatorApproval != nil:
		a := r.OperatorApproval
		// Same authentication as operator_stop: headers only from the identity
		// console BFF connection, operator role and matching actor.
		if !security || peer.SAN != health.ConsoleBFFSAN || !slices.Contains(console.Roles, "operator") || console.Actor == "" || console.Actor != a.AuthenticatedActor ||
			a.ApprovedAt.After(now.Add(health.MaxClockSkew)) || a.ApprovedAt.Before(now.Add(-health.MaxApprovalAge)) {
			return ack, health.ErrForbidden
		}
		ref, releasedBy, refs = "operator:"+a.AuthenticatedActor+":"+a.ConsoleRequestID, a.AuthenticatedActor, slices.Clone(r.EvidenceRefs)
		if hold.ReleasedAt.Valid {
			return stored()
		}
		// One (actor, console_request_id) approves one hold release.
		reused, err := q.OtherReleaseWithRef(ctx, healthdb.OtherReleaseWithRefParams{ReleaseRef: ref, HoldID: hold.HoldID})
		if err != nil {
			return ack, err
		}
		if reused {
			return ack, health.ErrConflict
		}
	default:
		principal, err := q.Principal(ctx, peer.SAN)
		if errors.Is(err, pgx.ErrNoRows) {
			return ack, health.ErrForbidden
		}
		if err != nil {
			return ack, err
		}
		if security || hold.OwnerComponent != principal.Component || !slices.Contains(principal.ReleasableHoldReasons, hold.Reason) {
			return ack, health.ErrForbidden
		}
		// A node-local owner's certificate must be bound to the held node/boot;
		// a target owner must be installed for that target.
		switch {
		case hold.Scope == "node" && slices.Contains(nodeLocalComponents, principal.Component):
			var node pgtype.UUID
			_ = node.Scan(hold.ScopeID)
			if cert.NodeUid != node || (cert.BootID.Valid && (current == nil || cert.BootID.String != current.BootID)) {
				return ack, health.ErrForbidden
			}
		case hold.Scope == "node" && !slices.Contains(principal.AllowedScopes, "node"):
			return ack, health.ErrForbidden
		case hold.Scope == "target" && !s.targetBound(peer.SAN, hold.ScopeID):
			return ack, health.ErrForbidden
		}
		releasedBy = peer.SAN
		if r.ProbeResultIDs == nil {
			// Owner-attested release (#159): the owner's flow verified evidence
			// that probe-results cannot carry.
			if health.AttestedOwners[hold.Reason] != principal.Component {
				return ack, health.ErrConflict
			}
			ref, refs = "attested:"+principal.Component+":"+r.EvidenceRefs[0], slices.Clone(r.EvidenceRefs)
			if hold.ReleasedAt.Valid {
				return stored()
			}
			break
		}
		if !health.AutoReleasable(hold.Scope, hold.Reason) {
			return ack, health.ErrConflict
		}
		kinds, single := health.ReleaseProbeKinds(hold.Scope, hold.Reason)
		var runs []health.ProbeRun
		leasesOK := false
		switch {
		case single:
			// Lag normalization: the owner's global lease is live.
			if leasesOK, err = componentLeaseValid(ctx, q, "global", "*", principal.Component, now); err != nil {
				return ack, err
			}
			rows, err := q.ScopeProbes(ctx, healthdb.ScopeProbesParams{Scope: hold.Scope, ScopeID: hold.ScopeID})
			if err != nil {
				return ack, err
			}
			runs = toRuns(rows)
		case hold.Scope == "node":
			if current == nil {
				return ack, health.ErrConflict
			}
			if leasesOK, err = s.nodeLeasesValid(ctx, q, *current, now); err != nil {
				return ack, err
			}
			if runs, err = nodeRuns(ctx, q, *current); err != nil {
				return ack, err
			}
		default:
			if leasesOK, err = componentLeaseValid(ctx, q, hold.Scope, hold.ScopeID, principal.Component, now); err != nil {
				return ack, err
			}
			rows, err := q.ScopeProbes(ctx, healthdb.ScopeProbesParams{Scope: hold.Scope, ScopeID: hold.ScopeID})
			if err != nil {
				return ack, err
			}
			runs = toRuns(rows)
		}
		ref = "auto:" + principal.Component + ":" + newestCited(runs, r.ProbeResultIDs)
		refs = append(slices.Clone(r.EvidenceRefs), r.ProbeResultIDs...)
		if hold.ReleasedAt.Valid {
			return stored()
		}
		if single {
			pass, ok := health.LatestPass(runs, kinds[0], hold.CreatedAt.Time)
			if !leasesOK || !ok || !health.Recent(pass, now) || len(r.ProbeResultIDs) != 1 || r.ProbeResultIDs[0] != pass.ID {
				return ack, health.ErrConflict
			}
		} else {
			passes := health.VerifiedPasses(runs, hold.CreatedAt.Time)
			if !leasesOK || !health.ProbesSatisfy(passes, kinds, r.ProbeResultIDs, now) {
				return ack, health.ErrConflict
			}
		}
	}
	at, err := s.release(ctx, q, hold, ref, releasedBy, r.Justification, refs, now)
	if err != nil {
		return ack, err
	}
	if current != nil {
		leasesOK, err := s.nodeLeasesValid(ctx, q, *current, now)
		if err != nil {
			return ack, err
		}
		runs, err := nodeRuns(ctx, q, *current)
		if err != nil {
			return ack, err
		}
		if err := s.afterNodeRelease(ctx, q, *current, now, leasesOK, runs); err != nil {
			return ack, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return health.ReleaseAck{HoldID: holdID, ReleasedAt: at, ReleaseRef: ref}, nil
}
