// Package store owns the transactional health facts and TASK-07 audit adapter.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SourceBinding struct {
	SourceID string `json:"source_id"`
	SAN      string `json:"san"`
	ScopeID  string `json:"scope_id"`
}
type Config struct {
	Sources        []SourceBinding `json:"sources"`
	Readers        []string        `json:"readers"`
	GuardedProfile bool            `json:"guarded_profile"`
	AuditSourceID  string          `json:"audit_source_id"`
	Version        string          `json:"version"`
	// Environment is the release.active_policy scope_id whose epoch a
	// work-readiness check pins (TASK-10 3.5a). Empty disables readiness.
	Environment string `json:"environment,omitempty"`
}
type Store struct {
	Pool      *pgxpool.Pool
	Config    Config
	Epoch     string
	NodeFacts NodeFactsSource
}

func New(pool *pgxpool.Pool, cfg Config) (*Store, error) {
	if cfg.AuditSourceID == "" || cfg.Version == "" {
		return nil, errors.New("audit source/version required")
	}
	seen := map[string]bool{}
	for _, b := range cfg.Sources {
		if b.SourceID == "" || b.SAN == "" || b.ScopeID == "" || seen[b.SourceID] {
			return nil, errors.New("invalid source binding")
		}
		seen[b.SourceID] = true
	}
	return &Store{Pool: pool, Config: cfg}, nil
}
func (s *Store) allowedSource(peer health.Peer, l health.Lease, cert healthdb.CertificateRow) bool {
	switch l.Scope {
	case "global":
		return l.ScopeID == "*"
	case "node":
		// A node lease source is per node (`<component>-node/<node_uid>`), so
		// one node's certificate can neither report nor cover another node.
		return cert.NodeUid.Valid && l.ScopeID == uuid.UUID(cert.NodeUid.Bytes).String() && health.NodeSourceID(l.SourceID, l.ScopeID)
	case "workload":
		return l.ScopeID == cert.Namespace+"/"+cert.Ksa
	}
	// Target identities have no certified target binding; keep the explicit
	// installation mapping for these scopes only.
	for _, b := range s.Config.Sources {
		if b.SourceID == l.SourceID && b.SAN == peer.SAN && b.ScopeID == l.ScopeID {
			return true
		}
	}
	return false
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func (s *Store) Put(ctx context.Context, peer health.Peer, l health.Lease) (health.LeaseAck, error) {
	var ack health.LeaseAck
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return ack, err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	principal, err := q.Principal(ctx, peer.SAN)
	if errors.Is(err, pgx.ErrNoRows) {
		return ack, health.ErrForbidden
	}
	if err != nil {
		return ack, err
	}
	if principal.Component != l.Component || !slices.Contains(principal.AllowedScopes, l.Scope) {
		return ack, health.ErrForbidden
	}
	cert, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN})
	if errors.Is(err, pgx.ErrNoRows) {
		return ack, health.ErrForbidden
	}
	if err != nil {
		return ack, err
	}
	if !s.allowedSource(peer, l, cert) {
		return ack, health.ErrForbidden
	}
	var node pgtype.UUID
	var boot pgtype.Text
	startup := health.StartupUnsupported
	if l.Scope == "node" {
		_ = node.Scan(l.ScopeID)
		if cert.NodeUid != node || !cert.BootID.Valid {
			return ack, health.ErrForbidden
		}
		// node-lock -> holds -> node_boot_generation, as in hold writers.
		if err := q.SetNodeBootstrapLockTimeout(ctx); err != nil {
			return ack, err
		}
		if err := q.LockNodeBootstrap(ctx, l.ScopeID); err != nil {
			return ack, err
		}
		current, err := currentNode(ctx, q, node)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && current.BootID != cert.BootID.String) {
			current, err = s.bootstrapNode(ctx, q, cert, l)
		}
		if err != nil {
			return ack, err
		}
		boot = cert.BootID
		startup = current.StartupCapture
		if l.Component == "node-sensors" && (l.SensorGeneration == nil || *l.SensorGeneration != current.SensorGeneration) {
			return ack, health.ErrForbidden
		}
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return ack, err
	}
	until, err := health.Expiry(l, clock.Time)
	if err != nil {
		return ack, err
	}
	previous, err := q.ExistingLease(ctx, healthdb.ExistingLeaseParams{SourceID: l.SourceID, Component: l.Component})
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ack, err
	}
	details, _ := json.Marshal(map[string]any{"principal_san": peer.SAN, "certificate_serial": peer.Serial, "canonical_version": l.CanonicalVersion})
	changed, err := q.PutLease(ctx, healthdb.PutLeaseParams{SourceID: l.SourceID, Component: l.Component, Scope: l.Scope, ScopeID: l.ScopeID, NodeUid: node, BootID: boot, LoadedArtifactDigest: text(l.LoadedArtifactDigest), ActiveVersion: text(l.ActiveVersion), ActiveBundleRevision: text(l.ActiveBundleRevision), SensorGeneration: number(l.SensorGeneration), ObservedState: l.ObservedState, Details: details, LeaseUntil: timestamp(until), ReportedAt: timestamp(l.ReportedAt)})
	if err != nil {
		return ack, err
	}
	if changed != 1 {
		return ack, health.ErrInvalid
	}
	if exists && !previous.LeaseUntil.Time.After(clock.Time) && l.Component != health.ComponentNetpol &&
		(l.Component != health.ComponentStartCoord || s.Config.GuardedProfile) &&
		(l.Scope != "node" || previous.BootID == boot) {
		peers, err := q.ScopeLeases(ctx, healthdb.ScopeLeasesParams{Scope: l.Scope, ScopeID: l.ScopeID})
		if err != nil {
			return ack, err
		}
		covered := false
		for _, p := range peers {
			// Node scope has exactly one source per component and node; another
			// row on the node is never coverage for an expired one.
			if l.Scope != "node" && p.SourceID != l.SourceID && p.Component == l.Component && p.LeaseUntil.Time.After(clock.Time) && p.ObservedState != "unhealthy" && p.BootID == boot {
				covered = true
			}
		}
		required := slices.Contains(health.RequiredGlobal, l.Component) || slices.Contains(health.RequiredPerNode, l.Component) || (l.Component == health.ComponentRuntimeGrd && startup == health.StartupGuarded) || l.Component == "adapter" || l.Component == "destination-evidence" || (l.Component == "start-coordinator" && s.Config.GuardedProfile)
		if required && !covered {
			hold, err := q.ExpiryHold(ctx, healthdb.ExpiryHoldParams{Scope: l.Scope, ScopeID: l.ScopeID, RequestedBy: "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return ack, err
			}
			if err == nil {
				if err := s.audit(ctx, q, "execution_held", map[string]any{"hold_id": uuid.UUID(hold.HoldID.Bytes).String(), "scope": l.Scope, "scope_id": l.ScopeID, "reason": "lease_expired", "owner_component": "control-health"}, clock.Time); err != nil {
					return ack, err
				}
				if err := markExpiryNodeHeld(ctx, q, l.Scope, node); err != nil {
					return ack, err
				}
			}
		}
	}
	if exists && previous.ObservedState != l.ObservedState {
		if err := s.audit(ctx, q, "source_health_changed", map[string]any{"source_id": l.SourceID, "scope": l.Scope, "from_state": previous.ObservedState, "to_state": l.ObservedState, "lease_until": until.UTC().Format(time.RFC3339Nano)}, clock.Time); err != nil {
			return ack, err
		}
	}
	snapshot, err := s.snapshot(ctx, q, l.Scope, l.ScopeID, clock.Time)
	if err != nil {
		return ack, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return health.LeaseAck{LeaseUntil: until, ScopeState: snapshot.State}, nil
}
func (s *Store) Get(ctx context.Context, peer health.Peer, scope, id string) (health.Snapshot, error) {
	var empty health.Snapshot
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	cert, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN})
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, health.ErrForbidden
	}
	if err != nil {
		return empty, err
	}
	principal, principalErr := q.Principal(ctx, peer.SAN)
	if principalErr != nil && !errors.Is(principalErr, pgx.ErrNoRows) {
		return empty, principalErr
	}
	if principal.Component == "node-sensors" || !slices.Contains(s.Config.Readers, peer.SAN) {
		if errors.Is(principalErr, pgx.ErrNoRows) {
			return empty, health.ErrForbidden
		}
		if principal.Component != "node-sensors" || scope != "node" || !cert.NodeUid.Valid || uuid.UUID(cert.NodeUid.Bytes).String() != id {
			return empty, health.ErrForbidden
		}
		current, err := currentNode(ctx, q, cert.NodeUid)
		if err != nil {
			return empty, err
		}
		if !cert.BootID.Valid || current.BootID != cert.BootID.String {
			return empty, health.ErrForbidden
		}
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return empty, err
	}
	snapshot, err := s.snapshot(ctx, q, scope, id, clock.Time)
	if err != nil {
		return empty, err
	}
	if principal.Component == "node-sensors" {
		// Only the node's own sensors see its nonces (TASK-10 chapter 4).
		snapshot.PendingWorkerObservationChallenges, snapshot.PendingWorkReadinessChallenges, err = nodeChallenges(ctx, tx, id, cert.BootID.String)
		if err != nil {
			return empty, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, err
	}
	return snapshot, nil
}
func (s *Store) snapshot(ctx context.Context, q *healthdb.Queries, scope, id string, now time.Time) (health.Snapshot, error) {
	result := health.Snapshot{Scope: scope, ScopeID: id, EvaluatedAt: now, Leases: []health.LeaseStatus{}, MissingComponents: []string{}, OpenHolds: []health.Hold{}, Probes: []health.Probe{}, OpenGaps: []health.Gap{}, BundleAck: json.RawMessage("null"), PendingWorkReadinessChallenges: []json.RawMessage{}, PendingWorkerObservationChallenges: []json.RawMessage{}}
	var current *healthdb.HealthNodeBootGeneration
	if scope == "node" {
		var node pgtype.UUID
		_ = node.Scan(id)
		row, err := currentNode(ctx, q, node)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		if err == nil {
			current = &row
			result.StartupCapture = &row.StartupCapture
		}
	}
	leases, err := q.ScopeLeases(ctx, healthdb.ScopeLeasesParams{Scope: scope, ScopeID: id})
	if err != nil {
		return result, err
	}
	for _, l := range leases {
		if scope == "node" && (current == nil || !l.BootID.Valid || l.BootID.String != current.BootID) {
			continue
		}
		var details struct {
			CanonicalVersion *string `json:"canonical_version"`
		}
		if err := json.Unmarshal(l.Details, &details); err != nil {
			return result, err
		}
		result.Leases = append(result.Leases, health.LeaseStatus{Lease: health.Lease{SourceID: l.SourceID, Component: l.Component, Scope: l.Scope, ScopeID: l.ScopeID, ActiveVersion: strptr(l.ActiveVersion), ActiveBundleRevision: strptr(l.ActiveBundleRevision), LoadedArtifactDigest: strptr(l.LoadedArtifactDigest), CanonicalVersion: details.CanonicalVersion, SensorGeneration: intptr(l.SensorGeneration), LeaseUntil: l.LeaseUntil.Time, ObservedState: l.ObservedState, ReportedAt: l.ReportedAt.Time}, BootID: strptr(l.BootID)})
	}
	holds, err := q.ScopeHolds(ctx, healthdb.ScopeHoldsParams{Scope: scope, ScopeID: id})
	if err != nil {
		return result, err
	}
	for _, h := range holds {
		result.OpenHolds = append(result.OpenHolds, health.Hold{HoldID: uuid.UUID(h.HoldID.Bytes).String(), Scope: h.Scope, ScopeID: h.ScopeID, Reason: h.Reason, OwnerComponent: h.OwnerComponent, CreatedAt: h.CreatedAt.Time})
	}
	if current != nil {
		probes, err := q.NodeProbes(ctx, healthdb.NodeProbesParams{NodeUid: current.NodeUid, BootID: pgtype.Text{String: current.BootID, Valid: true}})
		if err != nil {
			return result, err
		}
		// Count only the current consecutive run, never bridge >60s+clock-skew gaps.
		byKind := map[string][]healthdb.HealthProbeResult{}
		for _, p := range probes {
			byKind[p.ProbeKind] = append(byKind[p.ProbeKind], p)
		}
		for _, kind := range []string{"process", "tcp", "file", "export", "receipt"} {
			rows := byKind[kind]
			if len(rows) == 0 {
				continue
			}
			latest := rows[0]
			passes := 0
			last := latest.JudgedAt.Time
			for _, p := range rows {
				if p.Result != "pass" || last.Sub(p.JudgedAt.Time) > 62*time.Second {
					break
				}
				passes++
				last = p.JudgedAt.Time
			}
			at := latest.JudgedAt.Time
			result.Probes = append(result.Probes, health.Probe{ProbeKind: kind, LastJudgedAt: &at, LastResult: latest.Result, ConsecutivePasses: passes, BootID: strptr(latest.BootID)})
		}
		gaps, err := q.NodeGaps(ctx, healthdb.NodeGapsParams{NodeUid: current.NodeUid, BootID: text(&current.BootID)})
		if err != nil {
			return result, err
		}
		for _, g := range gaps {
			result.OpenGaps = append(result.OpenGaps, health.Gap{GapID: uuid.UUID(g.GapID.Bytes).String(), Stage: g.Stage, StartAt: g.StartAt.Time})
		}
	}
	health.Evaluate(&result, s.Config.GuardedProfile)
	return result, nil
}
func (s *Store) Expire(ctx context.Context) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	// Take node locks (sorted) before any lease or hold row lock.
	if err := q.SetNodeBootstrapLockTimeout(ctx); err != nil {
		return err
	}
	lockedNodes, err := q.ExpiredLeaseNodes(ctx)
	if err != nil {
		return err
	}
	for _, id := range lockedNodes {
		if err := q.LockNodeBootstrap(ctx, id); err != nil {
			return err
		}
	}
	leases, err := q.ExpiredLeases(ctx)
	if err != nil {
		return err
	}
	now, err := q.Clock(ctx)
	if err != nil {
		return err
	}
	for _, l := range leases {
		required := false
		switch l.Scope {
		case "global":
			required = slices.Contains(health.RequiredGlobal, l.Component) || (s.Config.GuardedProfile && l.Component == "start-coordinator")
		case "node":
			required = slices.Contains(health.RequiredPerNode, l.Component)
			if l.Component == "runtime-guard" {
				node, err := currentNode(ctx, q, l.NodeUid)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) {
					return err
				}
				required = err == nil && node.StartupCapture == health.StartupGuarded
			}
		case "workload":
			required = l.Component == "adapter"
		case "target":
			required = l.Component == "destination-evidence"
		}
		if !required {
			continue
		}
		if l.Scope == "node" {
			// A lease that expired after the node locks were taken waits for
			// the next tick rather than writing a hold without its node lock.
			if !l.NodeUid.Valid || !slices.Contains(lockedNodes, uuid.UUID(l.NodeUid.Bytes).String()) {
				continue
			}
			node, err := currentNode(ctx, q, l.NodeUid)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if !l.BootID.Valid || l.BootID.String != node.BootID {
				continue
			}
		}
		// A retired replica must not create a new hold while another valid replica
		// of the same required component covers this scope.
		peers, err := q.ScopeLeases(ctx, healthdb.ScopeLeasesParams{Scope: l.Scope, ScopeID: l.ScopeID})
		if err != nil {
			return err
		}
		covered := false
		for _, p := range peers {
			// Node scope has one source per component and node (see Put).
			if l.Scope != "node" && p.Component == l.Component && p.LeaseUntil.Time.After(now.Time) && p.ObservedState != "unhealthy" && p.BootID == l.BootID {
				covered = true
			}
		}
		if covered {
			continue
		}
		h, err := q.ExpiryHold(ctx, healthdb.ExpiryHoldParams{Scope: l.Scope, ScopeID: l.ScopeID, RequestedBy: "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"})
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return err
		}
		if err := s.audit(ctx, q, "execution_held", map[string]any{"hold_id": uuid.UUID(h.HoldID.Bytes).String(), "scope": l.Scope, "scope_id": l.ScopeID, "reason": "lease_expired", "owner_component": "control-health"}, now.Time); err != nil {
			return err
		}
		if err := s.audit(ctx, q, "source_health_changed", map[string]any{"source_id": l.SourceID, "scope": l.Scope, "from_state": l.ObservedState, "to_state": "unhealthy", "lease_until": l.LeaseUntil.Time.UTC().Format(time.RFC3339Nano)}, now.Time); err != nil {
			return err
		}
		if err := markExpiryNodeHeld(ctx, q, l.Scope, l.NodeUid); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// markExpiryNodeHeld records COMMON's node_boot_generation "held" state for a
// new node-scope lease_expired hold, in the hold's transaction.
func markExpiryNodeHeld(ctx context.Context, q *healthdb.Queries, scope string, node pgtype.UUID) error {
	if scope != "node" {
		return nil
	}
	current, err := currentNode(ctx, q, node)
	if err != nil {
		return err
	}
	return setNodeState(ctx, q, current, "held")
}
func (s *Store) audit(ctx context.Context, q *healthdb.Queries, kind string, payload map[string]any, now time.Time) error {
	return s.auditEvidence(ctx, q, kind, payload, now, []string{})
}
func (s *Store) auditEvidence(ctx context.Context, q *healthdb.Queries, kind string, payload map[string]any, now time.Time, refs []string) error {
	if s.Epoch == "" {
		return errors.New("producer epoch unavailable")
	}
	event := map[string]any{"event_id": uuid.NewString(), "event_type": kind, "tenant": "*", "source_id": s.Config.AuditSourceID, "source_version": s.Config.Version, "source_epoch": s.Epoch, "source_sequence": nil, "source_time": now.UTC().Format(time.RFC3339Nano), "schema_version": 1, "safe_payload": payload, "evidence_refs": refs}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return err
	}
	event["payload_digest"] = digest
	raw, err = json.Marshal(event)
	if err != nil {
		return err
	}
	result, err := q.AppendAudit(ctx, raw)
	if err != nil {
		return err
	}
	if result != "created" {
		return errors.New("health audit append did not create event")
	}
	return nil
}
func text(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}
func number(n *int64) pgtype.Int8 {
	if n == nil {
		return pgtype.Int8{}
	}
	return pgtype.Int8{Int64: *n, Valid: true}
}
func timestamp(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
func strptr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	return &t.String
}
func intptr(n pgtype.Int8) *int64 {
	if !n.Valid {
		return nil
	}
	return &n.Int64
}
