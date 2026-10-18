package store

import (
	"context"
	"errors"
	"slices"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func (s *Store) RequestHold(ctx context.Context, peer health.Peer, request health.HoldRequest) (health.HoldAck, error) {
	empty := health.HoldAck{}
	if !request.Valid() {
		return empty, health.ErrInvalid
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return empty, err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	if err := q.SetNodeBootstrapLockTimeout(ctx); err != nil {
		return empty, err
	}
	principal, err := q.Principal(ctx, peer.SAN)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, health.ErrForbidden
	}
	if err != nil {
		return empty, err
	}
	if !slices.Contains(principal.AllowedScopes, request.Scope) || !slices.Contains(principal.AllowedHoldReasons, request.Reason) || principal.Component == "" || principal.Component == "probe-runner" || principal.Component == health.ComponentNetpol {
		return empty, health.ErrForbidden
	}
	// Probe runners report results, never request holds. Only the verified
	// result controller or destination evidence component owns probe_failed.
	if request.Reason == "probe_failed" && principal.Component != "control-health" && principal.Component != "destination-evidence" {
		return empty, health.ErrForbidden
	}
	// Only the correlation evaluator decides risk events (TASK-10 3.2).
	if request.Reason == "risk_event" && principal.Component != "correlation" {
		return empty, health.ErrForbidden
	}
	cert, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN})
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, health.ErrForbidden
	}
	if err != nil {
		return empty, err
	}
	localNode := slices.Contains([]string{"node-sensors", "lifecycle-recorder", "runtime-guard"}, principal.Component)
	if localNode && request.Scope != "node" {
		return empty, health.ErrForbidden
	}
	var current healthdb.HealthNodeBootGeneration
	if request.Scope == "node" {
		var node pgtype.UUID
		if err := node.Scan(request.ScopeID); err != nil {
			return empty, health.ErrInvalid
		}
		// Serialize with boot creation/retirement without taking a node row
		// lock ahead of the hold row. Row lock order remains holds -> node.
		if err := q.LockNodeBootstrap(ctx, request.ScopeID); err != nil {
			return empty, err
		}
		boots, err := q.CurrentNodeForHold(ctx, node)
		if err != nil {
			return empty, err
		}
		if len(boots) != 1 {
			return empty, errors.New("current node boot unavailable or ambiguous")
		}
		current = boots[0]
		if localNode && (cert.NodeUid != node || !cert.BootID.Valid || cert.BootID.String != current.BootID) {
			return empty, health.ErrForbidden
		}
	}
	owner := health.HoldOwner(request.Reason, principal.Component)
	holdID, err := q.CreateHold(ctx, healthdb.CreateHoldParams{Scope: request.Scope, ScopeID: request.ScopeID, Reason: request.Reason, ReasonDetail: text(request.ReasonDetail), OwnerComponent: owner, RequestedBy: peer.SAN})
	decision := "created"
	if errors.Is(err, pgx.ErrNoRows) {
		// Under READ COMMITTED this separate statement sees the concurrent
		// insert that won the unique open-hold constraint. No fake UPDATE is
		// used to obtain a row, and the existing owner's metadata is preserved.
		decision = "existing"
		holdID, err = q.OpenHold(ctx, healthdb.OpenHoldParams{Scope: request.Scope, ScopeID: request.ScopeID, Reason: request.Reason})
	}
	if err != nil {
		return empty, err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return empty, err
	}
	id := uuid.UUID(holdID.Bytes).String()
	if err := s.auditEvidence(ctx, q, "hold_requested", map[string]any{"scope": request.Scope, "scope_id": request.ScopeID, "reason": request.Reason, "requester": peer.SAN, "evidence_refs": request.EvidenceRefs}, clock.Time, request.EvidenceRefs); err != nil {
		return empty, err
	}
	if decision == "created" {
		if err := s.auditEvidence(ctx, q, "execution_held", map[string]any{"hold_id": id, "scope": request.Scope, "scope_id": request.ScopeID, "reason": request.Reason, "owner_component": owner}, clock.Time, request.EvidenceRefs); err != nil {
			return empty, err
		}
	}
	if request.Scope == "node" {
		changed, err := q.MarkNodeHeld(ctx, healthdb.MarkNodeHeldParams{NodeUid: current.NodeUid, BootID: current.BootID})
		if err != nil {
			return empty, err
		}
		if changed != 1 {
			return empty, errors.New("current node boot changed")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, err
	}
	return health.HoldAck{HoldID: &id, Decision: decision, ReasonCodes: []string{}}, nil
}

// OwnedHolds lists the caller component's own open holds whose reason it may
// release (#177). It widens no release right: releases still need evidence.
func (s *Store) OwnedHolds(ctx context.Context, peer health.Peer, owner string) (health.OwnedHolds, error) {
	empty := health.OwnedHolds{}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return empty, err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	if _, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN}); errors.Is(err, pgx.ErrNoRows) {
		return empty, health.ErrForbidden
	} else if err != nil {
		return empty, err
	}
	principal, err := q.Principal(ctx, peer.SAN)
	if errors.Is(err, pgx.ErrNoRows) {
		return empty, health.ErrForbidden
	}
	if err != nil {
		return empty, err
	}
	if principal.Component != owner || len(principal.ReleasableHoldReasons) == 0 {
		return empty, health.ErrForbidden
	}
	rows, err := q.OwnedOpenHolds(ctx, healthdb.OwnedOpenHoldsParams{OwnerComponent: owner, Reasons: principal.ReleasableHoldReasons})
	if err != nil {
		return empty, err
	}
	out := health.OwnedHolds{Holds: []health.Hold{}}
	for _, h := range rows {
		// Security reasons are never listed, even if mis-registered as releasable.
		if slices.Contains([]string{"control_drift", "bypass_detected", "sensor_tampering", "alignment_mismatch", "audit_integrity", "risk_event", "operator_stop"}, h.Reason) {
			continue
		}
		out.Holds = append(out.Holds, health.Hold{HoldID: uuid.UUID(h.HoldID.Bytes).String(), Scope: h.Scope, ScopeID: h.ScopeID, Reason: h.Reason, OwnerComponent: h.OwnerComponent, CreatedAt: h.CreatedAt.Time})
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, err
	}
	return out, nil
}
