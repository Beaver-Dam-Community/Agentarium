package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FinalFlushGrace is TASK-10 3.7 network_policy_log.final_flush_grace_seconds.
const FinalFlushGrace = 120 * time.Second

// RecordNetpolGaps opens one NETPOL_COLLECTOR_STOPPED gap per node whose
// netpol-collector leases all expired, judged on the node's latest lease, and
// that has not delivered a batch since (TASK-10 3.7). It never creates a hold and
// never affects scope state. start_at is the node's latest acknowledged
// record source time so unacknowledged records stay inside the gap; with no
// acknowledged record it is the collector's first lease on the node. After a
// recorded final flush the gap waits FinalFlushGrace and starts at the final
// flush caught_up_at. Node deletion is not observed here, so after the grace
// the gap is opened even for a deleted node (the correlation side must close
// it). The gap, source_health_changed and observation_gap_recorded commit
// together.
func (s *Store) RecordNetpolGaps(ctx context.Context) error {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	leases, err := q.ExpiredNetpolLeases(ctx)
	if err != nil {
		return err
	}
	clock, err := q.Clock(ctx)
	if err != nil {
		return err
	}
	for _, l := range leases {
		if l.LeaseUntil.Time.After(clock.Time) {
			continue
		}
		state, err := q.NetpolAckState(ctx, l.NodeUid)
		if err != nil {
			return err
		}
		refs := []string{"lease:" + l.SourceID}
		start := state.AckedSourceTime
		if state.FinalFlushCaughtUpAt.Valid {
			// The final flush grace is decided first; once it has passed the
			// gap opens even if a late batch was acknowledged.
			if clock.Time.Before(l.LeaseUntil.Time.Add(FinalFlushGrace)) {
				continue
			}
			start = state.FinalFlushCaughtUpAt
			refs = append(refs, "final_flush")
		} else {
			delivering, err := q.NetpolAckedAfter(ctx, healthdb.NetpolAckedAfterParams{NodeUid: l.NodeUid, LeaseUntil: l.LeaseUntil})
			if err != nil {
				return err
			}
			if delivering {
				continue
			}
			if !start.Valid {
				// No record was ever acknowledged: the conservative start is the
				// earliest first lease of any collector of the node since its
				// latest ack, never later than the current collector's.
				if start, err = q.NetpolConservativeStart(ctx, l.NodeUid); err != nil {
					return err
				}
				if !start.Valid || start.Time.After(l.FirstReportedAt.Time) {
					start = l.FirstReportedAt
				}
				refs = append(refs, "start_at:first_lease")
			}
		}
		raw, _ := json.Marshal(refs)
		gap, err := q.OpenNetpolCollectorGap(ctx, healthdb.OpenNetpolCollectorGapParams{NodeUid: l.NodeUid, BootID: l.BootID, StartAt: start, EvidenceRefs: raw})
		if err != nil {
			return err
		}
		if !gap.Valid {
			continue // the node already has an open collector-stopped gap
		}
		if err := s.auditEvidence(ctx, q, "source_health_changed", map[string]any{"source_id": l.SourceID, "scope": "node", "from_state": l.ObservedState, "to_state": health.StateUnhealthy, "lease_until": l.LeaseUntil.Time.UTC().Format(time.RFC3339Nano)}, clock.Time, refs); err != nil {
			return err
		}
		if err := s.auditEvidence(ctx, q, "observation_gap_recorded", map[string]any{"gap_id": uuid.UUID(gap.Bytes).String(), "stage": "network_policy_log", "reason": "NETPOL_COLLECTOR_STOPPED", "count_quality": "unknown"}, clock.Time, refs); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
