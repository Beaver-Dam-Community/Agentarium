package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// ReceiveWatchGap stores a pod-watcher WATCH_HISTORY_EXPIRED gap (#178). Only
// the exact pod-watcher SAN with a live certificate and an allowlisted scope
// may report; source_id is the caller SAN. The gap row, its
// observation_gap_recorded event and outbox commit together before the ack;
// the same gap_id with the same body returns existing, another body conflicts.
func (s *Store) ReceiveWatchGap(ctx context.Context, peer health.Peer, r health.WatchGapRequest) (health.WatchGapAck, error) {
	var ack health.WatchGapAck
	if peer.SAN != health.PodWatcherSAN {
		return ack, health.ErrForbidden
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return ack, err
	}
	defer rollback(tx)
	q := healthdb.New(tx)
	if _, err := q.Certificate(ctx, healthdb.CertificateParams{Serial: peer.Serial, San: peer.SAN}); errors.Is(err, pgx.ErrNoRows) {
		return ack, health.ErrForbidden
	} else if err != nil {
		return ack, err
	}
	id, _ := uuid.Parse(r.Gap.GapID)
	refs, err := json.Marshal(r.Gap.EvidenceRefs)
	if err != nil {
		return ack, err
	}
	row, err := q.RecordWatchGap(ctx, healthdb.RecordWatchGapParams{GapID: pgtype.UUID{Bytes: id, Valid: true}, Scope: r.Scope, SourceEpoch: r.Gap.SourceEpoch,
		StartAt: pgtype.Timestamptz{Time: r.Gap.StartAt, Valid: true}, EndAt: pgtype.Timestamptz{Time: r.Gap.EndAt, Valid: true}, EvidenceRefs: refs, RequestDigest: r.Digest})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42501" {
		return ack, health.ErrForbidden // scope not in the installed allowlist
	}
	if errors.As(err, &pgErr) && pgErr.Code == "22023" {
		return ack, health.ErrInvalid
	}
	if err != nil {
		return ack, err
	}
	if !row.Created {
		if row.RequestDigest != r.Digest {
			return ack, health.ErrConflict
		}
		return health.WatchGapAck{GapID: r.Gap.GapID, Result: "existing", RecordedAt: row.CreatedAt.Time}, nil
	}
	at := row.CreatedAt
	if err := s.auditActor(ctx, q, "observation_gap_recorded", map[string]any{"gap_id": r.Gap.GapID, "stage": "lifecycle_capture", "reason": "WATCH_HISTORY_EXPIRED", "count_quality": "unknown"}, at.Time, peer.SAN, r.Gap.EvidenceRefs); err != nil {
		return ack, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ack, err
	}
	return health.WatchGapAck{GapID: r.Gap.GapID, Result: "created", RecordedAt: at.Time}, nil
}

// auditActor appends a TASK-10 event naming the verified caller as actor.
func (s *Store) auditActor(ctx context.Context, q *healthdb.Queries, kind string, payload map[string]any, now time.Time, actor string, refs []string) error {
	if s.Epoch == "" {
		return errors.New("producer epoch unavailable")
	}
	event := map[string]any{"event_id": uuid.NewString(), "event_type": kind, "tenant": "*", "source_id": s.Config.AuditSourceID, "source_version": s.Config.Version,
		"source_epoch": s.Epoch, "source_sequence": nil, "source_time": now.UTC().Format(time.RFC3339Nano), "schema_version": 1, "authenticated_actor": actor,
		"safe_payload": payload, "evidence_refs": refs}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return err
	}
	event["payload_digest"] = digest
	if raw, err = json.Marshal(event); err != nil {
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
