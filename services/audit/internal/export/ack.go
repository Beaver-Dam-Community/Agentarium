package export

import (
	"context"
	"errors"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrAckMismatch is a definite ACK discrepancy, as opposed to a DB error.
var ErrAckMismatch = errors.New("batch absent, incomplete, or not wholly acknowledged")

type PGAcks struct {
	Queries     *auditdb.Queries
	Destination string
}

func (p PGAcks) Check(ctx context.Context, batchID, ackRef string, count int) error {
	if p.Queries == nil || (p.Destination != "gcs" && p.Destination != "gcs_decision_inputs") || !validUUID(batchID) || count < 1 || count > 100 {
		return errors.New("invalid ack verification configuration")
	}
	key, _, ok := strings.Cut(ackRef, "#")
	if !ok {
		return errors.New("invalid ack reference")
	}
	id, _ := uuid.Parse(batchID)
	result, err := p.Queries.CheckBatchAck(ctx, auditdb.CheckBatchAckParams{BatchID: pgtype.UUID{Bytes: id, Valid: true}, Destination: p.Destination, ObjectKey: key, AckRef: ackRef})
	if err != nil {
		return err
	}
	if result.Total != int64(count) || result.Acknowledged != int64(count) {
		return ErrAckMismatch
	}
	return nil
}

// Members returns the fixed batch members with their outbox_id in ordinal
// order. It needs only the audit_verifier column grants.
func (p PGAcks) Members(ctx context.Context, batchID string) ([]Member, error) {
	if p.Queries == nil || (p.Destination != "gcs" && p.Destination != "gcs_decision_inputs") || !validUUID(batchID) {
		return nil, errors.New("invalid coverage verification configuration")
	}
	rows, err := p.Queries.BatchCoverage(ctx, auditdb.BatchCoverageParams{BatchID: batchUUID(batchID), Destination: p.Destination})
	if err != nil {
		return nil, err
	}
	members := make([]Member, 0, len(rows))
	for i, r := range rows {
		if r.Ordinal != int32(i+1) {
			return nil, errors.New("batch ordinals are not contiguous")
		}
		members = append(members, Member{Kind: r.RecordKind, ID: r.RecordID, OutboxID: r.OutboxID})
	}
	return members, nil
}
