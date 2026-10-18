package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/store/auditdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// IngestLifecycle uses the authenticated six-argument SQL contract and returns
// only after a validated result and successful COMMIT. SQL repeats source checks.
func (s Store) IngestLifecycle(ctx context.Context, source ingest.LifecycleSource, raw []byte) (json.RawMessage, error) {
	if s.WriterVersion == "" || s.WriterEpoch == "" || source.CertificateSerial == "" || source.ExactSAN == "" || source.SourceID != source.ExactSAN {
		return nil, errors.New("lifecycle identity/configuration unavailable")
	}
	b, err := ingest.DecodeLifecycleEnvelope(raw)
	if err != nil {
		return nil, err
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	ack, err := auditdb.New(tx).IngestLifecycleBatch(ctx, auditdb.IngestLifecycleBatchParams{SourceID: source.SourceID, Batch: raw, CertificateSerial: source.CertificateSerial, ExactSan: source.ExactSAN, WriterVersion: s.WriterVersion, WriterEpoch: s.WriterEpoch})
	if err != nil {
		return nil, classifyLifecycle(err)
	}
	if err := ingest.ValidateLifecycleAck(ack, b); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ack, nil
}

// LifecycleCheckpoint never queries checkpoint tables directly. Its caller has
// authenticated the current watcher certificate and installation scope allowlist.
func (s Store) LifecycleCheckpoint(ctx context.Context, source, scope string) (ingest.LifecycleCheckpointResult, error) {
	r, err := auditdb.New(s.Pool).LifecycleCheckpoint(ctx, auditdb.LifecycleCheckpointParams{SourceID: source, Scope: scope})
	if errors.Is(err, pgx.ErrNoRows) {
		return ingest.LifecycleCheckpointResult{}, ingest.ErrLifecycleCheckpointNotFound
	}
	if err != nil {
		return ingest.LifecycleCheckpointResult{}, classify(err)
	}
	if !r.CommittedAt.Valid {
		return ingest.LifecycleCheckpointResult{}, ingest.ErrLifecycleResult
	}
	return ingest.LifecycleCheckpointResult{Scope: r.Scope, ResourceVersion: r.ResourceVersion, Revision: r.CheckpointRevision, CommittedAt: r.CommittedAt.Time}, nil
}

// DML constraint failures are storage failures, not caller schema rejections.
// The ingest function validates record fields before executing writes.
func classifyLifecycle(err error) error {
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		switch pgerr.Code {
		case "42501":
			return ingest.ErrForbidden
		case "22023", "22P02", "22P05":
			return ingest.ErrSchema
		}
	}
	return err
}
