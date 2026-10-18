package sessions

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditConfig is trusted installation/process configuration, never request data.
// Epoch must come from the producer's durable restart counter. This adapter does
// not allocate epochs or claim that the identity command has wired that source.
type AuditConfig struct{ SourceID, Version, Epoch string }

// PGAuditor appends to TASK-07 in the business transaction. The login still needs
// its audit_producer membership and exact source/event/tenant registration.
type PGAuditor struct {
	config AuditConfig
	newID  func() string
}

func NewPGAuditor(config AuditConfig) (*PGAuditor, error) {
	for _, value := range []string{config.SourceID, config.Version, config.Epoch} {
		if value == "" || len(value) > 16384 || !utf8.ValidString(value) {
			return nil, errors.New("identity audit requires trusted source, version and epoch")
		}
	}
	return &PGAuditor{config: config, newID: uuid.NewString}, nil
}

func (a *PGAuditor) Append(ctx context.Context, tx pgx.Tx, ev Event) error {
	if a == nil || tx == nil || a.newID == nil || ev.Type == "" || ev.Tenant == "" || ev.Actor == "" || ev.Payload == nil {
		return errors.New("incomplete identity audit event")
	}
	var sourceTime time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&sourceTime); err != nil {
		return err
	}
	// Production uses a fresh random UUID per append. Conflict handling remains
	// defensive for collisions and future deterministic-ID producers; it does
	// not establish HTTP request idempotency for this adapter.
	id := a.newID()
	record := map[string]any{
		"event_id": id, "event_type": ev.Type, "tenant": ev.Tenant,
		"source_id": a.config.SourceID, "source_version": a.config.Version, "source_epoch": a.config.Epoch,
		// COMMON permits null for unsequenced business events. Do not infer a
		// sequence from a session ID or use a counter that escapes SQL rollback.
		"source_sequence": nil, "source_time": sourceTime.UTC().Format(time.RFC3339Nano),
		"schema_version": 1, "authenticated_actor": ev.Actor,
		"evidence_refs": []string{}, "safe_payload": ev.Payload,
	}
	if ev.SessionID != "" {
		record["session_id"] = ev.SessionID
	}
	if ev.ActionID != "" {
		record["action_id"] = ev.ActionID
	}
	if ev.WorkloadID != "" {
		record["workload_id"] = ev.WorkloadID
	}
	raw, err := canonical.CanonicalJSON(record)
	if err != nil {
		return err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return err
	}
	record["payload_digest"] = digest
	raw, err = canonical.CanonicalJSON(record)
	if err != nil {
		return err
	}
	if len(raw) > canonical.MaxBodyBytes {
		return errors.New("identity audit event too large")
	}
	if err = canonical.CheckStrictJSON(raw); err != nil {
		return err
	}
	var result string
	if err = tx.QueryRow(ctx, "SELECT audit.audit_append($1::jsonb, ARRAY['gcs']::text[])", raw).Scan(&result); err != nil {
		return err
	}
	switch result {
	case "created", "duplicate":
		return nil
	case "conflict":
		return &auditConflict{eventID: id, digest: digest, sourceID: a.config.SourceID}
	default:
		return fmt.Errorf("unexpected audit append result %q", result)
	}
}

// Only the adapter can construct this error. InTx records the incident after
// the business transaction has rolled back, never on its aborted connection.
type auditConflict struct{ eventID, digest, sourceID string }

func (*auditConflict) Error() string { return "identity audit event ID conflict" }
