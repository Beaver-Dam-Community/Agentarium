package collector

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/jackc/pgx/v5"
)

// AuditConfig is trusted installation/process configuration. SourceID is the
// audit.db_role_sources source of the collector's DB login; Epoch comes from
// the durable --epoch-dir counter.
type AuditConfig struct{ SourceID, Version, Epoch string }

func (c AuditConfig) validate() error {
	for _, v := range []string{c.SourceID, c.Version, c.Epoch} {
		if v == "" || len(v) > 16384 || !utf8.ValidString(v) {
			return errors.New("collector audit requires trusted source, version and epoch")
		}
	}
	return nil
}

// ErrAuditConflict is an audit_append "conflict": the event ID already holds
// another payload. The observation transaction is rolled back.
var ErrAuditConflict = errors.New("collector: destination_observed event ID conflict")

// appendDestinationObserved appends one destination_observed AuditEvent with
// TASK-07 audit_append() in tx, the transaction of its observation revision.
// payload is the safe_payload (a Payload in production).
func appendDestinationObserved(ctx context.Context, tx pgx.Tx, cfg AuditConfig, tenant, eventID, actionID string, attemptID *string, sourceTime time.Time, payload any) error {
	record := map[string]any{
		"event_id": eventID, "event_type": "destination_observed", "tenant": tenant,
		"source_id": cfg.SourceID, "source_version": cfg.Version, "source_epoch": cfg.Epoch,
		// Business events are unsequenced: no counter escapes a SQL rollback.
		"source_sequence": nil, "source_time": sourceTime.UTC().Format(time.RFC3339Nano),
		"schema_version": 1, "action_id": actionID,
		"evidence_refs": []string{}, "safe_payload": payload,
	}
	if attemptID != nil {
		record["attempt_id"] = *attemptID
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
	if raw, err = canonical.CanonicalJSON(record); err != nil {
		return err
	}
	if len(raw) > canonical.MaxBodyBytes {
		return errors.New("collector: destination_observed event too large")
	}
	var result string
	if err = tx.QueryRow(ctx, "SELECT audit.audit_append($1::jsonb, ARRAY['gcs']::text[])", raw).Scan(&result); err != nil {
		return err
	}
	switch result {
	case "created", "duplicate":
		return nil
	case "conflict":
		return ErrAuditConflict
	default:
		return fmt.Errorf("collector: unexpected audit append result %q", result)
	}
}
