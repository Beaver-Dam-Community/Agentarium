package dispatch

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// AuditConfig is trusted process configuration (flags), never request data.
// Epoch identifies this process instance; the coordinator's events are
// unsequenced business events (source_sequence null).
type AuditConfig struct{ SourceID, Version, Epoch string }

// PGAuditor appends coordinator events through TASK-07 audit.audit_append()
// in the business transaction. The tenant, session and action come from the
// rows the transaction already wrote or read (the attempt's reservation and
// its session, or the probe's service session), not from the caller. The
// login needs audit_producer membership and its source/event/tenant grants.
type PGAuditor struct {
	config AuditConfig
	newID  func() string
}

var _ Auditor = (*PGAuditor)(nil)

func NewPGAuditor(c AuditConfig) (*PGAuditor, error) {
	for _, v := range []string{c.SourceID, c.Version, c.Epoch} {
		if v == "" || len(v) > 16384 || !utf8.ValidString(v) {
			return nil, errors.New("coordinator audit requires trusted source, version and epoch")
		}
	}
	return &PGAuditor{config: c, newID: uuid.NewString}, nil
}

func (a *PGAuditor) Append(ctx context.Context, tx pgx.Tx, ev Event) error {
	if a == nil || tx == nil || ev.Type == "" || ev.Payload == nil {
		return errors.New("incomplete coordinator audit event")
	}
	var tenant, sessionID, actionID, attemptID *string
	switch {
	case ev.Payload["attempt_id"] != nil:
		id := fmt.Sprint(ev.Payload["attempt_id"])
		attemptID = &id
		if err := tx.QueryRow(ctx, `
SELECT COALESCE(s.tenant, ss.tenant), COALESCE(r.session_id, r.service_session_id)::text, r.action_id::text
FROM coordinator.attempts t
JOIN coordinator.reservations r ON r.reservation_id = t.reservation_id
LEFT JOIN identity.sessions s ON s.session_id = r.session_id
LEFT JOIN identity.service_sessions ss ON ss.service_session_id = r.service_session_id
WHERE t.attempt_id = $1`, id).Scan(&tenant, &sessionID, &actionID); err != nil {
			return fmt.Errorf("audit context of attempt %s: %w", id, err)
		}
	case ev.Payload["service_session_id"] != nil:
		id := fmt.Sprint(ev.Payload["service_session_id"])
		sessionID = &id
		if err := tx.QueryRow(ctx, `SELECT tenant FROM identity.service_sessions WHERE service_session_id = $1`, id).Scan(&tenant); err != nil {
			return fmt.Errorf("audit context of service session %s: %w", id, err)
		}
	default:
		return errors.New("coordinator audit event has neither attempt_id nor service_session_id")
	}
	if tenant == nil || *tenant == "" {
		return errors.New("coordinator audit event has no tenant")
	}
	var sourceTime time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&sourceTime); err != nil {
		return err
	}
	record := map[string]any{
		"event_id": a.newID(), "event_type": ev.Type, "tenant": *tenant,
		"source_id": a.config.SourceID, "source_version": a.config.Version, "source_epoch": a.config.Epoch,
		"source_sequence": nil, "source_time": sourceTime.UTC().Format(time.RFC3339Nano),
		"schema_version": 1, "evidence_refs": []string{}, "safe_payload": ev.Payload,
	}
	for k, v := range map[string]*string{"session_id": sessionID, "action_id": actionID, "attempt_id": attemptID} {
		if v != nil && *v != "" {
			record[k] = *v
		}
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
		return errors.New("coordinator audit event too large")
	}
	var result string
	if err := tx.QueryRow(ctx, "SELECT audit.audit_append($1::jsonb, ARRAY['gcs']::text[])", raw).Scan(&result); err != nil {
		return err
	}
	if result != "created" && result != "duplicate" {
		return fmt.Errorf("audit append result %q", result)
	}
	return nil
}
