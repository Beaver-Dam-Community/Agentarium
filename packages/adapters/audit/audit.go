// Package audit is the execute.Auditor of the adapters: it appends the
// TASK-05 events (preflight_passed, preflight_rejected, dispatch_started,
// response_received, attempt_uncertain, attempt_failed) with TASK-07
// audit.audit_append() over the adapter's own DB login, as the identity and
// coordinator do (COMMON: every adapter DB role is an audit_producer
// member). Each event is one transaction.
//
// The trusted context of the event (tenant, session, workload) is read in
// that transaction from the action's stored envelope
// (decisions.adapter_action_envelopes, which shows only actions allowed for
// this adapter's login), never from the execute request. The source
// (source_id, version, durable epoch) is process configuration;
// audit_append checks source_id against audit.db_role_sources for
// session_user and the (source, event_type, tenant) grant.
//
// SPEC-QUESTION: TASK-05 lists POST /internal/audit/events for the adapter,
// while COMMON makes adapter DB roles audit_producer members and TASK-07 3.2
// prefers the DB transaction. The DB path is used (no extra network route,
// same contract as the coordinator).
//
// A replayed event (same event_id after a restart, see execute.Event) has a
// new source_epoch and source_time, so audit_append answers conflict. The
// stored event has the same event_id, source and tenant, so it is the same
// logical event: the conflict is recorded with audit_record_conflict in its
// own transaction (COMMON) and the event counts as recorded.
package audit

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Config is trusted process configuration (flags), never request data.
// Epoch is the durable producer epoch of this process.
type Config struct{ SourceID, Version, Epoch string }

// PG appends events with audit.audit_append.
type PG struct {
	Pool   *pgxpool.Pool
	config Config
}

var _ execute.Auditor = (*PG)(nil)

// New checks the source configuration.
func New(pool *pgxpool.Pool, c Config) (*PG, error) {
	if pool == nil {
		return nil, errors.New("adapter audit requires a database pool")
	}
	for _, v := range []string{c.SourceID, c.Version, c.Epoch} {
		if v == "" || len(v) > 16384 || !utf8.ValidString(v) {
			return nil, errors.New("adapter audit requires trusted source, version and epoch")
		}
	}
	return &PG{Pool: pool, config: c}, nil
}

var reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ErrUnknownAction means the action's envelope is not visible to this
// adapter login, so the event has no trusted tenant.
var ErrUnknownAction = errors.New("audit: action envelope not visible to this adapter")

// Emit appends ev. created and duplicate are success; conflict is recorded
// and treated as recorded (see the package comment).
func (a *PG) Emit(ctx context.Context, ev execute.Event) error {
	if a == nil || a.Pool == nil {
		return errors.New("audit: not configured")
	}
	if !reUUID.MatchString(ev.EventID) || ev.Type == "" || ev.Payload == nil || !reUUID.MatchString(ev.ActionID) {
		return errors.New("audit: incomplete adapter event")
	}
	var digest string
	var result string
	err := pgx.BeginFunc(ctx, a.Pool, func(tx pgx.Tx) error {
		raw, d, err := a.record(ctx, tx, ev)
		if err != nil {
			return err
		}
		digest = d
		if err := tx.QueryRow(ctx, "SELECT audit.audit_append($1::jsonb, ARRAY['gcs']::text[])", raw).Scan(&result); err != nil {
			return err
		}
		if result == "conflict" {
			return errConflict
		}
		if result != "created" && result != "duplicate" {
			return fmt.Errorf("audit: append result %q", result)
		}
		return nil
	})
	if !errors.Is(err, errConflict) {
		return err
	}
	// The business transaction is rolled back; the incident is its own
	// transaction (COMMON audit_record_conflict).
	var id string
	if err := a.Pool.QueryRow(ctx, "SELECT audit.audit_record_conflict('audit_event', $1, $2, $3)::text",
		ev.EventID, digest, a.config.SourceID).Scan(&id); err != nil {
		return fmt.Errorf("audit: record conflict of %s: %w", ev.EventID, err)
	}
	return nil
}

var errConflict = errors.New("audit: event_id conflict")

// record builds the canonical AuditEvent and its payload_digest.
func (a *PG) record(ctx context.Context, tx pgx.Tx, ev execute.Event) ([]byte, string, error) {
	var tenant, kind, session, workload *string
	err := tx.QueryRow(ctx, `
SELECT envelope->>'tenant', envelope->>'session_kind', envelope->>'session_id', envelope->>'workload_id'
FROM decisions.adapter_action_envelopes WHERE action_id = $1`, ev.ActionID).Scan(&tenant, &kind, &session, &workload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", ErrUnknownAction
	}
	if err != nil {
		return nil, "", err
	}
	if tenant == nil || *tenant == "" {
		return nil, "", errors.New("audit: action has no tenant")
	}
	var sourceTime time.Time
	if err := tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&sourceTime); err != nil {
		return nil, "", err
	}
	rec := map[string]any{
		"event_id": ev.EventID, "event_type": ev.Type, "tenant": *tenant,
		"source_id": a.config.SourceID, "source_version": a.config.Version, "source_epoch": a.config.Epoch,
		"source_sequence": nil, "source_time": sourceTime.UTC().Format(time.RFC3339Nano),
		"schema_version": 1, "evidence_refs": []string{}, "safe_payload": ev.Payload,
		"action_id": ev.ActionID,
	}
	if session != nil && reUUID.MatchString(*session) {
		rec["session_id"] = *session
	}
	if kind != nil && *kind == "user" && workload != nil && *workload != "" {
		rec["workload_id"] = *workload
	}
	if reUUID.MatchString(ev.RequestID) {
		rec["request_id"] = ev.RequestID
	}
	if reUUID.MatchString(ev.AttemptID) {
		rec["attempt_id"] = ev.AttemptID
	}
	raw, err := canonical.CanonicalJSON(rec)
	if err != nil {
		return nil, "", err
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return nil, "", err
	}
	rec["payload_digest"] = digest
	if raw, err = canonical.CanonicalJSON(rec); err != nil {
		return nil, "", err
	}
	if len(raw) > canonical.MaxBodyBytes {
		return nil, "", errors.New("audit: adapter event too large")
	}
	return raw, digest, nil
}
