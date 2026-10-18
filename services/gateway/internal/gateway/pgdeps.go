package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// The PostgreSQL implementations of the dependencies other Tasks own. Each
// reads only through the caller's transaction (types.go), with the grants
// COMMON gives the gateway: gateway_reader (TASK-04 chapter 4 SELECT table, held by
// gateway_app through membership), audit_producer (audit_append) and
// EXECUTE on audit.enqueue_decision_input and
// coordinator.bind_activation_probe_action.

// maxRows bounds every list read of another Task's table. The open holds of
// one request are at most 4 scopes × 13 reasons (holds_open_unique) and a
// component has one lease row per replica, so a longer answer is not a state
// the gateway can judge and fails closed.
const maxRows = 256

var errTooManyRows = errors.New("gateway: dependency returned more rows than the read bound")

// PGPolicy reads this environment's TASK-14 active_policy row
// (COMMON active_policy: scope_id = environment).
type PGPolicy struct{ Environment string }

func (p PGPolicy) ActivePolicy(ctx context.Context, tx pgx.Tx) (ActivePolicy, error) {
	var a ActivePolicy
	err := tx.QueryRow(ctx, `SELECT epoch, expected_opa_revision FROM release.active_policy WHERE scope_id = $1`,
		p.Environment).Scan(&a.Epoch, &a.ExpectedOPARevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActivePolicy{}, unavailable("POLICY_UNAVAILABLE", "no active_policy row for environment "+p.Environment)
	}
	return a, err
}

// PGHealth reads TASK-10 health.holds and health.control_health_leases.
type PGHealth struct{}

// Holds returns the unreleased holds of the request's scopes (COMMON hold
// selection): global plus workload, target and session. An empty selector matches
// no row: scope_id is never empty (TASK-10 3.6 CHECK and ValidScopeID).
func (PGHealth) Holds(ctx context.Context, tx pgx.Tx, s HoldScope) ([]Hold, error) {
	rows, err := tx.Query(ctx, `
SELECT hold_id::text, scope, scope_id, reason
FROM health.holds
WHERE released_at IS NULL
  AND ((scope = 'global' AND scope_id = '*')
    OR (scope = 'workload' AND scope_id = $1 AND $1 <> '')
    OR (scope = 'target' AND scope_id = $2 AND $2 <> '')
    OR (scope = 'session' AND scope_id = $3 AND $3 <> ''))
ORDER BY hold_id
LIMIT $4`, s.WorkloadID, s.TargetID, s.SessionID, maxRows+1)
	if err != nil {
		return nil, err
	}
	holds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Hold, error) {
		var h Hold
		err := r.Scan(&h.HoldID, &h.Scope, &h.ScopeID, &h.Reason)
		return h, err
	})
	if err != nil {
		return nil, err
	}
	if len(holds) > maxRows {
		return nil, errTooManyRows
	}
	return holds, nil
}

// Leases returns every lease row of one required component in its lease
// scope (TASK-10 3.2 ExpiryScope, COMMON ControlHealthLease):
//   - gateway, coordinator, audit-db, audit-export: scope global/*;
//   - adapter: scope workload/<namespace>/<ksa> of the adapter's Deployment
//     (control-health checks it against the reporter's certificate) and
//     source_id <adapter_id>/<pod> (TASK-05 lease duty);
//   - destination-evidence: scope target/<target_id>;
//   - node-sensors: scope node/<node_uid>, source_id tetragon-node/<node_uid>.
//
// A key whose scope id is unknown (no adapter, target or node) has no rows,
// so the component aggregates to unhealthy.
func (PGHealth) Leases(ctx context.Context, tx pgx.Tx, k LeaseKey) ([]LeaseRow, error) {
	var scope, scopeID, sourcePrefix string
	switch k.Component {
	case "gateway", "coordinator", "audit-db", "audit-export":
		scope, scopeID = "global", "*"
	case "adapter":
		ksa, ok := adapterKSA[k.AdapterID]
		if !ok {
			return nil, nil
		}
		scope, scopeID, sourcePrefix = "workload", AdapterNamespace+"/"+ksa, k.AdapterID+"/"
	case "destination-evidence":
		scope, scopeID = "target", k.TargetID
	case "node-sensors":
		scope, scopeID, sourcePrefix = "node", k.NodeUID, "tetragon-node/"+k.NodeUID
	default:
		return nil, fmt.Errorf("gateway: no lease scope for component %q", k.Component)
	}
	if scopeID == "" {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
SELECT source_id, component, observed_state, lease_until, active_version
FROM health.control_health_leases
WHERE component = $1 AND scope = $2 AND scope_id = $3 AND starts_with(source_id, $4)
ORDER BY source_id
LIMIT $5`, k.Component, scope, scopeID, sourcePrefix, maxRows+1)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (LeaseRow, error) {
		var l LeaseRow
		err := r.Scan(&l.SourceID, &l.Component, &l.ObservedState, &l.LeaseUntil, &l.ActiveVersion)
		return l, err
	})
	if err != nil {
		return nil, err
	}
	if len(out) > maxRows {
		return nil, errTooManyRows
	}
	return out, nil
}

// PGAdapters reads the TASK-05 adapter tables.
type PGAdapters struct{}

func (PGAdapters) DataState(ctx context.Context, tx pgx.Tx, key DataStateKey) (DataState, bool, error) {
	var d DataState
	var err error
	switch {
	case key.WorkloadID != "" && key.ServiceSessionID == "":
		err = tx.QueryRow(ctx, `
SELECT data_class_high_water::text, data_sources FROM adapter.workload_data_state WHERE workload_id = $1`,
			key.WorkloadID).Scan(&d.DataClassHighWater, &d.DataSources)
	case key.ServiceSessionID != "" && key.WorkloadID == "":
		err = tx.QueryRow(ctx, `
SELECT data_class_high_water::text, data_sources FROM adapter.workload_data_state WHERE service_session_id = $1::uuid`,
			key.ServiceSessionID).Scan(&d.DataClassHighWater, &d.DataSources)
	default:
		return DataState{}, false, errors.New("gateway: workload_data_state key needs exactly one of workload_id, service_session_id")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return DataState{}, false, nil
	}
	if err != nil {
		return DataState{}, false, err
	}
	if d.DataSources == nil {
		d.DataSources = []string{}
	}
	return d, true, nil
}

func (PGAdapters) ExecutionState(ctx context.Context, tx pgx.Tx, decisionID string) (string, bool, error) {
	var st string
	err := tx.QueryRow(ctx, `SELECT state FROM adapter.adapter_executions WHERE decision_id = $1::uuid`, decisionID).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return st, err == nil, err
}

// Result returns the latest action_results row of the action (one row per
// attempt; a later attempt supersedes an earlier one).
func (PGAdapters) Result(ctx context.Context, tx pgx.Tx, actionID string) (*ActionResult, error) {
	var r ActionResult
	var body []byte
	err := tx.QueryRow(ctx, `
SELECT action_id::text, attempt_id::text, execution_state, data_class::text, result_body, truncated,
       truncation_reason, evidence_level, result_digest, created_at
FROM adapter.action_results WHERE action_id = $1::uuid
ORDER BY created_at DESC, attempt_id DESC LIMIT 1`, actionID).Scan(
		&r.ActionID, &r.AttemptID, &r.ExecutionState, &r.DataClass, &body, &r.Truncated,
		&r.TruncationReason, &r.EvidenceLevel, &r.ResultDigest, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.ResultBody = json.RawMessage(body)
	return &r, nil
}

// PGProbes reads coordinator.activation_probes and binds the action through
// coordinator.bind_activation_probe_action (COMMON DB function table).
type PGProbes struct{}

// Lookup returns the registration of (service_session_id, client_request_key)
// with action_id set to actionID, or nil when there is none or it is already
// bound to another action (Rego then has no probe and denies).
func (PGProbes) Lookup(ctx context.Context, tx pgx.Tx, serviceSessionID, clientRequestKey, actionID string) (*ActivationProbe, error) {
	var p ActivationProbe
	var expires time.Time
	err := tx.QueryRow(ctx, `
SELECT activation_probe_id::text, change_id::text, service_session_id::text, target_epoch, expires_at
FROM coordinator.activation_probes
WHERE service_session_id = $1::uuid AND client_request_key = $2 AND (action_id IS NULL OR action_id = $3::uuid)`,
		serviceSessionID, clientRequestKey, actionID).Scan(&p.ActivationProbeID, &p.ChangeID, &p.ServiceSessionID, &p.TargetEpoch, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.ActionID = actionID
	p.ExpiresAt = rfc3339(expires)
	return &p, nil
}

func (PGProbes) Bind(ctx context.Context, tx pgx.Tx, serviceSessionID, clientRequestKey, actionID string) error {
	_, err := tx.Exec(ctx, `SELECT coordinator.bind_activation_probe_action($1::uuid, $2, $3::uuid)`,
		serviceSessionID, clientRequestKey, actionID)
	return err
}

// AuditConfig is the gateway's TASK-07 producer identity, from installation
// configuration and never from a request. SourceID must be the source
// registered for the gateway's DB login (audit.db_role_sources) with grants
// for the gateway event types and tenant (audit.producer_event_grants).
type AuditConfig struct{ SourceID, Version, Epoch string }

// PGAuditor appends AuditEvents with audit.audit_append in the decision
// transaction and enqueues decision inputs with audit.enqueue_decision_input,
// so a failed append rolls back the decision (COMMON decision storage
// transaction). Gateway events are unsequenced business events:
// source_sequence is null (COMMON AuditEvent).
type PGAuditor struct {
	cfg   AuditConfig
	newID func() string
}

func NewPGAuditor(cfg AuditConfig) (*PGAuditor, error) {
	for _, v := range []string{cfg.SourceID, cfg.Version, cfg.Epoch} {
		if v == "" || len(v) > 16384 || !utf8.ValidString(v) {
			return nil, errors.New("gateway audit requires a source_id, source_version and source_epoch")
		}
	}
	return &PGAuditor{cfg: cfg, newID: uuid.NewString}, nil
}

func (a *PGAuditor) Append(ctx context.Context, tx pgx.Tx, ev Event) error {
	if ev.Type == "" || ev.Tenant == "" || ev.Payload == nil {
		return errors.New("gateway audit event needs type, tenant and payload")
	}
	var sourceTime time.Time
	if err := tx.QueryRow(ctx, `SELECT statement_timestamp()`).Scan(&sourceTime); err != nil {
		return err
	}
	id := a.newID()
	record := map[string]any{
		"event_id": id, "event_type": ev.Type, "tenant": ev.Tenant,
		"source_id": a.cfg.SourceID, "source_version": a.cfg.Version, "source_epoch": a.cfg.Epoch,
		"source_sequence": nil, "source_time": sourceTime.UTC().Format(time.RFC3339Nano),
		"schema_version": 1, "evidence_refs": []string{}, "safe_payload": ev.Payload,
	}
	if ev.Actor != "" {
		record["authenticated_actor"] = ev.Actor
	}
	if ev.SessionID != "" {
		record["session_id"] = ev.SessionID
	}
	// The envelope action_id and request_id index the event (AuditEvent);
	// without explicit values they come from the payload.
	for k, v := range map[string]string{"action_id": ev.ActionID, "request_id": ev.RequestID} {
		if v == "" {
			v, _ = ev.Payload[k].(string)
		}
		if v != "" {
			record[k] = v
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
	var result string
	if err := tx.QueryRow(ctx, `SELECT audit.audit_append($1::jsonb, ARRAY['gcs']::text[])`, raw).Scan(&result); err != nil {
		return err
	}
	switch result {
	case "created", "duplicate":
		return nil
	default:
		// A fresh random event_id cannot legitimately conflict.
		return fmt.Errorf("audit_append %s: unexpected result %q", ev.Type, result)
	}
}

// EnqueueDecisionInput registers the stored decision_inputs row for export
// (TASK-04 chapter 4): the function takes the digest and the record size.
func (a *PGAuditor) EnqueueDecisionInput(ctx context.Context, tx pgx.Tx, digest string, record []byte) error {
	_, err := tx.Exec(ctx, `SELECT audit.enqueue_decision_input($1, $2)`, digest, len(record))
	return err
}
