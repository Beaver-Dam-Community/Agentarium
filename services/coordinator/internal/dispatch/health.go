package dispatch

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PGHealth reads holds and node_boot_generation (TASK-10) through the
// SECURITY DEFINER functions of COMMON "coordinator health row lock":
// health.lock_dispatch_holds and health.lock_dispatch_node. coordinator_reader
// has SELECT on the tables but no UPDATE, so FOR SHARE is taken inside the
// functions. Both run in the caller's transaction, and the row locks last
// until that transaction ends; the caller's SET LOCAL lock_timeout applies to
// them, and a 55P03 from inside a function reaches inTx unchanged.
//
// Leases are read from health.control_health_leases (coordinator_reader
// SELECT, TASK-03 DB roles). The activation hold is the open global
// policy_activation hold, locked through health.lock_dispatch_holds.
type PGHealth struct {
	// RequiredGlobal and RequiredTarget are the installed profile's
	// required_components (TASK-10 3.2 health_contract) that a reservation
	// checks: global-scope components, and per-target components whose
	// lease scope_id is the decision's target. nil means the TASK-10
	// default; an explicitly empty list requires none.
	RequiredGlobal []string
	RequiredTarget []string
}

// TASK-10 3.2 required_components defaults. per_node components are covered
// by node_boot_generation and the lease_expired holds TASK-10 creates;
// per_adapter_deployment needs an adapter_id → Deployment mapping that no
// registered object provides (SPEC-QUESTION), so it is left to the
// lease_expired workload hold.
var (
	DefaultRequiredGlobal = []string{"audit-db", "audit-export", "gateway", "coordinator", "node-readiness"}
	DefaultRequiredTarget = []string{"destination-evidence"}
)

// operationReceiverSubmit is the only operation that requires a per-target
// destination-evidence lease (COMMON required lease rules, TASK-08).
const operationReceiverSubmit = "receiver.submit"

var _ Health = PGHealth{}

// LockHolds locks the unreleased holds that match scope (global always) FOR
// SHARE, in hold_id order. An empty scope field is passed as NULL: the
// function rejects an empty text with 22023, and an empty string is not a
// valid uuid (22P02). A
// service-session decision has no workload, and some decisions no target.
func (PGHealth) LockHolds(ctx context.Context, tx pgx.Tx, scope HoldScope) ([]Hold, error) {
	rows, err := tx.Query(ctx, `
SELECT hold_id::text, reason
FROM health.lock_dispatch_holds($1::uuid, $2::text, $3::text, $4::uuid, $5::uuid)`,
		nullable(scope.NodeUID), nullable(scope.WorkloadID), nullable(scope.TargetID),
		nullable(scope.SessionID), nullable(scope.ServiceSessionID))
	if err != nil {
		return nil, healthErr(err, "holds")
	}
	holds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Hold, error) {
		var h Hold
		err := r.Scan(&h.HoldID, &h.Reason)
		return h, err
	})
	if err != nil {
		return nil, healthErr(err, "holds")
	}
	return holds, nil
}

// LockNodeBoot locks the node's rows with state <> 'retired' FOR SHARE and
// returns the only one. No row is ErrNotFound; more than one is not a ready
// node (COMMON: zero or several rows do not count as ready), so all
// rows are read and none is picked.
func (PGHealth) LockNodeBoot(ctx context.Context, tx pgx.Tx, nodeUID string) (NodeBoot, error) {
	if nodeUID == "" {
		return NodeBoot{}, unavailable("CONTROL_HEALTH_UNAVAILABLE", "node_boot_generation: adapter has no node")
	}
	rows, err := tx.Query(ctx, `
SELECT boot_id, sensor_generation, guard_generation, state
FROM health.lock_dispatch_node($1::uuid)`, nodeUID)
	if err != nil {
		return NodeBoot{}, healthErr(err, "node_boot_generation")
	}
	boots, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (NodeBoot, error) {
		var nb NodeBoot
		err := r.Scan(&nb.BootID, &nb.SensorGeneration, &nb.GuardGeneration, &nb.State)
		return nb, err
	})
	if err != nil {
		return NodeBoot{}, healthErr(err, "node_boot_generation")
	}
	switch len(boots) {
	case 0:
		return NodeBoot{}, ErrNotFound
	case 1:
		return boots[0], nil
	default:
		return NodeBoot{}, unavailable("CONTROL_HEALTH_UNAVAILABLE",
			"node_boot_generation: node has "+strconv.Itoa(len(boots))+" current boot rows")
	}
}

// CheckLeases requires an unexpired lease (lease_until >
// statement_timestamp(), TASK-03 3.2 hold/lease reads) for every required
// global component and, for a receiver.submit decision, every required
// per-target component. Leases are not locked: an expiring lease becomes a
// lease_expired hold, which the permit check reads again.
//
// Any source counts (gateway and adapter replicas report one source_id
// each). observed_state is not read: TASK-03 3.2 checks lease_until only,
// and control-health turns a degraded component into a hold.
//
// Per-target components (destination-evidence) are required only for
// receiver.submit: COMMON adds destination-evidence to that operation alone,
// and only the receiver evidence collector reports it (TASK-08). Other
// operations have a target_id too (decisions.target_id is non-null after
// normalization), so keying the per-target requirement on target_id would
// make every k8s/model/evidence/discovery reservation fail on a lease no one
// reports.
func (h PGHealth) CheckLeases(ctx context.Context, tx pgx.Tx, operationID, targetID string) error {
	global, target := h.RequiredGlobal, h.RequiredTarget
	if global == nil {
		global = DefaultRequiredGlobal
	}
	if target == nil {
		target = DefaultRequiredTarget
	}
	// Per-target leases apply only to receiver.submit (COMMON required lease
	// rules). Without a target or for any other operation, require none.
	if targetID == "" || operationID != operationReceiverSubmit {
		target = []string{}
	}
	rows, err := tx.Query(ctx, `
SELECT r.component, r.scope
FROM (SELECT unnest($1::text[]) AS component, 'global' AS scope, '*' AS scope_id
      UNION ALL
      SELECT unnest($2::text[]), 'target', $3) r
WHERE NOT EXISTS (
    SELECT 1 FROM health.control_health_leases l
    WHERE l.component = r.component AND l.scope = r.scope AND l.scope_id = r.scope_id
      AND l.lease_until > statement_timestamp())
ORDER BY 2, 1`, global, target, targetID)
	if err != nil {
		return healthErr(err, "leases")
	}
	missing, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (string, error) {
		var c, sc string
		err := r.Scan(&c, &sc)
		return sc + "/" + c, err
	})
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", "no valid lease for "+strings.Join(missing, ", "))
	}
	return nil
}

// LockActivationHold returns the open global policy_activation hold FOR
// SHARE, through health.lock_dispatch_holds with every selector NULL (global
// holds only). See the Health interface for why changeID cannot be checked.
//
// SPEC-QUESTION: COMMON registers lock_dispatch_holds for the reservation
// and permit check; probe registration reuses it because COMMON gives it no
// other row lock function and coordinator_reader has no UPDATE on holds.
func (PGHealth) LockActivationHold(ctx context.Context, tx pgx.Tx, _ string) (Hold, error) {
	rows, err := tx.Query(ctx, `
SELECT hold_id::text, reason FROM health.lock_dispatch_holds(NULL::uuid, NULL::text, NULL::text, NULL::uuid, NULL::uuid)`)
	if err != nil {
		return Hold{}, healthErr(err, "holds")
	}
	holds, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Hold, error) {
		var h Hold
		err := r.Scan(&h.HoldID, &h.Reason)
		return h, err
	})
	if err != nil {
		return Hold{}, healthErr(err, "holds")
	}
	for _, h := range holds {
		if h.Reason == "policy_activation" {
			return h, nil
		}
	}
	return Hold{}, ErrNotFound
}

// nullable is nil for "", so that an unused selector reaches SQL as NULL.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// healthErr maps a function call failure. 22023 (an empty selector or a
// NULL node, which the arguments above never send) is
// CONTROL_HEALTH_UNAVAILABLE. Anything else, 55P03 included, is returned
// as is: depErr lets a lock timeout through to inTx, and maps the rest.
func healthErr(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "22023" {
		return unavailable("CONTROL_HEALTH_UNAVAILABLE", what+": "+pgErr.Message)
	}
	return err
}
