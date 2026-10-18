//go:build integration

package dispatch

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The TASK-10 functions health.lock_dispatch_holds and
// health.lock_dispatch_node come from a TASK-10 migration that may not be in
// migrations/ yet. Apply it to the database before the run, or these tests
// skip.

// healthSetup returns the env with empty holds and node_boot_generation, and
// coordinator_app a member of coordinator_reader. The membership is granted
// here only if missing (another migration adds it), and revoked afterwards.
func healthSetup(t *testing.T) *env {
	t.Helper()
	e := setup(t)
	ctx := context.Background()
	var ok bool
	if err := e.admin.QueryRow(ctx, `
SELECT to_regprocedure('health.lock_dispatch_holds(uuid,text,text,uuid,uuid)') IS NOT NULL
   AND to_regprocedure('health.lock_dispatch_node(uuid)') IS NOT NULL`).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Skip("health.lock_dispatch_holds/lock_dispatch_node do not exist: apply the TASK-10 health dispatch lock migration first")
	}
	var member bool
	if err := e.admin.QueryRow(ctx, `SELECT pg_has_role('coordinator_app', 'coordinator_reader', 'MEMBER')`).Scan(&member); err != nil {
		t.Fatal(err)
	}
	if !member {
		if _, err := e.admin.Exec(ctx, `GRANT coordinator_reader TO coordinator_app`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = e.admin.Exec(context.Background(), `REVOKE coordinator_reader FROM coordinator_app`) })
	}
	if _, err := e.admin.Exec(ctx, `TRUNCATE health.holds, health.node_boot_generation`); err != nil {
		t.Fatal(err)
	}
	return e
}

func putHold(t *testing.T, e *env, scope, scopeID, reason string) string {
	t.Helper()
	id := uuid.NewString()
	if _, err := e.admin.Exec(context.Background(), `
INSERT INTO health.holds (hold_id, scope, scope_id, reason, owner_component, requested_by)
VALUES ($1, $2, $3, $4, 'control-health', 'test')`, id, scope, scopeID, reason); err != nil {
		t.Fatal(err)
	}
	return id
}

// putBoot inserts a guarded boot. Migration 20261017172321 requires every row
// to state startup_capture_measurement, and a guarded row to be measured.
func putBoot(t *testing.T, e *env, node, boot, state string) {
	t.Helper()
	if _, err := e.admin.Exec(context.Background(), `
INSERT INTO health.node_boot_generation (node_uid, boot_id, sensor_generation, guard_generation, startup_capture,
    startup_capture_measurement, state, updated_at)
VALUES ($1, $2, 3, 5, 'guarded', 'measured', $3, now())`, node, boot, state); err != nil {
		t.Fatal(err)
	}
}

// inAppTx runs fn in a coordinator_app transaction and returns fn's error.
func inAppTx(t *testing.T, e *env, fn func(pgx.Tx) error) error {
	t.Helper()
	var ferr error
	err := pgx.BeginTxFunc(context.Background(), e.svc.Pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		ferr = fn(tx)
		return ferr
	})
	if ferr != nil {
		return ferr
	}
	if err != nil {
		t.Fatal(err)
	}
	return nil
}

func holdIDs(hs []Hold) []string {
	ids := make([]string, len(hs))
	for i, h := range hs {
		ids[i] = h.HoldID
	}
	return ids
}

func TestPGHealthHolds(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	svcSess := uuid.NewString()
	global := putHold(t, e, "global", "*", "operator_stop")
	node := putHold(t, e, "node", adapterNode, "probe_failed")
	workload := putHold(t, e, "workload", "agent-exec/agent-runtime", "control_drift")
	target := putHold(t, e, "target", "receiver-primary", "export_lag")
	userSess := putHold(t, e, "session", e.session, "operator_stop")
	serviceSess := putHold(t, e, "session", svcSess, "operator_stop")
	// Never returned: another node, another workload, and a released hold.
	putHold(t, e, "node", uuid.NewString(), "probe_failed")
	putHold(t, e, "workload", "agent-exec/other", "control_drift")
	released := putHold(t, e, "global", "*", "db_unavailable")
	if _, err := e.admin.Exec(ctx, `UPDATE health.holds SET released_at = now(), release_ref = 'r' WHERE hold_id = $1`, released); err != nil {
		t.Fatal(err)
	}
	sorted := func(ids ...string) []string { sort.Strings(ids); return ids }

	for name, c := range map[string]struct {
		scope HoldScope
		want  []string
	}{
		"global only": {HoldScope{}, []string{global}},
		"user session": {HoldScope{NodeUID: adapterNode, WorkloadID: "agent-exec/agent-runtime", TargetID: "receiver-primary", SessionID: e.session},
			sorted(global, node, workload, target, userSess)},
		// A service-session decision has no workload; empty fields go as NULL.
		"service session": {HoldScope{NodeUID: adapterNode, TargetID: "receiver-primary", ServiceSessionID: svcSess},
			sorted(global, node, target, serviceSess)},
		"service session, no target": {HoldScope{NodeUID: adapterNode, ServiceSessionID: svcSess}, sorted(global, node, serviceSess)},
		"other node":                 {HoldScope{NodeUID: uuid.NewString()}, []string{global}},
	} {
		var holds []Hold
		err := inAppTx(t, e, func(tx pgx.Tx) error {
			var err error
			holds, err = PGHealth{}.LockHolds(ctx, tx, c.scope)
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := holdIDs(holds); len(got) != len(c.want) || !sort.StringsAreSorted(got) || !slices.Equal(got, c.want) {
			t.Errorf("%s: holds %v, want %v (hold_id order)", name, got, c.want)
		}
	}
}

func TestPGHealthNodeBoot(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	lock := func(node string) (NodeBoot, error) {
		var nb NodeBoot
		err := inAppTx(t, e, func(tx pgx.Tx) error {
			var err error
			nb, err = PGHealth{}.LockNodeBoot(ctx, tx, node)
			return err
		})
		return nb, err
	}

	if _, err := lock(adapterNode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no row: %v", err)
	}
	putBoot(t, e, adapterNode, "boot-0", "retired")
	if _, err := lock(adapterNode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("only retired: %v", err)
	}
	putBoot(t, e, adapterNode, adapterBoot, "ready")
	nb, err := lock(adapterNode)
	if err != nil || nb != (NodeBoot{BootID: adapterBoot, SensorGeneration: 3, GuardGeneration: 5, State: "ready"}) {
		t.Fatalf("one row: %+v %v", nb, err)
	}
	putBoot(t, e, adapterNode, "boot-2", "preparing")
	_, err = lock(adapterNode)
	var de *Error
	if !errors.As(err, &de) || de.Code != "CONTROL_HEALTH_UNAVAILABLE" {
		t.Fatalf("two rows: %v", err)
	}
}

// liveLeases is PGHealth with every lease valid, to run checkHealth.
type liveLeases struct{ PGHealth }

func (liveLeases) CheckLeases(context.Context, pgx.Tx, string, string) error { return nil }

func TestPGHealthCheckHealth(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	putBoot(t, e, adapterNode, adapterBoot, "ready")
	svc := &Service{Pool: e.svc.Pool, Health: liveLeases{}}
	dec := Decision{DecisionBasis: "approval", SessionID: e.session, WorkloadID: "agent-exec/agent-runtime",
		OperationID: "receiver.submit", TargetID: "receiver-primary"}
	check := func() error {
		return inAppTx(t, e, func(tx pgx.Tx) error { return svc.checkHealth(ctx, tx, e.adapter, dec, ActivePolicy{}) })
	}
	if err := check(); err != nil {
		t.Fatalf("ready node, no hold: %v", err)
	}
	putHold(t, e, "target", "receiver-primary", "export_lag")
	var de *Error
	if err := check(); !errors.As(err, &de) || de.Code != "HOLD_ACTIVE" {
		t.Fatalf("target hold: %v", err)
	}
}

// The function's FOR SHARE lasts until the caller's transaction ends: a
// concurrent UPDATE waits, and with a short lock_timeout fails with 55P03.
func TestPGHealthLocksHeldUntilCommit(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	global := putHold(t, e, "global", "*", "operator_stop")
	putBoot(t, e, adapterNode, adapterBoot, "ready")

	update := func(sql string, args ...any) error {
		conn, err := e.admin.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '200ms'`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
	}
	releaseHold := `UPDATE health.holds SET released_at = now(), release_ref = 'r' WHERE hold_id = $1`
	holdBoot := `UPDATE health.node_boot_generation SET state = 'held' WHERE node_uid = $1`

	err := inAppTx(t, e, func(tx pgx.Tx) error {
		if _, err := (PGHealth{}).LockHolds(ctx, tx, HoldScope{NodeUID: adapterNode}); err != nil {
			return err
		}
		if _, err := (PGHealth{}).LockNodeBoot(ctx, tx, adapterNode); err != nil {
			return err
		}
		for what, err := range map[string]error{
			"hold release": update(releaseHold, global),
			"boot state":   update(holdBoot, adapterNode),
		} {
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
				t.Errorf("%s during the transaction: %v, want 55P03", what, err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := update(releaseHold, global); err != nil {
		t.Fatalf("hold release after commit: %v", err)
	}
	if err := update(holdBoot, adapterNode); err != nil {
		t.Fatalf("boot state after commit: %v", err)
	}
}

// A lock wait inside the function longer than the coordinator's
// lock_timeout is 503 LOCK_TIMEOUT, not CONTROL_HEALTH_UNAVAILABLE.
func TestPGHealthLockTimeout(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	global := putHold(t, e, "global", "*", "operator_stop")
	putBoot(t, e, adapterNode, adapterBoot, "ready")
	svc := &Service{Pool: e.svc.Pool, Health: PGHealth{}}

	for what, c := range map[string]struct {
		lockSQL string
		arg     string
		call    func(pgx.Tx) error
	}{
		"holds": {`SELECT 1 FROM health.holds WHERE hold_id = $1 FOR UPDATE`, global, func(tx pgx.Tx) error {
			_, err := svc.health().LockHolds(ctx, tx, HoldScope{NodeUID: adapterNode})
			return depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "holds")
		}},
		"node": {`SELECT 1 FROM health.node_boot_generation WHERE node_uid = $1 FOR UPDATE`, adapterNode, func(tx pgx.Tx) error {
			_, err := svc.health().LockNodeBoot(ctx, tx, adapterNode)
			return depErr(err, "CONTROL_HEALTH_UNAVAILABLE", "node_boot_generation")
		}},
	} {
		blocker, err := e.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := blocker.Exec(ctx, c.lockSQL, c.arg); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		err = svc.inTx(ctx, c.call)
		_ = blocker.Rollback(ctx)
		var de *Error
		if !errors.As(err, &de) || de.Code != "LOCK_TIMEOUT" {
			t.Errorf("%s: %v, want LOCK_TIMEOUT", what, err)
		}
		if d := time.Since(start); d < 1500*time.Millisecond {
			t.Errorf("%s: failed after %v, before lock_timeout", what, d)
		}
	}
}

// coordinator_app reaches the functions through coordinator_reader, and has
// no UPDATE on the tables, so it cannot take the lock with direct SQL.
func TestPGHealthGrants(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	var appExec, readerExec, publicExec, gatewayExec, appUpdate, appUpdateNode bool
	if err := e.admin.QueryRow(ctx, `
SELECT has_function_privilege('coordinator_app', 'health.lock_dispatch_holds(uuid,text,text,uuid,uuid)', 'EXECUTE')
   AND has_function_privilege('coordinator_app', 'health.lock_dispatch_node(uuid)', 'EXECUTE'),
       has_function_privilege('coordinator_reader', 'health.lock_dispatch_holds(uuid,text,text,uuid,uuid)', 'EXECUTE')
   AND has_function_privilege('coordinator_reader', 'health.lock_dispatch_node(uuid)', 'EXECUTE'),
       EXISTS (SELECT FROM pg_proc p, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
               WHERE p.oid IN ('health.lock_dispatch_holds(uuid,text,text,uuid,uuid)'::regprocedure,
                               'health.lock_dispatch_node(uuid)'::regprocedure)
                 AND a.grantee = 0 AND a.privilege_type = 'EXECUTE'),
       has_function_privilege('gateway_reader', 'health.lock_dispatch_holds(uuid,text,text,uuid,uuid)', 'EXECUTE')
    OR has_function_privilege('gateway_reader', 'health.lock_dispatch_node(uuid)', 'EXECUTE'),
       has_table_privilege('coordinator_app', 'health.holds', 'UPDATE'),
       has_table_privilege('coordinator_app', 'health.node_boot_generation', 'UPDATE')`).Scan(
		&appExec, &readerExec, &publicExec, &gatewayExec, &appUpdate, &appUpdateNode); err != nil {
		t.Fatal(err)
	}
	if !appExec || !readerExec || publicExec || gatewayExec || appUpdate || appUpdateNode {
		t.Fatalf("app exec %v, reader exec %v, PUBLIC exec %v, gateway_reader exec %v, app UPDATE holds %v / node %v",
			appExec, readerExec, publicExec, gatewayExec, appUpdate, appUpdateNode)
	}
	err := inAppTx(t, e, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT 1 FROM health.holds FOR SHARE`)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("direct FOR SHARE as coordinator_app: %v, want 42501", err)
	}
}

// putLease writes a control_health_leases row valid for ttl (negative:
// already expired).
func putLease(t *testing.T, e *env, source, component, scope, scopeID string, ttl time.Duration) {
	t.Helper()
	if _, err := e.admin.Exec(context.Background(), `
INSERT INTO health.control_health_leases (source_id, component, scope, scope_id, observed_state, lease_until, reported_at, first_reported_at)
VALUES ($1, $2, $3, $4, 'healthy', now() + make_interval(secs => $5), now(), now())
ON CONFLICT (source_id, component) DO UPDATE SET scope = excluded.scope, scope_id = excluded.scope_id,
    lease_until = excluded.lease_until, reported_at = excluded.reported_at`,
		source, component, scope, scopeID, ttl.Seconds()); err != nil {
		t.Fatal(err)
	}
}

// putRequiredLeases makes every default required lease valid for target.
func putRequiredLeases(t *testing.T, e *env, target string) {
	t.Helper()
	for _, c := range DefaultRequiredGlobal {
		putLease(t, e, c+"/1", c, "global", "*", time.Minute)
	}
	for _, c := range DefaultRequiredTarget {
		putLease(t, e, c+"/"+target, c, "target", target, time.Minute)
	}
}

func TestPGHealthCheckLeasesPostgres(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `TRUNCATE health.control_health_leases`); err != nil {
		t.Fatal(err)
	}
	check := func(target string) error {
		return inAppTx(t, e, func(tx pgx.Tx) error { return PGHealth{}.CheckLeases(ctx, tx, "receiver.submit", target) })
	}
	checkOp := func(op, target string) error {
		return inAppTx(t, e, func(tx pgx.Tx) error { return PGHealth{}.CheckLeases(ctx, tx, op, target) })
	}
	wantMissing := func(err error, what string) {
		t.Helper()
		var de *Error
		if !errors.As(err, &de) || de.Code != "CONTROL_HEALTH_UNAVAILABLE" || !strings.Contains(de.Msg, what) {
			t.Fatalf("want CONTROL_HEALTH_UNAVAILABLE for %s, got %v", what, err)
		}
	}
	wantMissing(check("receiver-primary"), "global/audit-db")

	putRequiredLeases(t, e, "receiver-primary")
	if err := check("receiver-primary"); err != nil {
		t.Fatalf("all live: %v", err)
	}
	// Another target's destination-evidence lease does not count.
	wantMissing(check("receiver-other"), "target/destination-evidence")
	// No target: only the global set.
	if err := check(""); err != nil {
		t.Fatalf("no target: %v", err)
	}
	// A non-receiver operation does not require destination-evidence even
	// though its decision carries a target_id (review #222): only the global
	// set is checked, so these pass with the globals live and no target lease.
	if _, err := e.admin.Exec(ctx, `DELETE FROM health.control_health_leases WHERE component = 'destination-evidence'`); err != nil {
		t.Fatal(err)
	}
	for _, op := range []string{"model.generate", "k8s.pods.logs", "evidence.get", "discovery.list"} {
		if err := checkOp(op, "some-target"); err != nil {
			t.Fatalf("%s must not require destination-evidence: %v", op, err)
		}
	}
	// receiver.submit still requires it, now that the lease is gone.
	wantMissing(check("receiver-primary"), "target/destination-evidence")
	putRequiredLeases(t, e, "receiver-primary")

	// An expired lease of one replica is covered by a live one; once every
	// source is expired the lease is missing.
	putLease(t, e, "gateway/2", "gateway", "global", "*", -time.Second)
	if err := check("receiver-primary"); err != nil {
		t.Fatalf("one live gateway replica: %v", err)
	}
	putLease(t, e, "gateway/1", "gateway", "global", "*", -time.Second)
	wantMissing(check("receiver-primary"), "global/gateway")
	putLease(t, e, "gateway/1", "gateway", "global", "*", time.Minute)

	// A required component reported at another scope does not count.
	if _, err := e.admin.Exec(ctx, `DELETE FROM health.control_health_leases WHERE component = 'coordinator'`); err != nil {
		t.Fatal(err)
	}
	putLease(t, e, "coordinator/1", "coordinator", "node", adapterNode, time.Minute)
	wantMissing(check("receiver-primary"), "global/coordinator")
}

func TestPGHealthLockActivationHoldPostgres(t *testing.T) {
	e := healthSetup(t)
	ctx := context.Background()
	lock := func() (Hold, error) {
		var h Hold
		err := inAppTx(t, e, func(tx pgx.Tx) error {
			var err error
			h, err = PGHealth{}.LockActivationHold(ctx, tx, uuid.NewString())
			return err
		})
		return h, err
	}
	if _, err := lock(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no hold: %v", err)
	}
	// A policy_activation hold at another scope is not the activation hold.
	putHold(t, e, "node", adapterNode, "policy_activation")
	putHold(t, e, "global", "*", "operator_stop")
	if _, err := lock(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no global activation hold: %v", err)
	}
	id := putHold(t, e, "global", "*", "policy_activation")
	if h, err := lock(); err != nil || h != (Hold{HoldID: id, Reason: "policy_activation"}) {
		t.Fatalf("open hold: %+v %v", h, err)
	}
}

// PGPolicy locks the environment's active_policy row FOR SHARE through
// release.lock_active_policy, which coordinator_app may execute without any
// privilege on the table.
func TestPGPolicyPostgres(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `ALTER TABLE release.active_policy DISABLE TRIGGER active_policy_epoch;
DELETE FROM release.active_policy; ALTER TABLE release.active_policy ENABLE TRIGGER active_policy_epoch`); err != nil {
		t.Fatal(err)
	}
	lock := func(env string) (ActivePolicy, error) {
		var a ActivePolicy
		err := inAppTx(t, e, func(tx pgx.Tx) error {
			var err error
			a, err = PGPolicy{Environment: env}.LockActivePolicy(ctx, tx)
			return err
		})
		return a, err
	}
	var de *Error
	if _, err := lock("test"); !errors.As(err, &de) || de.Code != "POLICY_UNAVAILABLE" {
		t.Fatalf("no row: %v", err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO release.active_policy VALUES ('test', 7, 'bundle-1', repeat('a', 64), repeat('b', 64), $1, $2, repeat('c', 64), gen_random_uuid(), now())`,
		opaRev, catalogD); err != nil {
		t.Fatal(err)
	}
	if a, err := lock("test"); err != nil || a != (ActivePolicy{Epoch: 7, CatalogDigest: catalogD, ExpectedOPARevision: opaRev}) {
		t.Fatalf("row: %+v %v", a, err)
	}
	if _, err := lock("other"); !errors.As(err, &de) || de.Code != "POLICY_UNAVAILABLE" {
		t.Fatalf("other environment: %v", err)
	}

	// The lock lasts until the transaction ends: the epoch CAS waits.
	err := inAppTx(t, e, func(tx pgx.Tx) error {
		if _, err := (PGPolicy{Environment: "test"}).LockActivePolicy(ctx, tx); err != nil {
			return err
		}
		conn, err := e.admin.Acquire(ctx)
		if err != nil {
			return err
		}
		defer conn.Release()
		cas := pgx.BeginFunc(ctx, conn, func(c pgx.Tx) error {
			if _, err := c.Exec(ctx, `SET LOCAL lock_timeout = '200ms'`); err != nil {
				return err
			}
			_, err := c.Exec(ctx, `UPDATE release.active_policy SET epoch = epoch + 1 WHERE scope_id = 'test'`)
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(cas, &pgErr) || pgErr.Code != "55P03" {
			t.Errorf("epoch CAS during the reservation: %v, want 55P03", cas)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Direct SQL as coordinator_app is denied.
	err = inAppTx(t, e, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT 1 FROM release.active_policy`)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("direct SELECT as coordinator_app: %v, want 42501", err)
	}
}
