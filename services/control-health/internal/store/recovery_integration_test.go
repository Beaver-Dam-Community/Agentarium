package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/store/healthdb"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRecoveryPostgres is the M2-4 end-to-end scenario on a disposable real
// PostgreSQL 16 database with the merged audit, health and identity migrations
// plus the recovery migration: sensor lease expiry -> node hold -> readers see
// it over mTLS -> verified probe passes -> automatic release, every state
// change committed with its audit event. The CA is local; this is not CAS,
// Tetragon, probe-runner or GKE evidence.
func TestRecoveryPostgres(t *testing.T) {
	dsn := os.Getenv("HEALTH_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set HEALTH_TEST_ADMIN_DSN for disposable PostgreSQL integration")
	}
	auditPath := os.Getenv("HEALTH_TEST_AUDIT_MIGRATION")
	if auditPath == "" {
		t.Fatal("HEALTH_TEST_AUDIT_MIGRATION must point to real TASK-07 migration")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := uuid.NewString()[:8]
	database, login, migrator := "recovery_test_"+suffix, "recovery_login_"+suffix, "recovery_migrator_"+suffix
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v: %s", err, q)
		}
	}
	exec(admin, "CREATE ROLE "+migrator+" LOGIN NOSUPERUSER CREATEROLE")
	exec(admin, "CREATE DATABASE "+database+" OWNER "+migrator)
	// Health roles are cluster-wide. Reuse pre-existing ones the way the
	// installer does (ADMIN only, no inherited privileges) and drop the ones this
	// test created, so other suites on the same cluster start from the same state.
	healthRoles := []string{"health_owner", "control_health_writer", "health_reader", "coordinator_reader", "gateway_reader", "correlation_reader", "correlation_writer"}
	created := []string{}
	for _, role := range healthRoles {
		var exists bool
		if err := admin.QueryRow(ctx, "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)", role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			exec(admin, "GRANT "+role+" TO "+migrator+" WITH ADMIN TRUE, INHERIT FALSE, SET FALSE")
		} else {
			created = append(created, role)
		}
	}
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = database
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		db.Close(ctx)
		_, _ = admin.Exec(ctx, "DROP DATABASE "+database+" WITH(FORCE)")
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+login)
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+migrator)
		for _, role := range created {
			if _, err := admin.Exec(ctx, "DROP ROLE IF EXISTS "+role); err != nil {
				t.Errorf("cleanup %s: %v", role, err)
			}
		}
	}()
	read := func(path string) string {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	exec(db, read(auditPath))
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	one := func(pattern string) string {
		t.Helper()
		paths, _ := filepath.Glob(filepath.Join(root, "migrations", pattern))
		if len(paths) != 1 {
			t.Fatalf("migration %s not found", pattern)
		}
		return paths[0]
	}
	migrationCfg := cfg.Copy()
	migrationCfg.User = migrator
	migrationDB, err := pgx.ConnectConfig(ctx, migrationCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close(ctx)
	exec(migrationDB, read(one("*_health_control_health.up.sql")))
	// Health migrations merged before this one, in version order: the store
	// writes first_reported_at and the watch-gap columns.
	exec(migrationDB, read(one("*_health_lease_first_report.up.sql")))
	exec(migrationDB, read(one("*_health_watch_gap_receiver.up.sql")))
	recoveryUp, recoveryDown := read(one("*_health_probe_recovery.up.sql")), read(one("*_health_probe_recovery.down.sql"))
	exec(migrationDB, recoveryUp)
	exec(migrationDB, recoveryDown)
	exec(migrationDB, recoveryUp)
	integrityUp, integrityDown := read(one("*_health_audit_integrity.up.sql")), read(one("*_health_audit_integrity.down.sql"))
	exec(migrationDB, integrityUp)
	exec(migrationDB, integrityDown)
	exec(migrationDB, integrityUp)
	// #199 NodeFacts measurement column, the latest health migration.
	exec(migrationDB, read(one("*_health_startup_capture_measurement.up.sql")))
	var leaked bool
	if err := migrationDB.QueryRow(ctx, "SELECT pg_has_role(current_user,'health_owner','SET') OR pg_has_role(current_user,'health_owner','USAGE')").Scan(&leaked); err != nil || leaked {
		t.Fatalf("recovery migration leaked health_owner: %v %v", leaked, err)
	}
	exec(db, read(filepath.Join(root, "migrations/20261014144500_identity_workload_pki.up.sql")))
	exec(db, read(one("*_audit_probe_evidence.up.sql")))
	exec(db, read(one("*_correlation_lifecycle_intervals.up.sql")))
	exec(db, "GRANT SELECT ON identity.registered_workloads,identity.issued_certificates TO control_health_writer")
	exec(admin, "CREATE ROLE "+login+" LOGIN")
	exec(db, "GRANT control_health_writer,audit_producer TO "+login)
	exec(db, "INSERT INTO audit.db_role_sources VALUES($1,'health-source',false)", login)
	exec(db, "INSERT INTO audit.producer_event_grants VALUES ('health-source','execution_held','*'),('health-source','source_health_changed','*'),('health-source','hold_released','*')")

	node := uuid.NewString()
	otherNode := uuid.NewString()
	runnerPod := uuid.NewString()
	const (
		gatewaySAN   = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
		sensorSAN    = "spiffe://agentarium.internal/ns/agent-sensors/sa/sensor-exporter"
		otherSensor  = "spiffe://agentarium.internal/ns/agent-sensors/sa/sensor-exporter-b"
		lifecycleSAN = "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"
		probeSAN     = "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner"
		exportSAN    = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter"
		receiptSAN   = "spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector"
		writerSAN    = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
		releaserSAN  = "spiffe://agentarium.internal/ns/agent-release/sa/releaser"
		isolatedSAN  = "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner-isolated"
	)
	type principal struct {
		san, ns, ksa, serial, component, scopes, releasable string
		node                                                string
	}
	principals := []principal{
		{gatewaySAN, "agent-control", "policy-gateway", "11", "gateway", "{global}", "{}", ""},
		{sensorSAN, "agent-sensors", "sensor-exporter", "12", "node-sensors", "{node}", "{sensor_degraded}", node},
		{lifecycleSAN, "agent-sensors", "lifecycle-recorder", "13", "lifecycle-recorder", "{node}", "{}", node},
		{probeSAN, "agent-adapters", "probe-runner", "14", "probe-runner", "{node}", "{}", node},
		{health.ConsoleBFFSAN, "agent-control", "workload-identity", "15", "console-bff", "{global}", "{}", ""},
		{otherSensor, "agent-sensors", "sensor-exporter-b", "16", "node-sensors", "{node}", "{sensor_degraded}", otherNode},
		{exportSAN, "agent-observe", "audit-exporter", "17", "audit-export", "{global,node}", "{export_lag}", ""},
		{receiptSAN, "agent-observe", "evidence-collector", "18", "destination-evidence", "{target}", "{probe_failed}", ""},
		{writerSAN, "agent-observe", "audit-writer", "19", "audit-db", "{global}", "{db_unavailable}", ""},
		{releaserSAN, "agent-release", "releaser", "1a", "releaser", "{global}", "{policy_activation}", ""},
		{isolatedSAN, "agent-adapters", "probe-runner-isolated", "1b", "probe-runner", "{node}", "{}", node},
	}
	isolatedPod := uuid.NewString()
	exec(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
		VALUES(gen_random_uuid(),gen_random_uuid(),$1,$2,'boot-1','isolated-container',now()-interval '1 hour','open',1,ARRAY[gen_random_uuid()])`, isolatedPod, node)
	exec(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
		VALUES(gen_random_uuid(),gen_random_uuid(),$1,$2,'boot-1','runner-container',now()-interval '1 hour','open',1,ARRAY[gen_random_uuid()])`, runnerPod, node)
	for _, p := range principals {
		exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ($1,$2,'service',true)", p.ns, p.ksa)
		var nodeArg, bootArg any
		if p.node != "" {
			nodeArg, bootArg = p.node, "boot-1"
		}
		var podArg any
		switch p.san {
		case probeSAN:
			podArg = runnerPod
		case isolatedSAN:
			podArg = isolatedPod
		}
		exec(db, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,pod_uid,node_uid,boot_id,issued_at,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,now()-interval '1 hour',now()+interval '1 hour')", p.serial, p.san, p.ns, p.ksa, podArg, nodeArg, bootArg)
		if p.san == exportSAN {
			continue // registered by the audit_integrity migration
		}
		exec(db, "INSERT INTO health.component_principals VALUES ($1,$2,$3::text[],'{}'::text[],$4::text[])", p.san, p.component, p.scopes, p.releasable)
	}
	var registered int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM health.component_principals WHERE
		(principal_san=$1 AND component='audit-export' AND allowed_scopes='{global,node}' AND allowed_hold_reasons='{export_lag}' AND releasable_hold_reasons='{export_lag}') OR
		(principal_san='spiffe://agentarium.internal/ns/agent-observe/sa/audit-verifier' AND component='audit-verifier' AND allowed_scopes='{global}' AND allowed_hold_reasons='{audit_integrity}' AND releasable_hold_reasons='{}')`, exportSAN).Scan(&registered); err != nil || registered != 2 {
		t.Fatalf("audit principals not registered as #163 specifies: %d %v", registered, err)
	}
	exec(db, "INSERT INTO health.node_boot_generation VALUES($1,'boot-1',1,1,'unsupported','preparing',now(),'not_measured'),($2,'boot-1',1,1,'unsupported','preparing',now(),'not_measured')", node, otherNode)

	// Real probe runner certificates are Pod-bound (TASK-03 3.3.1 probe
	// profile): one principal row per KSA service SAN, one issued record per
	// Pod SAN. runnerNode keeps these reports apart from the main node.
	runnerNode, execPod, adaptersPod, revokedPod := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	execPodSAN := "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/" + execPod
	adaptersPodSAN := "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + adaptersPod
	revokedPodSAN := "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/" + revokedPod
	exec(db, "INSERT INTO health.node_boot_generation VALUES($1,'boot-1',1,1,'unsupported','preparing',now(),'not_measured')", runnerNode)
	exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-exec','probe-runner','probe',true)")
	exec(db, "INSERT INTO health.component_principals VALUES ('spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner','probe-runner','{node}','{}','{}')")
	for _, c := range []struct{ serial, san, ns, pod, container, revoked string }{
		{"21", execPodSAN, "agent-exec", execPod, "exec-runner-container", ""},
		{"22", adaptersPodSAN, "agent-adapters", adaptersPod, "adapters-runner-container", ""},
		{"23", revokedPodSAN, "agent-exec", revokedPod, "revoked-runner-container", "now()"},
	} {
		revoked := "NULL"
		if c.revoked != "" {
			revoked = c.revoked
		}
		exec(db, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,pod_uid,node_uid,boot_id,issued_at,expires_at,revoked_at) VALUES ($1,$2,$3,'probe-runner',$4,$5,'boot-1',now()-interval '1 hour',now()+interval '1 hour',"+revoked+")", c.serial, c.san, c.ns, c.pod, runnerNode)
		exec(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
			VALUES(gen_random_uuid(),gen_random_uuid(),$1,$2,'boot-1',$3,now()-interval '1 hour','open',1,ARRAY[gen_random_uuid()])`, c.pod, runnerNode, c.container)
	}

	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database = database
	pc.ConnConfig.User = login
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := New(pool, Config{Sources: []SourceBinding{{"receipt-1", receiptSAN, "receiver-a"}}, Readers: []string{gatewaySAN}, AuditSourceID: "health-source", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Epoch = "1"
	call := newMTLSHarness(t, s, map[string]int64{gatewaySAN: 0x11, sensorSAN: 0x12, lifecycleSAN: 0x13, probeSAN: 0x14, health.ConsoleBFFSAN: 0x15, otherSensor: 0x16, exportSAN: 0x17, receiptSAN: 0x18, writerSAN: 0x19, releaserSAN: 0x1a, isolatedSAN: 0x1b, execPodSAN: 0x21, adaptersPodSAN: 0x22})

	generation := int64(1)
	putLease := func(san, source, component, scope, id string, sensorGeneration *int64) {
		t.Helper()
		now := time.Now().UTC()
		lease := health.Lease{SourceID: source, Component: component, Scope: scope, ScopeID: id, ReportedAt: now, LeaseUntil: now.Add(15 * time.Second), ObservedState: "healthy", SensorGeneration: sensorGeneration}
		raw, _ := json.Marshal(lease)
		if status := call(san, "POST", "/internal/control-health/leases", raw, nil, nil); status != 200 {
			t.Fatalf("lease %s: HTTP %d", component, status)
		}
	}
	renew := func() {
		t.Helper()
		putLease(sensorSAN, "tetragon-node/"+node, "node-sensors", "node", node, &generation)
		putLease(lifecycleSAN, "lifecycle-node/"+node, "lifecycle-recorder", "node", node, nil)
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	events := func(kind string) int {
		return count("SELECT count(*) FROM audit.audit_events WHERE event_type=$1", kind)
	}
	nodeState := func() string {
		var state string
		if err := db.QueryRow(ctx, "SELECT state FROM health.node_boot_generation WHERE node_uid=$1", node).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	snapshot := func() health.Snapshot {
		t.Helper()
		var snap health.Snapshot
		if status := call(gatewaySAN, "GET", "/internal/control-health?scope=node&scope_id="+node, nil, nil, &snap); status != 200 {
			t.Fatalf("GET HTTP %d", status)
		}
		return snap
	}
	report := func(san string, body map[string]any) (string, int) {
		t.Helper()
		raw, _ := json.Marshal(body)
		var ack health.ProbeAck
		status := call(san, "POST", "/internal/control-health/probe-results", raw, nil, &ack)
		return ack.ProbeResultID, status
	}
	probe := func(kind, outcome string) (string, int) {
		t.Helper()
		body := map[string]any{"probe_kind": kind, "node_uid": node, "boot_id": "boot-1", "outcome": outcome, "evidence_refs": []string{}}
		if outcome == "pass" {
			stimulus := time.Now().UTC()
			kernelEvidence(t, db, node, "runner-container", kind, stimulus, "")
			body["stimulus_at"], body["evidence_refs"] = stimulus.Format(time.RFC3339Nano), []string{"runner:" + kind}
		}
		return report(probeSAN, body)
	}
	passAll := func() []string {
		t.Helper()
		ids := []string{}
		for _, kind := range health.NodeProbeKinds {
			id, status := probe(kind, "pass")
			if status != 201 {
				t.Fatalf("probe %s HTTP %d", kind, status)
			}
			ids = append(ids, id)
		}
		return ids
	}
	// Simulate one 60s probe interval: earlier stimulus windows are moved back.
	age := func(ids []string, seconds int) {
		t.Helper()
		exec(db, fmt.Sprintf("UPDATE health.probe_results SET judged_at=judged_at-interval '%[1]d seconds',stimulus_at=stimulus_at-interval '%[1]d seconds' WHERE probe_result_id=ANY($1::uuid[])", seconds), ids)
	}
	ageHolds := func() {
		exec(db, "UPDATE health.holds SET created_at=created_at-interval '10 minutes' WHERE released_at IS NULL")
	}

	t.Run("sensor_lease_expiry_holds_node", func(t *testing.T) {
		renew()
		exec(db, "UPDATE health.control_health_leases SET lease_until=now()-interval '1 second' WHERE source_id='tetragon-node/'||$1", node)
		if err := s.Expire(ctx); err != nil {
			t.Fatal(err)
		}
		snap := snapshot()
		if snap.State != "unhealthy" || len(snap.OpenHolds) != 1 || snap.OpenHolds[0].Reason != "lease_expired" || snap.OpenHolds[0].OwnerComponent != "control-health" {
			t.Fatalf("gated reader did not see the node hold: %+v", snap)
		}
		if nodeState() != "held" || events("execution_held") != 1 || events("source_health_changed") != 1 {
			t.Fatalf("hold/state/audit not atomic: state=%s held=%d changed=%d", nodeState(), events("execution_held"), events("source_health_changed"))
		}
		ageHolds()
	})
	t.Run("probes_without_lease_do_not_release", func(t *testing.T) {
		age(passAll(), 60)
		passAll()
		if err := s.Recover(ctx); err != nil {
			t.Fatal(err)
		}
		if len(snapshot().OpenHolds) != 1 || events("hold_released") != 0 {
			t.Fatal("probe passes released a hold while the sensor lease was expired")
		}
	})
	t.Run("heartbeat_alone_does_not_release", func(t *testing.T) {
		// Passes recorded while the lease was expired stay in place (#158
		// review): renewing the lease later must not release with them.
		age(probeIDs(t, db), 300)
		renew()
		if err := s.Recover(ctx); err != nil {
			t.Fatal(err)
		}
		if len(snapshot().OpenHolds) != 1 || nodeState() != "held" {
			t.Fatal("renewed heartbeat released the hold without probes")
		}
	})
	t.Run("burst_of_passes_is_one_stimulus", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			passAll()
		}
		if err := s.Recover(ctx); err != nil {
			t.Fatal(err)
		}
		if len(snapshot().OpenHolds) != 1 || events("hold_released") != 0 {
			t.Fatal("a burst of pass reports inside one probe interval released the hold")
		}
		exec(db, "DELETE FROM health.probe_evidence_uses; DELETE FROM health.probe_results")
	})
	t.Run("probe_reporter_is_per_kind", func(t *testing.T) {
		// Only the probe runner reports node answer probes; the sensor exporter
		// (also bound to this node) cannot, and the runner cannot report export.
		pass := map[string]any{"probe_kind": "tcp", "node_uid": node, "boot_id": "boot-1", "stimulus_at": time.Now().UTC().Format(time.RFC3339Nano), "outcome": "pass", "evidence_refs": []string{"k"}}
		if _, status := report(sensorSAN, pass); status != 403 {
			t.Fatalf("node-sensors reported an answer probe: HTTP %d", status)
		}
		if _, status := report(probeSAN, map[string]any{"probe_kind": "export", "scope": "global", "scope_id": "*", "outcome": "pass", "evidence_refs": []string{"k"}}); status != 403 {
			t.Fatalf("probe runner reported export: HTTP %d", status)
		}
		stale := map[string]any{"probe_kind": "tcp", "node_uid": node, "boot_id": "boot-0", "stimulus_at": time.Now().UTC().Format(time.RFC3339Nano), "outcome": "pass", "evidence_refs": []string{"k"}}
		if _, status := report(probeSAN, stale); status != 403 {
			t.Fatalf("stale boot probe: HTTP %d", status)
		}
		if _, status := report(probeSAN, map[string]any{"probe_kind": "tcp", "node_uid": otherNode, "boot_id": "boot-1", "outcome": "fail", "evidence_refs": []string{}}); status != 403 {
			t.Fatalf("other node probe: HTTP %d", status)
		}
		if _, status := report(gatewaySAN, map[string]any{"probe_kind": "export", "scope": "global", "scope_id": "*", "outcome": "fail", "evidence_refs": []string{}}); status != 403 {
			t.Fatalf("unregistered reporter: HTTP %d", status)
		}
		if count("SELECT count(*) FROM health.probe_results") != 0 {
			t.Fatal("rejected report stored")
		}
	})
	t.Run("probe_failure_holds_node", func(t *testing.T) {
		id, status := probe("tcp", "fail")
		if status != 201 {
			t.Fatalf("HTTP %d", status)
		}
		reasons := []string{}
		for _, h := range snapshot().OpenHolds {
			reasons = append(reasons, h.Reason)
		}
		slices.Sort(reasons)
		if !slices.Equal(reasons, []string{"lease_expired", "probe_failed"}) || events("execution_held") != 2 {
			t.Fatalf("probe failure hold: %v", reasons)
		}
		ageHolds()
		age([]string{id}, 120)
	})
	t.Run("release_audit_failure_rolls_back", func(t *testing.T) {
		renew()
		age(passAll(), 60)
		before := count("SELECT count(*) FROM health.probe_results")
		exec(db, "DELETE FROM audit.producer_event_grants WHERE event_type='hold_released'")
		for _, kind := range health.NodeProbeKinds {
			if _, status := probe(kind, "pass"); status == 201 && kind == "file" {
				t.Fatal("release committed without its audit event")
			}
		}
		if count("SELECT count(*) FROM health.holds WHERE released_at IS NOT NULL") != 0 || count("SELECT count(*) FROM health.probe_results") != before+2 {
			t.Fatal("partial release or probe commit")
		}
		exec(db, "INSERT INTO audit.producer_event_grants VALUES('health-source','hold_released','*')")
	})
	t.Run("verified_probes_recover_node", func(t *testing.T) {
		renew()
		// Exactly one probe interval apart, independent of how long the
		// earlier subtests took.
		exec(db, "DELETE FROM health.probe_evidence_uses; DELETE FROM health.probe_results")
		age(passAll(), 60)
		passAll()
		snap := snapshot()
		if len(snap.OpenHolds) != 0 || snap.State != "healthy" || nodeState() != "ready" {
			t.Fatalf("not recovered: state=%s node=%s holds=%+v", snap.State, nodeState(), snap.OpenHolds)
		}
		rows, err := db.Query(ctx, "SELECT release_ref FROM health.holds WHERE released_at IS NOT NULL")
		if err != nil {
			t.Fatal(err)
		}
		refs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil || len(refs) != 2 {
			t.Fatalf("released %v %v", refs, err)
		}
		for _, ref := range refs {
			var probeID string
			if _, err := fmt.Sscanf(ref, "auto:control-health:%s", &probeID); err != nil || count("SELECT count(*) FROM health.probe_results WHERE probe_result_id=$1::uuid AND result='pass'", probeID) != 1 {
				t.Fatalf("release_ref %s does not cite a stored pass", ref)
			}
		}
		if events("hold_released") != 2 || count("SELECT count(*) FROM audit.audit_events WHERE event_type='hold_released' AND safe_payload->>'released_by'=$1", controlHealthSAN) != 2 {
			t.Fatal("hold_released audit missing")
		}
		if count("SELECT count(*) FROM health.probe_results WHERE (result='pass') <> (stimulus_at IS NOT NULL) OR namespace<>'agent-adapters' OR scope<>'node' OR scope_id<>$1", node) != 0 {
			t.Fatal("stored node probe columns do not follow the wire mapping")
		}
	})
	release := func(san, hold string, body map[string]any, headers map[string]string, out any) int {
		raw, _ := json.Marshal(body)
		return call(san, "POST", "/internal/holds/"+hold+"/release", raw, headers, out)
	}
	insertHold := func(scope, id, reason, owner string) string {
		t.Helper()
		var hold string
		if err := db.QueryRow(ctx, "INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by,created_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,'test',now()-interval '10 minutes') RETURNING hold_id::text", scope, id, reason, owner).Scan(&hold); err != nil {
			t.Fatal(err)
		}
		return hold
	}
	t.Run("owner_auto_release_rechecks_probes", func(t *testing.T) {
		renew()
		exec(db, "DELETE FROM health.probe_evidence_uses; DELETE FROM health.probe_results")
		hold := insertHold("node", node, "sensor_degraded", "node-sensors")
		first := passAll()
		age(first, 60)
		second := passAll()
		all := append(slices.Clone(first), second...)
		body := func(ids []string) map[string]any {
			return map[string]any{"justification": "drop counter flat", "evidence_refs": []string{"lease:sensor-1"}, "probe_result_ids": ids}
		}
		if status := release(probeSAN, hold, body(all), nil, nil); status != 403 {
			t.Fatalf("non-owner release HTTP %d", status)
		}
		if status := release(otherSensor, hold, body(all), nil, nil); status != 403 {
			t.Fatalf("owner component bound to another node released this node: HTTP %d", status)
		}
		if status := release(sensorSAN, hold, body(second), nil, nil); status != 409 {
			t.Fatalf("partial probe citation HTTP %d", status)
		}
		exec(db, "DELETE FROM audit.producer_event_grants WHERE event_type='hold_released'")
		if status := release(sensorSAN, hold, body(all), nil, nil); status != 503 || count("SELECT count(*) FROM health.holds WHERE hold_id=$1::uuid AND released_at IS NULL", hold) != 1 {
			t.Fatalf("release without audit HTTP %d", status)
		}
		exec(db, "INSERT INTO audit.producer_event_grants VALUES('health-source','hold_released','*')")
		var ack health.ReleaseAck
		if status := release(sensorSAN, hold, body(all), nil, &ack); status != 200 || ack.HoldID != hold || ack.ReleaseRef != "auto:node-sensors:"+second[2] || ack.ReleasedAt.IsZero() {
			t.Fatalf("owner release retry HTTP %d %+v", status, ack)
		}
		// The same request again (a lost response) returns the stored answer.
		var again health.ReleaseAck
		if status := release(sensorSAN, hold, body(all), nil, &again); status != 200 || again != ack {
			t.Fatalf("repeated release HTTP %d %+v", status, again)
		}
		var justification string
		if err := db.QueryRow(ctx, "SELECT safe_payload->>'justification' FROM audit.audit_events WHERE event_type='hold_released' AND safe_payload->>'hold_id'=$1", hold).Scan(&justification); err != nil || justification != "drop counter flat" {
			t.Fatalf("justification %q %v", justification, err)
		}
		if status := release(sensorSAN, hold, body(first), nil, nil); status != 409 {
			t.Fatalf("different request on a released hold HTTP %d", status)
		}
	})
	t.Run("stale_passes_never_release", func(t *testing.T) {
		renew()
		exec(db, "DELETE FROM health.probe_evidence_uses; DELETE FROM health.probe_results")
		hold := insertHold("node", node, "sensor_degraded", "node-sensors")
		first := passAll()
		age(first, 360)
		second := passAll()
		age(second, 300)
		if status := release(sensorSAN, hold, map[string]any{"justification": "x", "evidence_refs": []string{}, "probe_result_ids": append(first, second...)}, nil, nil); status != 409 {
			t.Fatalf("passes five minutes old released the hold: HTTP %d", status)
		}
		exec(db, "UPDATE health.holds SET released_at=now(),release_ref='test-cleanup' WHERE hold_id=$1::uuid", hold)
	})
	t.Run("recency_is_per_probe_kind", func(t *testing.T) {
		// #158 review: fresh process passes must not release a hold whose tcp
		// and file passes are five minutes old (after the hold was created).
		renew()
		exec(db, "DELETE FROM health.probe_evidence_uses; DELETE FROM health.probe_results")
		hold := insertHold("node", node, "sensor_degraded", "node-sensors")
		first := passAll()
		age(first, 360)
		second := passAll()
		age(second, 300)
		older, status := probe("process", "pass")
		if status != 201 {
			t.Fatalf("process pass HTTP %d", status)
		}
		age([]string{older}, 60)
		newer, status := probe("process", "pass")
		if status != 201 {
			t.Fatalf("process pass HTTP %d", status)
		}
		cited := []string{newer, older, second[1], first[1], second[2], first[2]}
		if status := release(sensorSAN, hold, map[string]any{"justification": "x", "evidence_refs": []string{}, "probe_result_ids": cited}, nil, nil); status != 409 {
			t.Fatalf("fresh process passes released with old tcp/file passes: HTTP %d", status)
		}
		exec(db, "UPDATE health.holds SET released_at=now(),release_ref='test-cleanup' WHERE hold_id=$1::uuid", hold)
	})
	t.Run("delayed_retry_keeps_stimulus_spacing", func(t *testing.T) {
		// #179 review: a runner waiting for kernel ingest retries with the same
		// stimulus_at, so the second pass is judged 90s after the first while
		// the stimuli are 60s apart. Spacing follows stimulus_at.
		renew()
		exec(db, "DELETE FROM health.probe_evidence_uses; DELETE FROM health.probe_results")
		hold := insertHold("node", node, "sensor_degraded", "node-sensors")
		first := passAll()
		age(first, 90)
		second := []string{}
		for _, kind := range health.NodeProbeKinds {
			stimulus := time.Now().UTC().Add(-30 * time.Second)
			kernelEvidence(t, db, node, "runner-container", kind, stimulus, "")
			id, status := report(probeSAN, map[string]any{"probe_kind": kind, "node_uid": node, "boot_id": "boot-1", "outcome": "pass",
				"stimulus_at": stimulus.Format(time.RFC3339Nano), "evidence_refs": []string{"runner:" + kind}})
			if status != 201 {
				t.Fatalf("retried %s pass HTTP %d", kind, status)
			}
			second = append(second, id)
		}
		if status := release(sensorSAN, hold, map[string]any{"justification": "x", "evidence_refs": []string{}, "probe_result_ids": append(second, first...)}, nil, nil); status != 200 {
			t.Fatalf("delayed retry with 60s stimulus spacing not released: HTTP %d", status)
		}
	})
	t.Run("owner_attested_release", func(t *testing.T) {
		db1 := insertHold("global", "*", "db_unavailable", "audit-db")
		evidence := map[string]any{"justification": "audit DB write/read probe passed", "evidence_refs": []string{"audit_event:" + uuid.NewString()}}
		if status := release(exportSAN, db1, evidence, nil, nil); status != 403 {
			t.Fatalf("non-owner attested release HTTP %d", status)
		}
		var ack health.ReleaseAck
		if status := release(writerSAN, db1, evidence, nil, &ack); status != 200 || ack.ReleaseRef != "attested:audit-db:"+evidence["evidence_refs"].([]string)[0] {
			t.Fatalf("db_unavailable attested release HTTP %d %+v", status, ack)
		}
		lag := insertHold("global", "*", "export_lag", "audit-export")
		if status := release(exportSAN, lag, evidence, nil, nil); status != 409 {
			t.Fatalf("export_lag released without a probe: HTTP %d", status)
		}
		activation := insertHold("global", "*", "policy_activation", "releaser")
		if status := release(releaserSAN, activation, map[string]any{"justification": "activation probe ok", "evidence_refs": []string{"action:" + uuid.NewString()}}, nil, nil); status != 200 {
			t.Fatalf("policy_activation attested release HTTP %d", status)
		}
		if status := release(releaserSAN, lag, map[string]any{"justification": "x", "evidence_refs": []string{}}, nil, nil); status != 422 {
			t.Fatalf("release without any evidence HTTP %d", status)
		}
		exec(db, "UPDATE health.holds SET released_at=now(),release_ref='test' WHERE hold_id=$1::uuid", lag)
	})
	t.Run("export_probe_releases_export_lag_after_one_pass", func(t *testing.T) {
		hold := insertHold("global", "*", "export_lag", "audit-export")
		export := func(scope, id, outcome string) string {
			t.Helper()
			body := map[string]any{"probe_kind": "export", "scope": scope, "scope_id": id, "outcome": outcome, "evidence_refs": []string{"gs://evidence/probes/" + uuid.NewString() + ".json#1"}}
			if scope == "node" {
				body["node_uid"] = id
			}
			pid, status := report(exportSAN, body)
			if status != 201 {
				t.Fatalf("export probe HTTP %d", status)
			}
			return pid
		}
		older := export("global", "*", "pass")
		if count("SELECT count(*) FROM health.probe_results WHERE probe_result_id=$1::uuid AND scope='global' AND scope_id='*' AND node_uid IS NULL AND boot_id IS NULL AND namespace IS NULL AND stimulus_at IS NULL AND result='pass'", older) != 1 {
			t.Fatal("node-less export probe not stored per contract")
		}
		body := func(id string) map[string]any {
			return map[string]any{"justification": "lag normal", "evidence_refs": []string{}, "probe_result_ids": []string{id}}
		}
		if status := release(exportSAN, hold, body(older), nil, nil); status != 409 {
			t.Fatalf("release without a live audit-export lease HTTP %d", status)
		}
		putLease(exportSAN, "export-1", "audit-export", "global", "*", nil)
		latest := export("global", "*", "pass")
		if status := release(exportSAN, hold, body(older), nil, nil); status != 409 {
			t.Fatalf("stale export pass released the hold: HTTP %d", status)
		}
		failed := export("global", "*", "fail")
		if status := release(exportSAN, hold, body(latest), nil, nil); status != 409 {
			t.Fatalf("pass followed by a failure released the hold: HTTP %d", status)
		}
		_ = failed
		latest = export("global", "*", "pass")
		var ack health.ReleaseAck
		if status := release(exportSAN, hold, body(latest), nil, &ack); status != 200 || ack.ReleaseRef != "auto:audit-export:"+latest {
			t.Fatalf("export_lag release HTTP %d %+v", status, ack)
		}
		// Node-scoped export backlog: node_uid without boot_id, same single-pass rule.
		nodeHold := insertHold("node", otherNode, "export_lag", "audit-export")
		pid := export("node", otherNode, "pass")
		if count("SELECT count(*) FROM health.probe_results WHERE probe_result_id=$1::uuid AND scope='node' AND node_uid=$2::uuid AND boot_id IS NULL", pid, otherNode) != 1 {
			t.Fatal("node export probe not stored per contract")
		}
		if status := release(exportSAN, nodeHold, body(pid), nil, &ack); status != 200 || ack.ReleaseRef != "auto:audit-export:"+pid {
			t.Fatalf("node export_lag release HTTP %d %+v", status, ack)
		}
		if _, status := report(sensorSAN, map[string]any{"probe_kind": "export", "scope": "node", "scope_id": node, "node_uid": node, "outcome": "pass", "evidence_refs": []string{"k"}}); status != 403 {
			t.Fatalf("node-sensors reported export: HTTP %d", status)
		}
		if status := release(exportSAN, uuid.NewString(), body(pid), nil, nil); status != 404 {
			t.Fatalf("unknown hold HTTP %d", status)
		}
		if _, status := report(receiptSAN, map[string]any{"probe_kind": "receipt", "scope": "target", "scope_id": "receiver-a", "outcome": "fail", "evidence_refs": []string{}}); status != 201 {
			t.Fatalf("receipt probe HTTP %d", status)
		}
		if _, status := report(receiptSAN, map[string]any{"probe_kind": "receipt", "scope": "target", "scope_id": "receiver-b", "outcome": "fail", "evidence_refs": []string{}}); status != 403 {
			t.Fatalf("unbound target receipt HTTP %d", status)
		}
	})
	t.Run("audit_integrity_is_operator_only", func(t *testing.T) {
		hold := insertHold("global", "*", "audit_integrity", "control-health")
		if status := release(exportSAN, hold, map[string]any{"justification": "x", "evidence_refs": []string{}, "probe_result_ids": []string{uuid.NewString()}}, nil, nil); status != 403 {
			t.Fatalf("audit_integrity auto-released: HTTP %d", status)
		}
		approval := map[string]any{"justification": "chain repaired", "evidence_refs": []string{"audit_event:1"}, "operator_approval": map[string]any{"authenticated_actor": "google:alice", "approved_at": time.Now().UTC().Format(time.RFC3339Nano), "console_request_id": "req-ai"}}
		var ack health.ReleaseAck
		if status := release(health.ConsoleBFFSAN, hold, approval, map[string]string{"X-Agentarium-Console-Actor": "google:alice", "X-Agentarium-Console-Roles": "operator"}, &ack); status != 200 || ack.ReleaseRef != "operator:google:alice:req-ai" {
			t.Fatalf("operator release HTTP %d %+v", status, ack)
		}
	})
	t.Run("probe_row_constraints", func(t *testing.T) {
		for _, sql := range []string{
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,probe_kind,judged_at,result) VALUES(gen_random_uuid(),'global','*','tcp',now(),'pass')",
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,node_uid,boot_id,probe_kind,judged_at,result) VALUES(gen_random_uuid(),'target','t',gen_random_uuid(),'b','receipt',now(),'pass')",
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,probe_kind,judged_at,result,namespace) VALUES(gen_random_uuid(),'global','*','export',now(),'pass','agent-sensors')",
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,node_uid,boot_id,probe_kind,judged_at,result,namespace) VALUES(gen_random_uuid(),'node','x',gen_random_uuid(),'b','file',now(),'pass','agent-exec')",
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,node_uid,boot_id,probe_kind,judged_at,result,namespace) VALUES(gen_random_uuid(),'node',$1,$1::uuid,'b','process',now(),'pass','agent-sensors')",
		} {
			args := []any{}
			if strings.Contains(sql, "$1") {
				args = append(args, node)
			}
			if _, err := db.Exec(ctx, sql, args...); err == nil {
				t.Fatalf("constraint accepted %s", sql)
			}
		}
	})
	t.Run("security_release_requires_operator_approval", func(t *testing.T) {
		renew()
		hold := insertHold("node", node, "sensor_tampering", "control-health")
		approval := map[string]any{"justification": "rule hash restored", "evidence_refs": []string{"drift:1"}, "operator_approval": map[string]any{"authenticated_actor": "google:alice", "approved_at": time.Now().UTC().Format(time.RFC3339Nano), "console_request_id": "req-1"}}
		ok := map[string]string{"X-Agentarium-Console-Actor": "google:alice", "X-Agentarium-Console-Roles": "viewer,operator"}
		first := passAll()
		age(first, 60)
		ids := append(first, passAll()...)
		if status := release(sensorSAN, hold, map[string]any{"justification": "x", "evidence_refs": []string{}, "probe_result_ids": ids}, nil, nil); status != 403 {
			t.Fatalf("security hold auto-released: HTTP %d", status)
		}
		if status := release(gatewaySAN, hold, approval, ok, nil); status != 403 {
			t.Fatalf("headers trusted from non-BFF caller: HTTP %d", status)
		}
		if status := release(health.ConsoleBFFSAN, hold, approval, map[string]string{"X-Agentarium-Console-Actor": "google:alice", "X-Agentarium-Console-Roles": "viewer"}, nil); status != 403 {
			t.Fatalf("non-operator role: HTTP %d", status)
		}
		if status := release(health.ConsoleBFFSAN, hold, approval, map[string]string{"X-Agentarium-Console-Actor": "google:mallory", "X-Agentarium-Console-Roles": "operator"}, nil); status != 403 {
			t.Fatalf("actor mismatch: HTTP %d", status)
		}
		if count("SELECT count(*) FROM health.holds WHERE hold_id=$1::uuid AND released_at IS NULL", hold) != 1 {
			t.Fatal("rejected approval released the security hold")
		}
		var ack health.ReleaseAck
		if status := release(health.ConsoleBFFSAN, hold, approval, ok, &ack); status != 200 || ack.ReleaseRef != "operator:google:alice:req-1" {
			t.Fatalf("operator release HTTP %d %+v", status, ack)
		}
		if nodeState() != "ready" || count("SELECT count(*) FROM audit.audit_events WHERE event_type='hold_released' AND safe_payload->>'release_ref'='operator:google:alice:req-1' AND safe_payload->>'released_by'='google:alice' AND safe_payload->>'justification'='rule hash restored'") != 1 {
			t.Fatal("operator release audit or node state missing")
		}
		other := insertHold("node", node, "control_drift", "control-health")
		if status := release(health.ConsoleBFFSAN, other, approval, ok, nil); status != 409 {
			t.Fatalf("console_request_id reused for another hold: HTTP %d", status)
		}
		old := map[string]any{"justification": "x", "evidence_refs": []string{}, "operator_approval": map[string]any{"authenticated_actor": "google:alice", "approved_at": time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano), "console_request_id": "req-old"}}
		if status := release(health.ConsoleBFFSAN, other, old, ok, nil); status != 403 {
			t.Fatalf("ten-minute-old approval HTTP %d", status)
		}
		fresh := map[string]any{"justification": "drift fixed", "evidence_refs": []string{}, "operator_approval": map[string]any{"authenticated_actor": "google:alice", "approved_at": time.Now().UTC().Format(time.RFC3339Nano), "console_request_id": "req-3"}}
		if status := release(health.ConsoleBFFSAN, other, fresh, ok, nil); status != 200 {
			t.Fatalf("fresh approval HTTP %d", status)
		}
	})
	t.Run("transient_hold_not_operator_releasable", func(t *testing.T) {
		if _, status := probe("file", "fail"); status != 201 {
			t.Fatal(status)
		}
		var hold string
		if err := db.QueryRow(ctx, "SELECT hold_id::text FROM health.holds WHERE reason='probe_failed' AND released_at IS NULL").Scan(&hold); err != nil {
			t.Fatal(err)
		}
		approval := map[string]any{"justification": "x", "evidence_refs": []string{}, "operator_approval": map[string]any{"authenticated_actor": "google:alice", "approved_at": time.Now().UTC().Format(time.RFC3339Nano), "console_request_id": "req-2"}}
		if status := release(health.ConsoleBFFSAN, hold, approval, map[string]string{"X-Agentarium-Console-Actor": "google:alice", "X-Agentarium-Console-Roles": "operator"}, nil); status != 403 {
			t.Fatalf("operator bypassed probe verification: HTTP %d", status)
		}
	})
	t.Run("ready_never_overrides_open_hold", func(t *testing.T) {
		// Even if a caller evaluated "no holds" earlier, the SQL transition to
		// ready refuses while an unreleased node hold exists.
		var current healthdbNode
		current.load(t, db, node)
		if err := setNodeState(ctx, healthdbNew(pool), current.row, "ready"); err != nil {
			t.Fatal(err)
		}
		if nodeState() == "ready" {
			t.Fatal("node marked ready with an open probe_failed hold")
		}
	})
	t.Run("concurrent_expiry_and_recovery_keep_state_consistent", func(t *testing.T) {
		testConcurrentRecovery(t, ctx, s, db, probeSAN)
	})
	t.Run("answer_pass_requires_stored_kernel_evidence", func(t *testing.T) {
		before := count("SELECT count(*) FROM health.probe_results")
		pass := func(kind string, stimulus time.Time) int {
			_, status := report(isolatedSAN, map[string]any{"probe_kind": kind, "node_uid": node, "boot_id": "boot-1", "stimulus_at": stimulus.UTC().Format(time.RFC3339Nano), "outcome": "pass", "evidence_refs": []string{"runner-ref"}})
			return status
		}
		// Stimuli must be within 40s of server time; windows are kept apart.
		at := func(seconds int) time.Time { return time.Now().Add(time.Duration(-seconds) * time.Second) }
		kernelEvidence(t, db, node, "isolated-container", "tcp", at(38), "close")
		kernelEvidence(t, db, node, "isolated-container", "file", at(38), "denied")
		kernelEvidence(t, db, node, "isolated-container", "file", at(24), "noreturn")
		kernelEvidence(t, db, node, "other-pod-container", "process", at(38), "")
		kernelEvidence(t, db, otherNode, "isolated-container", "process", at(38), "")
		valid := at(24)
		kernelEvidence(t, db, node, "isolated-container", "process", valid, "")
		for name, c := range map[string]struct {
			kind     string
			stimulus time.Time
		}{
			"tcp without CLOSE":         {"tcp", at(38)},
			"file without denied open":  {"file", at(38)},
			"openat without a return":   {"file", at(24)},
			"another Pod's events":      {"process", at(38)},
			"another node's events":     {"process", at(38)},
			"no events in the window":   {"process", at(36)},
			"stimulus older than 40s":   {"process", at(100)},
			"events outside the window": {"process", valid.Add(-15 * time.Second)},
		} {
			if status := pass(c.kind, c.stimulus); status != 409 {
				t.Fatalf("%s: HTTP %d", name, status)
			}
		}
		if count("SELECT count(*) FROM health.probe_results") != before {
			t.Fatal("unverified pass stored")
		}
		if status := pass("process", valid); status != 201 {
			t.Fatalf("verified pass HTTP %d", status)
		}
		// The same window again: its events are consumed, so no second pass.
		if status := pass("process", valid); status != 409 {
			t.Fatalf("replayed evidence window HTTP %d", status)
		}
		if count("SELECT count(*) FROM health.probe_results WHERE stimulus_at IS NOT NULL AND evidence_refs @> '[\"runner-ref\"]' AND jsonb_array_length(evidence_refs)=3") < 1 {
			t.Fatal("server-found kernel evidence not stored with the pass")
		}
		if _, err := pool.Exec(ctx, "SELECT * FROM audit.kernel_events LIMIT 1"); err == nil {
			t.Fatal("writer can read kernel_events directly")
		}
	})
	t.Run("pod_bound_and_relayed_runner_reports", func(t *testing.T) {
		post := func(san string, headers map[string]string, kind, outcome, container string) int {
			t.Helper()
			body := map[string]any{"probe_kind": kind, "node_uid": runnerNode, "boot_id": "boot-1", "outcome": outcome, "evidence_refs": []string{"runner:" + kind}}
			if outcome == "pass" {
				stimulus := time.Now().UTC()
				kernelEvidence(t, db, runnerNode, container, kind, stimulus, "")
				body["stimulus_at"] = stimulus.Format(time.RFC3339Nano)
			}
			raw, _ := json.Marshal(body)
			return call(san, "POST", "/internal/control-health/probe-results", raw, headers, nil)
		}
		relayed := func(identity, serial string) map[string]string {
			h := map[string]string{}
			if identity != "" {
				h[health.PeerIdentityHeader] = identity
			}
			if serial != "" {
				h[health.PeerSerialHeader] = serial
			}
			return h
		}
		stored := func(namespace string) int {
			return count("SELECT count(*) FROM health.probe_results WHERE node_uid=$1 AND namespace=$2", runnerNode, namespace)
		}
		// agent-adapters runner: direct mTLS with its Pod SAN.
		if status := post(adaptersPodSAN, nil, "process", "pass", "adapters-runner-container"); status != 201 || stored("agent-adapters") != 1 {
			t.Fatalf("direct Pod-bound report: HTTP %d stored=%d", status, stored("agent-adapters"))
		}
		// agent-exec runner: the gateway connection plus both forwarded headers.
		if status := post(gatewaySAN, relayed(execPodSAN, "21"), "tcp", "pass", "exec-runner-container"); status != 201 || stored("agent-exec") != 1 {
			t.Fatalf("relayed report: HTTP %d stored=%d", status, stored("agent-exec"))
		}
		if count("SELECT count(*) FROM health.probe_results WHERE node_uid=$1 AND namespace='agent-exec' AND probe_kind='tcp' AND result='pass' AND stimulus_at IS NOT NULL AND jsonb_array_length(evidence_refs)=4", runnerNode) != 1 {
			t.Fatal("relayed pass not stored with the server-found kernel evidence of the agent-exec Pod")
		}
		before := count("SELECT count(*) FROM health.probe_results")
		for name, c := range map[string]struct {
			san     string
			headers map[string]string
			want    int
		}{
			"gateway without headers":          {gatewaySAN, nil, 403},
			"gateway without serial":           {gatewaySAN, relayed(execPodSAN, ""), 403},
			"gateway without identity":         {gatewaySAN, relayed("", "21"), 403},
			"serial of another certificate":    {gatewaySAN, relayed(execPodSAN, "22"), 403},
			"relayed agent-adapters runner":    {gatewaySAN, relayed(adaptersPodSAN, "22"), 403},
			"relayed revoked certificate":      {gatewaySAN, relayed(revokedPodSAN, "23"), 403},
			"relayed service SAN":              {gatewaySAN, relayed("spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner", "21"), 403},
			"headers ignored off the gateway":  {probeSAN, relayed(execPodSAN, "21"), 403},
			"agent-exec Pod connects directly": {execPodSAN, nil, 401},
		} {
			if status := post(c.san, c.headers, "file", "fail", ""); status != c.want {
				t.Errorf("%s: HTTP %d, want %d", name, status, c.want)
			}
		}
		if count("SELECT count(*) FROM health.probe_results") != before {
			t.Fatal("a rejected report was stored")
		}
		// A probe runner Pod certificate is accepted for probe results only.
		if status := call(adaptersPodSAN, "GET", "/internal/control-health?scope=node&scope_id="+runnerNode, nil, nil, nil); status != 401 {
			t.Fatalf("Pod-bound runner read the snapshot: HTTP %d", status)
		}
	})
	t.Run("runtime_permissions", func(t *testing.T) {
		for _, sql := range []string{"UPDATE health.holds SET reason='export_lag'", "UPDATE health.holds SET owner_component='x'", "DELETE FROM health.holds", "UPDATE health.probe_results SET result='pass'", "DELETE FROM health.probe_results"} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("writer allowed %s", sql)
			}
		}
	})
}

var kernelSequence int64

// kernelEvidence stores the 3.2 probe table events of kind for a container on
// node/boot-1 around stimulus (base TASK-07 columns). omit drops one required
// event: "close" (tcp CLOSE), "denied" (file EACCES openat) or "noreturn"
// (the allowed openat without a return value).
func kernelEvidence(t *testing.T, db *pgx.Conn, node, container, kind string, stimulus time.Time, omit string) {
	t.Helper()
	type ev struct {
		eventType string
		container any
		state     any
		attrs     string
	}
	var events []ev
	switch kind {
	case "process":
		events = []ev{{"process_exec", container, nil, "{}"}, {"process_exit", container, nil, "{}"}}
	case "tcp":
		events = []ev{{"tcp_connect", container, nil, "{}"}, {"tcp_state", nil, 1, "{}"}}
		if omit != "close" {
			events = append(events, ev{"tcp_state", nil, 7, "{}"})
		}
	case "file":
		events = []ev{{"file_open", container, nil, `{"path":"/probe/allowed","flags":0,"return_code":0}`}, {"openat", container, nil, `{"path":"/probe/allowed","flags":0,"return_errno":0}`}}
		if omit == "noreturn" {
			events[1] = ev{"openat", container, nil, `{"path":"/probe/allowed","flags":0}`}
		}
		if omit != "denied" {
			events = append(events, ev{"openat", container, nil, `{"path":"/probe/denied","flags":0,"return_errno":-13}`})
		}
	}
	kernelSequence++
	sport := 30000 + int(kernelSequence%30000)
	for i, e := range events {
		kernelSequence++
		if _, err := db.Exec(context.Background(), `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,container_id,saddr,sport,daddr,dport,tcp_new_state,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
			VALUES(gen_random_uuid(),'sensor','sensor-1','1',$1,'exp-1',1,$2::uuid,'boot-1',$3,$3,$3,$4,'exec-1',$5,'10.0.0.5',$6,'10.96.0.30',8443,$7,'resolved','v1',$8,'full',$9::jsonb,$8)`,
			kernelSequence, node, stimulus.Add(time.Duration(i+1)*100*time.Millisecond), e.eventType, e.container, sport, e.state, strings.Repeat("e", 64), e.attrs); err != nil {
			t.Fatal(err)
		}
	}
}

func probeIDs(t *testing.T, db *pgx.Conn) []string {
	t.Helper()
	rows, err := db.Query(context.Background(), "SELECT probe_result_id::text FROM health.probe_results")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

type healthdbNode struct {
	row healthdb.HealthNodeBootGeneration
}

func (n *healthdbNode) load(t *testing.T, db *pgx.Conn, node string) {
	t.Helper()
	rows, err := healthdb.New(db).CurrentNodes(context.Background(), pgUUID(node))
	if err != nil || len(rows) != 1 {
		t.Fatalf("current node: %v %d", err, len(rows))
	}
	n.row = rows[0]
}

func healthdbNew(pool *pgxpool.Pool) *healthdb.Queries { return healthdb.New(pool) }

func pgUUID(s string) pgtype.UUID {
	var u pgtype.UUID
	_ = u.Scan(s)
	return u
}

// testConcurrentRecovery races a final passing probe (which releases the last
// node hold and may mark ready) with a sensor lease expiry (which creates a
// new node hold) on fresh nodes. Whatever order wins, a ready boot never has
// an open node hold and a boot with an open hold is held.
func testConcurrentRecovery(t *testing.T, ctx context.Context, s *Store, db *pgx.Conn, probeSAN string) {
	for i := 0; i < 12; i++ {
		node := uuid.NewString()
		serial := fmt.Sprintf("c%02d", i)
		for _, q := range []string{
			"INSERT INTO health.node_boot_generation VALUES($1::uuid,'boot-1',1,1,'unsupported','held',now(),'not_measured')",
			"INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,pod_uid,node_uid,boot_id,issued_at,expires_at) VALUES ('" + serial + "','" + probeSAN + "','agent-adapters','probe-runner',$1::uuid,$1::uuid,'boot-1',now()-interval '1 hour',now()+interval '1 hour')",
			"INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids) VALUES(gen_random_uuid(),gen_random_uuid(),$1::uuid,$1::uuid,'boot-1','c-'||$1::text,now()-interval '1 hour','open',1,ARRAY[gen_random_uuid()])",
			"INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,sensor_generation,observed_state,details,lease_until,reported_at,first_reported_at) VALUES('tetragon-node/'||$1::text,'node-sensors','node',$1::text,$1::uuid,'boot-1',1,'healthy','{}',now()+interval '1 minute',now(),now())",
			"INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,lease_until,reported_at,first_reported_at) VALUES('lifecycle-node/'||$1::text,'lifecycle-recorder','node',$1::text,$1::uuid,'boot-1','healthy','{}',now()+interval '1 minute',now(),now())",
			"INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by,created_at) VALUES(gen_random_uuid(),'node',$1::text,'probe_failed','control-health','test',now()-interval '10 minutes')",
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,node_uid,boot_id,namespace,probe_kind,judged_at,result,evidence_refs) SELECT gen_random_uuid(),'node',$1::text,$1::uuid,'boot-1','agent-adapters',k,now()-interval '60 seconds','pass','[\"k\"]' FROM unnest(ARRAY['process','tcp','file']) k",
			"INSERT INTO health.probe_results(probe_result_id,scope,scope_id,node_uid,boot_id,namespace,probe_kind,judged_at,result,evidence_refs) SELECT gen_random_uuid(),'node',$1::text,$1::uuid,'boot-1','agent-adapters',k,now(),'pass','[\"k\"]' FROM unnest(ARRAY['process','tcp']) k",
		} {
			if _, err := db.Exec(ctx, q, node); err != nil {
				t.Fatal(err)
			}
		}
		scope, nodeID, boot := "node", node, "boot-1"
		stimulus := time.Now().UTC()
		kernelEvidence(t, db, node, "c-"+node, "file", stimulus, "")
		report := health.ProbeReport{ProbeKind: "file", Scope: &scope, ScopeID: &nodeID, NodeUID: &nodeID, BootID: &boot, StimulusAt: &stimulus, Outcome: "pass", EvidenceRefs: []string{"runner-ref"}}
		start := make(chan struct{})
		errs := make(chan error, 2)
		go func() {
			<-start
			_, err := s.ReportProbe(ctx, health.Peer{SAN: probeSAN, Serial: serial}, health.ProbeRelay{}, report)
			errs <- err
		}()
		go func() {
			<-start
			if _, err := db.Exec(ctx, "UPDATE health.control_health_leases SET lease_until=now()-interval '1 second' WHERE source_id='cs-'||$1::text", node); err != nil {
				errs <- err
				return
			}
			errs <- s.Expire(ctx)
		}()
		close(start)
		for j := 0; j < 2; j++ {
			if err := <-errs; err != nil {
				t.Fatalf("iteration %d: %v", i, err)
			}
		}
		var state string
		var open int
		if err := db.QueryRow(ctx, "SELECT g.state,(SELECT count(*) FROM health.holds h WHERE h.scope='node' AND h.scope_id=$1::text AND h.released_at IS NULL) FROM health.node_boot_generation g WHERE g.node_uid=$1::uuid", node).Scan(&state, &open); err != nil {
			t.Fatal(err)
		}
		if (state == "ready" && open > 0) || (open > 0 && state != "held") {
			t.Fatalf("iteration %d: state=%s open_holds=%d", i, state, open)
		}
	}
}

// newMTLSHarness serves the production handler over TLS 1.3 with client
// certificates whose serial/SAN match identity.issued_certificates rows.
func newMTLSHarness(t *testing.T, backend health.Backend, serials map[string]int64) func(san, method, path string, body []byte, headers map[string]string, out any) int {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(200), Subject: pkix.Name{CommonName: "local recovery CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	issue := func(san string, serial int64, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(san)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	certPEM, keyPEM := issue("spiffe://agentarium.internal/ns/agent-observe/sa/control-health", 201, x509.ExtKeyUsageServerAuth)
	paths := map[string][]byte{"server.crt": certPEM, "server.key": keyPEM, "ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})}
	for name, data := range paths {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewUnstartedServer(health.Handler{Backend: backend})
	server.TLS, err = health.LoadTLS(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	clients := map[string]*http.Client{}
	for san, serial := range serials {
		c, k := issue(san, serial, x509.ExtKeyUsageClientAuth)
		pair, err := tls.X509KeyPair(c, k)
		if err != nil {
			t.Fatal(err)
		}
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}}
		t.Cleanup(tr.CloseIdleConnections)
		clients[san] = &http.Client{Transport: tr, Timeout: 5 * time.Second}
	}
	return func(san, method, path string, body []byte, headers map[string]string, out any) int {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := clients[san].Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if out != nil && (resp.StatusCode == 200 || resp.StatusCode == 201) {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				t.Fatal(err)
			}
		}
		return resp.StatusCode
	}
}
