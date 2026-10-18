package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgres(t *testing.T) {
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
	database := "health_test_" + suffix
	login := "health_login_" + suffix
	migrator := "health_migrator_" + suffix
	exec := func(c *pgx.Conn, q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(admin, "CREATE ROLE "+migrator+" LOGIN NOSUPERUSER CREATEROLE")
	exec(admin, "CREATE DATABASE "+database+" OWNER "+migrator)
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
	}()
	audit, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	exec(db, string(audit))
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	paths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_control_health.up.sql"))
	if len(paths) != 1 {
		t.Fatal("health migration not found")
	}
	migration, _ := os.ReadFile(paths[0])
	migrationCfg := cfg.Copy()
	migrationCfg.User = migrator
	migrationDB, err := pgx.ConnectConfig(ctx, migrationCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer migrationDB.Close(ctx)
	exec(migrationDB, string(migration))
	assertOwnerRevoked := func() {
		t.Helper()
		var canSet, inherit, super bool
		var current string
		err := migrationDB.QueryRow(ctx, "SELECT pg_has_role(current_user,'health_owner','SET'),pg_has_role(current_user,'health_owner','USAGE'),rolsuper,current_user FROM pg_roles WHERE rolname=current_user").Scan(&canSet, &inherit, &super, &current)
		if err != nil || canSet || inherit || super || current != migrator {
			t.Fatalf("migration privilege leak: set=%v inherit=%v super=%v user=%s err=%v", canSet, inherit, super, current, err)
		}
	}
	assertOwnerRevoked()
	downPaths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_control_health.down.sql"))
	down, err := os.ReadFile(downPaths[0])
	if err != nil {
		t.Fatal(err)
	}
	exec(migrationDB, string(down))
	assertOwnerRevoked()
	exec(migrationDB, string(migration))
	assertOwnerRevoked()
	// The store reads the probe scope columns added by the recovery migration.
	recoveryPaths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_probe_recovery.up.sql"))
	if len(recoveryPaths) != 1 {
		t.Fatal("recovery migration not found")
	}
	recovery, _ := os.ReadFile(recoveryPaths[0])
	exec(migrationDB, string(recovery))
	integrityPaths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_audit_integrity.up.sql"))
	if len(integrityPaths) != 1 {
		t.Fatal("audit_integrity migration not found")
	}
	integrity, _ := os.ReadFile(integrityPaths[0])
	exec(migrationDB, string(integrity))
	assertOwnerRevoked()
	watchPaths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_watch_gap_receiver.up.sql"))
	watchDownPaths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_watch_gap_receiver.down.sql"))
	if len(watchPaths) != 1 || len(watchDownPaths) != 1 {
		t.Fatal("watch gap migration not found")
	}
	watchUp, _ := os.ReadFile(watchPaths[0])
	watchDown, _ := os.ReadFile(watchDownPaths[0])
	exec(migrationDB, string(watchUp))
	exec(migrationDB, string(watchDown))
	exec(migrationDB, string(watchUp))
	assertOwnerRevoked()
	// The store writes first_reported_at, added by a later health migration.
	firstPaths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_lease_first_report.up.sql"))
	if len(firstPaths) != 1 {
		t.Fatal("first-report migration not found")
	}
	first, _ := os.ReadFile(firstPaths[0])
	exec(migrationDB, string(first))
	assertOwnerRevoked()
	// NodeFacts measurement column (#189): up, down, up as the migrator.
	for _, name := range []string{"up", "down", "up"} {
		paths, _ := filepath.Glob(filepath.Join(root, "migrations/*_health_startup_capture_measurement."+name+".sql"))
		if len(paths) != 1 {
			t.Fatal("measurement migration not found")
		}
		raw, _ := os.ReadFile(paths[0])
		if name == "up" {
			// A guarded boot without measurement evidence must stop the migration.
			guarded := uuid.NewString()
			exec(db, "INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at) VALUES($1,'g','guarded','ready',now())", guarded)
			if _, err := migrationDB.Exec(ctx, string(raw)); err == nil {
				t.Fatal("measurement migration accepted an unproven guarded boot")
			}
			exec(migrationDB, "ROLLBACK")
			exec(db, "DELETE FROM health.node_boot_generation WHERE node_uid=$1", guarded)
			assertOwnerRevoked()
		}
		exec(migrationDB, string(raw))
		assertOwnerRevoked()
	}

	// Work-readiness tables (TASK-10 3.5a/3.5b): the node-scope health GET
	// lists their nonces for node-sensors.
	for _, m := range []struct {
		conn    *pgx.Conn
		pattern string
	}{{db, "*_audit_worker_exec_evidence.up.sql"}, {migrationDB, "*_health_work_readiness.up.sql"}} {
		paths, _ := filepath.Glob(filepath.Join(root, "migrations", m.pattern))
		if len(paths) != 1 {
			t.Fatalf("migration %s not found", m.pattern)
		}
		raw, _ := os.ReadFile(paths[0])
		exec(m.conn, string(raw))
	}
	assertOwnerRevoked()

	t.Run("restricted_dispatch_locks", func(t *testing.T) { testDispatchLocks(t, ctx, migrationDB, db, cfg, root) })

	// Authorization uses the actual merged TASK-03 schema.
	identity, err := os.ReadFile(filepath.Join(root, "migrations/20261014144500_identity_workload_pki.up.sql"))
	if err != nil {
		t.Fatal(err)
	}
	exec(db, string(identity))
	exec(db, "GRANT SELECT ON identity.registered_workloads,identity.issued_certificates TO control_health_writer")

	exec(admin, "CREATE ROLE "+login+" LOGIN")
	exec(db, "GRANT control_health_writer,audit_producer TO "+login)
	exec(db, "INSERT INTO audit.db_role_sources VALUES($1,'health-source',false)", login)
	exec(db, "INSERT INTO audit.producer_event_grants VALUES ('health-source','execution_held','*'),('health-source','source_health_changed','*')")
	gatewaySAN := "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	sensorSAN := "spiffe://agentarium.internal/ns/agent-sensors/sa/sensor-exporter"
	node := uuid.NewString()
	otherNode := uuid.NewString()
	exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-control','policy-gateway','service',true),('agent-sensors','sensor-exporter','service',true)")
	exec(db, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at,revoked_at) VALUES ('01',$1,'agent-control','policy-gateway',NULL,NULL,now()-interval '1 hour',now()+interval '1 hour',NULL),('02',$2,'agent-sensors','sensor-exporter',$3,'boot-1',now()-interval '1 hour',now()+interval '1 hour',NULL)", gatewaySAN, sensorSAN, node)
	exec(db, "INSERT INTO health.component_principals VALUES ($1,'gateway',ARRAY['global'],ARRAY[]::text[],ARRAY[]::text[]),($2,'node-sensors',ARRAY['node'],ARRAY[]::text[],ARRAY[]::text[])", gatewaySAN, sensorSAN)
	exec(db, "INSERT INTO health.node_boot_generation VALUES($1,'boot-1',1,1,'unsupported','preparing',now(),'not_measured')", node)
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database = database
	pc.ConnConfig.User = login
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := New(pool, Config{Sources: []SourceBinding{{"gateway-1", gatewaySAN, "*"}, {"sensor-1", sensorSAN, node}}, Readers: []string{gatewaySAN, sensorSAN}, AuditSourceID: "health-source", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Epoch = "1"
	gateway := health.Peer{SAN: gatewaySAN, Serial: "01"}
	sensor := health.Peer{SAN: sensorSAN, Serial: "02"}
	lease := func(source, component, scope, id string) health.Lease {
		now := time.Now().UTC()
		return health.Lease{SourceID: source, Component: component, Scope: scope, ScopeID: id, ReportedAt: now, LeaseUntil: now.Add(15 * time.Second), ObservedState: "healthy"}
	}
	t.Run("mutual_tls_to_committed_lease", func(t *testing.T) {
		testHealthHTTPPostgres(t, s, db, lease("gateway-1", "gateway", "global", "*"))
	})
	t.Run("lease_snapshot_and_replay", func(t *testing.T) {
		l := lease("gateway-1", "gateway", "global", "*")
		ack, err := s.Put(ctx, gateway, l)
		if err != nil || ack.ScopeState != "unhealthy" {
			t.Fatalf("%+v %v", ack, err)
		}
		if _, err := s.Put(ctx, gateway, l); !errors.Is(err, health.ErrInvalid) {
			t.Fatal("replay extended lease")
		}
		snapshot, err := s.Get(ctx, gateway, "global", "*")
		if err != nil || len(snapshot.Leases) != 1 || len(snapshot.MissingComponents) != 4 {
			t.Fatalf("%+v %v", snapshot, err)
		}
		raw, _ := json.Marshal(snapshot)
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(raw, &fields)
		for _, key := range []string{"leases", "missing_components", "open_holds", "probes", "open_gaps", "startup_capture", "bundle_ack", "pending_work_readiness_challenges", "pending_worker_observation_challenges"} {
			if _, ok := fields[key]; !ok {
				t.Fatalf("missing response key %s", key)
			}
		}
	})
	t.Run("audit_transaction_rollback", func(t *testing.T) {
		l := lease("gateway-1", "gateway", "global", "*")
		l.ObservedState = "degraded"
		exec(db, "DELETE FROM audit.producer_event_grants WHERE event_type='source_health_changed'")
		if _, err := s.Put(ctx, gateway, l); err == nil {
			t.Fatal("accepted unaudited state change")
		}
		var state string
		_ = db.QueryRow(ctx, "SELECT observed_state FROM health.control_health_leases WHERE source_id='gateway-1'").Scan(&state)
		if state != "healthy" {
			t.Fatal("partial state commit")
		}
		exec(db, "INSERT INTO audit.producer_event_grants VALUES('health-source','source_health_changed','*')")
		if _, err := s.Put(ctx, gateway, l); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("node_binding", func(t *testing.T) {
		l := lease("sensors-node/"+node, "node-sensors", "node", node)
		generation := int64(1)
		l.SensorGeneration = &generation
		if _, err := s.Put(ctx, sensor, l); err != nil {
			t.Fatal(err)
		}
		l.ScopeID = otherNode
		if _, err := s.Put(ctx, sensor, l); !errors.Is(err, health.ErrForbidden) {
			t.Fatal("other node lease accepted")
		}
		// Node leases are keyed per node: a shared or another node's source ID
		// is refused even on the caller's own node.
		l.ScopeID = node
		for _, source := range []string{"sensor-1", "sensors-node/" + otherNode, "sensors-node/" + strings.ToUpper(node), "Sensors-node/" + node, "-node/" + node} {
			l.SourceID = source
			l.ReportedAt = time.Now().UTC()
			if _, err := s.Put(ctx, sensor, l); !errors.Is(err, health.ErrForbidden) {
				t.Fatalf("node lease with source %q accepted: %v", source, err)
			}
		}
		l.SourceID = "sensors-node/" + node
		l.ScopeID = otherNode
		if _, err := s.Get(ctx, sensor, "node", otherNode); !errors.Is(err, health.ErrForbidden) {
			t.Fatal("reader allowlist bypassed own-node boundary")
		}
		l.ScopeID = node
		l.ReportedAt = time.Now().UTC()
		l.LeaseUntil = l.ReportedAt.Add(15 * time.Second)
		exec(db, "UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='02'")
		if _, err := s.Put(ctx, sensor, l); !errors.Is(err, health.ErrForbidden) {
			t.Fatal("revoked certificate accepted")
		}
		exec(db, "UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='02'")
	})
	t.Run("node_lease_not_covered_by_another_source", func(t *testing.T) {
		// A second healthy row for the same component and node (for example a
		// legacy shared source) must not hide the node source's expiry.
		exec(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,observed_state,details,reported_at,first_reported_at,lease_until)
			SELECT 'sensor-1','node-sensors','node',$1::text,$1::text::uuid,boot_id,'healthy',details,now(),now(),now()+interval '1 minute'
			FROM health.control_health_leases WHERE source_id='sensors-node/'||$1`, node)
		exec(db, "UPDATE health.control_health_leases SET lease_until=now()-interval '1 second' WHERE source_id='sensors-node/'||$1", node)
		l := lease("sensors-node/"+node, "node-sensors", "node", node)
		generation := int64(1)
		l.SensorGeneration = &generation
		if _, err := s.Put(ctx, sensor, l); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM health.holds WHERE scope='node' AND scope_id=$1 AND reason='lease_expired' AND released_at IS NULL", node).Scan(&count); err != nil || count != 1 {
			t.Fatalf("expired node source covered by another row: holds=%d %v", count, err)
		}
		// The same holds for the expiry sweep when the node source stops
		// reporting while the other row is still live.
		exec(db, "UPDATE health.holds SET released_at=now(), release_ref='test:cleanup' WHERE scope='node' AND scope_id=$1 AND released_at IS NULL", node)
		exec(db, "UPDATE health.control_health_leases SET lease_until=now()-interval '1 second' WHERE source_id='sensors-node/'||$1", node)
		if err := s.Expire(ctx); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(ctx, "SELECT count(*) FROM health.holds WHERE scope='node' AND scope_id=$1 AND reason='lease_expired' AND released_at IS NULL", node).Scan(&count); err != nil || count != 1 {
			t.Fatalf("Expire treated another row as coverage: holds=%d %v", count, err)
		}
		exec(db, "DELETE FROM health.control_health_leases WHERE source_id='sensor-1'")
		exec(db, "UPDATE health.control_health_leases SET lease_until=now()+interval '15 seconds' WHERE source_id='sensors-node/'||$1", node)
		exec(db, "UPDATE health.holds SET released_at=now(), release_ref='test:cleanup' WHERE scope='node' AND scope_id=$1 AND released_at IS NULL", node)
	})
	t.Run("expiry_hold_survives_renewal", func(t *testing.T) {
		exec(db, "UPDATE health.control_health_leases SET lease_until=now()-interval '1 second' WHERE source_id='gateway-1'")
		if err := s.Expire(ctx); err != nil {
			t.Fatal(err)
		}
		if err := s.Expire(ctx); err != nil {
			t.Fatal(err)
		}
		var count int
		_ = db.QueryRow(ctx, "SELECT count(*) FROM health.holds WHERE scope='global'").Scan(&count)
		if count != 1 {
			t.Fatalf("holds=%d", count)
		}
		l := lease("gateway-1", "gateway", "global", "*")
		if _, err := s.Put(ctx, gateway, l); err != nil {
			t.Fatal(err)
		}
		snap, err := s.Get(ctx, gateway, "global", "*")
		if err != nil || len(snap.OpenHolds) != 1 || snap.State != "unhealthy" {
			t.Fatalf("heartbeat released hold %+v %v", snap, err)
		}
		_ = db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_type='execution_held' AND safe_payload->>'scope'='global'").Scan(&count)
		if count != 1 {
			t.Fatal("hold audit not atomic or deduped")
		}
	})
	t.Run("optional_guard_renewal_does_not_hold", func(t *testing.T) {
		guardSAN := "spiffe://agentarium.internal/ns/agent-sensors/sa/runtime-guard"
		exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-sensors','runtime-guard','service',true)")
		exec(db, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at,revoked_at) VALUES ('03',$1,'agent-sensors','runtime-guard',$2,'boot-1',now()-interval '1 hour',now()+interval '1 hour',NULL)", guardSAN, node)
		exec(db, "INSERT INTO health.component_principals VALUES ($1,'runtime-guard',ARRAY['node'],ARRAY[]::text[],ARRAY[]::text[])", guardSAN)
		s.Config.Sources = append(s.Config.Sources, SourceBinding{"guard-1", guardSAN, node})
		peer := health.Peer{SAN: guardSAN, Serial: "03"}
		if _, err := s.Put(ctx, peer, lease("runtime-guard-node/"+node, "runtime-guard", "node", node)); err != nil {
			t.Fatal(err)
		}
		exec(db, "UPDATE health.control_health_leases SET lease_until=now()-interval '1 second' WHERE source_id='runtime-guard-node/'||$1", node)
		if _, err := s.Put(ctx, peer, lease("runtime-guard-node/"+node, "runtime-guard", "node", node)); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM health.holds WHERE scope='node' AND released_at IS NULL").Scan(&count); err != nil || count != 0 {
			t.Fatalf("optional guard created hold: count=%d err=%v", count, err)
		}
	})
	t.Run("old_boot_not_ready", func(t *testing.T) {
		exec(db, "UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1", node)
		exec(db, "INSERT INTO health.node_boot_generation VALUES($1,'boot-2',2,1,'unsupported','preparing',now(),'not_measured')", node)
		snap, err := s.Get(ctx, gateway, "node", node)
		if err != nil || len(snap.Leases) != 0 || len(snap.MissingComponents) != 2 {
			t.Fatalf("old boot reused %+v %v", snap, err)
		}
		if _, err := s.Get(ctx, sensor, "node", node); !errors.Is(err, health.ErrForbidden) {
			t.Fatal("old boot certificate accepted")
		}
	})
	t.Run("runtime_permissions", func(t *testing.T) {
		for _, sql := range []string{"CREATE TABLE health.evil(x int)", "UPDATE health.component_principals SET component='adapter'", "DELETE FROM health.holds", "UPDATE health.holds SET requested_by='forged'", "SELECT * FROM audit.audit_events"} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("writer allowed %s", sql)
			}
		}
	})
	t.Run("dynamic_replica_and_certified_workload_scope", func(t *testing.T) {
		sources := s.Config.Sources
		s.Config.Sources = nil
		defer func() { s.Config.Sources = sources }()
		for _, id := range []string{"gateway-new-pod-1", "gateway-new-pod-2"} {
			l := lease(id, "gateway", "global", "*")
			digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			l.LoadedArtifactDigest = &digest
			if _, err := s.Put(ctx, gateway, l); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := db.QueryRow(ctx, "SELECT loaded_artifact_digest FROM health.control_health_leases WHERE source_id=$1", id).Scan(&got); err != nil || got != digest {
				t.Fatalf("digest column: %s %v", got, err)
			}
		}
		adapterSAN := "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
		exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,adapter_id,enabled) VALUES ('agent-adapters','receiver-sender','adapter','receiver-sender',true)")
		exec(db, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,issued_at,expires_at) VALUES ('04',$1,'agent-adapters','receiver-sender',now()-interval '1 minute',now()+interval '1 hour')", adapterSAN)
		exec(db, "INSERT INTO health.component_principals VALUES ($1,'adapter',ARRAY['workload'],ARRAY[]::text[],ARRAY[]::text[])", adapterSAN)
		peer := health.Peer{SAN: adapterSAN, Serial: "04"}
		l := lease("adapter-new-pod", "adapter", "workload", "agent-adapters/receiver-sender")
		if _, err := s.Put(ctx, peer, l); err != nil {
			t.Fatal(err)
		}
		l.ScopeID = "agent-adapters/other"
		if _, err := s.Put(ctx, peer, l); !errors.Is(err, health.ErrForbidden) {
			t.Fatalf("accepted other workload: %v", err)
		}
		// Even a principal registered for the same component cannot take another
		// principal's source ID: PutLease retains the original principal SAN.
		otherSAN := "spiffe://agentarium.internal/ns/agent-control/sa/other-gateway"
		exec(db, "INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES ('agent-control','other-gateway','service',true)")
		exec(db, "INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,issued_at,expires_at) VALUES ('05',$1,'agent-control','other-gateway',now()-interval '1 minute',now()+interval '1 hour')", otherSAN)
		exec(db, "INSERT INTO health.component_principals VALUES ($1,'gateway',ARRAY['global'],ARRAY[]::text[],ARRAY[]::text[])", otherSAN)
		if _, err := s.Put(ctx, health.Peer{SAN: otherSAN, Serial: "05"}, lease("gateway-new-pod-1", "gateway", "global", "*")); !errors.Is(err, health.ErrInvalid) {
			t.Fatalf("source stolen: %v", err)
		}
	})
	t.Run("cross_task_read_grants", func(t *testing.T) {
		for _, role := range []string{"coordinator_reader", "gateway_reader"} {
			tx, err := db.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"holds", "control_health_leases"} {
				if _, err = tx.Exec(ctx, "SELECT * FROM health."+table+" LIMIT 1"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = tx.Exec(ctx, "UPDATE health.holds SET requested_by='forged'"); err == nil {
				t.Fatal("reader allowed mutation")
			}
			_ = tx.Rollback(ctx)
		}
	})

	t.Run("ambiguous_current_boot", func(t *testing.T) { testAmbiguousCurrentBoot(t, s, db) })
	t.Run("watch_history_gaps", func(t *testing.T) { testWatchGaps(t, s, db) })

	t.Run("first_sensor_bootstrap", func(t *testing.T) { testPostgresNodeBootstrap(t, s, db) })
	t.Run("hold_requests", func(t *testing.T) {
		testHoldRequests(t, s, db, sensor, node, otherNode)
	})
	t.Run("global_hold_requests", func(t *testing.T) { testGlobalHoldRequests(t, s, db) })
	t.Run("owned_hold_listing", func(t *testing.T) { testOwnedHolds(t, s, db) })
	t.Run("risk_event_hold_requests", func(t *testing.T) { testRiskEventHolds(t, s, db) })
	t.Run("mutual_tls_to_committed_hold", func(t *testing.T) {
		testHoldHTTPPostgres(t, s, db)
	})
	t.Run("kube_node_facts_bootstrap", func(t *testing.T) { testPostgresKubeNodeFacts(t, s, db) })
}
