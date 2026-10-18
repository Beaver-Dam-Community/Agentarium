package store

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestWorkReadinessPostgres drives TASK-10 3.5a/3.5b end to end on
// PostgreSQL 16 through the HTTP handler: every migration is installed by a
// non-superuser installer (the two work-readiness migrations go down and up
// again), control-health runs as a control_health_writer login, and a
// runtime worker becomes ready only after a node-sensors witness matched to
// a committed kernel exec row and a node answer to the readiness nonce.
//
// Needs its own disposable cluster (roles are cluster-wide):
// HEALTH_READINESS_TEST_ADMIN_DSN, started by tests/correlation/run-health-local.sh.
func TestWorkReadinessPostgres(t *testing.T) {
	dsn := os.Getenv("HEALTH_READINESS_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable HEALTH_READINESS_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	run := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%.120s: %v", sql, err)
		}
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	dbName, installer, login := "wready_"+suffix, "wreadyinst_"+suffix, "wreadyapp_"+suffix
	run(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	run(admin, "CREATE ROLE "+login+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	run(admin, "CREATE DATABASE "+dbName+" OWNER "+installer)
	defer func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)") }()
	connect := func(user string) *pgx.Conn {
		t.Helper()
		cfg, err := pgx.ParseConfig(dsn)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Database, cfg.User = dbName, user
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close(context.Background()) })
		return c
	}
	owner := connect(installer)
	run(owner, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$")
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "../../../..")
	files, err := filepath.Glob(filepath.Join(root, "migrations/*.up.sql"))
	if err != nil || len(files) == 0 {
		t.Fatal("no migrations", err)
	}
	sort.Strings(files)
	apply := func(path string) {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(path), err)
		}
	}
	for _, f := range files {
		apply(f)
	}
	ours := []string{"20261017210000_audit_worker_exec_evidence", "20261017210001_health_work_readiness"}
	inspect := connect(admin.Config().User)
	present := func() bool {
		var ok bool
		if err := inspect.QueryRow(ctx, "SELECT to_regclass('health.work_readiness_checks') IS NOT NULL AND to_regprocedure('audit.worker_exec_evidence(uuid,uuid,text,text)') IS NOT NULL").Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if !present() {
		t.Fatal("work-readiness objects missing after up")
	}
	for i := len(ours) - 1; i >= 0; i-- {
		apply(filepath.Join(root, "migrations", ours[i]+".down.sql"))
	}
	if present() {
		t.Fatal("work-readiness objects left after down")
	}
	for _, m := range ours {
		apply(filepath.Join(root, "migrations", m+".up.sql"))
	}
	var leaked bool
	if err := owner.QueryRow(ctx, `SELECT pg_has_role(current_user,'health_owner','SET') OR pg_has_role(current_user,'health_owner','USAGE')
 OR pg_has_role(current_user,'audit_owner','SET') OR pg_has_role(current_user,'audit_owner','USAGE')`).Scan(&leaked); err != nil || leaked {
		t.Fatalf("migration leaked an owner role: %v %v", leaked, err)
	}

	// Installation inputs (TASK-16) use the complete active_policy schema.
	db := inspect
	run(db, `INSERT INTO release.active_policy
 (scope_id,epoch,bundle_id,bundle_digest,artifact_digest,expected_opa_revision,
  catalog_digest,sensor_release_policies_digest,activated_by_change_id,updated_at)
 VALUES ('test',7,'test-bundle',repeat('a',64),repeat('b',64),'test-revision',
         repeat('c',64),repeat('d',64),gen_random_uuid(),now())`)
	run(db, "GRANT SELECT ON identity.registered_workloads,identity.issued_certificates TO control_health_writer")
	run(db, "GRANT control_health_writer, audit_producer TO "+login)
	run(db, "INSERT INTO audit.db_role_sources VALUES($1,'health-source',false)", login)
	for _, ev := range []string{"session_worker_registered", "session_worker_observed", "session_worker_closed", "session_worker_invalidated", "work_readiness_requested", "work_readiness_passed", "work_readiness_blocked"} {
		run(db, "INSERT INTO audit.producer_event_grants VALUES('health-source',$1,'hackathon')", ev)
	}
	gwSAN := "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	sensorSAN := "spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon"
	watcherSAN := "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"
	node, boot, cluster, pod := uuid.NewString(), "boot-1", uuid.NewString(), uuid.NewString()
	rtSAN := "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + pod
	otherSAN := "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + uuid.NewString()
	container := "containerd://" + strings.Repeat("ab", 32)
	rule := strings.Repeat("c", 64)
	run(db, `INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES
 ('agent-control','policy-gateway','service',true),('agent-sensors','tetragon','service',true),
 ('agent-observe','pod-watcher','service',true),('agent-exec','agent-runtime','runtime',true)`)
	run(db, `INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,pod_uid,node_uid,boot_id,issued_at,expires_at) VALUES
 ('0a',$1,'agent-control','policy-gateway',NULL,NULL,NULL,now()-interval '1 hour',now()+interval '1 hour'),
 ('0b',$2,'agent-sensors','tetragon',NULL,$4,$5,now()-interval '1 hour',now()+interval '1 hour'),
 ('0c',$3,'agent-observe','pod-watcher',NULL,NULL,NULL,now()-interval '1 hour',now()+interval '1 hour'),
 ('0d',$6,'agent-exec','agent-runtime',$7,$4,$5,now()-interval '1 hour',now()+interval '1 hour')`, gwSAN, sensorSAN, watcherSAN, node, boot, rtSAN, pod)
	run(db, `INSERT INTO health.component_principals VALUES ($1,'gateway',ARRAY['global'],ARRAY[]::text[],ARRAY[]::text[]),
 ($2,'node-sensors',ARRAY['node'],ARRAY[]::text[],ARRAY[]::text[]),($3,'pod-watcher',ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::text[])`, gwSAN, sensorSAN, watcherSAN)
	run(db, "INSERT INTO health.node_boot_generation VALUES($1,$2,1,1,'unsupported','ready',now(),'not_measured')", node, boot)
	for _, c := range []string{"audit-db", "audit-export", "gateway", "coordinator", "node-readiness"} {
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,observed_state,details,reported_at,first_reported_at,lease_until)
 VALUES($1,$1,'global','*','healthy','{}',now(),now(),now()+interval '1 hour')`, c)
	}
	for _, c := range []string{"node-sensors", "lifecycle-recorder"} {
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,active_version,observed_state,details,reported_at,first_reported_at,lease_until)
 VALUES($1||'-node/'||$2,$1,'node',$2,$2::uuid,$3,$4,'healthy','{}',now(),now(),now()+interval '1 hour')`, c, node, boot, rule)
	}
	run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance,cgroup_inode,started_at,end_quality,mapping_version,source_event_ids)
 VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,0,4242,now()-interval '1 minute','open',1,'{}')`, cluster, pod, node, boot, container)
	newSession := func(san string) string {
		id := uuid.NewString()
		run(db, `INSERT INTO identity.sessions(session_id,authenticated_actor,tenant,workload_id,task_statement,allowed_operation_ids,state,
 claim_code_digest,claim_expires_at,claimed_workload_identity,created_at,expires_at,max_expires_at)
 VALUES($1,'google:1','hackathon','agent-exec/agent-runtime','demo',ARRAY['receiver.submit'],'claimed','\x00',now()+interval '5 minutes',$2,now(),now()+interval '1 hour',now()+interval '8 hours')`, id, san)
		return id
	}
	session := newSession(rtSAN)
	kernelEvent := func(execID string, pid int) string {
		id := uuid.NewString()
		run(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,
 node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,parent_exec_id,process_start,host_pid,container_id,
 metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
 VALUES($1,'tetragon','tetragon','e1',(SELECT count(*)+1 FROM audit.kernel_events),'x',1,$2,$3,now(),now(),now(),'process_exec',$4,'exec-supervisor',now(),$5,$6,
 'complete','1',$7,'full','{}',$7)`, id, node, boot, execID, pid, container, rule)
		return id
	}
	execRef := kernelEvent("exec-root-1", 9001)

	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.Database, pc.ConnConfig.User = dbName, login
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s, err := New(pool, Config{Readers: []string{gwSAN}, AuditSourceID: "health-source", Version: "test", Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	s.Epoch = "1"
	h := health.Handler{Backend: s, Workers: s}
	peerTLS := func(san, serial string) *tls.ConnectionState {
		u, _ := url.Parse(san)
		n, _ := new(big.Int).SetString(serial, 16)
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}, SerialNumber: n}}}}
	}
	gw, sensor, watcher := peerTLS(gwSAN, "0a"), peerTLS(sensorSAN, "0b"), peerTLS(watcherSAN, "0c")
	call := func(peer *tls.ConnectionState, method, path string, forwarded string, body any, sessionOverride ...string) (int, map[string]any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.TLS = peer
		if forwarded != "" {
			req.Header.Set(health.PeerIdentityHeader, forwarded)
			// The gateway forwards the verified session on worker/check
			// relays; default to this test's session and let a caller override
			// it to exercise the cross-session guard (review #228).
			s := session
			if len(sessionOverride) == 1 {
				s = sessionOverride[0]
			}
			if s != "" {
				req.Header.Set(health.PeerSessionHeader, s)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	codeOf := func(m map[string]any) string {
		codes, _ := m["reason_codes"].([]any)
		if len(codes) == 0 {
			return ""
		}
		s, _ := codes[0].(string)
		return s
	}
	expect := func(what string, gotStatus int, got map[string]any, wantStatus int, wantCode string) {
		t.Helper()
		if gotStatus != wantStatus || (wantCode != "" && codeOf(got) != wantCode) {
			t.Fatalf("%s: HTTP %d %v, want %d %s", what, gotStatus, got, wantStatus, wantCode)
		}
	}
	hint := func(pid int) map[string]any {
		return map[string]any{"local_pid": pid, "pid_ns_inode": 4026531836, "start_ticks": 100 + pid}
	}
	workerID, runtimeEpoch := uuid.NewString(), uuid.NewString()
	registration := map[string]any{"worker_instance_id": workerID, "runtime_process_epoch": runtimeEpoch,
		"supervisor_process_hint": hint(1), "worker_process_hint": hint(7), "isolation_profile_digest": strings.Repeat("d", 64),
		"controls_report": map[string]any{"no_new_privs": true, "dumpable": false}}
	const workers = "/internal/control-health/session-workers"
	const checks = "/internal/control-health/work-readiness/checks"

	// No check → 404 (the gateway maps it to 503 WORK_READINESS_EXPIRED).
	st, out := call(gw, "GET", checks+"/"+uuid.NewString(), rtSAN, nil)
	expect("unknown check", st, out, 404, "RESOURCE_NOT_FOUND")

	// Only the gateway SAN may forward a peer identity.
	st, out = call(watcher, "POST", workers, rtSAN, registration)
	expect("non-gateway forwarder registers", st, out, 403, "")
	st, out = call(sensor, "GET", checks+"/"+uuid.NewString(), rtSAN, nil)
	expect("node-sensors forwards identity", st, out, 403, "")
	st, out = call(gw, "POST", workers, "", registration)
	expect("gateway without forwarded identity", st, out, 422, "SCHEMA_INVALID")
	st, out = call(gw, "POST", workers, gwSAN, registration)
	expect("forwarded identity is not a runtime Pod SAN", st, out, 422, "SCHEMA_INVALID")
	st, out = call(sensor, "POST", "/internal/control-health/worker-observation-results", rtSAN, map[string]any{})
	expect("forwarded identity on a node route", st, out, 403, "")

	// Registration: 202 pending, idempotent, conflicting content 409.
	st, out = call(gw, "POST", workers, rtSAN, registration)
	expect("register", st, out, 202, "")
	binding, _ := out["worker_binding_id"].(string)
	if out["state"] != "pending" || binding == "" || out["caller_identity"] != rtSAN {
		t.Fatalf("registration: %v", out)
	}
	st, out = call(gw, "POST", workers, rtSAN, registration)
	if st != 202 || out["worker_binding_id"] != binding {
		t.Fatalf("idempotent registration: %d %v", st, out)
	}
	changed := map[string]any{}
	for k, v := range registration {
		changed[k] = v
	}
	changed["worker_process_hint"] = hint(8)
	st, out = call(gw, "POST", workers, rtSAN, changed)
	expect("same worker, other content", st, out, 409, health.CodeRegistrationConflict)
	changed["worker_instance_id"] = uuid.NewString()
	st, out = call(gw, "POST", workers, rtSAN, changed)
	expect("second active worker for the session", st, out, 409, health.CodeRegistrationConflict)
	st, out = call(gw, "GET", workers+"/"+binding, otherSAN, nil)
	expect("another runtime reads the binding", st, out, 403, health.CodeWorkerMismatch)
	// Same Pod/runtime identity but a different session must not reach this
	// session's worker (review #228).
	otherSession := newSession(rtSAN)
	st, out = call(gw, "GET", workers+"/"+binding, rtSAN, nil, otherSession)
	expect("another session reads the worker", st, out, 403, health.CodeWorkerMismatch)
	st, out = call(gw, "POST", workers+"/"+binding+":close", rtSAN, map[string]any{"reason": "done", "evidence_refs": []string{}}, otherSession)
	expect("another session closes the worker", st, out, 403, health.CodeWorkerMismatch)

	// Registration alone is not observation.
	checkReq := map[string]any{"work_run_id": uuid.NewString(), "runtime_process_epoch": runtimeEpoch,
		"checkpoint": "start", "worker_instance_id": workerID, "worker_binding_id": binding}
	st, out = call(gw, "POST", checks, rtSAN, checkReq)
	expect("check before observation", st, out, 503, health.CodeWorkerNotReady)

	nodeHealth := func(peer *tls.ConnectionState) map[string]any {
		t.Helper()
		st, out := call(peer, "GET", "/internal/control-health?scope=node&scope_id="+node, "", nil)
		if st != 200 {
			t.Fatalf("node health: %d %v", st, out)
		}
		return out
	}
	if got := nodeHealth(gw)["pending_worker_observation_challenges"].([]any); len(got) != 0 {
		t.Fatalf("gateway sees node nonces: %v", got)
	}
	pendingWorkers := nodeHealth(sensor)["pending_worker_observation_challenges"].([]any)
	if len(pendingWorkers) != 1 {
		t.Fatalf("worker challenges: %v", pendingWorkers)
	}
	wc := pendingWorkers[0].(map[string]any)
	ib := wc["instance_binding"].(map[string]any)
	if wc["worker_binding_id"] != binding || ib["container_id"] != container || ib["pod_uid"] != pod || wc["rule_hash"] != rule {
		t.Fatalf("worker challenge: %v", wc)
	}
	image := "sha256:" + strings.Repeat("e", 64)
	observedBinding := map[string]any{}
	for k, v := range ib {
		observedBinding[k] = v
	}
	observedBinding["image_manifest_digest"] = image
	witness := func(ref string, alive bool) map[string]any {
		return map[string]any{"worker_binding_id": binding, "challenge_id": wc["challenge_id"], "instance_binding": observedBinding,
			"supervisor_identity": map[string]any{"local_pid": 1, "pid_ns_inode": 4026531836, "start_ticks": 101, "host_pid": 9000},
			"worker_identity":     map[string]any{"local_pid": 7, "pid_ns_inode": 4026531836, "start_ticks": 107, "host_pid": 9001},
			"root_exec_id":        "exec-root-1", "exec_event_ref": ref, "worker_alive": alive,
			"observed_controls": map[string]any{"seccomp": 2}, "sensor_generation": 1,
			"reported_at": time.Now().UTC().Format(time.RFC3339Nano), "evidence_refs": []string{"node-witness:1"}}
	}
	const workerResults = "/internal/control-health/worker-observation-results"
	st, out = call(sensor, "POST", workerResults, "", witness(uuid.NewString(), true))
	expect("witness without a committed kernel exec", st, out, 503, health.CodeWorkerNotReady)
	wrongPID := kernelEvent("exec-root-1", 9002)
	st, out = call(sensor, "POST", workerResults, "", witness(wrongPID, true))
	expect("kernel exec of another PID", st, out, 409, health.CodeWorkerMismatch)
	st, out = call(sensor, "POST", workerResults, "", witness(execRef, false))
	expect("dead worker", st, out, 409, health.CodeWorkerExited)
	st, out = call(watcher, "POST", workerResults, "", witness(execRef, true))
	expect("non-sensor witness", st, out, 403, "")
	good := witness(execRef, true)
	st, out = call(sensor, "POST", workerResults, "", good)
	expect("witness", st, out, 201, "")
	st, out = call(sensor, "POST", workerResults, "", good)
	if st != 200 || out["result"] != "existing" {
		t.Fatalf("witness replay: %d %v", st, out)
	}
	st, out = call(gw, "GET", workers+"/"+binding, rtSAN, nil)
	if st != 200 || out["state"] != "observed" || out["root_exec_id"] != "exec-root-1" {
		t.Fatalf("observed binding: %d %v", st, out)
	}

	// Binding mismatch: other worker instance, other session.
	bad := map[string]any{}
	for k, v := range checkReq {
		bad[k] = v
	}
	bad["worker_instance_id"] = uuid.NewString()
	st, out = call(gw, "POST", checks, rtSAN, bad)
	expect("other worker instance", st, out, 403, health.CodeWorkerMismatch)
	bad["worker_instance_id"] = workerID
	st, out = call(gw, "POST", checks, rtSAN, bad, newSession(otherSAN))
	expect("session claimed by another Pod", st, out, 403, health.CodeReadinessMismatch)

	// gatewayView is the gateway HTTPReadiness contract (rina/m3-1-gateway readiness.go).
	type gatewayView struct {
		CheckID          string   `json:"check_id"`
		WorkRunID        string   `json:"work_run_id"`
		SessionID        string   `json:"session_id"`
		WorkloadID       string   `json:"workload_id"`
		CallerIdentity   string   `json:"caller_identity"`
		State            string   `json:"state"`
		ReasonCodes      []string `json:"reason_codes"`
		RemainingValidMS *int64   `json:"remaining_valid_ms"`
	}
	getCheck := func(id, san string, sessionOverride ...string) (int, gatewayView) {
		t.Helper()
		req := httptest.NewRequest("GET", checks+"/"+id, nil)
		req.TLS = gw
		req.Header.Set(health.PeerIdentityHeader, san)
		s := session
		if len(sessionOverride) == 1 {
			s = sessionOverride[0]
		}
		if s != "" {
			req.Header.Set(health.PeerSessionHeader, s)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var v gatewayView
		_ = json.Unmarshal(rec.Body.Bytes(), &v)
		return rec.Code, v
	}
	podAnswer := func(check, challenge string) map[string]any {
		root := "exec-root-1"
		alive := true
		return map[string]any{"check_id": check, "challenge_id": challenge, "instance_binding": observedBinding, "sensor_generation": 1,
			"rule_hash": rule, "filter_included": true, "wal_fsync_ready": true, "worker_binding_id": binding, "root_exec_id": root,
			"worker_alive": alive, "worker_evidence_refs": []string{"node-liveness:1"}, "reported_at": time.Now().UTC().Format(time.RFC3339Nano),
			"evidence_refs": []string{"node-pod:1"}}
	}
	const podResults = "/internal/control-health/pod-observation-results"
	readyCheck := func() string {
		t.Helper()
		req := map[string]any{}
		for k, v := range checkReq {
			req[k] = v
		}
		req["work_run_id"] = uuid.NewString()
		st, out := call(gw, "POST", checks, rtSAN, req)
		expect("request check", st, out, 202, "")
		id := out["check_id"].(string)
		if st, v := getCheck(id, rtSAN); st != 200 || v.State != "pending" || *v.RemainingValidMS != 0 {
			t.Fatalf("pending check: %d %+v", st, v)
		}
		var challenge string
		for _, raw := range nodeHealth(sensor)["pending_work_readiness_challenges"].([]any) {
			c := raw.(map[string]any)
			if c["check_id"] == id {
				challenge = c["challenge_id"].(string)
			}
		}
		if challenge == "" {
			t.Fatal("no readiness challenge for the node")
		}
		st, out = call(sensor, "POST", podResults, "", podAnswer(id, challenge))
		expect("pod observation", st, out, 201, "")
		return id
	}

	// Ready only after the independent observations; the gateway contract holds.
	first := readyCheck()
	st, v := getCheck(first, rtSAN)
	if st != 200 || v.State != "ready" || v.CheckID != first || v.SessionID != session || v.WorkloadID != "agent-exec/agent-runtime" ||
		v.CallerIdentity != rtSAN || v.RemainingValidMS == nil || *v.RemainingValidMS <= 0 || *v.RemainingValidMS > 3000 {
		t.Fatalf("ready check: %d %+v", st, v)
	}
	st, out = call(gw, "GET", checks+"/"+first, otherSAN, nil)
	expect("another caller reads the check", st, out, 403, health.CodeReadinessMismatch)

	// Expired: at most 3 s after the final check, never reused.
	time.Sleep(3100 * time.Millisecond)
	if st, v := getCheck(first, rtSAN); st != 200 || v.State != "expired" || v.ReasonCodes[0] != health.CodeReadinessExpired || *v.RemainingValidMS != 0 {
		t.Fatalf("expired check: %d %+v", st, v)
	}

	// A hold after ready blocks the stored ready result.
	second := readyCheck()
	run(db, "INSERT INTO health.holds(hold_id,scope,scope_id,reason,owner_component,requested_by) VALUES(gen_random_uuid(),'session',$1,'operator_stop','console','test')", session)
	if st, v := getCheck(second, rtSAN); st != 200 || v.State != "blocked" || v.ReasonCodes[0] != health.CodeHoldActive {
		t.Fatalf("held check: %d %+v", st, v)
	}
	run(db, "UPDATE health.holds SET released_at=now(), release_ref='test' WHERE scope='session' AND scope_id=$1", session)

	// A node answer that the filter does not cover blocks the check.
	req := map[string]any{}
	for k, v := range checkReq {
		req[k] = v
	}
	req["work_run_id"] = uuid.NewString()
	st, out = call(gw, "POST", checks, rtSAN, req)
	expect("request check", st, out, 202, "")
	blocked := out["check_id"].(string)
	answer := podAnswer(blocked, out["challenge_id"].(string))
	answer["filter_included"] = false
	st, out = call(sensor, "POST", podResults, "", answer)
	expect("pod observation", st, out, 201, "")
	if st, v := getCheck(blocked, rtSAN); st != 200 || v.State != "blocked" || v.ReasonCodes[0] != health.CodePodNotReady {
		t.Fatalf("filter-excluded check: %d %+v", st, v)
	}

	// The writer cannot rewrite or delete readiness records.
	for _, sql := range []string{
		"UPDATE health.work_readiness_checks SET expires_at=now()+interval '1 hour' WHERE check_id='" + first + "'",
		"DELETE FROM health.work_readiness_checks",
		"UPDATE health.worker_evidence SET body='{}'",
		"UPDATE health.session_process_bindings SET root_exec_id='forged' WHERE worker_binding_id='" + binding + "'",
		"SELECT * FROM audit.kernel_events",
	} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatalf("writer allowed %s", sql)
		}
	}

	// Close: new work stops at once and the old ready result is not reused.
	third := readyCheck()
	st, out = call(gw, "POST", workers+"/"+binding+":close", rtSAN, map[string]any{"reason": "session_end", "evidence_refs": []string{}})
	if st != 200 || out["state"] != "closed" {
		t.Fatalf("close: %d %v", st, out)
	}
	st, out = call(gw, "POST", workers+"/"+binding+":close", rtSAN, map[string]any{"reason": "again", "evidence_refs": []string{}})
	if st != 200 || out["state"] != "closed" {
		t.Fatalf("idempotent close: %d %v", st, out)
	}
	if st, v := getCheck(third, rtSAN); st != 200 || v.State == "ready" {
		t.Fatalf("closed worker still ready: %d %+v", st, v)
	}
	st, out = call(gw, "POST", checks, rtSAN, checkReq)
	expect("check on a closed worker", st, out, 503, health.CodeWorkerExited)

	var events int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM audit.audit_events WHERE event_type IN ('session_worker_registered','session_worker_observed','session_worker_closed','work_readiness_requested','work_readiness_passed','work_readiness_blocked') AND session_id=$1", session).Scan(&events); err != nil || events < 10 {
		t.Fatalf("audit events: %d %v", events, err)
	}
}
