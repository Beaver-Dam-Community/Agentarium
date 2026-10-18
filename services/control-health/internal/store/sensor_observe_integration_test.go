package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
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

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/observe"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/podmeta"
	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type sensorProc map[int64]struct {
	status observe.Status
	ticks  int64
	cgroup string
}

func (p sensorProc) PIDs() ([]int64, error) {
	var out []int64
	for pid := range p {
		out = append(out, pid)
	}
	return out, nil
}
func (p sensorProc) Status(pid int64) (observe.Status, error) {
	if e, ok := p[pid]; ok {
		return e.status, nil
	}
	return observe.Status{}, observe.ErrUnavailable
}
func (p sensorProc) StartTicks(pid int64) (int64, error) {
	if e, ok := p[pid]; ok {
		return e.ticks, nil
	}
	return 0, observe.ErrUnavailable
}
func (p sensorProc) Cgroup(pid int64) (string, error) {
	if e, ok := p[pid]; ok {
		return e.cgroup, nil
	}
	return "", observe.ErrUnavailable
}
func (p sensorProc) CgroupInode(string) (int64, error) { return 4242, nil }

type sensorPods map[string]podmeta.Container

func (s sensorPods) Container(id string) (podmeta.Container, bool) { c, ok := s[id]; return c, ok }

// TestSensorObservationPostgres runs the TASK-09 exporter responder
// (sensors/exporter/observe) with its real mTLS control-health client against
// this store on PostgreSQL 16. The node process view (/proc, cgroup, Pod API)
// is a fixture; everything else is the shipped code: the sensor polls its
// node-scope nonces, witnesses a registered worker whose final exec row is
// committed in audit.kernel_events, the binding becomes observed, and the
// sensor's Pod answer makes a work-readiness check ready.
//
// Needs its own disposable cluster: HEALTH_SENSOR_TEST_ADMIN_DSN, started by
// tests/correlation/run-health-local.sh.
func TestSensorObservationPostgres(t *testing.T) {
	dsn := os.Getenv("HEALTH_SENSOR_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable HEALTH_SENSOR_TEST_ADMIN_DSN")
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
	dbName, installer, login := "wsensor_"+suffix, "wsensorinst_"+suffix, "wsensorapp_"+suffix
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
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
	}
	db := connect(admin.Config().User)
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
	node, boot, cluster, pod := uuid.NewString(), "boot-1", uuid.NewString(), uuid.NewString()
	rtSAN := "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + pod
	// Bare containerd ID, as the exporter's KernelEvents carry it.
	container := strings.Repeat("ab", 32)
	rule := strings.Repeat("c", 64)
	run(db, `INSERT INTO identity.registered_workloads(namespace,ksa,role,enabled) VALUES
 ('agent-control','policy-gateway','service',true),('agent-sensors','tetragon','service',true),('agent-exec','agent-runtime','runtime',true)`)
	run(db, `INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,pod_uid,node_uid,boot_id,issued_at,expires_at) VALUES
 ('0a',$1,'agent-control','policy-gateway',NULL,NULL,NULL,now()-interval '1 hour',now()+interval '1 hour'),
 ('0b',$2,'agent-sensors','tetragon',NULL,$3,$4,now()-interval '1 hour',now()+interval '1 hour'),
 ('0d',$5,'agent-exec','agent-runtime',$6,$3,$4,now()-interval '1 hour',now()+interval '1 hour')`, gwSAN, sensorSAN, node, boot, rtSAN, pod)
	run(db, `INSERT INTO health.component_principals VALUES ($1,'gateway',ARRAY['global'],ARRAY[]::text[],ARRAY[]::text[]),
 ($2,'node-sensors',ARRAY['node'],ARRAY[]::text[],ARRAY[]::text[])`, gwSAN, sensorSAN)
	run(db, "INSERT INTO health.node_boot_generation VALUES($1,$2,1,1,'unsupported','ready',now(),'not_measured')", node, boot)
	for _, c := range []string{"audit-db", "audit-export", "gateway", "coordinator", "node-readiness"} {
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,observed_state,details,reported_at,first_reported_at,lease_until)
 VALUES($1,$1,'global','*','healthy','{}',now(),now(),now()+interval '1 hour')`, c)
	}
	// The node-sensors lease carries the verified rule_hash as active_version
	// (exporter main.go); control-health issues it as the expected rule hash.
	for _, c := range []string{"node-sensors", "lifecycle-recorder"} {
		run(db, `INSERT INTO health.control_health_leases(source_id,component,scope,scope_id,node_uid,boot_id,active_version,observed_state,details,reported_at,first_reported_at,lease_until)
 VALUES($1||'-node/'||$2,$1,'node',$2,$2::uuid,$3,$4,'healthy','{}',now(),now(),now()+interval '1 hour')`, c, node, boot, rule)
	}
	run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance,cgroup_inode,started_at,end_quality,mapping_version,source_event_ids)
 VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,0,4242,now()-interval '1 minute','open',1,'{}')`, cluster, pod, node, boot, container)
	session := uuid.NewString()
	run(db, `INSERT INTO identity.sessions(session_id,authenticated_actor,tenant,workload_id,task_statement,allowed_operation_ids,state,
 claim_code_digest,claim_expires_at,claimed_workload_identity,created_at,expires_at,max_expires_at)
 VALUES($1,'google:1','hackathon','agent-exec/agent-runtime','demo',ARRAY['receiver.submit'],'claimed','\x00',now()+interval '5 minutes',$2,now(),now()+interval '1 hour',now()+interval '8 hours')`, session, rtSAN)

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

	// Real mTLS: the sensor's certificate serial 0x0b is the issued row.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := func(serial int64, san string, eku x509.ExtKeyUsage) tls.Certificate {
		u, _ := url.Parse(san)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{u}}, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	server := httptest.NewUnstartedServer(h)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf(2, "spiffe://agentarium.internal/ns/agent-observe/sa/control-health", x509.ExtKeyUsageServerAuth)},
		ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	sensorCert := leaf(11, sensorSAN, x509.ExtKeyUsageClientAuth)
	client, err := healthreport.NewClient(server.URL, roots, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &sensorCert, nil })
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Node view: supervisor (host 9000, local 1) forked the worker (host 9001,
	// local 7) in the runtime container's cgroup.
	const pidNS = 4026532001
	cg := "/../../kubepods.slice/cri-containerd-" + container + ".scope"
	one, two := int64(1), int64(2)
	procs := sensorProc{
		9000: {status: observe.Status{NSpid: []int64{9000, 1}, PPid: 8000}, ticks: 101, cgroup: cg},
		9001: {status: observe.Status{NSpid: []int64{9001, 7}, PPid: 9000, UID: []int64{10001, 10001, 10001, 10001}, NoNewPrivs: &one, Seccomp: &two}, ticks: 107, cgroup: cg},
	}
	image := "sha256:" + strings.Repeat("e", 64)
	pods := sensorPods{container: {PodUID: pod, Namespace: "agent-exec", Observed: true, Running: true, ImageID: "us-docker.pkg.dev/p/agentarium/runtime@" + image}}
	index := observe.NewIndex(nil)
	var posts int
	counting := &countingHealth{Client: client, posts: &posts}
	r, err := observe.New(observe.Config{NodeUID: node, BootID: boot, RuleHash: rule, SensorGeneration: 1, WorkerBinaries: []string{"/usr/local/bin/python3"},
		Health: counting, Proc: procs, Containers: pods, Index: index, Ready: func(time.Time) bool { return true }, Log: func(m string) { t.Log(m) }})
	if err != nil {
		t.Fatal(err)
	}
	// commit stores a process_exec row as the audit writer would and hands the
	// same record to the exporter index, as delivery.Config.Committed does
	// after the collector's acknowledgement.
	seq := 0
	commit := func(execID, parent string, pid int64, binary string) string {
		t.Helper()
		seq++
		id, err := canonical.KernelEventID(sensorSAN, "e1", int64(seq))
		if err != nil {
			t.Fatal(err)
		}
		var parentArg any
		if parent != "" {
			parentArg = parent
		}
		run(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,
 node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,parent_exec_id,process_start,host_pid,container_id,
 metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
 VALUES($1,'tetragon',$2,'e1',$3,'x',1,$4,$5,now(),now(),now(),'process_exec',$6,$7,now(),$8,$9,'complete','1',$10,'full','{}',$10)`,
			id, sensorSAN, seq, node, boot, execID, parentArg, pid, container, rule)
		raw, _ := json.Marshal(map[string]any{"event_type": "process_exec", "source_event_id": id, "process_exec_id": execID, "parent_exec_id": parentArg,
			"host_pid": pid, "container_id": container, "pod_uid": pod, "node_uid": node, "boot_id": boot, "rule_hash": rule, "sensor_generation": 1,
			"safe_attributes": map[string]any{"binary": canonical.SHA256Hex([]byte(binary))}})
		index.Namespace(execID, pidNS)
		index.Committed(raw)
		return id
	}
	commit("exec-supervisor", "", 9000, "/app/bin/agent-runtime")

	gw := func() *tls.ConnectionState {
		u, _ := url.Parse(gwSAN)
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}, SerialNumber: big.NewInt(10)}}}}
	}()
	call := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(raw))
		req.TLS = gw
		req.Header.Set(health.PeerIdentityHeader, rtSAN)
		req.Header.Set("X-Agentarium-Peer-Session", session)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	hint := func(local, ticks int64) map[string]any {
		return map[string]any{"local_pid": local, "pid_ns_inode": pidNS, "start_ticks": ticks}
	}
	workerID, epoch := uuid.NewString(), uuid.NewString()
	st, out := call("POST", "/internal/control-health/session-workers", map[string]any{"worker_instance_id": workerID,
		"runtime_process_epoch": epoch, "supervisor_process_hint": hint(1, 101), "worker_process_hint": hint(7, 107),
		"isolation_profile_digest": strings.Repeat("d", 64), "controls_report": map[string]any{"no_new_privs": true}})
	binding, _ := out["worker_binding_id"].(string)
	if st != 202 || binding == "" {
		t.Fatalf("register: %d %v", st, out)
	}
	worker := func() map[string]any {
		t.Helper()
		st, out := call("GET", "/internal/control-health/session-workers/"+binding, nil)
		if st != 200 {
			t.Fatalf("binding: %d %v", st, out)
		}
		return out
	}

	// The worker's exec is not committed yet: the sensor reports nothing.
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if posts != 0 || worker()["state"] != "pending" {
		t.Fatalf("reported before the kernel exec was committed: %d posts", posts)
	}
	execRef := commit("exec-worker", "exec-supervisor", 9001, "/usr/local/bin/python3")
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if b := worker(); posts != 1 || b["state"] != "observed" || b["root_exec_id"] != "exec-worker" || !strings.Contains(string(must(json.Marshal(b["evidence_refs"]))), "kernel_event:"+execRef) {
		t.Fatalf("binding after witness (%d posts): %v", posts, b)
	}
	// The answered nonce left the list: no replay, no second evidence.
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("answered nonce posted again: %d", posts)
	}

	st, out = call("POST", "/internal/control-health/work-readiness/checks", map[string]any{"work_run_id": uuid.NewString(),
		"runtime_process_epoch": epoch, "checkpoint": "start", "worker_instance_id": workerID, "worker_binding_id": binding})
	check, _ := out["check_id"].(string)
	if st != 202 || check == "" {
		t.Fatalf("request check: %d %v", st, out)
	}
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	st, out = call("GET", "/internal/control-health/work-readiness/checks/"+check, nil)
	if st != 200 || out["state"] != "ready" || posts != 2 {
		t.Fatalf("check after the sensor's Pod answer (%d posts): %d %v", posts, st, out)
	}

	// The worker exits: the next check gets the observed exit, not a pass.
	delete(procs, 9001)
	st, out = call("POST", "/internal/control-health/work-readiness/checks", map[string]any{"work_run_id": uuid.NewString(),
		"runtime_process_epoch": epoch, "checkpoint": "control_step", "worker_instance_id": workerID, "worker_binding_id": binding})
	check, _ = out["check_id"].(string)
	if st != 202 {
		t.Fatalf("second check: %d %v", st, out)
	}
	if err := r.Step(ctx); err != nil {
		t.Fatal(err)
	}
	st, out = call("GET", "/internal/control-health/work-readiness/checks/"+check, nil)
	codes, _ := json.Marshal(out["reason_codes"])
	if st != 200 || out["state"] != "blocked" || !strings.Contains(string(codes), "WORKER_EXITED") {
		t.Fatalf("check after worker exit: %d %v", st, out)
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

type countingHealth struct {
	*healthreport.Client
	posts *int
}

func (c *countingHealth) ReportWorker(ctx context.Context, r healthreport.WorkerResult) (healthreport.EvidenceAck, error) {
	*c.posts++
	return c.Client.ReportWorker(ctx, r)
}

func (c *countingHealth) ReportPod(ctx context.Context, r healthreport.PodResult) (healthreport.EvidenceAck, error) {
	*c.posts++
	return c.Client.ReportPod(ctx, r)
}
