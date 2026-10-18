//go:build integration

package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRiskPostgres goes from stored kernel and lifecycle rows to risk_event
// hold requests on a disposable PostgreSQL 16 database. The hold endpoint is
// a wire-checking stand-in; control-health's own acceptance of the request is
// covered by its PostgreSQL suite (risk_hold_integration_test.go).
func TestRiskPostgres(t *testing.T) {
	dsn := os.Getenv("CORRELATION_RISK_TEST_DSN")
	if dsn == "" {
		t.Skip("set disposable CORRELATION_RISK_TEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, reader := "risk_"+suffix, "riskreader_"+suffix
	run := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL: %v\n%.300s", err, sql)
		}
	}
	run(admin, "CREATE DATABASE "+dbName)
	run(admin, "CREATE ROLE "+reader+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)")
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+reader)
	}()
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = dbName
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	run(db, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`)
	files, _ := filepath.Glob("../../../../migrations/*.up.sql")
	slices.Sort(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		run(db, string(raw))
	}
	// Mirrors the TASK-07 grant of #171 (20261017144104_audit_correlation_reader)
	// until that migration is on main; then this stand-in is removed.
	run(db, "GRANT USAGE ON SCHEMA audit TO correlation_reader")
	run(db, "GRANT SELECT ON audit.kernel_events, audit.lifecycle_events TO correlation_reader")
	run(db, "GRANT correlation_writer TO "+reader)
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database, pc.ConnConfig.User = dbName, reader
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	cluster, node, pod := uuid.New(), uuid.New(), uuid.New()
	container := strings.Repeat("a", 64)
	workload := "agent-exec/runtime"
	base := time.Now().UTC().Add(-10 * time.Minute)
	// The entrypoint exec lies at the lifecycle start (root). The second
	// container's entrypoint was missed: its first observed exec is an
	// injected one 30 minutes after the start and must not become the root.
	missed := strings.Repeat("b", 64)
	run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
		VALUES(gen_random_uuid(),$1,$2,$3,'boot-1',$4,$5,'open',1,ARRAY[gen_random_uuid()]),
		(gen_random_uuid(),$1,$2,$3,'boot-1',$6,$7,'open',1,ARRAY[gen_random_uuid()])`, cluster, pod, node, container, base.Add(-time.Second), missed, base.Add(-30*time.Minute))
	sequence := int64(0)
	insert := func(kind, containerID, execID, parent string, at time.Time, dest string, sock string, attrs string) uuid.UUID {
		t.Helper()
		sequence++
		id := uuid.New()
		var cont, proc, par, daddr, sockArg, state any = nil, nil, nil, nil, nil, nil
		if containerID != "" {
			cont = containerID
		}
		if execID != "" {
			proc = execID
		}
		if parent != "" {
			par = parent
		}
		saddr, sport, dport := any(nil), any(nil), any(nil)
		if dest != "" {
			daddr, saddr, sport, dport, sockArg = dest, "10.0.0.5", 40000+int(sequence), 443, sock
		}
		if kind == "tcp_state" {
			state, proc = 1, nil
		}
		run(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,parent_exec_id,container_id,saddr,sport,daddr,dport,sock_ptr,tcp_new_state,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
			VALUES($1,'sensor','sensor-1','1',$2,'exp-1',1,$3,'boot-1',$4,$4,$4,$5,$6,$7,$8,$9::inet,$10,$11::inet,$12,$13,$14,'resolved','v1',$15,'full',$16::jsonb,$15)`,
			id, sequence, node, at, kind, proc, par, cont, saddr, sport, daddr, dport, sockArg, state, strings.Repeat("e", 64), attrs)
		return id
	}
	insert("process_exec", container, "root", "", base, "", "", "{}")
	insert("process_exec", container, "child", "root", base.Add(time.Second), "", "", "{}")
	insert("process_exec", "", "shim", "", base.Add(2*time.Second), "", "", "{}")
	injected := insert("process_exec", container, "injected", "shim", base.Add(3*time.Second), "", "", "{}")
	connect := insert("tcp_connect", container, "child", "", base.Add(4*time.Second), "198.51.100.9", "00000000000000c1", "{}")
	state := insert("tcp_state", "", "", "", base.Add(4*time.Second+10*time.Millisecond), "198.51.100.9", "00000000000000c1", "{}")
	run(db, `UPDATE audit.kernel_events s SET sport=k.sport FROM audit.kernel_events k WHERE s.source_event_id=$1 AND k.source_event_id=$2`, state, connect)
	insert("tcp_connect", container, "child", "", base.Add(5*time.Second), "10.0.0.9", "00000000000000c2", "{}") // not established
	write := insert("openat", container, "child", "", base.Add(6*time.Second), "", "", `{"path":"/work/protected-fixture","flags":577,"return_errno":0}`)
	insert("file_open", container, "child", "", base.Add(7*time.Second), "", "", `{"path":"/work/protected-fixture","flags":0,"return_code":0}`)
	// A non-numeric flags value is unreadable, not an evaluation failure.
	insert("file_open", container, "child", "", base.Add(8*time.Second), "", "", `{"path":"/work/protected-fixture","flags":"O_RDWR","return_code":0}`)
	missedFirst := insert("process_exec", missed, "injected-first", "shim", base.Add(10*time.Second), "", "", "{}")
	missedChild := insert("process_exec", missed, "injected-child", "injected-first", base.Add(11*time.Second), "", "", "{}")

	workloads := func(p uuid.UUID) *string {
		if p == pod {
			return &workload
		}
		return nil
	}
	allowed := func(w string, dest netip.Addr, port int) bool { return dest == netip.MustParseAddr("10.0.0.9") }
	events, roots, err := Load(ctx, pool, node, base.Add(-time.Minute), base.Add(time.Minute), workloads, allowed)
	if err != nil {
		t.Fatal(err)
	}
	if roots[RootKey(node.String(), "boot-1", container)] != "root" || roots[RootKey(node.String(), "boot-1", missed)] != "" {
		t.Fatalf("roots %v", roots)
	}
	cfg2 := Config{ProtectedPaths: []string{"/work/protected-fixture"}, FlagsVerified: true, ContainerRoots: roots, WorkerRoots: map[string]bool{}}
	decisions, candidates := Evaluate(events, cfg2)
	marked := map[string]bool{}
	for _, c := range candidates {
		marked[c.KernelEventID] = c.Detail == DetailExec
	}
	if !marked[missedFirst.String()] || !marked[missedChild.String()] {
		t.Fatalf("execs of a container without an observed start process were not marked undeterminable: %+v", candidates)
	}
	got := map[string]string{}
	for _, d := range decisions {
		got[d.KernelEventID] = d.Detail
	}
	want := map[string]string{connect.String(): DetailConnect, injected.String(): DetailExec, write.String(): DetailWrite}
	if len(got) != len(want) {
		t.Fatalf("decisions %+v", decisions)
	}
	for id, detail := range want {
		if got[id] != detail {
			t.Fatalf("decision for %s = %q, want %q (%+v)", id, got[id], detail, decisions)
		}
	}
	// Until TASK-09 Q0 verifies open flags, the write is marked only.
	cfg2.FlagsVerified = false
	if d, _ := Evaluate(events, cfg2); len(d) != 2 {
		t.Fatalf("unverified flags: %+v", d)
	}

	var mu sync.Mutex
	requests := []map[string]any{}
	open := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		var req struct {
			Scope        string   `json:"scope"`
			ScopeID      string   `json:"scope_id"`
			Reason       string   `json:"reason"`
			ReasonDetail string   `json:"reason_detail"`
			EvidenceRefs []string `json:"evidence_refs"`
		}
		if r.URL.Path != "/internal/holds" || d.Decode(&req) != nil || req.Scope != "workload" || req.Reason != "risk_event" || len(req.EvidenceRefs) != 1 || !strings.HasPrefix(req.EvidenceRefs[0], "kernel_event:") {
			w.WriteHeader(422)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		requests = append(requests, m)
		decision := "existing"
		if open[req.ScopeID] == "" {
			open[req.ScopeID], decision = uuid.NewString(), "created"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"hold_id": open[req.ScopeID], "decision": decision, "reason_codes": []string{}})
	}))
	defer server.Close()
	client := HoldClient{URL: server.URL, Client: server.Client()}
	decisions, _ = Evaluate(events, Config{ProtectedPaths: cfg2.ProtectedPaths, FlagsVerified: true, ContainerRoots: roots})
	created := 0
	for _, d := range decisions {
		ack, err := client.Request(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		if ack.Decision == "created" {
			created++
		}
	}
	if created != 1 || len(requests) != 3 || requests[0]["reason_detail"] == nil || requests[0]["scope_id"] != workload {
		t.Fatalf("created %d requests %+v", created, requests)
	}
	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_ = json.NewEncoder(w).Encode(map[string]any{"hold_id": nil, "decision": "rejected", "reason_codes": []string{"HOLD_REQUEST_DENIED"}})
	}))
	defer rejecting.Close()
	if _, err := (HoldClient{URL: rejecting.URL, Client: rejecting.Client()}).Request(ctx, decisions[0]); !errors.Is(err, ErrRejected) {
		t.Fatalf("rejection: %v", err)
	}
}
