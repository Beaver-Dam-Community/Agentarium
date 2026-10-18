//go:build integration

package netpol

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNetworkFindingsPostgres runs on a disposable PostgreSQL 16 cluster with
// every merged migration plus this change, then uses a restricted runtime
// login that holds only correlation_writer and audit_producer. It shows that
// denied and established flows become different findings, that collector
// gaps mark kernel-only attempts unknown, and that recovery backfills the gap.
func TestNetworkFindingsPostgres(t *testing.T) {
	dsn := os.Getenv("NETPOL_TEST_DSN")
	if dsn == "" {
		t.Skip("set disposable NETPOL_TEST_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, writer := "netpol_"+suffix, "netpolwriter_"+suffix
	run := func(c *pgx.Conn, sql string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL: %v\n%s", err, sql)
		}
	}
	run(admin, "CREATE DATABASE "+dbName)
	run(admin, "CREATE ROLE "+writer+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	defer func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+dbName+" WITH (FORCE)")
		_, _ = admin.Exec(context.Background(), "DROP ROLE "+writer)
	}()
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = dbName
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close(context.Background())
	// Installer bootstrap: the NOLOGIN health writer exists before migrations.
	run(db, `DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$`)
	files, _ := filepath.Glob("../../../migrations/*.up.sql")
	slices.Sort(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		run(db, string(raw))
	}
	source := "correlation-netpol-" + suffix
	run(db, "GRANT correlation_writer, audit_producer TO "+writer)
	run(db, `INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,$2,false)`, writer, source)
	run(db, `INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES($1,'network_finding_recorded','*'),($1,'evidence_gap_resolved','*'),($1,'observation_gap_recorded','*'),($1,'sequence_range_abandoned','*')`, source)
	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database, pc.ConnConfig.User = dbName, writer
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	classifier, err := NewClassifier(Environment{LockDigest: strings.Repeat("a", 64),
		PodsRange: netip.MustParsePrefix("10.0.0.0/16"), ServicesRange: netip.MustParsePrefix("10.96.0.0/16"), NodeCIDR: netip.MustParsePrefix("10.128.0.0/20"),
		ControlPlane: netip.MustParseAddr("10.128.15.2"), CloudSQL: netip.MustParseAddr("10.129.0.3"), Gateway: netip.MustParseAddr("10.96.0.10"), DNS: netip.MustParseAddr("10.96.0.53"),
		Metadata: []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}, PGA: []netip.Prefix{netip.MustParsePrefix("199.36.153.8/30")}})
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Pool: pool, Config: Config{SourceID: source, Version: "test", Epoch: "1"}, Classifier: classifier}

	cluster, node := uuid.New(), uuid.New()
	pod := uuid.New()
	container := strings.Repeat("c", 64)
	workload := "agent-exec/runtime"
	run(db, `INSERT INTO audit.lifecycle_events(lifecycle_event_id,source_id,source_kind,source_epoch,source_sequence,cluster_uid,pod_uid,namespace,pod_name,node_uid,boot_id,container_id,transition,source_time,received_at,mapping_version,record_digest)
		VALUES(gen_random_uuid(),'watcher','pod_watcher','1',1,$1,$2,'agent-exec','runtime-a',$3,'boot-1',$4,'created',now()-interval '1 hour',now(),1,$5)`, cluster, pod, node, container, strings.Repeat("d", 64))
	run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
		VALUES(gen_random_uuid(),$1,$2,$3,'boot-1',$4,now()-interval '1 hour','open',1,ARRAY[gen_random_uuid()])`, cluster, pod, node, container)
	sequence := int64(0)
	kernel := func(kind string, at time.Time, dest string, port int, sock string) uuid.UUID {
		t.Helper()
		sequence++
		id := uuid.New()
		var state any
		process := any("exec-1")
		if kind == "tcp_state" {
			state, process = 1, nil
		}
		run(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,container_id,saddr,sport,daddr,dport,sock_ptr,tcp_new_state,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
			VALUES($1,'sensor','sensor-1','1',$2,'exp-1',1,$3,'boot-1',$4,$4,$4,$5,$6,$7,'10.0.0.5',40000+('x'||right($10,4))::bit(16)::int,$8::inet,$9,$10,$11,'resolved','v1',$12,'full','{}',$12)`,
			id, sequence, node, at, kind, process, container, dest, port, sock, state, strings.Repeat("e", 64))
		return id
	}
	allowed := func(w *string, dest netip.Addr, port int) bool {
		return w != nil && *w == workload && dest == netip.MustParseAddr("10.0.0.9") && port == 8443
	}
	workloads := func(p uuid.UUID) *string {
		if p == pod {
			return &workload
		}
		return nil
	}
	ref := func(ns, name string) *EndpointRef { return &EndpointRef{Namespace: &ns, PodName: &name} }
	p := func(v int) *int { return &v }
	now := time.Now().UTC()
	base := now.Add(-10 * time.Minute)
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	findings := func(dest string) []map[string]any {
		t.Helper()
		rows, err := db.Query(ctx, `SELECT finding_id::text, revision, kind, outcome, network_segment, boundary_crossing, confidence, coalesce(workload_id,''), limitations, cardinality(kernel_event_ids), cardinality(policy_record_ids), coalesce(attempt_count,-1), count_quality, reason
			FROM correlation.network_findings WHERE merge_key LIKE '%|'||$1||'|%' ORDER BY revision`, dest)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := []map[string]any{}
		for rows.Next() {
			var id, kind, outcome, segment, boundary, confidence, wl, quality, reason string
			var revision, kernels, records int
			var attempts int64
			var limits []string
			if err := rows.Scan(&id, &revision, &kind, &outcome, &segment, &boundary, &confidence, &wl, &limits, &kernels, &records, &attempts, &quality, &reason); err != nil {
				t.Fatal(err)
			}
			out = append(out, map[string]any{"id": id, "revision": revision, "kind": kind, "outcome": outcome, "segment": segment, "boundary": boundary, "confidence": confidence, "workload": wl, "limits": limits, "kernels": kernels, "records": records, "attempts": attempts, "quality": quality, "reason": reason})
		}
		return out
	}
	identity := NodeIdentity{ClusterUID: cluster, NodeUID: node}

	t.Run("ingest_dedupes_and_acks_contiguously", func(t *testing.T) {
		records := []BatchRecord{
			{SourceSequence: 1, SourceTime: base.Add(2 * time.Second), Disposition: "deny", Direction: "egress", Protocol: "tcp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("203.0.113.10"), DestPort: p(443), SrcEndpoint: ref("agent-exec", "runtime-a"), Count: p(3), NormalizationVersion: "v1"},
			{SourceSequence: 2, SourceTime: base, Disposition: "allow", Direction: "egress", Protocol: "tcp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("198.51.100.20"), DestPort: p(8443), SrcEndpoint: ref("agent-exec", "runtime-a"), Policies: []PolicyRef{{Name: "allow-egress", Namespace: "agent-exec"}}, NormalizationVersion: "v1"},
			{SourceSequence: 4, SourceTime: base.Add(time.Second), Disposition: "deny", Direction: "egress", Protocol: "udp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("8.8.8.8"), DestPort: p(53), SrcEndpoint: ref("agent-exec", "runtime-a"), NormalizationVersion: "v1"},
		}
		ack, err := ingestT(ctx, s, identity, Batch{SourceEpoch: "e1", Records: records})
		if err != nil || len(ack.AcceptedIDs) != 3 || ack.AckedThrough != 2 {
			t.Fatalf("ack %+v %v", ack, err)
		}
		// Resend plus the missing sequence: duplicates keep their IDs, watermark moves.
		ack2, err := ingestT(ctx, s, identity, Batch{SourceEpoch: "e1", Records: append(records[:1:1], BatchRecord{SourceSequence: 3, SourceTime: base.Add(time.Second), Disposition: "allow", Direction: "egress", Protocol: "tcp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("10.0.0.9"), DestPort: p(8443), SrcEndpoint: ref("agent-exec", "runtime-a"), Policies: []PolicyRef{{Name: "gateway", Namespace: "agent-exec"}}, NormalizationVersion: "v1"})})
		if err != nil || len(ack2.DuplicateIDs) != 1 || ack2.DuplicateIDs[0] != ack.AcceptedIDs[0] || ack2.AckedThrough != 4 {
			t.Fatalf("resend %+v %v", ack2, err)
		}
		if count(`SELECT count(*) FROM correlation.network_policy_records WHERE node_uid=$1`, node) != 4 {
			t.Fatal("duplicate record stored")
		}
	})
	t.Run("denied_and_established_are_distinguished", func(t *testing.T) {
		kernel("tcp_connect", base, "203.0.113.10", 443, "0000000000000001") // denied: no ESTABLISHED
		kernel("tcp_connect", base, "198.51.100.20", 8443, "0000000000000002")
		kernel("tcp_state", base.Add(10*time.Millisecond), "198.51.100.20", 8443, "0000000000000002")
		kernel("tcp_connect", base.Add(time.Second), "10.0.0.9", 8443, "0000000000000003")
		kernel("tcp_state", base.Add(time.Second+10*time.Millisecond), "10.0.0.9", 8443, "0000000000000003")
		written, err := s.Evaluate(ctx, node, base.Add(-time.Minute), base.Add(time.Minute), now, workloads, allowed)
		if err != nil || len(written) != 3 {
			t.Fatalf("written %v %v", written, err)
		}
		denied := findings("203.0.113.10")
		if len(denied) != 1 || denied[0]["kind"] != "blocked_attempt" || denied[0]["outcome"] != "blocked" || denied[0]["kernels"] != 1 || denied[0]["records"] != 1 || denied[0]["attempts"] != int64(3) || denied[0]["quality"] != "estimated" || denied[0]["confidence"] != "workload_inferred" || denied[0]["workload"] != workload || denied[0]["boundary"] != "external" {
			t.Fatalf("denied %+v", denied)
		}
		established := findings("198.51.100.20")
		if len(established) != 1 || established[0]["kind"] != "unregistered_established" || established[0]["outcome"] != "established" || established[0]["records"] != 1 || !strings.Contains(established[0]["reason"].(string), "agent-exec/allow-egress") {
			t.Fatalf("established %+v", established)
		}
		udp := findings("8.8.8.8")
		if len(udp) != 1 || udp[0]["kind"] != "blocked_attempt" || !slices.Contains(udp[0]["limits"].([]string), "no_kernel_hook_for_protocol") || udp[0]["kernels"] != 0 {
			t.Fatalf("udp %+v", udp)
		}
		if len(findings("10.0.0.9")) != 0 {
			t.Fatal("allowed established connection produced a finding")
		}
		if count(`SELECT count(*) FROM audit.audit_events WHERE event_type='network_finding_recorded'`) != 3 || count(`SELECT count(*) FROM health.holds`) != 0 {
			t.Fatal("finding audit missing or a hold was created")
		}
		if count(`SELECT count(*) FROM correlation.correlations`) != 0 {
			t.Fatal("finding changed correlation confidence")
		}
		again, err := s.Evaluate(ctx, node, base.Add(-time.Minute), base.Add(time.Minute), now, workloads, allowed)
		if err != nil || len(again) != 0 {
			t.Fatalf("re-evaluation appended revisions: %v %v", again, err)
		}
	})
	late := base.Add(2 * time.Minute)
	t.Run("late_deny_record_revises_same_finding", func(t *testing.T) {
		kernel("tcp_connect", late, "203.0.113.30", 443, "0000000000000004")
		if _, err := s.Evaluate(ctx, node, late.Add(-time.Minute), late.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		first := findings("203.0.113.30")
		if len(first) != 1 || first[0]["kind"] != "unmatched_attempt" || first[0]["outcome"] != "unknown" || !slices.Contains(first[0]["limits"].([]string), "log_drop_unmeasured") {
			t.Fatalf("unmatched %+v", first)
		}
		if _, err := ingestT(ctx, s, identity, Batch{SourceEpoch: "e1", Records: []BatchRecord{{SourceSequence: 5, SourceTime: late.Add(3 * time.Second), Disposition: "deny", Direction: "egress", Protocol: "tcp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("203.0.113.30"), DestPort: p(443), SrcEndpoint: ref("agent-exec", "runtime-a"), NormalizationVersion: "v1"}}}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Evaluate(ctx, node, late.Add(-time.Minute), late.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		revised := findings("203.0.113.30")
		if len(revised) != 2 || revised[1]["id"] != revised[0]["id"] || revised[1]["revision"] != 2 || revised[1]["kind"] != "blocked_attempt" || revised[0]["kind"] != "unmatched_attempt" || !strings.HasPrefix(revised[1]["reason"].(string), "kind changed from unmatched_attempt") {
			t.Fatalf("revision %+v", revised)
		}
	})
	gapAt := base.Add(5 * time.Minute)
	t.Run("collection_gap_marks_unknown_then_backfills", func(t *testing.T) {
		// The open gap as control-health records it on netpol-collector lease expiry.
		var gap string
		if err := db.QueryRow(ctx, `INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,boot_id,source_id,start_at,count_quality,evidence_refs,recovery_state,created_by)
			VALUES(gen_random_uuid(),'network_policy_log','NETPOL_COLLECTOR_STOPPED',$1,'boot-1',$2,$3,'unknown','["lease:netpol-1"]','open','TASK-10') RETURNING gap_id::text`, node, "netpol-node/"+node.String(), gapAt.Add(-10*time.Second)).Scan(&gap); err != nil {
			t.Fatal(err)
		}
		kernel("tcp_connect", gapAt, "203.0.113.40", 443, "0000000000000005")
		if _, err := s.Evaluate(ctx, node, gapAt.Add(-time.Minute), gapAt.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		during := findings("203.0.113.40")
		if len(during) != 1 || during[0]["kind"] != "unmatched_attempt" || during[0]["outcome"] != "unknown" || !slices.Contains(during[0]["limits"].([]string), "network_policy_log_gap") {
			t.Fatalf("during gap %+v", during)
		}
		// Recovery: the collector resends the stopped interval and reports it caught up.
		caught := gapAt.Add(30 * time.Second)
		ack, err := ingestT(ctx, s, identity, Batch{SourceEpoch: "e1", CaughtUpAt: &caught, Records: []BatchRecord{{SourceSequence: 6, SourceTime: gapAt.Add(2 * time.Second), Disposition: "deny", Direction: "egress", Protocol: "tcp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("203.0.113.40"), DestPort: p(443), SrcEndpoint: ref("agent-exec", "runtime-a"), NormalizationVersion: "v1"}}})
		if err != nil || len(ack.BackfilledGapIDs) != 1 || ack.BackfilledGapIDs[0].String() != gap {
			t.Fatalf("backfill ack %+v %v", ack, err)
		}
		var state string
		var end time.Time
		var refs []string
		if err := db.QueryRow(ctx, `SELECT recovery_state,end_at,evidence_refs FROM health.observation_gaps WHERE gap_id=$1`, gap).Scan(&state, &end, &refs); err != nil {
			t.Fatal(err)
		}
		if state != "backfilled" || !end.Equal(caught.Truncate(time.Microsecond)) || !slices.Contains(refs, "netpol-sequence:e1:6-6") || count(`SELECT count(*) FROM audit.audit_events WHERE event_type='evidence_gap_resolved' AND safe_payload->>'gap_id'=$1`, gap) != 1 {
			t.Fatalf("gap %s %v %v", state, end, refs)
		}
		if _, err := s.Evaluate(ctx, node, gapAt.Add(-time.Minute), gapAt.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		after := findings("203.0.113.40")
		if len(after) != 2 || after[1]["kind"] != "blocked_attempt" || after[1]["id"] != after[0]["id"] {
			t.Fatalf("after backfill %+v", after)
		}
	})
	t.Run("finding_audit_is_atomic", func(t *testing.T) {
		run(db, `DELETE FROM audit.producer_event_grants WHERE event_type='network_finding_recorded'`)
		at := base.Add(8 * time.Minute)
		kernel("tcp_connect", at, "203.0.113.50", 443, "0000000000000006")
		if _, err := s.Evaluate(ctx, node, at.Add(-time.Minute), at.Add(30*time.Second), now, workloads, allowed); err == nil {
			t.Fatal("finding committed without its audit event")
		}
		if len(findings("203.0.113.50")) != 0 {
			t.Fatal("partial finding commit")
		}
	})
	t.Run("runtime_cannot_rewrite_evidence", func(t *testing.T) {
		for _, sql := range []string{
			"UPDATE correlation.network_policy_records SET count=9",
			"DELETE FROM correlation.network_policy_records",
			"UPDATE correlation.network_findings SET kind='unmatched_deny'",
			"DELETE FROM correlation.network_findings",
			"UPDATE health.observation_gaps SET reason='NETPOL_NODE_LOG_DROPPED'",
			"DELETE FROM health.observation_gaps",
		} {
			if _, err := pool.Exec(ctx, sql); err == nil {
				t.Fatalf("writer allowed %s", sql)
			}
		}
	})
	t.Run("grown_finding_does_not_stall_evaluation", func(t *testing.T) {
		run(db, `INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES($1,'network_finding_recorded','*') ON CONFLICT DO NOTHING`, source)
		t0 := now.Add(-50 * time.Minute)
		kernel("tcp_connect", t0, "203.0.113.60", 443, "0000000000000010")
		if _, err := s.Evaluate(ctx, node, t0.Add(-time.Minute), t0.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		t1 := t0.Add(10 * time.Minute)
		kernel("tcp_connect", t1, "203.0.113.60", 443, "0000000000000011")
		kernel("tcp_connect", t1, "203.0.113.61", 443, "0000000000000012")
		if _, err := s.Evaluate(ctx, node, t1.Add(-time.Minute), t1.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatalf("evaluation stalled on a finding whose inputs left the window: %v", err)
		}
		grown := findings("203.0.113.60")
		if len(grown) != 2 || grown[1]["id"] != grown[0]["id"] || grown[1]["kernels"] != 2 || len(findings("203.0.113.61")) != 1 {
			t.Fatalf("grown %+v new %+v", grown, findings("203.0.113.61"))
		}
	})
	t.Run("merge_window_applies_within_one_evaluation", func(t *testing.T) {
		t0 := now.Add(-55 * time.Minute)
		kernel("tcp_connect", t0, "203.0.113.70", 443, "0000000000000020")
		kernel("tcp_connect", t0.Add(30*time.Minute), "203.0.113.70", 443, "0000000000000021")
		if _, err := s.Evaluate(ctx, node, t0.Add(-time.Minute), t0.Add(31*time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		ids := map[any]bool{}
		for _, f := range findings("203.0.113.70") {
			ids[f["id"]] = true
		}
		if len(ids) != 2 {
			t.Fatalf("events 30 minutes apart merged into %d findings", len(ids))
		}
	})
	t.Run("unknown_workload_is_never_unregistered", func(t *testing.T) {
		other := uuid.New()
		otherContainer := strings.Repeat("f", 64)
		run(db, `INSERT INTO audit.lifecycle_events(lifecycle_event_id,source_id,source_kind,source_epoch,source_sequence,cluster_uid,pod_uid,namespace,pod_name,node_uid,boot_id,container_id,transition,source_time,received_at,mapping_version,record_digest)
			VALUES(gen_random_uuid(),'watcher','pod_watcher','1',2,$1,$2,'agent-adapters','adapter-a',$3,'boot-1',$4,'created',now()-interval '1 hour',now(),1,$5)`, cluster, other, node, otherContainer, strings.Repeat("d", 64))
		run(db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,started_at,end_quality,mapping_version,source_event_ids)
			VALUES(gen_random_uuid(),$1,$2,$3,'boot-1',$4,now()-interval '1 hour','open',1,ARRAY[gen_random_uuid()])`, cluster, other, node, otherContainer)
		at := now.Add(-40 * time.Minute)
		sequence++
		id := uuid.New()
		run(db, `INSERT INTO audit.kernel_events(source_event_id,source_id,sensor_id,source_epoch,source_sequence,exporter_instance_id,sensor_generation,node_uid,boot_id,source_time,spooled_at,received_at,event_type,process_exec_id,container_id,saddr,sport,daddr,dport,sock_ptr,metadata_status,normalization_version,rule_hash,coverage,safe_attributes,record_digest)
			VALUES($1,'sensor','sensor-1','1',$2,'exp-1',1,$3,'boot-1',$4,$4,$4,'tcp_connect','exec-2',$5,'10.0.0.6',41000,'198.51.100.80',443,'0000000000000030','resolved','v1',$6,'full','{}',$6)`, id, sequence, node, at, otherContainer, strings.Repeat("e", 64))
		kernel("tcp_state", at.Add(10*time.Millisecond), "198.51.100.80", 443, "0000000000000030")
		run(db, `UPDATE audit.kernel_events SET saddr='10.0.0.6',sport=41000,container_id=NULL WHERE sock_ptr='0000000000000030' AND event_type='tcp_state'`)
		if _, err := s.Evaluate(ctx, node, at.Add(-time.Minute), at.Add(time.Minute), now, workloads, allowed); err != nil {
			t.Fatal(err)
		}
		if f := findings("198.51.100.80"); len(f) != 0 {
			t.Fatalf("adapter traffic without a verified workload was called unregistered: %+v", f)
		}
	})
	t.Run("resent_sequence_with_other_content_conflicts", func(t *testing.T) {
		rec := BatchRecord{SourceSequence: 1, SourceTime: base.Add(2 * time.Second), Disposition: "allow", Direction: "egress", Protocol: "tcp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("203.0.113.10"), DestPort: p(443), SrcEndpoint: ref("agent-exec", "runtime-a"), NormalizationVersion: "v1"}
		ack, err := ingestT(ctx, s, identity, Batch{SourceEpoch: "e1", Records: []BatchRecord{rec}})
		if err != nil || len(ack.AcceptedIDs)+len(ack.DuplicateIDs) != 0 || len(ack.Rejected) != 1 || ack.Rejected[0].ReasonCodes[0] != "EVENT_ID_CONFLICT" {
			t.Fatalf("different content for a stored sequence: %+v %v", ack, err)
		}
	})
	t.Run("older_epoch_hole_keeps_gap_open", func(t *testing.T) {
		holed := NodeIdentity{ClusterUID: cluster, NodeUID: uuid.New()}
		start := now.Add(-20 * time.Minute)
		var gap string
		if err := db.QueryRow(ctx, `INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,boot_id,source_id,start_at,count_quality,evidence_refs,recovery_state,created_by)
			VALUES(gen_random_uuid(),'network_policy_log','NETPOL_COLLECTOR_STOPPED',$1,'boot-1',$2,$3,'unknown','[]','open','TASK-10') RETURNING gap_id::text`, holed.NodeUID, "netpol-node/"+holed.NodeUID.String(), start).Scan(&gap); err != nil {
			t.Fatal(err)
		}
		record := func(seq int64) BatchRecord {
			return BatchRecord{SourceSequence: seq, SourceTime: start.Add(time.Duration(seq) * time.Second), Disposition: "deny", Direction: "egress", Protocol: "udp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("8.8.8.8"), DestPort: p(53), NormalizationVersion: "v1"}
		}
		if _, err := ingestT(ctx, s, holed, Batch{SourceEpoch: "old", Records: []BatchRecord{record(1), record(3)}}); err != nil {
			t.Fatal(err)
		}
		caught := now.Add(-time.Minute)
		ack, err := ingestT(ctx, s, holed, Batch{SourceEpoch: "new", CaughtUpAt: &caught, Records: []BatchRecord{record(1)}})
		if err != nil || len(ack.BackfilledGapIDs) != 0 {
			t.Fatalf("gap backfilled while an older epoch has a hole: %+v %v", ack, err)
		}
	})
	t.Run("abandoned_range_is_an_exact_gap_and_moves_the_watermark", func(t *testing.T) {
		n := NodeIdentity{ClusterUID: cluster, NodeUID: uuid.New()}
		start := now.Add(-15 * time.Minute)
		record := func(seq int64) BatchRecord {
			return BatchRecord{SourceSequence: seq, SourceTime: start.Add(time.Duration(seq) * time.Second), Disposition: "deny", Direction: "egress", Protocol: "udp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("8.8.8.8"), DestPort: p(53), NormalizationVersion: "v1"}
		}
		rng := AbandonedRange{From: 2, To: 3, Reason: "record_rejected", Digest: strings.Repeat("a", 64)}
		ack, err := ingestT(ctx, s, n, Batch{SourceEpoch: "e", Records: []BatchRecord{record(1), record(4)}, Abandoned: []AbandonedRange{rng}})
		if err != nil || ack.AckedThrough != 4 || len(ack.LossGapIDs) != 1 || len(ack.Rejected) != 0 {
			t.Fatalf("abandoned range %+v %v", ack, err)
		}
		var reason, state, quality string
		var loss, from, to int64
		var end *time.Time
		if err := db.QueryRow(ctx, `SELECT reason,recovery_state,count_quality,loss_count,sequence_from,sequence_to,end_at FROM health.observation_gaps WHERE gap_id=$1`, ack.LossGapIDs[0]).Scan(&reason, &state, &quality, &loss, &from, &to, &end); err != nil {
			t.Fatal(err)
		}
		if reason != "SEQUENCE_RANGE_ABANDONED" || state != "unrecoverable" || quality != "exact" || loss != 2 || from != 2 || to != 3 || end == nil {
			t.Fatalf("gap %s %s %s %d %d-%d %v", reason, state, quality, loss, from, to, end)
		}
		// The same declaration reuses its gap; a different one at the same
		// start, an overlapping one and a record inside the range conflict.
		again, err := ingestT(ctx, s, n, Batch{SourceEpoch: "e", Abandoned: []AbandonedRange{rng}})
		if err != nil || len(again.LossGapIDs) != 0 || len(again.Rejected) != 0 || again.AckedThrough != 4 {
			t.Fatalf("resend %+v %v", again, err)
		}
		other := rng
		other.To = 5
		bad, err := ingestT(ctx, s, n, Batch{SourceEpoch: "e", Records: []BatchRecord{record(2)}, Abandoned: []AbandonedRange{other, {From: 6, To: 6, Reason: "record_rejected", Digest: strings.Repeat("b", 64)}}})
		if err != nil || len(bad.Rejected) != 2 || len(bad.AcceptedIDs) != 0 || len(bad.LossGapIDs) != 1 || bad.AckedThrough != 4 {
			t.Fatalf("conflicts %+v %v", bad, err)
		}
		late, err := ingestT(ctx, s, n, Batch{SourceEpoch: "e", Abandoned: []AbandonedRange{{From: 4, To: 5, Reason: "record_rejected", Digest: strings.Repeat("c", 64)}}})
		if err != nil || len(late.Rejected) != 1 || late.Rejected[0].ReasonCodes[0] != "EVENT_ID_CONFLICT" {
			t.Fatalf("range at or below the watermark accepted: %+v %v", late, err)
		}
	})
	t.Run("rotation_loss_records_unrecoverable_gap_and_closes_stopped_gap", func(t *testing.T) {
		boot := "boot-r"
		n := NodeIdentity{ClusterUID: cluster, NodeUID: uuid.New(), BootID: &boot}
		start := now.Add(-12 * time.Minute)
		var stopped string
		if err := db.QueryRow(ctx, `INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,boot_id,source_id,start_at,count_quality,evidence_refs,recovery_state,created_by)
			VALUES(gen_random_uuid(),'network_policy_log','NETPOL_COLLECTOR_STOPPED',$1,'boot-r',$2,$3,'unknown','[]','open','TASK-10') RETURNING gap_id::text`, n.NodeUID, "netpol-node/"+n.NodeUID.String(), start.Add(5*time.Second)).Scan(&stopped); err != nil {
			t.Fatal(err)
		}
		record := func(seq int64) BatchRecord {
			return BatchRecord{SourceSequence: seq, SourceTime: start.Add(time.Duration(seq) * 3 * time.Second), Disposition: "deny", Direction: "egress", Protocol: "udp", SrcIP: netip.MustParseAddr("10.0.0.5"), DestIP: netip.MustParseAddr("8.8.8.8"), DestPort: p(53), NormalizationVersion: "v1"}
		}
		caught := now
		if _, err := ingestT(ctx, s, n, Batch{SourceEpoch: "r", CaughtUpAt: &caught, RotationLoss: &RotationLoss{DetectedAt: now, AfterSequence: 1}}); err == nil {
			t.Fatal("rotation_loss with caught_up_at accepted")
		}
		detected := now.Add(-time.Minute)
		ack, err := ingestT(ctx, s, n, Batch{SourceEpoch: "r", Records: []BatchRecord{record(1), record(2)}, RotationLoss: &RotationLoss{DetectedAt: detected, AfterSequence: 2}})
		if err != nil || len(ack.LossGapIDs) != 1 {
			t.Fatalf("rotation loss %+v %v", ack, err)
		}
		var reason, state string
		var gapStart, gapEnd time.Time
		if err := db.QueryRow(ctx, `SELECT reason,recovery_state,start_at,end_at FROM health.observation_gaps WHERE gap_id=$1`, ack.LossGapIDs[0]).Scan(&reason, &state, &gapStart, &gapEnd); err != nil {
			t.Fatal(err)
		}
		if reason != "NETPOL_FILE_ROTATION_LOSS" || state != "unrecoverable" || !gapStart.Equal(record(2).SourceTime) || !gapEnd.Equal(detected) {
			t.Fatalf("rotation gap %s %s %v %v", reason, state, gapStart, gapEnd)
		}
		if err := db.QueryRow(ctx, `SELECT recovery_state,end_at FROM health.observation_gaps WHERE gap_id=$1`, stopped).Scan(&state, &gapEnd); err != nil {
			t.Fatal(err)
		}
		if state != "partially_recovered" || !gapEnd.Equal(detected) {
			t.Fatalf("stopped gap %s %v", state, gapEnd)
		}
		again, err := ingestT(ctx, s, n, Batch{SourceEpoch: "r", RotationLoss: &RotationLoss{DetectedAt: detected, AfterSequence: 2}})
		if err != nil || len(again.LossGapIDs) != 0 {
			t.Fatalf("repeated declaration made another gap: %+v %v", again, err)
		}
	})
}

// ingestT fills the receiver-verified record identity the way the HTTP
// receiver does before calling Ingest.
func ingestT(ctx context.Context, s Store, id NodeIdentity, b Batch) (Ack, error) {
	for i := range b.Records {
		rid, err := canonical.NetworkPolicyRecordID(id.ClusterUID.String(), id.NodeUID.String(), b.SourceEpoch, b.Records[i].SourceSequence)
		if err != nil {
			return Ack{}, err
		}
		b.Records[i].RecordID = uuid.MustParse(rid)
		if b.Records[i].NodeName == "" {
			b.Records[i].NodeName = "gke-node"
		}
	}
	return s.Ingest(ctx, id, b)
}
