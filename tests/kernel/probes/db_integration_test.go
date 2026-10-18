//go:build integration

package probes

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// insert mirrors the audit.kernel_events column split of TASK-07 3.3 for the
// fixture rows; it is test setup, not the TASK-07 ingest path.
const insert = `
INSERT INTO audit.kernel_events (source_event_id, source_id, sensor_id, source_epoch, source_sequence, exporter_instance_id, sensor_generation, node_uid, boot_id, source_time, spooled_at, received_at, event_type, process_exec_id, parent_exec_id, process_start, host_pid, container_id, docker_id_prefix, pod_uid, netns_inode, saddr, sport, daddr, dport, sock_ptr, tcp_new_state, lifecycle_record_id, metadata_status, normalization_version, upstream_event_ref, rule_hash, coverage, safe_attributes, record_digest)
SELECT (r->>'source_event_id')::uuid, r->>'sensor_id', r->>'sensor_id', r->>'source_epoch', (r->>'source_sequence')::bigint, r->>'exporter_instance_id', (r->>'sensor_generation')::bigint, (r->>'node_uid')::uuid, r->>'boot_id', (r->>'source_time')::timestamptz, (r->>'spooled_at')::timestamptz, now(), r->>'event_type', r->>'process_exec_id', r->>'parent_exec_id', (r->>'process_start')::timestamptz, (r->>'host_pid')::int, r->>'container_id', r->>'docker_id_prefix', (r->>'pod_uid')::uuid, (r->>'netns_inode')::bigint,
  (r->'socket_tuple'->>'saddr')::inet, (r->'socket_tuple'->>'sport')::int, (r->'socket_tuple'->>'daddr')::inet, (r->'socket_tuple'->>'dport')::int, r->>'sock_ptr', (r->>'tcp_new_state')::smallint, (r->>'lifecycle_record_id')::uuid, r->>'metadata_status', r->>'normalization_version', r->>'upstream_event_ref', r->>'rule_hash', r->>'coverage', r->'safe_attributes', r->>'record_digest'
FROM (SELECT $1::jsonb AS r) x`

func TestStoredKernelEventsQueryAgainstPostgres(t *testing.T) {
	admin := os.Getenv("KERNEL_PROBES_TEST_ADMIN_DSN")
	if admin == "" {
		t.Fatal("KERNEL_PROBES_TEST_ADMIN_DSN is required (tests/kernel/probes/run-local.sh)")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	db := fmt.Sprintf("kernel_probes_%d", time.Now().UnixNano())
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	cfg, _ := pgx.ParseConfig(admin)
	cfg.Database = db
	conn, err = pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Every migration that defines audit.kernel_events on main, in order.
	for _, m := range []string{"20261016132230_audit_store", "20261017103710_audit_kernel_wire", "20261017113838_audit_kernel_tcp_state"} {
		sql, err := os.ReadFile(filepath.Join("..", "..", "..", "migrations", m+".up.sql"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
	}
	events := q0Events(t)
	for _, line := range bytes.Split(bytes.TrimSpace(events), []byte("\n")) {
		if _, err := conn.Exec(ctx, insert, string(line)); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	walEvents, err := ReadEvents(bytes.NewReader(events), true)
	if err != nil {
		t.Fatal(err)
	}
	from, to := walEvents[0].SourceTime.Add(-time.Hour), walEvents[len(walEvents)-1].SourceTime.Add(time.Hour)
	stored, err := QueryEvents(ctx, conn, fixtureNod, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 245 {
		t.Fatalf("stored rows %d", len(stored))
	}
	if other, err := QueryEvents(ctx, conn, "00000000-0000-4000-8000-000000000000", from, to); err != nil || len(other) != 0 {
		t.Fatalf("node filter: %d %v", len(other), err)
	}
	// Stored rows alone satisfy the same cases as the WAL records.
	rep := evaluateEvents(t, stored)
	if !rep.Passed() {
		t.Fatalf("stored rows: %+v", rep.Cases)
	}
	merged, conflicts := Merge(walEvents, stored)
	if len(merged) != 245 || len(conflicts) != 0 {
		t.Fatalf("merge %d %v", len(merged), conflicts)
	}
	if _, err := conn.Exec(ctx, "UPDATE audit.kernel_events SET record_digest = repeat('0', 64) WHERE event_type = 'process_exec'"); err != nil {
		t.Fatal(err)
	}
	stored, _ = QueryEvents(ctx, conn, fixtureNod, from, to)
	if _, conflicts := Merge(walEvents, stored); len(conflicts) != 31 {
		t.Fatalf("digest divergence must be reported for every exec row, got %d", len(conflicts))
	}
}

func evaluateEvents(t *testing.T, events []Event) Report {
	sf, err := os.Open(q0Run + "run3-stimuli.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	stimuli, err := ReadStimuli(sf)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Evaluate(Input{Stimuli: stimuli, Events: events, PodUID: q0PodUID})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}
