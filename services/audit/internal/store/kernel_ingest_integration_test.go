//go:build integration

package store

// Kernel batch ingest (TASK-07 3.3, COMMON "Kernel source authentication and epoch", #92)
// on PostgreSQL 16 with every merged migration and a restricted writer login.
// The SQL function is the authoritative receiver; the HTTP part drives it with
// the TASK-09 producer libraries (wal, delivery, batch) over real mTLS.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/delivery"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const tetragonSAN = ingest.KernelSourceSAN

type kernelEnv struct {
	t        *testing.T
	ctx      context.Context
	fixture  *pgx.Conn
	writer   *pgx.Conn
	cfg      *pgx.ConnConfig
	login    string
	node     string
	receiver string
}

func installKernelDB(t *testing.T) *kernelEnv {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_ADMIN_DSN for disposable PostgreSQL")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	roles := func() map[string]bool {
		rows, err := admin.Query(ctx, "SELECT rolname FROM pg_roles")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[string]bool{}
		for rows.Next() {
			var r string
			_ = rows.Scan(&r)
			out[r] = true
		}
		return out
	}
	existing := roles()
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	name := "kernel_" + suffix
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = name
	db, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		db.Close(ctx)
		_, _ = admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		var added []string
		for r := range roles() {
			if !existing[r] {
				added = append(added, r)
			}
		}
		sort.Strings(added)
		for _, r := range added {
			if _, err := admin.Exec(ctx, "DROP ROLE "+pgx.Identifier{r}.Sanitize()); err != nil {
				t.Errorf("drop role %s: %v", r, err)
			}
		}
	})
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, q, args...); err != nil {
			t.Fatalf("SQL: %v\n%s", err, q)
		}
	}
	exec("DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $$")
	files, _ := filepath.Glob("../../../../migrations/*.up.sql")
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
	}
	e := &kernelEnv{t: t, ctx: ctx, fixture: db, cfg: cfg, login: "kwriter_" + suffix, node: uuid.NewString(), receiver: "audit-writer-test"}
	exec("CREATE ROLE " + e.login + " LOGIN INHERIT NOSUPERUSER")
	exec("GRANT audit_writer TO " + e.login)
	exec("INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES ($1,$2,true)", e.login, e.receiver)
	exec("INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES ($1,'kernel_event_observed','*'),($2,'sequence_range_abandoned','*'),($2,'observation_gap_recorded','*')", tetragonSAN, e.receiver)
	exec("GRANT SELECT (namespace,ksa,role,service_principal,enabled) ON identity.registered_workloads TO audit_writer")
	exec("INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal) VALUES ('agent-sensors','tetragon','service','tetragon'),('agent-sensors','lifecycle-recorder','service','lifecycle-recorder')")
	foreign := uuid.NewString()
	exec(`INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at,revoked_at) VALUES
 ('0a',$1,'agent-sensors','tetragon',$2,'boot-current',now()-interval '1 minute',now()+interval '1 hour',NULL),
 ('0b',$1,'agent-sensors','tetragon',$2,'boot-old',now()-interval '2 days',now()-interval '1 day',NULL),
 ('0c',$1,'agent-sensors','tetragon',$3,'boot-foreign',now()-interval '1 minute',now()+interval '1 hour',NULL),
 ('0d','spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder','agent-sensors','lifecycle-recorder',$2,'boot-current',now()-interval '1 minute',now()+interval '1 hour',NULL)`, tetragonSAN, e.node, foreign)
	exec(`INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,startup_capture_measurement,state,updated_at) VALUES ($1,'boot-current','unsupported','not_measured','held',now())`, e.node)
	wcfg := cfg.Copy()
	wcfg.User = e.login
	if e.writer, err = pgx.ConnectConfig(ctx, wcfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.writer.Close(context.Background()) })
	return e
}

func (e *kernelEnv) epoch(boot string) string {
	h := sha256.Sum256([]byte(boot))
	return strings.ReplaceAll(e.node, "-", "") + hex.EncodeToString(h[:]) + strings.ReplaceAll(uuid.NewString(), "-", "")
}

// record builds a COMMON KernelEvent with canonical ID and record digest.
func (e *kernelEnv) record(ep string, seq int64, boot string, mutate func(map[string]any)) map[string]any {
	id, err := canonical.KernelEventID(tetragonSAN, ep, seq)
	if err != nil {
		e.t.Fatal(err)
	}
	r := map[string]any{"source_event_id": id, "sensor_id": tetragonSAN, "source_epoch": ep, "source_sequence": seq, "exporter_instance_id": "instance-1",
		"sensor_generation": 3, "node_uid": e.node, "boot_id": boot, "source_time": "2026-10-17T01:02:03.000004Z", "spooled_at": "2026-10-17T01:02:04Z",
		"process_exec_id": "exec-" + id[:8], "parent_exec_id": nil, "process_start": "2026-10-17T01:00:00Z", "host_pid": 4242, "container_id": "c1",
		"pod_uid": uuid.NewString(), "netns_inode": 4026531992, "socket_tuple": map[string]any{"saddr": "10.0.0.5", "sport": 41000, "daddr": "10.1.2.3", "dport": 443},
		"sock_ptr": "ffff8a0012345678", "tcp_new_state": nil, "metadata_status": "resolved", "normalization_version": "n1", "event_type": "tcp_connect",
		"safe_attributes": map[string]any{"binary": "/usr/bin/curl"}, "rule_hash": strings.Repeat("ab", 32), "coverage": "complete"}
	if mutate != nil {
		mutate(r)
	}
	return seal(e.t, r)
}

func seal(t *testing.T, r map[string]any) map[string]any {
	delete(r, "record_digest")
	d, err := canonical.CanonicalDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	r["record_digest"] = d
	return r
}

func kernelBatch(t *testing.T, ep string, records []any, ranges []any) []byte {
	t.Helper()
	b := map[string]any{"batch_id": uuid.NewString(), "source_epoch": ep, "records": records, "sequence_range_abandoned": ranges}
	d, err := canonical.CanonicalDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	b["batch_digest"] = d
	raw, _ := json.Marshal(b)
	return raw
}

func (e *kernelEnv) call(c *pgx.Conn, source, serial string, raw []byte) (map[string]any, error) {
	var out []byte
	if err := c.QueryRow(e.ctx, `SELECT audit.ingest_kernel_batch($1,$2,$3,$1,'writer-v1','writer-epoch-1')`, source, raw, serial).Scan(&out); err != nil {
		return nil, err
	}
	var a map[string]any
	return a, json.Unmarshal(out, &a)
}

func (e *kernelEnv) must(raw []byte) map[string]any {
	e.t.Helper()
	a, err := e.call(e.writer, tetragonSAN, "0a", raw)
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *kernelEnv) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.fixture.QueryRow(e.ctx, q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func through(a map[string]any) float64 {
	return a["watermarks"].([]any)[0].(map[string]any)["acked_through"].(float64)
}
func ids(a map[string]any, key string) int { return len(a[key].([]any)) }
func reason(a map[string]any, i int) string {
	return a["rejected"].([]any)[i].(map[string]any)["reason_codes"].([]any)[0].(string)
}
func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != code {
		t.Fatalf("want SQLSTATE %s: %v", code, err)
	}
}

func rangeEntry(t *testing.T, ep string, from, to int64, why string) map[string]any {
	d, err := canonical.AbandonedRangeDigest(tetragonSAN, "kernel", ep, from, to, why)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"from_seq": from, "to_seq": to, "reason": why, "range_digest": d}
}

func TestKernelIngestSQLPostgres(t *testing.T) {
	e := installKernelDB(t)
	ep := e.epoch("boot-current")
	r2 := e.record(ep, 2, "boot-current", nil)
	b2 := kernelBatch(t, ep, []any{r2}, []any{})

	t.Run("out of order, retry and contiguous watermark", func(t *testing.T) {
		a := e.must(b2)
		if through(a) != 0 || ids(a, "accepted_ids") != 1 {
			t.Fatalf("out of order: %v", a)
		}
		if a = e.must(b2); ids(a, "duplicate_ids") != 1 || through(a) != 0 {
			t.Fatalf("retry: %v", a)
		}
		if a = e.must(kernelBatch(t, ep, []any{e.record(ep, 1, "boot-current", nil)}, []any{})); through(a) != 2 {
			t.Fatalf("contiguous: %v", a)
		}
		if e.count(`SELECT count(*) FROM audit.audit_outbox WHERE record_kind='kernel_event' AND source_class='kernel'`) != 2 ||
			e.count(`SELECT count(*) FROM audit.kernel_events WHERE source_id=$1 AND saddr='10.0.0.5' AND dport=443 AND sock_ptr='ffff8a0012345678'`, tetragonSAN) != 2 {
			t.Fatal("stored rows or outbox missing")
		}
	})
	t.Run("different digest is an atomic conflict incident", func(t *testing.T) {
		changed := e.record(ep, 2, "boot-current", func(r map[string]any) { r["container_id"] = "changed" })
		changed["source_event_id"], changed["pod_uid"] = r2["source_event_id"], r2["pod_uid"]
		seal(t, changed)
		a := e.must(kernelBatch(t, ep, []any{changed}, []any{}))
		if reason(a, 0) != "EVENT_ID_CONFLICT" || e.count(`SELECT count(*) FROM audit.event_conflicts WHERE record_kind='kernel_event' AND record_id=$1`, r2["source_event_id"]) != 1 ||
			e.count(`SELECT count(*) FROM audit.kernel_events WHERE source_event_id=$1 AND container_id='c1'`, r2["source_event_id"]) != 1 {
			t.Fatalf("conflict: %v", a)
		}
	})
	t.Run("partial rejection does not pollute max_seen", func(t *testing.T) {
		bad := e.record(ep, 99, "boot-current", nil)
		bad["record_digest"] = strings.Repeat("0", 64)
		a := e.must(kernelBatch(t, ep, []any{bad, e.record(ep, 4, "boot-current", nil)}, []any{}))
		if through(a) != 2 || ids(a, "rejected") != 1 || reason(a, 0) != "SCHEMA_INVALID" || ids(a, "accepted_ids") != 1 {
			t.Fatalf("partial: %v", a)
		}
		if e.count(`SELECT max_seen FROM audit.ingest_watermarks WHERE stream='kernel' AND source_epoch=$1`, ep) != 4 {
			t.Fatal("rejected sequence raised max_seen")
		}
	})
	gap := kernelBatch(t, ep, []any{}, []any{rangeEntry(t, ep, 3, 3, "wal_segment_corrupt")})
	t.Run("abandoned range writes gap, two receiver audits and outboxes", func(t *testing.T) {
		if a := e.must(gap); through(a) != 4 || ids(a, "accepted_ids") != 1 {
			t.Fatalf("gap: %v", a)
		}
		if e.count(`SELECT count(*) FROM health.observation_gaps WHERE stage='kernel_sensor_export' AND reason='SEQUENCE_RANGE_ABANDONED' AND source_epoch=$1 AND node_uid=$2 AND boot_id='boot-current' AND loss_count=1 AND recovery_state='unrecoverable'`, ep, e.node) != 1 {
			t.Fatal("gap row")
		}
		if e.count(`SELECT count(*) FROM audit.audit_events a JOIN audit.abandoned_ranges r ON a.event_id IN (r.sequence_event_id,r.gap_event_id)
			WHERE r.stream='kernel' AND r.source_epoch=$1 AND a.source_id=$2 AND a.tenant='*' AND a.source_sequence IS NULL AND a.source_version='writer-v1'
			AND a.source_epoch='writer-epoch-1' AND a.authenticated_actor='service:agent-sensors/tetragon'`, ep, e.receiver) != 2 ||
			e.count(`SELECT count(*) FROM audit.audit_outbox o JOIN audit.audit_events a ON o.record_id=a.event_id::text WHERE a.event_type IN ('sequence_range_abandoned','observation_gap_recorded')`) != 2 {
			t.Fatal("receiver audits/outboxes")
		}
	})
	t.Run("same-range retry, different body and overlaps", func(t *testing.T) {
		if a := e.must(gap); ids(a, "duplicate_ids") != 1 || e.count(`SELECT count(*) FROM health.observation_gaps`) != 1 {
			t.Fatalf("range retry: %v", a)
		}
		for name, raw := range map[string][]byte{
			"different reason": kernelBatch(t, ep, []any{}, []any{rangeEntry(t, ep, 3, 3, "record_rejected")}),
			"overlap":          kernelBatch(t, ep, []any{}, []any{rangeEntry(t, ep, 5, 6, "wal_segment_corrupt"), rangeEntry(t, ep, 6, 8, "wal_segment_corrupt")}),
			"record inside":    kernelBatch(t, ep, []any{e.record(ep, 3, "boot-current", nil)}, []any{}),
			"below watermark":  kernelBatch(t, ep, []any{}, []any{rangeEntry(t, ep, 1, 1, "wal_segment_corrupt")}),
		} {
			a := e.must(raw)
			if ids(a, "rejected") < 1 || reason(a, ids(a, "rejected")-1) != "EVENT_ID_CONFLICT" {
				t.Fatalf("%s: %v", name, a)
			}
		}
		if e.count(`SELECT count(*) FROM audit.event_conflicts WHERE record_kind='kernel_event'`) != 1 {
			t.Fatal("range conflict created a record incident without an original record")
		}
	})
	t.Run("second audit failure rolls back everything", func(t *testing.T) {
		rb := e.epoch("boot-current")
		raw := kernelBatch(t, rb, []any{e.record(rb, 1, "boot-current", nil)}, []any{rangeEntry(t, rb, 2, 2, "wal_segment_corrupt")})
		gaps, events := e.count(`SELECT count(*) FROM health.observation_gaps`), e.count(`SELECT count(*) FROM audit.audit_events`)
		if _, err := e.fixture.Exec(e.ctx, `DELETE FROM audit.producer_event_grants WHERE source_id=$1 AND event_type='observation_gap_recorded'`, e.receiver); err != nil {
			t.Fatal(err)
		}
		_, err := e.call(e.writer, tetragonSAN, "0a", raw)
		wantCode(t, err, "42501")
		if e.count(`SELECT count(*) FROM audit.kernel_events WHERE source_epoch=$1`, rb) != 0 || e.count(`SELECT count(*) FROM audit.ingest_watermarks WHERE source_epoch=$1`, rb) != 0 ||
			e.count(`SELECT count(*) FROM health.observation_gaps`) != gaps || e.count(`SELECT count(*) FROM audit.audit_events`) != events ||
			e.count(`SELECT count(*) FROM audit.abandoned_ranges WHERE source_epoch=$1`, rb) != 0 || e.count(`SELECT count(*) FROM audit.audit_outbox WHERE record_id IN (SELECT source_event_id::text FROM audit.kernel_events WHERE source_epoch=$1)`, rb) != 0 {
			t.Fatal("failed second audit partially committed")
		}
		if _, err := e.fixture.Exec(e.ctx, `INSERT INTO audit.producer_event_grants VALUES ($1,'observation_gap_recorded','*')`, e.receiver); err != nil {
			t.Fatal(err)
		}
		if a := e.must(raw); through(a) != 2 {
			t.Fatalf("after restore: %v", a)
		}
	})
	t.Run("provenance from the verified leaf and binding", func(t *testing.T) {
		wrongBoot := e.record(ep, 5, "boot-old", nil)
		if a := e.must(kernelBatch(t, ep, []any{wrongBoot}, []any{})); reason(a, 0) != "SCHEMA_INVALID" {
			t.Fatalf("record boot differs from binding: %v", a)
		}
		old := e.epoch("boot-old") // retained prior issuance evidence (0b) proves the historical boot
		if a := e.must(kernelBatch(t, old, []any{e.record(old, 1, "boot-old", nil)}, []any{})); through(a) != 1 {
			t.Fatalf("historical replay: %v", a)
		}
		for name, c := range map[string]struct {
			source, serial string
			raw            []byte
		}{
			"unissued boot":       {tetragonSAN, "0a", kernelBatch(t, e.epoch("never-issued"), []any{}, []any{})},
			"expired certificate": {tetragonSAN, "0b", b2},
			"other node cert":     {tetragonSAN, "0c", b2},
			"lifecycle source":    {"spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder", "0d", b2},
		} {
			if _, err := e.call(e.writer, c.source, c.serial, c.raw); err == nil {
				t.Fatalf("%s accepted", name)
			} else {
				wantCode(t, err, "42501")
			}
		}
		if _, err := e.fixture.Exec(e.ctx, `UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1`, e.node); err != nil {
			t.Fatal(err)
		}
		_, err := e.call(e.writer, tetragonSAN, "0a", b2)
		wantCode(t, err, "42501")
		_, _ = e.fixture.Exec(e.ctx, `UPDATE health.node_boot_generation SET state='held' WHERE node_uid=$1`, e.node)
		// Only audit_writer members can execute; no base-table access.
		for _, q := range []string{"SELECT * FROM audit.kernel_events", "INSERT INTO audit.kernel_events(source_event_id) VALUES (gen_random_uuid())", "SELECT * FROM identity.issued_certificates"} {
			if _, err := e.writer.Exec(e.ctx, q); err == nil {
				t.Fatalf("writer base access: %s", q)
			}
		}
	})
	t.Run("event-type field rules", func(t *testing.T) {
		te := e.epoch("boot-current")
		cases := []struct {
			name   string
			mutate func(map[string]any)
			ok     bool
		}{
			{"tcp_state without process", func(r map[string]any) {
				r["event_type"], r["process_exec_id"], r["tcp_new_state"], r["metadata_status"] = "tcp_state", nil, 7, "tuple_scoped"
			}, true},
			{"tcp_state without state", func(r map[string]any) { r["event_type"], r["process_exec_id"] = "tcp_state", nil }, false},
			{"tcp_state other state", func(r map[string]any) { r["event_type"], r["tcp_new_state"] = "tcp_state", 2 }, false},
			{"exec without process", func(r map[string]any) { r["event_type"], r["process_exec_id"] = "process_exec", nil }, false},
			{"connect with state", func(r map[string]any) { r["tcp_new_state"] = 1 }, false},
			{"unknown type", func(r map[string]any) { r["event_type"] = "kprobe" }, false},
			{"prefix address", func(r map[string]any) { r["socket_tuple"].(map[string]any)["saddr"] = "10.0.0.0/8" }, false},
			{"port range", func(r map[string]any) { r["socket_tuple"].(map[string]any)["dport"] = 70000 }, false},
			{"pointer case", func(r map[string]any) { r["sock_ptr"] = "FFFF8A0012345678" }, false},
			{"zero pid", func(r map[string]any) { r["host_pid"] = 0 }, false},
			{"received_at supplied", func(r map[string]any) { r["received_at"] = "2026-10-17T00:00:00Z" }, false},
			{"source_id supplied", func(r map[string]any) { r["source_id"] = tetragonSAN }, false},
			{"bad time", func(r map[string]any) { r["source_time"] = "yesterday" }, false},
			{"wrong sensor", func(r map[string]any) { r["sensor_id"] = "spiffe://agentarium.internal/ns/agent-sensors/sa/other" }, false},
			{"ipv6 tuple", func(r map[string]any) { r["socket_tuple"] = map[string]any{"saddr": "fd00::5", "sport": 1, "daddr": "fd00::6", "dport": 2} }, true},
			{"no tuple", func(r map[string]any) { r["socket_tuple"], r["sock_ptr"] = nil, nil }, true},
		}
		for i, c := range cases {
			r := e.record(te, int64(i+1), "boot-current", c.mutate)
			raw, _ := json.Marshal(r)
			_, goErr := ingest.DecodeKernelRecord(raw, tetragonSAN, te)
			a := e.must(kernelBatch(t, te, []any{r}, []any{}))
			sqlOK := ids(a, "accepted_ids") == 1
			if sqlOK != c.ok || (goErr == nil) != c.ok {
				t.Fatalf("%s: SQL accepted=%v Go err=%v want ok=%v (%v)", c.name, sqlOK, goErr, c.ok, a)
			}
		}
	})
	t.Run("concurrent identical requests store exactly once", func(t *testing.T) {
		ce := e.epoch("boot-current")
		records := []any{}
		for i := int64(1); i <= 20; i++ {
			records = append(records, e.record(ce, i, "boot-current", nil))
		}
		raw := kernelBatch(t, ce, records, []any{rangeEntry(t, ce, 21, 25, "wal_segment_corrupt")})
		pool, err := pgxpool.New(e.ctx, (&url.URL{Scheme: "postgres", User: url.User(e.login), Host: e.cfg.Host + ":" + itoa(int(e.cfg.Port)), Path: "/" + e.cfg.Database, RawQuery: "sslmode=disable"}).String())
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		var wg sync.WaitGroup
		var mu sync.Mutex
		succeeded, busy := 0, 0
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var out []byte
				err := pool.QueryRow(e.ctx, `SELECT audit.ingest_kernel_batch($1,$2,'0a',$1,'writer-v1','writer-epoch-1')`, tetragonSAN, raw).Scan(&out)
				mu.Lock()
				defer mu.Unlock()
				var pe *pgconn.PgError
				switch {
				case err == nil:
					succeeded++
				case errors.As(err, &pe) && pe.Code == "55P03":
					busy++
				default:
					t.Errorf("concurrent request: %v", err)
				}
			}()
		}
		wg.Wait()
		if succeeded < 1 || succeeded+busy != 8 {
			t.Fatalf("succeeded=%d busy=%d", succeeded, busy)
		}
		if e.count(`SELECT count(*) FROM audit.kernel_events WHERE source_epoch=$1`, ce) != 20 || e.count(`SELECT count(*) FROM audit.abandoned_ranges WHERE source_epoch=$1`, ce) != 1 ||
			e.count(`SELECT count(*) FROM health.observation_gaps WHERE source_epoch=$1`, ce) != 1 || e.count(`SELECT acked_through FROM audit.ingest_watermarks WHERE source_epoch=$1`, ce) != 25 {
			t.Fatal("concurrent requests duplicated or lost writes")
		}
		if a := e.must(raw); ids(a, "duplicate_ids") != 21 || through(a) != 25 {
			t.Fatalf("retry after concurrency: %v", a)
		}
	})
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// The TASK-09 producer libraries drive the real handler over mTLS: WAL append,
// delivery pump, batch client acknowledgement validation and WAL ack.
func TestKernelIngestWithSensorProducer(t *testing.T) {
	e := installKernelDB(t)
	ctx := e.ctx
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kernel test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(san string, serial int64, usage x509.ExtKeyUsage) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse(san)
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		leaf, _ := x509.ParseCertificate(der)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	}
	serverCert := issue("spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer", 2, x509.ExtKeyUsageServerAuth)
	clientCert := issue(tetragonSAN, 0x0a, x509.ExtKeyUsageClientAuth) // matches issued_certificates serial 0a
	pool, err := pgxpool.New(ctx, (&url.URL{Scheme: "postgres", User: url.User(e.login), Host: e.cfg.Host + ":" + itoa(int(e.cfg.Port)), Path: "/" + e.cfg.Database, RawQuery: "sslmode=disable"}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	auth, err := NewAuthorizer(pool, []SourceBinding{{SourceID: tetragonSAN, Namespace: "agent-sensors", KSA: "tetragon", Principal: "tetragon"}})
	if err != nil {
		t.Fatal(err)
	}
	cidrs := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if err := auth.ValidateKernelConfiguration(cidrs); err != nil {
		t.Fatal(err)
	}
	s := Store{Pool: pool, WriterVersion: "writer-v1", WriterEpoch: "writer-epoch-1"}
	server := httptest.NewUnstartedServer(ingest.KernelHandler{Identity: auth, Validator: auth, Store: s, NodeCIDRs: cidrs})
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client, err := batch.NewClient(server.URL, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ep := e.epoch("boot-current")
	spool := filepath.Join(t.TempDir(), "spool")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := wal.Open(spool, ep, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	appendRecord := func(corrupt bool) {
		t.Helper()
		_, err := journal.Append(func(epoch string, seq uint64) ([]byte, error) {
			r := e.record(epoch, int64(seq), "boot-current", nil)
			if corrupt {
				r["host_pid"] = -1 // schema-invalid at the receiver; producer quarantines it
				seal(t, r)
			}
			return canonical.JCS(mustJSON(t, r))
		}, wal.Checkpoint{Inode: 1, Offset: int64(1000 + time.Now().Nanosecond()%1000)})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		appendRecord(false)
	}
	pump, err := delivery.New(delivery.Config{Journal: journal, Client: client, SourceID: tetragonSAN, Stream: batch.Kernel, RecoveryReason: "wal_segment_corrupt"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := pump.Flush(ctx)
	if err != nil || res.Acked != 5 {
		t.Fatalf("first flush: %+v %v", res, err)
	}
	if pending, _ := journal.Pending(); len(pending) != 0 {
		t.Fatalf("WAL not acknowledged: %d", len(pending))
	}
	// A receiver SCHEMA_INVALID rejection is quarantined by the producer and
	// declared as an abandoned range, which the receiver turns into a gap with
	// two audits; the producer's watermark then passes the rejected sequence.
	appendRecord(true)
	appendRecord(false)
	for i := 0; i < 4; i++ {
		if res, err = pump.Flush(ctx); err != nil {
			t.Fatalf("flush %d: %+v %v", i, res, err)
		}
		if pending, _ := journal.Pending(); len(pending) == 0 {
			break
		}
	}
	if pending, _ := journal.Pending(); len(pending) != 0 {
		t.Fatalf("rejected record not resolved: %d pending", len(pending))
	}
	if e.count(`SELECT acked_through FROM audit.ingest_watermarks WHERE stream='kernel' AND source_epoch=$1`, ep) != 7 ||
		e.count(`SELECT count(*) FROM audit.kernel_events WHERE source_epoch=$1`, ep) != 6 ||
		e.count(`SELECT count(*) FROM audit.abandoned_ranges WHERE stream='kernel' AND source_epoch=$1 AND from_seq=6 AND to_seq=6`, ep) != 1 ||
		e.count(`SELECT count(*) FROM health.observation_gaps WHERE source_epoch=$1 AND stage='kernel_sensor_export'`, ep) != 1 {
		t.Fatal("producer/receiver state differs")
	}
	// Transport identity: other SANs and non-node addresses are refused.
	other, _ := batch.NewClient(server.URL, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{issue("spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder", 0x0d, x509.ExtKeyUsageClientAuth)}})
	b, err := batch.New(batch.Input{Stream: batch.Kernel, SourceID: tetragonSAN, Epoch: ep, BatchID: uuid.NewString(), PreviousAck: 7, Records: []json.RawMessage{mustJSON(t, e.record(ep, 8, "boot-current", nil))}})
	if err != nil {
		t.Fatal(err)
	}
	var httpErr *batch.HTTPError
	if _, err := other.Send(ctx, b); !errors.As(err, &httpErr) || httpErr.Status != 403 {
		t.Fatalf("other SAN: %v", err)
	}
	if e.count(`SELECT count(*) FROM audit.kernel_events WHERE source_epoch=$1 AND source_sequence=8`, ep) != 0 {
		t.Fatal("refused caller stored a record")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
