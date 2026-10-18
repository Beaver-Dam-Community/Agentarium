//go:build integration

package receiver

import (
	"context"
	"crypto/x509"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestReceiverPostgres binds the shared collector SAN to its node and boot
// through the installed identity.audit_source_certificate function with only
// the correlation_writer grants of the migrations.
func TestReceiverPostgres(t *testing.T) {
	dsn := os.Getenv("NETPOL_TEST_DSN")
	if dsn == "" {
		t.Skip("set disposable NETPOL_TEST_DSN")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	dbName, writer := "receiver_"+suffix, "receiver_writer_"+suffix
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
	// Rollback must not revoke a schema privilege shared with pod_workloads.
	down, err := os.ReadFile("../../../../migrations/20261018102000_correlation_netpol_receiver.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	run(db, string(down))
	var usage bool
	if err := db.QueryRow(ctx, `SELECT has_schema_privilege('correlation_writer','identity','USAGE')`).Scan(&usage); err != nil || !usage {
		t.Fatalf("shared schema USAGE revoked: %v %v", usage, err)
	}
	up, err := os.ReadFile("../../../../migrations/20261018102000_correlation_netpol_receiver.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	run(db, string(up))
	source := "correlation-receiver-" + suffix
	run(db, "GRANT correlation_writer, audit_producer TO "+writer)
	run(db, `INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,$2,false)`, writer, source)
	run(db, `INSERT INTO audit.producer_event_grants(source_id,event_type,tenant) VALUES($1,'observation_gap_recorded','*'),($1,'sequence_range_abandoned','*'),($1,'evidence_gap_resolved','*')`, source)
	run(db, `INSERT INTO identity.registered_workloads(namespace,ksa,role,service_principal,enabled) VALUES('agent-sensors','netpol-collector','service','netpol-collector',true) ON CONFLICT DO NOTHING`)
	node := uuid.New()
	run(db, `INSERT INTO identity.issued_certificates(serial,san_uri,namespace,ksa,node_uid,boot_id,issued_at,expires_at) VALUES
		('0f',$1,'agent-sensors','netpol-collector',$2,'boot-old',now()-interval '3 hours',now()-interval '2 hours'),
		('1a2b',$1,'agent-sensors','netpol-collector',$2,'boot-a',now()-interval '1 hour',now()+interval '1 hour')`, netpol.CollectorSAN, node)

	pc, _ := pgxpool.ParseConfig(dsn)
	pc.ConnConfig.Database, pc.ConnConfig.User = dbName, writer
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var denied error
	_, denied = pool.Exec(ctx, `SELECT 1 FROM identity.issued_certificates LIMIT 1`)
	if denied == nil || !strings.Contains(denied.Error(), "permission denied") {
		t.Fatalf("correlation_writer can read identity base tables: %v", denied)
	}
	h := Handler{ClusterUID: cluster, Identity: PoolIdentity{Pool: pool}, Store: netpol.Store{Pool: pool, Config: netpol.Config{SourceID: source, Version: "test", Epoch: "1"}}}
	cert := &x509.Certificate{URIs: leaf(netpol.CollectorSAN).URIs, SerialNumber: big.NewInt(0x1a2b)}
	batch := func(epoch string, seq int64) []byte {
		id, _ := canonical.NetworkPolicyRecordID(cluster.String(), node.String(), epoch, seq)
		r := record(t, epoch, seq, func(r map[string]any) { r["node_uid"] = node.String(); r["record_id"] = id })
		return body(t, map[string]any{"batch_id": uuid.NewString(), "source_epoch": epoch, "records": []any{r}, "sequence_range_abandoned": []any{}})
	}
	count := func() int {
		var n int
		if err := db.QueryRow(ctx, `SELECT count(*) FROM correlation.network_policy_records WHERE node_uid=$1`, node).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	current := epochFor(node, "boot-a")
	w, resp := post(h, batch(current, 1), cert)
	want, _ := canonical.NetworkPolicyRecordID(cluster.String(), node.String(), current, 1)
	if w.Code != http.StatusOK || len(resp.AcceptedIDs) != 1 || resp.AcceptedIDs[0] != want || resp.Watermarks[0].AckedThrough != 1 {
		t.Fatalf("current boot %d %s", w.Code, w.Body)
	}
	// The expired prior certificate cannot authenticate, but its retained boot
	// lets the current certificate replay that boot's epoch.
	if w, _ := post(h, batch(epochFor(node, "boot-old"), 1), cert); w.Code != http.StatusOK || count() != 2 {
		t.Fatalf("prior boot replay %d %s", w.Code, w.Body)
	}
	// Loss declarations from an accepted historical epoch retain that boot,
	// even though authentication uses the currently valid certificate.
	oldEpoch := epochFor(node, "boot-old")
	digest, _ := canonical.AbandonedRangeDigest(netpol.CollectorSAN, "network_policy", oldEpoch, 2, 2, "record_rejected")
	raw := body(t, map[string]any{"batch_id": uuid.NewString(), "source_epoch": oldEpoch, "records": []any{},
		"sequence_range_abandoned": []any{map[string]any{"from_seq": 2, "to_seq": 2, "reason": "record_rejected", "range_digest": digest}},
		"rotation_loss":            map[string]any{"after_sequence": 2, "detected_at": time.Now().UTC().Format(time.RFC3339Nano)}})
	if w, _ := post(h, raw, cert); w.Code != http.StatusOK {
		t.Fatalf("historical gap %d %s", w.Code, w.Body)
	}
	var gaps int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM health.observation_gaps WHERE node_uid=$1 AND boot_id='boot-old' AND reason IN ('SEQUENCE_RANGE_ABANDONED','NETPOL_FILE_ROTATION_LOSS')`, node).Scan(&gaps); err != nil || gaps != 2 {
		t.Fatalf("historical boot gaps %d %v", gaps, err)
	}
	if w, _ := post(h, batch(epochFor(node, "boot-never-issued"), 1), cert); w.Code != http.StatusForbidden || count() != 2 {
		t.Fatalf("unissued boot %d", w.Code)
	}
	old := &x509.Certificate{URIs: cert.URIs, SerialNumber: big.NewInt(0x0f)}
	if w, _ := post(h, batch(current, 2), old); w.Code != http.StatusForbidden || count() != 2 {
		t.Fatalf("expired certificate %d", w.Code)
	}
	run(db, `UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='1a2b'`)
	if w, _ := post(h, batch(current, 2), cert); w.Code != http.StatusForbidden || count() != 2 {
		t.Fatalf("revoked certificate %d", w.Code)
	}
}
