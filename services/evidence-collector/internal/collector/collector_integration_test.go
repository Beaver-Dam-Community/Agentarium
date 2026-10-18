//go:build integration

package collector

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/feed"
	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	tenant      = "hackathon"
	auditSource = "evidence-collector-test"
	payloadMig  = "20261018092100_audit_destination_observed_payload"
	storeMig    = "20261018092101_evidence_collector_store"
)

type env struct {
	t                      *testing.T
	ctx                    context.Context
	admin, inspect, owner  *pgx.Conn
	pool                   *pgxpool.Pool
	dsn, db, login, prefix string
}

func (e *env) run(c *pgx.Conn, sql string, args ...any) {
	e.t.Helper()
	if _, err := c.Exec(e.ctx, sql, args...); err != nil {
		e.t.Fatalf("%.120s: %v", sql, err)
	}
}

func (e *env) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.inspect.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%.120s: %v", sql, err)
	}
	return n
}

func migration(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../../../migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// setup installs every migration as a non-superuser installer (TASK-16 step
// 2), checks up/down/up of this PR's two migrations, and connects a
// restricted collector login that is only an evidence_collector member.
func setup(t *testing.T) *env {
	dsn := os.Getenv("EVIDENCE_COLLECTOR_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("set disposable EVIDENCE_COLLECTOR_TEST_ADMIN_DSN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	e := &env{t: t, ctx: ctx, admin: admin, dsn: dsn, db: "evcol_" + suffix, login: "evcollogin_" + suffix, prefix: suffix}
	installer := "evcolinst_" + suffix
	e.run(admin, "CREATE ROLE "+installer+" LOGIN NOSUPERUSER NOCREATEDB CREATEROLE")
	e.run(admin, "CREATE ROLE "+e.login+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	e.run(admin, "CREATE DATABASE "+e.db+" OWNER "+installer)
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+e.db+" WITH (FORCE)")
	})
	e.owner = e.connect(installer)
	e.inspect = e.connect(admin.Config().User)
	for _, r := range []string{"control_health_writer", "gateway_app", "timeline_app", "broker_reader", "coordinator_app"} {
		e.run(e.owner, "DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='"+r+"') THEN CREATE ROLE "+r+" NOLOGIN; END IF; END $$")
	}
	files, err := filepath.Glob("../../../../migrations/*.up.sql")
	if err != nil || len(files) == 0 {
		t.Fatal("no migrations", err)
	}
	sort.Strings(files)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.owner.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("%s as non-superuser: %v", filepath.Base(f), err)
		}
	}
	e.checkDownUp(installer)
	// TASK-16 install inputs for the collector login.
	e.run(admin, "GRANT evidence_collector TO "+e.login)
	e.run(e.inspect, "INSERT INTO audit.db_role_sources(db_role,source_id,proxy) VALUES($1,$2,false)", e.login, auditSource)
	e.run(e.inspect, "INSERT INTO audit.producer_event_grants VALUES($1,'destination_observed',$2)", auditSource, tenant)
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	pc.ConnConfig.Database, pc.ConnConfig.User = e.db, e.login
	if e.pool, err = pgxpool.NewWithConfig(ctx, pc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.pool.Close)
	return e
}

func (e *env) connect(user string) *pgx.Conn {
	e.t.Helper()
	cfg, err := pgx.ParseConfig(e.dsn)
	if err != nil {
		e.t.Fatal(err)
	}
	cfg.Database, cfg.User = e.db, user
	c, err := pgx.ConnectConfig(e.ctx, cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

// checkDownUp applies down, down, up, up (and again) as the installer.
func (e *env) checkDownUp(installer string) {
	ownerGrants := func() string {
		var v string
		if err := e.admin.QueryRow(e.ctx, `SELECT coalesce(jsonb_agg(jsonb_build_array(r.rolname,m.admin_option,m.inherit_option,m.set_option) ORDER BY r.rolname, m.grantor)::text,'[]')
FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE m.member=$1::regrole AND r.rolname IN ('audit_owner','evidence_owner')`, installer).Scan(&v); err != nil {
			e.t.Fatal(err)
		}
		return v
	}
	required := func() string {
		var v string
		if err := e.inspect.QueryRow(e.ctx, "SELECT required_payload_fields::text FROM audit.event_types WHERE event_type='destination_observed'").Scan(&v); err != nil {
			e.t.Fatal(err)
		}
		return v
	}
	before := ownerGrants()
	if required() != `["action_id", "rule_id", "evidence_level"]` {
		e.t.Fatal("payload migration registry", required())
	}
	for i := 0; i < 2; i++ {
		e.run(e.owner, migration(e.t, storeMig+".down.sql"))
		e.run(e.owner, migration(e.t, payloadMig+".down.sql"))
		if e.count("SELECT count(*) FROM pg_namespace WHERE nspname='evidence'") != 0 ||
			e.count("SELECT count(*) FROM pg_trigger WHERE tgname='audit_events_destination_observed'") != 0 ||
			e.count("SELECT count(*) FROM pg_auth_members WHERE roleid='audit_producer'::regrole AND member='evidence_collector'::regrole") != 0 {
			e.t.Fatal("down left objects")
		}
		if required() != `["action_id", "action_key", "wire_body_digest", "bytes", "effect_count"]` {
			e.t.Fatal("down did not restore the audit_store registry", required())
		}
		if ownerGrants() != before {
			e.t.Fatal("down changed installer owner grants", ownerGrants(), before)
		}
		e.run(e.owner, migration(e.t, payloadMig+".up.sql"))
		e.run(e.owner, migration(e.t, storeMig+".up.sql"))
		if ownerGrants() != before {
			e.t.Fatal("up changed installer owner grants", ownerGrants(), before)
		}
	}
	// A pre-existing own membership without SET is preserved by up and down.
	e.run(e.owner, "GRANT audit_owner TO CURRENT_USER WITH INHERIT FALSE, SET FALSE")
	partial := ownerGrants()
	e.run(e.owner, migration(e.t, payloadMig+".down.sql"))
	e.run(e.owner, migration(e.t, payloadMig+".up.sql"))
	if ownerGrants() != partial {
		e.t.Fatal("existing partial owner membership changed")
	}
	e.run(e.owner, "REVOKE audit_owner FROM CURRENT_USER")
}

var fixtureSeq int

// event inserts a fixture feed row as the database administrator, as the
// adapter's audit_append would. received_at is in the past so that the
// settle window has passed.
func (e *env) event(eventType string, action uuid.UUID, attempt *uuid.UUID, payload any) uuid.UUID {
	e.t.Helper()
	fixtureSeq++
	id := uuid.New()
	raw, _ := json.Marshal(payload)
	e.run(e.inspect, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_time,received_at,schema_version,action_id,attempt_id,payload_digest,safe_payload)
VALUES($1,$2,$3,'adapter-fixture','v1','epoch',now(),now() - interval '1 hour' + make_interval(secs => $7),1,$4,$5,repeat('a',64),$6)`, id, eventType, tenant, action, attempt, raw, float64(fixtureSeq)/1000)
	return id
}

func (e *env) action(op string, targetID string) uuid.UUID {
	e.t.Helper()
	id := uuid.New()
	ct := `{"target_id":"` + targetID + `","route_id":"submissions-v1"}`
	e.run(e.inspect, `INSERT INTO decisions.actions(action_id,request_id,authenticated_actor,session_kind,session_id,client_request_key,raw_body_digest,tenant,environment,operation_id,canonical_target,created_at)
VALUES($1,$2,'service:fixture','service',$3,$4,repeat('a',64),$5,'test',$6,$7::jsonb,now())`, id, uuid.New(), uuid.New(), "req_"+id.String()[:8], tenant, op, ct)
	return id
}

// fakeReceipts answers Check from a per-action function.
type fakeReceipts struct {
	mu    sync.Mutex
	by    map[string]func(receipt.Expected) (receipt.Result, error)
	calls map[string][]receipt.Expected
}

func (f *fakeReceipts) set(action uuid.UUID, fn func(receipt.Expected) (receipt.Result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.by == nil {
		f.by, f.calls = map[string]func(receipt.Expected) (receipt.Result, error){}, map[string][]receipt.Expected{}
	}
	f.by[action.String()] = fn
}

func (f *fakeReceipts) Check(_ context.Context, want receipt.Expected) (receipt.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[want.ActionID] = append(f.calls[want.ActionID], want)
	fn := f.by[want.ActionID]
	if fn == nil {
		return receipt.Result{}, errors.New("no receipt fixture")
	}
	return fn(want)
}

func result(action uuid.UUID, rule string, effects, attempts int, outcome string) func(receipt.Expected) (receipt.Result, error) {
	r := fakeReceipt(action.String(), effects, attempts, outcome)
	return func(receipt.Expected) (receipt.Result, error) {
		return receipt.Result{RuleID: rule, EvidenceLevel: levelOf(rule), ReceiptDigest: strings.Repeat("c", 64), Receipt: r}, nil
	}
}

func (e *env) collector(r Receipts, settle time.Duration) *Collector {
	reader, err := feed.New(e.pool, tenant)
	if err != nil {
		e.t.Fatal(err)
	}
	return &Collector{Pool: e.pool, Feed: reader, Receipts: r,
		Cfg: Config{Tenant: tenant, Settle: settle, LateWindow: 10 * time.Minute, PageSize: 3,
			Audit: AuditConfig{SourceID: auditSource, Version: "test-v1", Epoch: "0123456789abcdef0123456789abcdef_1"}}}
}

type observed struct {
	revision      int
	rule, level   string
	digest        *string
	effects       *int
	eventID       string
	payload       map[string]any
	outbox, audit int
}

func (e *env) observations(action uuid.UUID) []observed {
	e.t.Helper()
	rows, err := e.inspect.Query(e.ctx, `SELECT o.revision,o.rule_id,o.evidence_level,o.receipt_digest,o.effect_count,o.event_id::text,a.safe_payload,
  (SELECT count(*) FROM audit.audit_outbox x WHERE x.record_kind='audit_event' AND x.record_id=o.event_id::text),
  (SELECT count(*) FROM audit.audit_events z WHERE z.event_id=o.event_id AND z.source_id=$2 AND z.action_id=o.action_id AND z.event_type='destination_observed')
FROM evidence.destination_observations o JOIN audit.audit_events a ON a.event_id=o.event_id WHERE o.action_id=$1 ORDER BY o.revision`, action, auditSource)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []observed
	for rows.Next() {
		var o observed
		var raw []byte
		if err := rows.Scan(&o.revision, &o.rule, &o.level, &o.digest, &o.effects, &o.eventID, &raw, &o.outbox, &o.audit); err != nil {
			e.t.Fatal(err)
		}
		_ = json.Unmarshal(raw, &o.payload)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) rules(action uuid.UUID) string {
	var s []string
	for _, o := range e.observations(action) {
		if o.outbox != 1 || o.audit != 1 {
			e.t.Fatalf("revision %d of %s has %d audit events and %d outbox rows", o.revision, action, o.audit, o.outbox)
		}
		s = append(s, o.rule)
	}
	return strings.Join(s, ",")
}

func pass(t *testing.T, c *Collector) {
	t.Helper()
	if err := c.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func digestOf(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestCollectorPostgres(t *testing.T) {
	e := setup(t)
	fr := &fakeReceipts{}
	c := e.collector(fr, 0)
	wire := digestOf([]byte("body"))
	pre := map[string]any{"action_id": "x", "decision_id": "x", "wire_body_digest": wire, "catalog_digest": wire}

	t.Run("runtime_boundary", func(t *testing.T) {
		var super, member bool
		if err := e.pool.QueryRow(e.ctx, "SELECT rolsuper OR rolcreaterole, pg_has_role(current_user,'evidence_owner','MEMBER') FROM pg_roles WHERE rolname=current_user").Scan(&super, &member); err != nil || super || member {
			t.Fatal("collector login privileged", err)
		}
		for _, q := range []string{"SELECT * FROM audit.audit_events", "DELETE FROM evidence.receipt_polls", "UPDATE evidence.destination_observations SET rule_id='R1'", "SET ROLE evidence_owner", "SET ROLE audit_owner"} {
			var pe *pgconn.PgError
			if _, err := e.pool.Exec(e.ctx, q); !errors.As(err, &pe) || pe.Code != "42501" {
				t.Fatalf("%s: %v", q, err)
			}
		}
	})

	// R4: a model call's response_received.
	model := e.action("model.generate", "model-primary")
	attM := uuid.New()
	e.event("preflight_passed", model, &attM, pre)
	e.event("dispatch_started", model, &attM, map[string]any{})
	e.event("response_received", model, &attM, map[string]any{})
	// R1: receiver.submit with one matching effect.
	r1 := e.action(ReceiverOperation, "receiver-primary")
	att1 := uuid.New()
	e.event("preflight_passed", r1, &att1, pre)
	e.event("response_received", r1, &att1, map[string]any{})
	fr.set(r1, result(r1, "R1", 1, 1, "effect_created"))
	// R2 with 65 effects, R3, R6.
	r2 := e.action(ReceiverOperation, "receiver-primary")
	e.event("preflight_passed", r2, &att1, pre)
	e.event("attempt_uncertain", r2, &att1, map[string]any{})
	fr.set(r2, result(r2, "R2", 65, 65, "effect_created"))
	r3 := e.action(ReceiverOperation, "receiver-primary")
	e.event("preflight_passed", r3, &att1, pre)
	e.event("response_received", r3, &att1, map[string]any{})
	fr.set(r3, result(r3, "R3", 0, 1, "key_body_conflict"))
	r6 := e.action(ReceiverOperation, "receiver-primary")
	e.event("preflight_passed", r6, &att1, pre)
	e.event("attempt_failed", r6, &att1, map[string]any{})
	fr.set(r6, func(w receipt.Expected) (receipt.Result, error) {
		if !w.AttemptFailed {
			return receipt.Result{}, errors.New("attempt_failed not passed")
		}
		return result(r6, "R6", 0, 0, "")(w)
	})
	// R5 then a late R1.
	r5 := e.action(ReceiverOperation, "receiver-primary")
	e.event("preflight_passed", r5, &att1, pre)
	e.event("response_received", r5, &att1, map[string]any{})
	fr.set(r5, func(receipt.Expected) (receipt.Result, error) {
		return receipt.Result{}, errors.New("receipt API down")
	})

	for i := 0; i < 6; i++ { // page size 3: several ingest pages
		pass(t, c)
	}
	t.Run("classification_and_audit", func(t *testing.T) {
		if got := e.rules(model); got != "R4" {
			t.Fatal("model", got)
		}
		o := e.observations(model)[0]
		if o.payload["action_key"] != nil || o.payload["missing_reason"] != MissingNotReceiverTarget || o.digest != nil || o.effects != nil {
			t.Fatalf("R4 %+v", o)
		}
		if got := e.rules(r1); got != "R1" {
			t.Fatal("r1", got)
		}
		o = e.observations(r1)[0]
		if o.payload["wire_body_digest"] != digestA || o.payload["bytes"] != float64(10) || o.payload["missing_reason"] != nil || *o.effects != 1 || *o.digest != strings.Repeat("c", 64) {
			t.Fatalf("R1 %+v", o)
		}
		want := fr.calls[r1.String()][0]
		if want.TargetID != "receiver-primary" || want.RouteID != "submissions-v1" || want.WireBodyDigest != wire || want.AttemptFailed {
			t.Fatalf("expected context %+v", want)
		}
		if got := e.rules(r2); got != "R2" || e.observations(r2)[0].payload["effects"] != nil || e.observations(r2)[0].payload["missing_reason"] != MissingEffectListLimit {
			t.Fatal("r2 65 effects", got, e.observations(r2))
		}
		if got := e.rules(r3); got != "R3" || e.observations(r3)[0].payload["missing_reason"] != MissingNoReceiverEffect {
			t.Fatal("r3", got)
		}
		if got := e.rules(r6); got != "R6" || e.observations(r6)[0].payload["missing_reason"] != MissingNoReceiverAttempt {
			t.Fatal("r6", got)
		}
		if got := e.rules(r5); got != "" {
			t.Fatal("R5 recorded before the deadline", got)
		}
		var attempt string
		if err := e.inspect.QueryRow(e.ctx, "SELECT attempt_id::text FROM evidence.destination_observations WHERE action_id=$1", r1).Scan(&attempt); err != nil || attempt != att1.String() {
			t.Fatal("observation attempt_id", attempt, err)
		}
		// Final judgments stop polling; the R5 action is still scheduled.
		if e.count("SELECT count(*) FROM evidence.receipt_polls WHERE next_poll_at IS NOT NULL") != 1 {
			t.Fatal("open polls")
		}
	})

	t.Run("deadline_r5_then_late_receipt_revision", func(t *testing.T) {
		e.run(e.inspect, "UPDATE evidence.receipt_polls SET deadline_at=now()-interval '1 second', next_poll_at=now() WHERE action_id=$1", r5)
		pass(t, c)
		if got := e.rules(r5); got != "R5" || e.observations(r5)[0].payload["missing_reason"] != MissingReceiptUnavailable || e.observations(r5)[0].digest != nil {
			t.Fatal("deadline", got, e.observations(r5))
		}
		// Still unavailable: no duplicate R5 revision.
		e.run(e.inspect, "UPDATE evidence.receipt_polls SET next_poll_at=now() WHERE action_id=$1", r5)
		pass(t, c)
		fr.set(r5, result(r5, "R1", 1, 1, "effect_created"))
		e.run(e.inspect, "UPDATE evidence.receipt_polls SET next_poll_at=now() WHERE action_id=$1", r5)
		pass(t, c)
		obs := e.observations(r5)
		if got := e.rules(r5); got != "R5,R1" || obs[0].level != "unknown" || obs[1].revision != 2 {
			t.Fatal("late receipt", got)
		}
		var polls int
		var next *time.Time
		if err := e.inspect.QueryRow(e.ctx, "SELECT polls,next_poll_at FROM evidence.receipt_polls WHERE action_id=$1", r5).Scan(&polls, &next); err != nil || next != nil || polls < 4 {
			t.Fatal("poll state", polls, next, err)
		}
	})

	t.Run("cursor_restart_and_replay_idempotent", func(t *testing.T) {
		total := func() (int, int) {
			return e.count("SELECT count(*) FROM evidence.destination_observations"), e.count("SELECT count(*) FROM audit.audit_events WHERE event_type='destination_observed'")
		}
		obsBefore, evBefore := total()
		var cursorBefore string
		if err := e.inspect.QueryRow(e.ctx, "SELECT last_received_at::text||last_event_id FROM evidence.collector_cursors WHERE feed=$1", FeedName).Scan(&cursorBefore); err != nil {
			t.Fatal(err)
		}
		// A restarted collector resumes after the cursor.
		restarted := e.collector(fr, 0)
		pass(t, restarted)
		if o, ev := total(); o != obsBefore || ev != evBefore {
			t.Fatal("restart duplicated revisions", o, ev)
		}
		// Replaying the whole feed (cursor lost) re-opens polls but adds no
		// revision for an unchanged judgment.
		e.run(e.inspect, "DELETE FROM evidence.collector_cursors")
		for i := 0; i < 8; i++ {
			pass(t, restarted)
		}
		if o, ev := total(); o != obsBefore || ev != evBefore {
			t.Fatal("replay duplicated revisions", o, ev)
		}
		var cursorAfter string
		if err := e.inspect.QueryRow(e.ctx, "SELECT last_received_at::text||last_event_id FROM evidence.collector_cursors WHERE feed=$1", FeedName).Scan(&cursorAfter); err != nil || cursorAfter != cursorBefore {
			t.Fatal("cursor after replay", cursorAfter, cursorBefore, err)
		}
	})

	t.Run("audit_failure_rolls_back_and_retry_is_idempotent", func(t *testing.T) {
		e.run(e.inspect, "DELETE FROM audit.producer_event_grants WHERE source_id=$1", auditSource)
		var cursorBefore string
		_ = e.inspect.QueryRow(e.ctx, "SELECT last_event_id::text FROM evidence.collector_cursors").Scan(&cursorBefore)
		m := e.action("model.generate", "model-primary")
		e.event("response_received", m, nil, map[string]any{})
		rx := e.action(ReceiverOperation, "receiver-primary")
		e.event("preflight_passed", rx, nil, pre)
		e.event("response_received", rx, nil, map[string]any{})
		fr.set(rx, result(rx, "R1", 1, 1, "effect_created"))
		for i := 0; i < 3; i++ {
			if err := c.Pass(context.Background()); err == nil {
				t.Fatal("pass succeeded without the producer grant")
			}
		}
		var cursorAfter string
		_ = e.inspect.QueryRow(e.ctx, "SELECT last_event_id::text FROM evidence.collector_cursors").Scan(&cursorAfter)
		if e.rules(m) != "" || e.rules(rx) != "" || cursorAfter != cursorBefore || e.count("SELECT count(*) FROM evidence.receipt_polls WHERE action_id=$1", rx) != 0 {
			t.Fatal("failed append left state", cursorAfter, cursorBefore)
		}
		e.run(e.inspect, "INSERT INTO audit.producer_event_grants VALUES($1,'destination_observed',$2)", auditSource, tenant)
		for i := 0; i < 4; i++ {
			pass(t, c)
		}
		if e.rules(m) != "R4" || e.rules(rx) != "R1" {
			t.Fatal("retry", e.rules(m), e.rules(rx))
		}
		// A failed poll transaction also leaves the poll due.
		ry := e.action(ReceiverOperation, "receiver-primary")
		e.event("preflight_passed", ry, nil, pre)
		e.event("response_received", ry, nil, map[string]any{})
		fr.set(ry, result(ry, "R1", 1, 1, "effect_created"))
		e.run(e.inspect, "UPDATE audit.db_role_sources SET source_id='someone-else' WHERE db_role=$1", e.login)
		_ = c.Pass(context.Background())
		if e.rules(ry) != "" || e.count("SELECT count(*) FROM evidence.receipt_polls WHERE action_id=$1 AND polls=0 AND next_poll_at IS NOT NULL", ry) != 1 {
			t.Fatal("failed poll committed")
		}
		e.run(e.inspect, "UPDATE audit.db_role_sources SET source_id=$2 WHERE db_role=$1", e.login, auditSource)
		pass(t, c)
		pass(t, c)
		if e.rules(ry) != "R1" {
			t.Fatal("poll retry", e.rules(ry))
		}
	})

	t.Run("destination_observed_payload_check", func(t *testing.T) {
		a := e.action(ReceiverOperation, "receiver-primary")
		appendRaw := func(p any) error {
			tx, err := e.pool.Begin(e.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			return appendDestinationObserved(e.ctx, tx, AuditConfig{SourceID: auditSource, Version: "v", Epoch: "e"}, tenant, uuid.NewString(), a.String(), nil, time.Now(), p)
		}
		ok := []Payload{notReceiverPayload(a.String()), unavailablePayload(a.String())}
		for _, s := range []struct {
			rule              string
			effects, attempts int
			outcome           string
		}{{"R1", 1, 1, "effect_created"}, {"R2", 1, 2, "effect_created"}, {"R2", 2, 2, "effect_created"}, {"R2", 64, 64, "effect_created"}, {"R2", 65, 65, "effect_created"}, {"R3", 0, 1, "key_body_conflict"}, {"R2", 0, 1, "key_missing_rejected"}, {"R5", 0, 0, ""}, {"R6", 0, 0, ""}} {
			p, err := receiptPayload(a.String(), receipt.Result{RuleID: s.rule, EvidenceLevel: levelOf(s.rule), ReceiptDigest: digestA, Receipt: fakeReceipt(a.String(), s.effects, s.attempts, s.outcome)})
			if err != nil {
				t.Fatal(err)
			}
			ok = append(ok, p)
		}
		for i, p := range ok {
			if err := appendRaw(p); err != nil {
				t.Fatalf("valid payload %d (%s %v) rejected: %v", i, p.RuleID, p.MissingReason, err)
			}
		}
		one, _ := receiptPayload(a.String(), receipt.Result{RuleID: "R1", EvidenceLevel: "effect_verified", ReceiptDigest: digestA, Receipt: fakeReceipt(a.String(), 1, 1, "effect_created")})
		two, _ := receiptPayload(a.String(), receipt.Result{RuleID: "R2", EvidenceLevel: "effect_mismatch", ReceiptDigest: digestA, Receipt: fakeReceipt(a.String(), 2, 2, "effect_created")})
		many, _ := receiptPayload(a.String(), receipt.Result{RuleID: "R2", EvidenceLevel: "effect_mismatch", ReceiptDigest: digestA, Receipt: fakeReceipt(a.String(), 65, 65, "effect_created")})
		bad := map[string]Payload{}
		p := one
		p.Bytes = ptr(0)
		bad["zero bytes for one effect"] = p
		p = two
		p.WireBodyDigest, p.Bytes, p.MissingReason = ptr(digestA), ptr(10), nil
		bad["first effect for two"] = p
		p = unavailablePayload(a.String())
		p.EffectCount = ptr(0)
		bad["zero count without receipt"] = p
		p = notReceiverPayload(a.String())
		p.ActionKey = ptr(a.String())
		bad["R4 with action key"] = p
		p = one
		p.EvidenceLevel = "accepted"
		bad["wrong level pair"] = p
		p = many
		list := make([]EffectRef, 65)
		for i := range list {
			list[i] = EffectRef{WireBodyDigest: digestA, BodyBytes: 1}
		}
		p.Effects = &list
		bad["65 item list"] = p
		p = one
		p.MissingReason = ptr(MissingMultipleEffects)
		bad["reason with scalars"] = p
		p = unavailablePayload(uuid.NewString())
		bad["payload action differs"] = p
		for name, p := range bad {
			var pe *pgconn.PgError
			if err := appendRaw(p); !errors.As(err, &pe) || pe.Code != "22023" {
				t.Fatalf("%s: %v", name, err)
			}
		}
		// A missing key (not null) is rejected too.
		var pe *pgconn.PgError
		if err := appendRaw(map[string]any{"action_id": a.String(), "rule_id": "R4", "evidence_level": "accepted", "missing_reason": MissingNotReceiverTarget}); !errors.As(err, &pe) || pe.Code != "22023" {
			t.Fatalf("missing keys: %v", err)
		}
	})
	// Review #227: a poll whose judgment cannot be stored (an unclassifiable
	// receipt here) is deferred, not left due, so it does not block or starve
	// the other polls and Pass still succeeds. This runs before
	// settle_window_holds_cursor, which advances the cursor to now() and would
	// leave these fixture events (received_at ~1h ago) behind it.
	t.Run("bad_poll_does_not_block_others", func(t *testing.T) {
		bad := e.action(ReceiverOperation, "receiver-primary")
		ab := uuid.New()
		e.event("preflight_passed", bad, &ab, pre)
		e.event("response_received", bad, &ab, map[string]any{})
		// Contradictory result: RuleID R1 (needs exactly one effect) with a
		// receipt that has none, which receiptPayload rejects.
		fr.set(bad, func(receipt.Expected) (receipt.Result, error) {
			return receipt.Result{RuleID: "R1", EvidenceLevel: levelOf("R1"), ReceiptDigest: strings.Repeat("c", 64),
				Receipt: fakeReceipt(bad.String(), 0, 0, "")}, nil
		})
		good := e.action(ReceiverOperation, "receiver-primary")
		ag := uuid.New()
		e.event("preflight_passed", good, &ag, pre)
		e.event("response_received", good, &ag, map[string]any{})
		fr.set(good, func(receipt.Expected) (receipt.Result, error) {
			return receipt.Result{RuleID: "R1", EvidenceLevel: levelOf("R1"), ReceiptDigest: strings.Repeat("c", 64),
				Receipt: fakeReceipt(good.String(), 1, 1, "effect_created")}, nil
		})

		pass(t, c) // must not error even though the bad poll's judgment fails

		if got := e.rules(good); got != "R1" {
			t.Fatalf("good action not judged while a bad poll was due: %q", got)
		}
		if got := e.rules(bad); got != "" {
			t.Fatalf("bad action should have no stored judgment, got %q", got)
		}
		var due *bool
		if err := e.inspect.QueryRow(e.ctx,
			"SELECT next_poll_at IS NOT NULL AND next_poll_at <= now() FROM evidence.receipt_polls WHERE action_id=$1", bad).Scan(&due); err != nil {
			t.Fatal(err)
		}
		if due == nil {
			t.Fatal("bad poll was closed instead of deferred")
		}
		if *due {
			t.Fatal("bad poll is still due; it would spin and starve others")
		}
	})

	// Last: its event has a current received_at, after every fixture.
	t.Run("settle_window_holds_cursor", func(t *testing.T) {
		late := e.action("model.generate", "model-primary")
		id := uuid.New()
		e.run(e.inspect, `INSERT INTO audit.audit_events(event_id,event_type,tenant,source_id,source_version,source_epoch,source_time,received_at,schema_version,action_id,payload_digest,safe_payload)
VALUES($1,'response_received',$2,'adapter-fixture','v1','epoch',now(),now(),1,$3,repeat('a',64),'{}')`, id, tenant, late)
		pass(t, e.collector(fr, time.Hour))
		if e.rules(late) != "" || e.count("SELECT count(*) FROM evidence.collector_cursors WHERE last_event_id=$1", id) != 0 {
			t.Fatal("event inside the settle window processed")
		}
		pass(t, c)
		if e.rules(late) != "R4" {
			t.Fatal("settled event not processed")
		}
	})

}

// TestCollectorReceiverMTLS runs the actual receiver binary and the actual
// receipt client over mTLS: a real submission becomes R1, a changed-body
// retry becomes R2 revision 2, and the probe key reads an empty receipt.
func TestCollectorReceiverMTLS(t *testing.T) {
	e := setup(t)
	// Receiver runtime login with only its two roles.
	rlogin := "evrcv_" + e.prefix
	e.run(e.admin, "CREATE ROLE "+rlogin+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE")
	e.run(e.admin, "GRANT receiver_writer, receipt_reader TO "+rlogin)
	u, err := url.Parse(e.dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path, u.User = "/"+e.db, url.User(rlogin)

	binary := filepath.Join(t.TempDir(), "receiver")
	if out, err := exec.CommandContext(e.ctx, "go", "build", "-o", binary, "../../../../services/receiver/cmd/receiver").CombinedOutput(); err != nil {
		t.Fatalf("build receiver %s: %v", out, err)
	}
	ca := newCA(t)
	sc, sk, _ := ca.leaf(t, "receiver", receipt.ReceiverSAN, x509.ExtKeyUsageServerAuth)
	cc, ck, _ := ca.leaf(t, "collector", receipt.CollectorSAN, x509.ExtKeyUsageClientAuth)
	_, _, sender := ca.leaf(t, "sender", "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender", x509.ExtKeyUsageClientAuth)
	keyDir := t.TempDir()
	key := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	if err := os.WriteFile(filepath.Join(keyDir, "1"), []byte(key+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	pctx, stop := context.WithCancel(e.ctx)
	cmd := exec.CommandContext(pctx, binary, "--listen", addr, "--receiver-mode", "idempotent", "--target-id", "receiver-primary", "--route-id", "submissions-v1",
		"--target-version", "it", "--trust-bundle", ca.ca, "--tls-cert", sc, "--tls-key", sk, "--api-key-dir", keyDir)
	cmd.Env = append(os.Environ(), "RECEIVER_DATABASE_URL="+u.String())
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stop()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log(logs.String())
		}
	})
	client, err := receipt.NewClient("https://"+addr, cc, ck, ca.ca)
	if err != nil {
		t.Fatal(err)
	}
	probeKey := uuid.NewString()
	var digest string
	for i := 0; i < 200; i++ {
		var r *receipt.Receipt
		if r, digest, err = client.Read(e.ctx, probeKey); err == nil {
			if r.TargetIdentity != "receiver-primary" || r.EffectCount != 0 {
				t.Fatal("probe receipt", r)
			}
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil || len(digest) != 64 {
		t.Fatal("receiver not ready / probe read", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.root)
	senderClient := &http.Client{Timeout: 4 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{sender},
		// The test server certificate has only a URI SAN.
		InsecureSkipVerify: true,
	}}}
	action := e.action(ReceiverOperation, "receiver-primary")
	submit := func(body []byte, status int) {
		t.Helper()
		req, _ := http.NewRequestWithContext(e.ctx, http.MethodPost, "https://"+addr+"/test/v1/submissions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", action.String())
		req.Header.Set("X-Agentarium-Attempt-Id", uuid.NewString())
		req.Header.Set("X-Agentarium-Receiver-Key", key)
		resp, err := senderClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatalf("submit %d %s", resp.StatusCode, b)
		}
	}
	body := []byte(`{"email":null,"summary":"collector e2e"}`)
	submit(body, http.StatusCreated)
	att := uuid.New()
	e.event("preflight_passed", action, &att, map[string]any{"wire_body_digest": digestOf(body)})
	e.event("dispatch_started", action, &att, map[string]any{})
	e.event("response_received", action, &att, map[string]any{})
	c := e.collector(client, 0)
	for i := 0; i < 4; i++ {
		pass(t, c)
	}
	if got := e.rules(action); got != "R1" {
		t.Fatal("real receipt", got)
	}
	o := e.observations(action)[0]
	if o.payload["wire_body_digest"] != digestOf(body) || o.payload["bytes"] != float64(len(body)) || o.payload["action_key"] != action.String() || o.payload["receipt_digest"] != *o.digest {
		t.Fatalf("R1 payload %v", o.payload)
	}
	// A changed-body retry gets 409 and becomes R2 on the next trigger.
	submit([]byte(`{"email":null,"summary":"collector e2e mutated"}`), http.StatusConflict)
	att2 := uuid.New()
	e.event("attempt_uncertain", action, &att2, map[string]any{})
	for i := 0; i < 4; i++ {
		pass(t, c)
	}
	obs := e.observations(action)
	if got := e.rules(action); got != "R1,R2" || obs[1].revision != 2 || obs[1].payload["effects"] == nil {
		t.Fatal("mutated retry", got)
	}
	var attempt string
	if err := e.inspect.QueryRow(e.ctx, "SELECT attempt_id::text FROM evidence.destination_observations WHERE action_id=$1 AND revision=2", action).Scan(&attempt); err != nil || attempt != att2.String() {
		t.Fatal("revision 2 attempt", attempt, err)
	}
}

type ca struct {
	dir, ca string
	root    *x509.Certificate
	key     *ecdsa.PrivateKey
}

func newCA(t *testing.T) *ca {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := x509.ParseCertificate(der)
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &ca{dir: dir, ca: p, root: root, key: key}
}

func (c *ca) leaf(t *testing.T, name, san string, usage x509.ExtKeyUsage) (string, string, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(san)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: c.root.NotBefore, NotAfter: c.root.NotAfter, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.root, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalPKCS8PrivateKey(key)
	cp, kp := filepath.Join(c.dir, name+".crt"), filepath.Join(c.dir, name+".key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
	if err := os.WriteFile(cp, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cp, kp, pair
}
