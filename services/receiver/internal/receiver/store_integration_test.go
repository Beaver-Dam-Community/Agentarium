//go:build integration

package receiver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Run against a scratch PostgreSQL database whose user is a superuser (the
// migration creates the receiver roles, and the tests create and drop
// helper roles). Every test re-applies the receiver migration, down and then
// up, so do not point it at shared data:
//
//	DATABASE_URL=postgres://... go test -race -tags integration ./services/receiver/...
//
// The store pools come from NewRolePool and run as receiver_writer and
// receipt_reader, so every query also checks the migration's grants. Fixtures
// use the admin pool. The tables are append-only, so a test starts from a
// fresh schema instead of truncating them.

const (
	migrationDir  = "../../../../migrations"
	migrationName = "20261015151000_receiver_effects"
)

// SQLSTATEs the tests expect.
const (
	sqlDenied     = "42501" // insufficient_privilege: no GRANT
	sqlRaised     = "P0001" // raise_exception: receiver.reject_change()
	sqlCheck      = "23514" // check_violation
	sqlUnique     = "23505" // unique_violation
	sqlNoArbiter  = "42P10" // ON CONFLICT without a matching unique index
	itMaxConns    = 32
	itOutsider    = "receiver_it_outsider"
	itMigrator    = "receiver_it_migrator"
	ownerRoleName = "receiver_owner"
)

type itEnv struct {
	dsn    *url.URL
	admin  *pgxpool.Pool
	store  *PGStore
	writer *pgxpool.Pool
	reader *pgxpool.Pool
}

func readMigration(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(migrationDir, migrationName+"."+dir+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// rolePoolT is the production NewRolePool with room for the concurrency
// tests (pool_max_conns).
func rolePoolT(t *testing.T, dsn *url.URL, role string) *pgxpool.Pool {
	t.Helper()
	u := *dsn
	q := u.Query()
	q.Set("pool_max_conns", fmt.Sprint(itMaxConns))
	u.RawQuery = q.Encode()
	p, err := NewRolePool(context.Background(), u.String(), role)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func setupIT(t *testing.T) *itEnv {
	t.Helper()
	raw := os.Getenv("DATABASE_URL")
	if raw == "" {
		t.Skip("DATABASE_URL not set")
	}
	dsn, err := url.Parse(raw)
	if err != nil || dsn.Scheme == "" {
		t.Fatalf("DATABASE_URL must be a postgres:// URL: %v", err)
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT to_regnamespace('receiver') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		if _, err := admin.Exec(ctx, readMigration(t, "down")); err != nil {
			t.Fatalf("down: %v", err)
		}
	}
	if _, err := admin.Exec(ctx, readMigration(t, "up")); err != nil {
		t.Fatalf("up: %v", err)
	}
	e := &itEnv{dsn: dsn, admin: admin, writer: rolePoolT(t, dsn, RoleWriter), reader: rolePoolT(t, dsn, RoleReader)}
	e.store = &PGStore{Writer: e.writer, Reader: e.reader}
	return e
}

// dropRole removes a role a test created, with whatever it was granted.
func (e *itEnv) dropRole(t *testing.T, role string) {
	t.Helper()
	ctx := context.Background()
	var db string
	if err := e.admin.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := e.admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil || !exists {
		return
	}
	id := pgx.Identifier{role}.Sanitize()
	for _, q := range []string{
		`REVOKE ALL ON DATABASE ` + pgx.Identifier{db}.Sanitize() + ` FROM ` + id,
		`DROP OWNED BY ` + id,
		`DROP ROLE ` + id,
	} {
		if _, err := e.admin.Exec(ctx, q); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}

func sub(mode Mode, key *string, body string) Submission {
	s := Submission{
		Mode:            mode,
		ActionKey:       key,
		ClientPrincipal: SubmitterSAN,
		WireBodyDigest:  canonical.SHA256Hex([]byte(body)),
		BodyBytes:       len(body),
	}
	if d, err := canonical.CanonicalDigestJSON([]byte(body)); err == nil {
		s.ContentDigestServer = &d
	}
	return s
}

func ptr(s string) *string { return &s }

func bodyN(n int) string { return fmt.Sprintf(`{"email":null,"summary":"body %d"}`, n) }

func outcomes(r ReceiptRecords) map[string]int {
	m := map[string]int{}
	for _, a := range r.Attempts {
		m[a.Outcome]++
	}
	return m
}

func TestITIdempotentDedupeAfterLostResponse(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	key := ptr(uuid.NewString())
	s := sub(ModeIdempotent, key, goodBody)
	s.ClientAttemptID = ptr(uuid.NewString())

	first, err := e.store.Submit(ctx, s)
	if err != nil || first.Outcome != OutcomeEffectCreated {
		t.Fatalf("first %+v %v", first, err)
	}
	// The response of the first submission is lost; the adapter's retry
	// attempt sends the same bytes under the same key.
	s.ClientAttemptID = ptr(uuid.NewString())
	second, err := e.store.Submit(ctx, s)
	if err != nil || second.Outcome != OutcomeDuplicateReturned {
		t.Fatalf("second %+v %v", second, err)
	}
	if second.EffectID != first.EffectID || second.ReceiptAttemptID == first.ReceiptAttemptID ||
		second.WireBodyDigest != s.WireBodyDigest || second.BodyBytes != len(goodBody) || *second.ActionKey != *key {
		t.Fatalf("duplicate does not return the existing effect: %+v vs %+v", second, first)
	}

	rec, err := e.store.Receipt(ctx, *key)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Effects) != 1 || rec.Effects[0].EffectID != first.EffectID || rec.Effects[0].WireBodyDigest != s.WireBodyDigest ||
		*rec.Effects[0].ContentDigestServer != *s.ContentDigestServer || rec.Effects[0].BodyBytes != len(goodBody) {
		t.Fatalf("effects %+v", rec.Effects)
	}
	if len(rec.Attempts) != 2 || rec.Attempts[0].Outcome != OutcomeEffectCreated || rec.Attempts[1].Outcome != OutcomeDuplicateReturned {
		t.Fatalf("attempts %+v", rec.Attempts)
	}
	var linked int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM receiver.receiver_attempts WHERE effect_id = $1`, first.EffectID).Scan(&linked); err != nil || linked != 2 {
		t.Fatalf("attempts linked to the effect: %d %v", linked, err)
	}
}

func TestITConflictAttemptSurvivesRollback(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	key := ptr(uuid.NewString())
	first, err := e.store.Submit(ctx, sub(ModeIdempotent, key, bodyN(1)))
	if err != nil || first.Outcome != OutcomeEffectCreated {
		t.Fatalf("first %+v %v", first, err)
	}
	conflict, err := e.store.Submit(ctx, sub(ModeIdempotent, key, bodyN(2)))
	if err != nil || conflict.Outcome != OutcomeKeyBodyConflict || conflict.ReceiptAttemptID == "" || conflict.EffectID != "" {
		t.Fatalf("conflict %+v %v", conflict, err)
	}
	rec, err := e.store.Receipt(ctx, *key)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Effects) != 1 || rec.Effects[0].EffectID != first.EffectID || rec.Effects[0].WireBodyDigest != canonical.SHA256Hex([]byte(bodyN(1))) {
		t.Fatalf("effects %+v", rec.Effects)
	}
	o := outcomes(rec)
	if len(rec.Attempts) != 2 || o[OutcomeEffectCreated] != 1 || o[OutcomeKeyBodyConflict] != 1 {
		t.Fatalf("attempts %+v", rec.Attempts)
	}
	var effectID *string
	var digest string
	if err := e.admin.QueryRow(ctx, `SELECT effect_id::text, wire_body_digest FROM receiver.receiver_attempts WHERE receipt_attempt_id = $1`,
		conflict.ReceiptAttemptID).Scan(&effectID, &digest); err != nil {
		t.Fatal(err)
	}
	if effectID != nil || digest != canonical.SHA256Hex([]byte(bodyN(2))) {
		t.Fatalf("conflict attempt row effect_id=%v digest=%s", effectID, digest)
	}
}

func TestITKeyMissingRecorded(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	s := sub(ModeIdempotent, nil, goodBody)
	s.ClientAttemptID = ptr(uuid.NewString())
	id, err := e.store.RecordKeyMissing(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	var outcome, principal string
	var key, effect *string
	if err := e.admin.QueryRow(ctx, `SELECT outcome, client_principal, action_key::text, effect_id::text FROM receiver.receiver_attempts WHERE receipt_attempt_id = $1`, id).
		Scan(&outcome, &principal, &key, &effect); err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeKeyMissingRejected || principal != SubmitterSAN || key != nil || effect != nil {
		t.Fatalf("row %s %s %v %v", outcome, principal, key, effect)
	}
	var effects int
	_ = e.admin.QueryRow(ctx, `SELECT count(*) FROM receiver.receiver_effects`).Scan(&effects)
	if effects != 0 {
		t.Fatalf("effects %d", effects)
	}
	// The schema also refuses a keyless idempotent effect.
	if _, err := e.writer.Exec(ctx, `INSERT INTO receiver.receiver_effects (receiver_mode, wire_body_digest, body_bytes, client_principal)
VALUES ('idempotent', $1, 1, 'x')`, strings.Repeat("a", 64)); err == nil {
		t.Fatal("keyless idempotent effect accepted")
	}
}

func TestITNonIdempotentRecordsEveryDuplicate(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	key := ptr(uuid.NewString())
	seen := map[string]bool{}
	for i := 0; i < 3; i++ { // adapter retries of one action
		r, err := e.store.Submit(ctx, sub(ModeNonIdempotent, key, goodBody))
		if err != nil || r.Outcome != OutcomeEffectCreated || seen[r.EffectID] {
			t.Fatalf("submit %d: %+v %v", i, r, err)
		}
		seen[r.EffectID] = true
	}
	for i := 0; i < 2; i++ { // keyless submissions
		r, err := e.store.Submit(ctx, sub(ModeNonIdempotent, nil, goodBody))
		if err != nil || r.Outcome != OutcomeEffectCreated || r.ActionKey != nil {
			t.Fatalf("keyless %d: %+v %v", i, r, err)
		}
	}
	otherKey := ptr(uuid.NewString()) // same content as a new logical action
	if _, err := e.store.Submit(ctx, sub(ModeNonIdempotent, otherKey, goodBody)); err != nil {
		t.Fatal(err)
	}

	rec, err := e.store.Receipt(ctx, *key)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Effects) != 3 || len(rec.Attempts) != 3 || outcomes(rec)[OutcomeEffectCreated] != 3 {
		t.Fatalf("receipt %+v", rec)
	}
	// TASK-08 3.3 metrics read from the same tables.
	var keyless, distinctKeys int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM receiver.receiver_effects WHERE action_key IS NULL AND receiver_mode = 'non_idempotent'`).Scan(&keyless); err != nil || keyless != 2 {
		t.Fatalf("keyless effects %d %v", keyless, err)
	}
	if err := e.admin.QueryRow(ctx, `
SELECT count(DISTINCT action_key) FROM receiver.receiver_attempts
WHERE client_principal = $1 AND wire_body_digest = $2 AND action_key IS NOT NULL`,
		SubmitterSAN, canonical.SHA256Hex([]byte(goodBody))).Scan(&distinctKeys); err != nil || distinctKeys != 2 {
		t.Fatalf("distinct keys for the same content %d %v", distinctKeys, err)
	}
}

func TestITClientAttemptIDReuseKeepsBothRows(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	key := ptr(uuid.NewString())
	s := sub(ModeIdempotent, key, goodBody)
	s.ClientAttemptID = ptr(uuid.NewString())
	a, err := e.store.Submit(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.store.Submit(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := e.store.Receipt(ctx, *key)
	if err != nil {
		t.Fatal(err)
	}
	if a.ReceiptAttemptID == b.ReceiptAttemptID || len(rec.Attempts) != 2 {
		t.Fatalf("attempts %+v", rec.Attempts)
	}
	for _, at := range rec.Attempts {
		if at.ClientAttemptID == nil || *at.ClientAttemptID != *s.ClientAttemptID {
			t.Fatalf("client_attempt_id %+v", at)
		}
	}
}

// submitConcurrently posts bodies[i] under one Idempotency-Key through the
// handler at once (each with its own attempt ID) and returns the responses in
// the order of bodies.
func submitConcurrently(h http.Handler, key string, bodies []string) []*httptest.ResponseRecorder {
	out := make([]*httptest.ResponseRecorder, len(bodies))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, b := range bodies {
		wg.Add(1)
		go func(i int, b string) {
			defer wg.Done()
			<-start
			out[i] = post(h, SubmitterSAN, b, map[string]string{HeaderIdempotencyKey: key, HeaderAttemptID: uuid.NewString()})
		}(i, b)
	}
	close(start)
	wg.Wait()
	return out
}

type submitBody struct {
	EffectID         string   `json:"effect_id"`
	ReceiptAttemptID string   `json:"receipt_attempt_id"`
	ReasonCodes      []string `json:"reason_codes"`
}

func decodeSubmit(w *httptest.ResponseRecorder) (submitBody, error) {
	var b submitBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		return b, fmt.Errorf("status %d body %q: %w", w.Code, w.Body.String(), err)
	}
	return b, nil
}

// checkConcurrentSame sends n identical submissions with one key at once and
// checks the idempotent result: exactly one 201 and n-1 200 responses, all
// with the same effect_id; the receipt has one effect and n attempts (one
// effect_created, n-1 duplicate_returned); receiver_effects has one row for
// the key. It returns an error instead of failing so the mutation test can
// expect a failure.
func checkConcurrentSame(e *itEnv, n int) error {
	ctx := context.Background()
	h := newHandler(ModeIdempotent, e.store)
	key := uuid.NewString()
	bodies := make([]string, n)
	for i := range bodies {
		bodies[i] = goodBody
	}
	codes := map[int]int{}
	effects := map[string]bool{}
	for _, w := range submitConcurrently(h, key, bodies) {
		codes[w.Code]++
		if w.Code == http.StatusCreated || w.Code == http.StatusOK {
			b, err := decodeSubmit(w)
			if err != nil {
				return err
			}
			effects[b.EffectID] = true
		}
	}
	if codes[http.StatusCreated] != 1 || codes[http.StatusOK] != n-1 || len(effects) != 1 {
		return fmt.Errorf("status counts %v, distinct effect_ids %d", codes, len(effects))
	}
	rec, err := e.store.Receipt(ctx, key)
	if err != nil {
		return err
	}
	o := outcomes(rec)
	if len(rec.Effects) != 1 || len(rec.Attempts) != n || o[OutcomeEffectCreated] != 1 || o[OutcomeDuplicateReturned] != n-1 {
		return fmt.Errorf("receipt effects=%d attempts=%d outcomes=%v", len(rec.Effects), len(rec.Attempts), o)
	}
	var rows int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM receiver.receiver_effects WHERE action_key = $1`, key).Scan(&rows); err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("receiver_effects rows for the key: %d", rows)
	}
	return nil
}

// TestITConcurrentSameBody: 32 concurrent identical submissions with one key
// create exactly one effect.
func TestITConcurrentSameBody(t *testing.T) {
	e := setupIT(t)
	if err := checkConcurrentSame(e, 32); err != nil {
		t.Fatal(err)
	}
}

// TestITMutationUniqueIndexIsLoadBearing drops the partial unique index and
// shows that the dedupe check then fails, so TestITConcurrentSameBody really
// depends on that index. Without it the ON CONFLICT arbiter is gone: every
// idempotent Submit fails (42P10, 503) and a second effect for one key is
// accepted by the table.
func TestITMutationUniqueIndexIsLoadBearing(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	const insert = `INSERT INTO receiver.receiver_effects (action_key, receiver_mode, wire_body_digest, body_bytes, client_principal)
VALUES ($1, 'idempotent', $2, 1, 'x')`
	key, digest := uuid.NewString(), strings.Repeat("a", 64)
	if _, err := e.writer.Exec(ctx, insert, key, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := e.writer.Exec(ctx, insert, key, digest); pgCode(err) != sqlUnique {
		t.Fatalf("second effect for one key with the index: %v, want SQLSTATE %s", err, sqlUnique)
	}

	if _, err := e.admin.Exec(ctx, `DROP INDEX receiver.receiver_effects_idempotent_key`); err != nil {
		t.Fatal(err)
	}
	err := checkConcurrentSame(e, 8)
	if err == nil {
		t.Fatal("concurrent dedupe check passed without receiver_effects_idempotent_key")
	}
	t.Logf("without the index: %v", err)
	_, err = e.store.Submit(ctx, sub(ModeIdempotent, ptr(uuid.NewString()), goodBody))
	if pgCode(err) != sqlNoArbiter {
		t.Fatalf("Submit without the index: %v, want SQLSTATE %s", err, sqlNoArbiter)
	}
	if _, err := e.writer.Exec(ctx, insert, key, digest); err != nil {
		t.Fatalf("second effect for one key without the index: %v", err)
	}
	// The next setupIT re-creates the schema with the index.
}

// TestITConcurrentDifferentBodies: 16 concurrent submissions with one key and
// 16 different bodies give exactly one 201 and fifteen 409
// TARGET_KEY_BODY_CONFLICT responses. The receipt has one effect (the 201
// body) and 16 attempts: 1 effect_created and 15 key_body_conflict, whose
// receipt_attempt_ids are the ones the 409 responses returned.
func TestITConcurrentDifferentBodies(t *testing.T) {
	e := setupIT(t)
	const n = 16
	key := uuid.NewString()
	bodies := make([]string, n)
	for i := range bodies {
		bodies[i] = bodyN(i)
	}
	winner := -1
	conflicts := map[string]bool{}
	for i, w := range submitConcurrently(newHandler(ModeIdempotent, e.store), key, bodies) {
		b, err := decodeSubmit(w)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case w.Code == http.StatusCreated && winner == -1:
			winner = i
		case w.Code == http.StatusConflict && len(b.ReasonCodes) == 1 && b.ReasonCodes[0] == ReasonTargetKeyBodyConflict && b.ReceiptAttemptID != "":
			conflicts[b.ReceiptAttemptID] = true
		default:
			t.Fatalf("body %d: %d %s", i, w.Code, w.Body)
		}
	}
	if winner == -1 || len(conflicts) != n-1 {
		t.Fatalf("winner %d, distinct conflict attempts %d", winner, len(conflicts))
	}
	checkConflictReceipt(t, e, key, bodies[winner], n, map[string]int{OutcomeEffectCreated: 1, OutcomeKeyBodyConflict: n - 1}, conflicts)
}

// TestITConcurrentTwoBodies: 16 concurrent submissions with one key alternate
// two bodies (8 each). The body that wins gets one 201 and seven 200
// responses; the other body gets eight 409 responses. The receipt has one
// effect and 16 attempts: 1 effect_created, 7 duplicate_returned and 8
// key_body_conflict.
func TestITConcurrentTwoBodies(t *testing.T) {
	e := setupIT(t)
	const n = 16
	key := uuid.NewString()
	bodies := make([]string, n)
	for i := range bodies {
		bodies[i] = bodyN(i % 2)
	}
	res := submitConcurrently(newHandler(ModeIdempotent, e.store), key, bodies)
	winner := -1
	for i, w := range res {
		if w.Code == http.StatusCreated {
			if winner != -1 {
				t.Fatal("two 201 responses")
			}
			winner = i % 2
		}
	}
	if winner == -1 {
		t.Fatal("no 201 response")
	}
	effect := ""
	conflicts := map[string]bool{}
	for i, w := range res {
		b, err := decodeSubmit(w)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case i%2 == winner && (w.Code == http.StatusCreated || w.Code == http.StatusOK) && (effect == "" || effect == b.EffectID):
			effect = b.EffectID
		case i%2 != winner && w.Code == http.StatusConflict && b.ReceiptAttemptID != "":
			conflicts[b.ReceiptAttemptID] = true
		default:
			t.Fatalf("body %d (winner %d): %d %s", i%2, winner, w.Code, w.Body)
		}
	}
	if len(conflicts) != n/2 {
		t.Fatalf("distinct conflict attempts %d", len(conflicts))
	}
	checkConflictReceipt(t, e, key, bodyN(winner), n,
		map[string]int{OutcomeEffectCreated: 1, OutcomeDuplicateReturned: n/2 - 1, OutcomeKeyBodyConflict: n / 2}, conflicts)
}

// checkConflictReceipt checks the receipt of a conflict test: one effect with
// the winner's digest, n attempts with the given outcome counts, and every
// key_body_conflict attempt returned to a caller and linked to no effect.
func checkConflictReceipt(t *testing.T, e *itEnv, key, winnerBody string, n int, want map[string]int, conflicts map[string]bool) {
	t.Helper()
	ctx := context.Background()
	rec, err := e.store.Receipt(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Effects) != 1 || rec.Effects[0].WireBodyDigest != canonical.SHA256Hex([]byte(winnerBody)) || len(rec.Attempts) != n {
		t.Fatalf("receipt effects=%+v attempts=%d", rec.Effects, len(rec.Attempts))
	}
	o := outcomes(rec)
	if len(o) != len(want) {
		t.Fatalf("outcomes %v, want %v", o, want)
	}
	for k, v := range want {
		if o[k] != v {
			t.Fatalf("outcomes %v, want %v", o, want)
		}
	}
	for _, a := range rec.Attempts {
		if a.Outcome == OutcomeKeyBodyConflict && !conflicts[a.ReceiptAttemptID] {
			t.Fatalf("conflict attempt %s was not returned to any caller", a.ReceiptAttemptID)
		}
	}
	var linked int
	if err := e.admin.QueryRow(ctx, `SELECT count(*) FROM receiver.receiver_attempts
WHERE action_key = $1 AND outcome = 'key_body_conflict' AND effect_id IS NOT NULL`, key).Scan(&linked); err != nil || linked != 0 {
		t.Fatalf("conflict attempts linked to an effect: %d %v", linked, err)
	}
}

// TestITRolePools: NewRolePool runs each pool as one role, and an unknown role
// stops it before the receiver starts.
func TestITRolePools(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	for pool, want := range map[*pgxpool.Pool]string{e.writer: RoleWriter, e.reader: RoleReader} {
		var user, session string
		if err := pool.QueryRow(ctx, `SELECT current_user, session_user`).Scan(&user, &session); err != nil || user != want {
			t.Errorf("pool runs as %q (session %q), want %q: %v", user, session, want, err)
		}
	}
	if p, err := NewRolePool(ctx, e.dsn.String(), "receiver_it_no_such_role"); err == nil {
		p.Close()
		t.Fatal("pool with an unknown role started")
	}
}

// TestITGrants: each pool's role gets SQLSTATE 42501 for everything its
// GRANTs leave out, and a role with no grant cannot read.
func TestITGrants(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	r, err := e.store.Submit(ctx, sub(ModeIdempotent, ptr(uuid.NewString()), goodBody))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.dropRole(t, itOutsider) })
	if _, err := e.admin.Exec(ctx, `CREATE ROLE `+itOutsider+` NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	outsider := rolePoolT(t, e.dsn, itOutsider)
	digest := strings.Repeat("a", 64)
	denied := []struct {
		name string
		pool *pgxpool.Pool
		sql  string
	}{
		{"writer update effect", e.writer, `UPDATE receiver.receiver_effects SET body_bytes = 0 WHERE effect_id = '` + r.EffectID + `'`},
		{"writer delete effect", e.writer, `DELETE FROM receiver.receiver_effects`},
		{"writer truncate effects", e.writer, `TRUNCATE receiver.receiver_effects CASCADE`},
		{"writer update attempt", e.writer, `UPDATE receiver.receiver_attempts SET outcome = 'effect_created'`},
		{"writer delete attempt", e.writer, `DELETE FROM receiver.receiver_attempts`},
		{"writer truncate attempts", e.writer, `TRUNCATE receiver.receiver_attempts`},
		{"writer ddl", e.writer, `CREATE TABLE receiver.x (a int)`},
		{"reader insert effect", e.reader, `INSERT INTO receiver.receiver_effects (action_key, receiver_mode, wire_body_digest, body_bytes, client_principal) VALUES (gen_random_uuid(), 'idempotent', '` + digest + `', 1, 'x')`},
		{"reader insert attempt", e.reader, `INSERT INTO receiver.receiver_attempts (client_principal, wire_body_digest, body_bytes, outcome) VALUES ('x', '` + digest + `', 1, 'key_missing_rejected')`},
		{"reader update", e.reader, `UPDATE receiver.receiver_effects SET body_bytes = 0`},
		{"reader delete", e.reader, `DELETE FROM receiver.receiver_attempts`},
		{"reader truncate", e.reader, `TRUNCATE receiver.receiver_attempts`},
		{"outsider select effects", outsider, `SELECT 1 FROM receiver.receiver_effects`},
		{"outsider select attempts", outsider, `SELECT 1 FROM receiver.receiver_attempts`},
	}
	for _, d := range denied {
		if _, err := d.pool.Exec(ctx, d.sql); pgCode(err) != sqlDenied {
			t.Errorf("%s: %v, want SQLSTATE %s", d.name, err, sqlDenied)
		}
	}
	for _, p := range []*pgxpool.Pool{e.writer, e.reader} {
		if _, err := p.Exec(ctx, `SELECT 1 FROM receiver.receiver_effects, receiver.receiver_attempts LIMIT 1`); err != nil {
			t.Errorf("select: %v", err)
		}
	}
	var owner string
	if err := e.admin.QueryRow(ctx, `SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'receiver'`).Scan(&owner); err != nil || owner != ownerRoleName {
		t.Errorf("schema owner %q %v", owner, err)
	}
	if err := e.admin.QueryRow(ctx, `SELECT string_agg(DISTINCT tableowner, ',') FROM pg_tables WHERE schemaname = 'receiver'`).Scan(&owner); err != nil || owner != ownerRoleName {
		t.Errorf("table owner %q %v", owner, err)
	}
}

// TestITAppendOnly: the triggers reject UPDATE, DELETE and TRUNCATE with
// SQLSTATE P0001 even for receiver_owner and a superuser, which the GRANTs do
// not restrict, and leave the rows in place.
func TestITAppendOnly(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	key := ptr(uuid.NewString())
	if _, err := e.store.Submit(ctx, sub(ModeIdempotent, key, bodyN(1))); err != nil {
		t.Fatal(err)
	}
	if r, err := e.store.Submit(ctx, sub(ModeIdempotent, key, bodyN(2))); err != nil || r.Outcome != OutcomeKeyBodyConflict {
		t.Fatalf("conflict %+v %v", r, err)
	}
	counts := func() (effects, attempts int) {
		if err := e.admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM receiver.receiver_effects), (SELECT count(*) FROM receiver.receiver_attempts)`).Scan(&effects, &attempts); err != nil {
			t.Fatal(err)
		}
		return effects, attempts
	}
	effects, attempts := counts()
	if effects != 1 || attempts != 2 {
		t.Fatalf("fixture effects=%d attempts=%d", effects, attempts)
	}
	// asRole runs sql in a transaction that is rolled back; role "" keeps the
	// superuser.
	asRole := func(role, sql string) error {
		tx, err := e.admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if role != "" {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				t.Fatal(err)
			}
		}
		_, err = tx.Exec(ctx, sql)
		return err
	}
	for _, role := range []string{ownerRoleName, ""} {
		for _, sql := range []string{
			`UPDATE receiver.receiver_effects SET body_bytes = 0`,
			`DELETE FROM receiver.receiver_effects`,
			`TRUNCATE receiver.receiver_effects CASCADE`,
			`UPDATE receiver.receiver_attempts SET outcome = 'effect_created'`,
			`DELETE FROM receiver.receiver_attempts`,
			`TRUNCATE receiver.receiver_attempts`,
		} {
			if err := asRole(role, sql); pgCode(err) != sqlRaised {
				t.Errorf("role %q: %s: %v, want SQLSTATE %s", role, sql, err, sqlRaised)
			}
		}
	}
	if ge, ga := counts(); ge != effects || ga != attempts {
		t.Fatalf("rows changed: effects %d->%d attempts %d->%d", effects, ge, attempts, ga)
	}
}

// TestITOutcomeMatchesEffect: effect_created and duplicate_returned attempts
// must refer to an effect, key_body_conflict and key_missing_rejected must
// not (receiver_attempts_effect_matches_outcome).
func TestITOutcomeMatchesEffect(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	key := uuid.NewString()
	r, err := e.store.Submit(ctx, sub(ModeIdempotent, &key, goodBody))
	if err != nil {
		t.Fatal(err)
	}
	const insert = `INSERT INTO receiver.receiver_attempts (action_key, client_principal, wire_body_digest, body_bytes, outcome, effect_id)
VALUES ($1, 'x', $2, 1, $3, $4)`
	digest := strings.Repeat("a", 64)
	for _, c := range []struct {
		outcome string
		effect  *string
		ok      bool
	}{
		{OutcomeEffectCreated, nil, false},
		{OutcomeDuplicateReturned, nil, false},
		{OutcomeKeyBodyConflict, &r.EffectID, false},
		{OutcomeKeyMissingRejected, &r.EffectID, false},
		{OutcomeEffectCreated, &r.EffectID, true},
		{OutcomeDuplicateReturned, &r.EffectID, true},
		{OutcomeKeyBodyConflict, nil, true},
		{OutcomeKeyMissingRejected, nil, true},
	} {
		_, err := e.writer.Exec(ctx, insert, key, digest, c.outcome, c.effect)
		var pe *pgconn.PgError
		switch {
		case c.ok && err != nil:
			t.Errorf("%s effect=%v: %v", c.outcome, c.effect != nil, err)
		case !c.ok && !(errors.As(err, &pe) && pe.Code == sqlCheck && pe.ConstraintName == "receiver_attempts_effect_matches_outcome"):
			t.Errorf("%s effect=%v: %v, want the outcome/effect check", c.outcome, c.effect != nil, err)
		}
	}
}

// TestITMigrationDownUp runs down and up as the superuser test user.
func TestITMigrationDownUp(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, readMigration(t, "down")); err != nil {
		t.Fatal(err)
	}
	var exists bool
	_ = e.admin.QueryRow(ctx, `SELECT to_regnamespace('receiver') IS NOT NULL`).Scan(&exists)
	if exists {
		t.Fatal("schema receiver still exists after down")
	}
	if _, err := e.admin.Exec(ctx, readMigration(t, "up")); err != nil {
		t.Fatal(err)
	}
}

// TestITMigrationNonSuperuser runs down, up, down and up as a CREATEROLE
// login without superuser, as on Cloud SQL. PostgreSQL 16+ gives the creator
// of a role ADMIN without INHERIT or SET (createrole_self_grant = ”); the
// roles already exist in the test cluster, so that grant is made by hand.
// Each migration grants itself receiver_owner and revokes it at the end, so
// the migrator never keeps the owner's privileges, and it cannot run a role
// pool for a role it may not SET.
func TestITMigrationNonSuperuser(t *testing.T) {
	e := setupIT(t)
	ctx := context.Background()
	var db string
	if err := e.admin.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	e.dropRole(t, itMigrator)
	t.Cleanup(func() { e.dropRole(t, itMigrator) })
	password := uuid.NewString()
	for _, q := range []string{
		`CREATE ROLE ` + itMigrator + ` LOGIN CREATEROLE PASSWORD '` + password + `'`,
		`GRANT receiver_owner, receiver_writer, receipt_reader TO ` + itMigrator + ` WITH ADMIN TRUE, INHERIT FALSE, SET FALSE`,
		`GRANT CREATE ON DATABASE ` + pgx.Identifier{db}.Sanitize() + ` TO ` + itMigrator,
	} {
		if _, err := e.admin.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	u := *e.dsn
	u.User = url.UserPassword(itMigrator, password)
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)

	ownerPrivileges := func() bool {
		var usage, set bool
		if err := e.admin.QueryRow(ctx, `SELECT pg_has_role($1, 'receiver_owner', 'USAGE'), pg_has_role($1, 'receiver_owner', 'SET')`,
			itMigrator).Scan(&usage, &set); err != nil {
			t.Fatal(err)
		}
		return usage || set
	}
	schema := func() bool {
		var exists bool
		if err := e.admin.QueryRow(ctx, `SELECT to_regnamespace('receiver') IS NOT NULL`).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	for i, dir := range []string{"down", "up", "down", "up"} {
		if _, err := conn.Exec(ctx, readMigration(t, dir)); err != nil {
			t.Fatalf("%s #%d as %s: %v", dir, i, itMigrator, err)
		}
		if schema() != (dir == "up") {
			t.Fatalf("%s #%d: schema exists = %v", dir, i, dir != "up")
		}
		if ownerPrivileges() {
			t.Fatalf("%s #%d: %s kept the privileges of receiver_owner", dir, i, itMigrator)
		}
	}
	var owners string
	if err := e.admin.QueryRow(ctx, `
SELECT string_agg(DISTINCT o, ',') FROM (
    SELECT nspowner::regrole::text FROM pg_namespace WHERE nspname = 'receiver'
    UNION ALL SELECT tableowner FROM pg_tables WHERE schemaname = 'receiver'
    UNION ALL SELECT proowner::regrole::text FROM pg_proc WHERE pronamespace = 'receiver'::regnamespace
) AS t(o)`).Scan(&owners); err != nil || owners != ownerRoleName {
		t.Fatalf("owners %q %v", owners, err)
	}
	// The migrator is not a member of receipt_reader with SET, so its role
	// pool fails at start instead of running with the login's own grants.
	if p, err := NewRolePool(ctx, u.String(), RoleReader); err == nil {
		p.Close()
		t.Fatal("role pool started without SET on receipt_reader")
	} else if pgCode(err) != sqlDenied {
		t.Fatalf("role pool error %v, want SQLSTATE %s", err, sqlDenied)
	}
}

// ---- HTTP over mTLS ----------------------------------------------------------

type testPKI struct {
	ca     *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPool *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &testPKI{ca: ca, caKey: key, caPool: pool}
}

func (p *testPKI) leaf(t *testing.T, san string, server bool) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = nil
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if san != "" {
		u, _ := url.Parse(san)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestITHTTPOverMTLS(t *testing.T) {
	e := setupIT(t)
	pki := newPKI(t)
	mux := http.NewServeMux()
	keyDir := t.TempDir()
	oldKey, newKey := testKey, "_-_-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxw"
	if err := os.WriteFile(filepath.Join(keyDir, "1"), []byte(oldKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keySet, err := NewKeySet(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	(&Handler{Store: e.store, Cfg: Config{Mode: ModeIdempotent, TargetID: "receiver-primary", RouteID: "submissions-v1", TargetVersion: "it"}, Keys: keySet}).Register(mux)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pki.leaf(t, "spiffe://agentarium.internal/ns/agent-targets/sa/receiver", true)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pki.caPool,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client := func(cert tls.Certificate) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pki.caPool, ServerName: "localhost", Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13,
		}}}
	}
	adapter := client(pki.leaf(t, SubmitterSAN, false))
	collector := client(pki.leaf(t, ReceiptReaderSAN, false))
	other := client(pki.leaf(t, "spiffe://agentarium.internal/ns/agent-adapters/sa/model-adapter", false))

	key := uuid.NewString()
	do := func(c *http.Client, method, path, body string, hdr map[string]string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if method == http.MethodPost {
			req.Header.Set(HeaderReceiverKey, oldKey)
		}
		for k, v := range hdr {
			if k == HeaderReceiverKey && v == "" {
				req.Header.Del(k)
				continue
			}
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("%s %s: %q", method, path, b)
		}
		return resp.StatusCode, m
	}
	h := map[string]string{HeaderIdempotencyKey: key, HeaderAttemptID: uuid.NewString()}

	if code, m := do(adapter, http.MethodPost, "/test/v1/submissions", goodBody, h); code != http.StatusCreated || m["action_key"] != key {
		t.Fatalf("new effect %d %v", code, m)
	}
	if code, m := do(adapter, http.MethodPost, "/test/v1/submissions", goodBody, h); code != http.StatusOK || m["duplicate"] != true {
		t.Fatalf("duplicate %d %v", code, m)
	}
	if code, m := do(adapter, http.MethodPost, "/test/v1/submissions", bodyN(9), h); code != http.StatusConflict || reasons(t, m) != ReasonTargetKeyBodyConflict || m["receipt_attempt_id"] == nil {
		t.Fatalf("conflict %d %v", code, m)
	}
	if code, m := do(adapter, http.MethodPost, "/test/v1/submissions", goodBody, nil); code != http.StatusUnprocessableEntity || m["receipt_attempt_id"] == nil {
		t.Fatalf("key missing %d %v", code, m)
	}
	if code, m := do(adapter, http.MethodPost, "/test/v1/submissions", `{"summary":"x"}`, h); code != http.StatusUnprocessableEntity || reasons(t, m) != ReasonSchemaInvalid {
		t.Fatalf("schema %d %v", code, m)
	}
	if code, _ := do(other, http.MethodPost, "/test/v1/submissions", goodBody, h); code != http.StatusUnauthorized {
		t.Fatalf("other caller submit %d", code)
	}
	if code, _ := do(adapter, http.MethodGet, "/test/v1/receipts/"+key, "", nil); code != http.StatusUnauthorized {
		t.Fatalf("adapter reading receipt %d", code)
	}
	// Receiver key: missing or wrong is 401 RECEIVER_KEY_INVALID with no
	// attempt row, with or without an Idempotency-Key.
	for name, k := range map[string]string{"missing": "", "wrong": newKey} {
		for _, hk := range []map[string]string{{HeaderReceiverKey: k}, {HeaderReceiverKey: k, HeaderIdempotencyKey: key, HeaderAttemptID: uuid.NewString()}} {
			if code, m := do(adapter, http.MethodPost, "/test/v1/submissions", goodBody, hk); code != http.StatusUnauthorized || reasons(t, m) != ReasonReceiverKeyInvalid || m["receipt_attempt_id"] != nil {
				t.Fatalf("%s receiver key: %d %v", name, code, m)
			}
		}
	}
	// Rotation: version 2 is added, both are accepted; version 1 is removed,
	// only version 2 is accepted. Each accepted request is a duplicate.
	if err := os.WriteFile(filepath.Join(keyDir, "2"), []byte(newKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keySet.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{oldKey, newKey} {
		hk := map[string]string{HeaderReceiverKey: k, HeaderIdempotencyKey: key, HeaderAttemptID: uuid.NewString()}
		if code, _ := do(adapter, http.MethodPost, "/test/v1/submissions", goodBody, hk); code != http.StatusOK {
			t.Fatalf("rotation overlap %d", code)
		}
	}
	if err := os.Remove(filepath.Join(keyDir, "1")); err != nil {
		t.Fatal(err)
	}
	if err := keySet.Reload(); err != nil {
		t.Fatal(err)
	}
	if code, _ := do(adapter, http.MethodPost, "/test/v1/submissions", goodBody, map[string]string{HeaderIdempotencyKey: key, HeaderAttemptID: uuid.NewString()}); code != http.StatusUnauthorized {
		t.Fatalf("retired key accepted: %d", code)
	}
	oldKey = newKey

	code, m := do(collector, http.MethodGet, "/test/v1/receipts/"+key, "", nil)
	if code != http.StatusOK || m["effect_count"] != float64(1) || m["receiver_mode"] != "idempotent" || m["target_identity"] != "receiver-primary" {
		t.Fatalf("receipt %d %v", code, m)
	}
	var got []string
	for _, a := range m["receiver_attempts"].([]any) {
		got = append(got, a.(map[string]any)["outcome"].(string))
	}
	if strings.Join(got, ",") != "effect_created,duplicate_returned,key_body_conflict,duplicate_returned,duplicate_returned" {
		t.Fatalf("attempt outcomes %v", got)
	}

	// A client certificate from another CA never reaches the handler.
	stranger := client(newPKI(t).leaf(t, SubmitterSAN, false))
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/test/v1/submissions", strings.NewReader(goodBody))
	if resp, err := stranger.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("certificate from an untrusted CA accepted")
	}
	var n int
	_ = e.admin.QueryRow(context.Background(), `SELECT count(*) FROM receiver.receiver_attempts`).Scan(&n)
	if n != 6 {
		t.Fatalf("attempt rows %d, want 6 (schema violation, rejected callers and rejected receiver keys are not recorded)", n)
	}
}
