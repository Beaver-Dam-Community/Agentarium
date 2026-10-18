package dispatch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// rowTx is a pgx.Tx whose QueryRow answers each statement with the first
// handler whose key the SQL contains. Every other method panics.
type rowTx struct {
	pgx.Tx
	answers []answer
	seen    []string
	args    [][]any
}

type answer struct {
	contains string
	values   []any
	err      error
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, d := range dest {
		switch d := d.(type) {
		case *string:
			*d = r.values[i].(string)
		case **string:
			if r.values[i] == nil {
				*d = nil
			} else {
				s := r.values[i].(string)
				*d = &s
			}
		case *int64:
			*d = r.values[i].(int64)
		case *time.Time:
			*d = r.values[i].(time.Time)
		default:
			return errors.New("unsupported scan destination")
		}
	}
	return nil
}

func (q *rowTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.seen = append(q.seen, sql)
	q.args = append(q.args, args)
	for _, a := range q.answers {
		if strings.Contains(sql, a.contains) {
			return fakeRow{values: a.values, err: a.err}
		}
	}
	return fakeRow{err: errors.New("unexpected query: " + sql)}
}

func TestPGPolicyLockActivePolicy(t *testing.T) {
	ctx := context.Background()
	tx := &rowTx{answers: []answer{{contains: "release.lock_active_policy($1)", values: []any{int64(7), catalogDigestT, "rev-7"}}}}
	a, err := PGPolicy{Environment: "prod"}.LockActivePolicy(ctx, tx)
	if err != nil || a != (ActivePolicy{Epoch: 7, CatalogDigest: catalogDigestT, ExpectedOPARevision: "rev-7"}) {
		t.Fatalf("active: %+v %v", a, err)
	}
	if len(tx.args) != 1 || tx.args[0][0] != "prod" {
		t.Fatalf("scope_id: %v", tx.args)
	}

	_, err = PGPolicy{Environment: "prod"}.LockActivePolicy(ctx, &rowTx{answers: []answer{{contains: "lock_active_policy", err: pgx.ErrNoRows}}})
	wantCode(t, err, "POLICY_UNAVAILABLE")

	if _, err := (PGPolicy{}).LockActivePolicy(ctx, &rowTx{}); !errors.Is(err, ErrUnwired) {
		t.Fatalf("no environment: %v", err)
	}
}

const catalogDigestT = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func TestNewPGAuditorRequiresConfig(t *testing.T) {
	for _, c := range []AuditConfig{{}, {SourceID: "coordinator", Version: "v1"}, {SourceID: "coordinator", Epoch: "1"}, {Version: "v1", Epoch: "1"}, {SourceID: "\xff", Version: "v1", Epoch: "1"}} {
		if _, err := NewPGAuditor(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
}

func TestPGAuditorAppend(t *testing.T) {
	ctx := context.Background()
	a, err := NewPGAuditor(AuditConfig{SourceID: "coordinator-test", Version: "v1", Epoch: "3"})
	if err != nil {
		t.Fatal(err)
	}
	a.newID = func() string { return "00000000-0000-4000-8000-000000000001" }
	now := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	attempt := func(result string) *rowTx {
		return &rowTx{answers: []answer{
			{contains: "FROM coordinator.attempts", values: []any{"hackathon", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}},
			{contains: "transaction_timestamp()", values: []any{now}},
			{contains: "audit.audit_append", values: []any{result}},
		}}
	}

	// The tenant, session and action come from the attempt's rows, the source
	// from the process configuration.
	tx := attempt("created")
	if err := a.Append(ctx, tx, Event{Type: "attempt_planned", Payload: map[string]any{"attempt_id": "a1", "policy_epoch": int64(7)}}); err != nil {
		t.Fatal(err)
	}
	raw, ok := tx.args[len(tx.args)-1][0].([]byte)
	if !ok {
		t.Fatalf("audit_append argument %T", tx.args[len(tx.args)-1][0])
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"event_type": "attempt_planned", "tenant": "hackathon", "source_id": "coordinator-test",
		"source_version": "v1", "source_epoch": "3", "session_id": "22222222-2222-4222-8222-222222222222",
		"action_id": "33333333-3333-4333-8333-333333333333", "attempt_id": "a1", "source_time": "2026-10-18T01:02:03Z"} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %v", k, rec[k], want)
		}
	}
	if rec["source_sequence"] != nil || rec["payload_digest"] == nil {
		t.Errorf("sequence %v digest %v", rec["source_sequence"], rec["payload_digest"])
	}
	if !strings.Contains(tx.seen[len(tx.seen)-1], "ARRAY['gcs']") {
		t.Errorf("sinks: %s", tx.seen[len(tx.seen)-1])
	}

	// A conflict or any unexpected result fails, so the transaction rolls back.
	if err := a.Append(ctx, attempt("conflict"), Event{Type: "attempt_planned", Payload: map[string]any{"attempt_id": "a1"}}); err == nil {
		t.Fatal("conflict accepted")
	}

	// Service-session events take the tenant of the service session.
	tx = &rowTx{answers: []answer{
		{contains: "FROM identity.service_sessions", values: []any{"hackathon"}},
		{contains: "transaction_timestamp()", values: []any{now}},
		{contains: "audit.audit_append", values: []any{"created"}},
	}}
	if err := a.Append(ctx, tx, Event{Type: "activation_probe_registered", Payload: map[string]any{"service_session_id": "s1"}}); err != nil {
		t.Fatal(err)
	}

	// No row to take the tenant from, or no tenant: nothing is appended.
	for name, ev := range map[string]Event{
		"no subject": {Type: "attempt_planned", Payload: map[string]any{"x": 1}},
		"no type":    {Payload: map[string]any{"attempt_id": "a1"}},
	} {
		if err := a.Append(ctx, attempt("created"), ev); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	tx = &rowTx{answers: []answer{{contains: "FROM coordinator.attempts", err: pgx.ErrNoRows}}}
	if err := a.Append(ctx, tx, Event{Type: "attempt_planned", Payload: map[string]any{"attempt_id": "a1"}}); err == nil {
		t.Fatal("unknown attempt accepted")
	}
	if err := a.Append(ctx, nil, Event{Type: "attempt_planned", Payload: map[string]any{"attempt_id": "a1"}}); err == nil {
		t.Fatal("nil tx accepted")
	}
}
