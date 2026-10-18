//go:build integration

package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/contractview"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// DATABASE_URL=postgres://... go test -tags integration ./services/identity/internal/approvals/

type env struct {
	pool    *pgxpool.Pool
	sess    *sessions.Service
	svc     *Service
	actions *fakeActions
	intent  *fakeIntent
	audit   *recorder
}

var migrated sync.Once

func setup(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrated.Do(func() {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass('identity.approvals') IS NOT NULL`).Scan(&exists); err != nil || exists {
			return
		}
		if _, err := pool.Exec(ctx, `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
        END $$`); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob("../../../../migrations/*.up.sql")
		sort.Strings(files)
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if _, err := pool.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	})
	if _, err := pool.Exec(ctx, `
TRUNCATE identity.approval_nonces, identity.approvals, identity.issue_candidates, identity.service_session_counters,
    identity.session_tokens, identity.service_sessions, identity.session_budgets, identity.sessions,
    identity.issued_certificates, identity.registered_workloads CASCADE;
INSERT INTO identity.registered_workloads (namespace, ksa, role) VALUES ('agent-exec', 'agent-runtime', 'runtime');`); err != nil {
		t.Fatal(err)
	}
	cat, err := canonical.LoadCatalogDir("../../../../packages/canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	pol := staticPolicy{sessions.Policy{Catalog: cat}}
	audit := &recorder{}
	e := &env{pool: pool, audit: audit, actions: &fakeActions{m: map[string]Action{}}, intent: &fakeIntent{}}
	e.sess = &sessions.Service{Pool: pool, Policy: pol, Audit: audit, Environment: "test", ClaimKey: []byte("k")}
	e.svc = &Service{Pool: pool, Policy: pol, Actions: e.actions, Pending: e.actions, Previews: fakePreviews{},
		Epochs: fixedEpoch(7), Intent: e.intent, Audit: audit}
	return e
}

type staticPolicy struct{ p sessions.Policy }

func (s staticPolicy) Policy(context.Context) (sessions.Policy, error) { return s.p, nil }

type recorder struct {
	mu     sync.Mutex
	events []sessions.Event
}

func (r *recorder) Append(_ context.Context, _ pgx.Tx, ev sessions.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *recorder) count(typ string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.Type == typ {
			n++
		}
	}
	return n
}

type fakeActions struct {
	mu     sync.Mutex
	m      map[string]Action
	reads  int
	onRead func(id string) // runs after each read, outside the lock
}

func (f *fakeActions) Action(_ context.Context, _ pgx.Tx, id string) (Action, error) {
	f.mu.Lock()
	a, ok := f.m[id]
	f.reads++
	hook := f.onRead
	f.mu.Unlock()
	if hook != nil {
		hook(id)
	}
	if !ok {
		return Action{}, sessions.Fail(404, "APPROVAL_UNAVAILABLE", "unknown action")
	}
	return a, nil
}

func (f *fakeActions) Pending(_ context.Context, _ pgx.Tx, sessionID string) ([]Pending, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Pending
	for _, a := range f.m {
		if a.Verdict == "approval_required" {
			out = append(out, Pending{ActionID: a.ActionID, SessionID: a.SessionID, OperationID: a.OperationID})
		}
	}
	return out, nil
}

type fakePreviews struct{}

func (fakePreviews) Preview(context.Context, pgx.Tx, string) (string, bool, error) {
	return "synthetic summary", false, nil
}

type fixedEpoch int64

func (e fixedEpoch) ActiveEpoch(context.Context, pgx.Tx) (int64, error) { return int64(e), nil }

type fakeIntent struct{ result *IntentResult }

func (f *fakeIntent) Check(context.Context, string, string, contractview.View) (IntentResult, error) {
	if f.result == nil {
		return IntentResult{}, errors.New("intent checker down")
	}
	return *f.result, nil
}

var (
	alice = sessions.Actor{AuthenticatedActor: "google:alice", Tenant: "hackathon"}
	bob   = sessions.Actor{AuthenticatedActor: "google:bob", Tenant: "hackathon"}
	ops   = sessions.Actor{AuthenticatedActor: "google:ops", Tenant: "hackathon", Roles: []string{"operator"}}
	pod   = sessions.RuntimePrincipal{SAN: "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/p1", Namespace: "agent-exec", KSA: "agent-runtime"}
)

func fresh(a sessions.Actor) sessions.Actor { a.AuthTime = time.Now(); return a }

// claimedSession creates a claimed session for actor and a pending receiver
// action in it.
func (e *env) claimedSession(t *testing.T, actor sessions.Actor) (sessionID, actionID string) {
	t.Helper()
	ctx := context.Background()
	cr, err := e.sess.Create(ctx, actor, sessions.CreateRequest{WorkloadID: "agent-exec/agent-runtime", TaskStatement: "send a summary",
		RequestedScope: sessions.RequestedScope{OperationIDs: []string{"receiver.submit"}, TargetIDs: []string{"receiver-primary"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sess.Claim(ctx, pod, cr.SessionID, cr.ClaimCode); err != nil {
		t.Fatal(err)
	}
	actionID = uuid.NewString()
	target, _ := json.Marshal(map[string]string{"target_id": "receiver-primary", "route_id": "submissions-v1"})
	e.actions.mu.Lock()
	e.actions.m[actionID] = Action{ActionID: actionID, SessionID: cr.SessionID, Tenant: "hackathon", Environment: "test",
		OperationID: "receiver.submit", CanonicalTarget: target, TargetID: "receiver-primary",
		DisclosureFields: []string{"summary"}, ContentDigest: strings.Repeat("1", 64), Verdict: "approval_required"}
	e.actions.mu.Unlock()
	return cr.SessionID, actionID
}

func code(t *testing.T, err error) string {
	t.Helper()
	var se *sessions.Error
	if !errors.As(err, &se) {
		t.Fatalf("want *sessions.Error, got %v", err)
	}
	return se.Code
}

func (e *env) approve(t *testing.T, actor sessions.Actor, actionID string, acks []string) (*ApproveResponse, error) {
	t.Helper()
	c, err := e.svc.Contract(context.Background(), actor, actionID)
	if err != nil {
		t.Fatal(err)
	}
	return e.svc.Approve(context.Background(), fresh(actor), ApproveRequest{ActionID: actionID, DisplayedContractDigest: c.ContractDigest, Nonce: c.Nonce, AcknowledgedFindings: acks})
}

func TestContractAndApprove(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	sid, aid := e.claimedSession(t, alice)
	c, err := e.svc.Contract(ctx, alice, aid)
	if err != nil {
		t.Fatal(err)
	}
	if c.IntentCheck.IntentCheckStatus != "not_run" || c.Contract.ExpiresInSeconds != 300 || c.Contract.ContentPreview == nil {
		t.Fatalf("contract %+v", c)
	}
	c2, _ := e.svc.Contract(ctx, alice, aid)
	if c2.ContractDigest != c.ContractDigest || c2.Nonce == c.Nonce {
		t.Fatal("digest not stable or nonce reused")
	}
	out, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: c.ContractDigest, Nonce: c.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	if out.Revision != 1 || out.PolicyEpoch != 7 || time.Until(out.ExpiresAt) > 5*time.Minute+time.Second {
		t.Fatalf("approval %+v", out)
	}
	var sess, op string
	var used, max int
	e.pool.QueryRow(ctx, `SELECT session_id::text, allowed_operation, used_actions, max_actions FROM identity.approvals WHERE approval_id = $1`, out.ApprovalID).Scan(&sess, &op, &used, &max)
	if sess != sid || op != "receiver.submit" || used != 0 || max != 1 {
		t.Fatalf("row %s %s %d %d", sess, op, used, max)
	}
	if e.audit.count("contract_created") != 2 || e.audit.count("approval_granted") != 1 {
		t.Fatalf("events %+v", e.audit.events)
	}
	for _, ev := range e.audit.events {
		if (ev.Type == "contract_created" || ev.Type == "approval_granted") && (ev.Tenant != alice.Tenant || ev.ActionID != aid || ev.SessionID != sid) {
			t.Fatalf("approval query context %+v", ev)
		}
	}
	// The nonce is single-use.
	if _, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: c.ContractDigest, Nonce: c.Nonce}); code(t, err) != "APPROVAL_UNAVAILABLE" {
		t.Fatal("nonce reused")
	}
	// A usable approval blocks another one.
	if _, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: c2.ContractDigest, Nonce: c2.Nonce}); code(t, err) != "APPROVAL_UNAVAILABLE" {
		t.Fatal("second usable approval created")
	}
	// After revoke, the next approval is revision 2 of the same approval_id.
	if _, err := e.svc.Revoke(ctx, alice, out.ApprovalID); err != nil {
		t.Fatal(err)
	}
	next, err := e.approve(t, alice, aid, nil)
	if err != nil || next.ApprovalID != out.ApprovalID || next.Revision != 2 {
		t.Fatalf("re-approve %+v %v", next, err)
	}
}

func TestApproveRejects(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	two := 2
	one := 1
	old := alice
	old.AuthTime = time.Now().Add(-6 * time.Minute)
	future := alice
	future.AuthTime = time.Now().Add(2 * time.Minute)
	cases := map[string]struct {
		actor sessions.Actor
		mod   func(*ApproveRequest)
		code  string
		// keepsNonce is true when the failure must not consume the owner's
		// nonce. Re-authentication is recoverable (refresh the token and
		// retry), so it preserves the contract nonce (review #220); other
		// failures by the owner still burn it.
		keepsNonce bool
	}{
		"stale auth_time":  {old, nil, "AUTH_REQUIRED", true},
		"future auth_time": {future, nil, "AUTH_REQUIRED", true},
		"no auth_time":     {alice, nil, "AUTH_REQUIRED", true},
		"max_actions 2":    {fresh(alice), func(r *ApproveRequest) { r.MaxActions = &two }, "SCHEMA_INVALID", false},
		"wrong digest":     {fresh(alice), func(r *ApproveRequest) { r.DisplayedContractDigest = strings.Repeat("0", 64) }, "APPROVAL_UNAVAILABLE", false},
		"other action":     {fresh(alice), func(r *ApproveRequest) { r.ActionID = uuid.NewString() }, "APPROVAL_UNAVAILABLE", false},
		"other user":       {fresh(bob), nil, "APPROVAL_UNAVAILABLE", false},
	}
	for name, c := range cases {
		ct, err := e.svc.Contract(ctx, alice, aid)
		if err != nil {
			t.Fatal(err)
		}
		req := ApproveRequest{ActionID: aid, DisplayedContractDigest: ct.ContractDigest, Nonce: ct.Nonce}
		if c.mod != nil {
			c.mod(&req)
		}
		if _, err := e.svc.Approve(ctx, c.actor, req); code(t, err) != c.code {
			t.Errorf("%s: got %v, want %s", name, err, c.code)
		}
		// A failed attempt by the nonce's owner uses it up, unless it is a
		// recoverable re-auth failure; another actor cannot burn it.
		var left int
		e.pool.QueryRow(ctx, `SELECT count(*) FROM identity.approval_nonces WHERE nonce = $1`, ct.Nonce).Scan(&left)
		consumed := c.actor.AuthenticatedActor == alice.AuthenticatedActor && !c.keepsNonce
		want := map[bool]int{true: 0, false: 1}[consumed]
		if left != want {
			t.Errorf("%s: %d nonce rows left, want %d", name, left, want)
		}
	}
	var n int
	e.pool.QueryRow(ctx, `SELECT count(*) FROM identity.approvals WHERE action_id = $1`, aid).Scan(&n)
	if n != 0 {
		t.Fatalf("%d approvals created by rejected requests", n)
	}
	// max_actions = 1 is accepted.
	ct, _ := e.svc.Contract(ctx, alice, aid)
	if _, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: ct.ContractDigest, Nonce: ct.Nonce, MaxActions: &one}); err != nil {
		t.Fatalf("max_actions 1: %v", err)
	}
}

func TestContractChangedAfterDisplay(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	ct, _ := e.svc.Contract(ctx, alice, aid)
	e.actions.mu.Lock()
	a := e.actions.m[aid]
	a.DisclosureFields = []string{"summary", "title"}
	e.actions.m[aid] = a
	e.actions.mu.Unlock()
	if _, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: ct.ContractDigest, Nonce: ct.Nonce}); code(t, err) != "APPROVAL_INVALID" {
		t.Fatalf("changed contract approved: %v", err)
	}
}

func TestContractChecks(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	if _, err := e.svc.Contract(ctx, bob, aid); code(t, err) != "SESSION_BINDING_INVALID" {
		t.Error("other user rendered the contract")
	}
	e.actions.mu.Lock()
	a := e.actions.m[aid]
	a.Verdict = "allow"
	e.actions.m[aid] = a
	e.actions.mu.Unlock()
	if _, err := e.svc.Contract(ctx, alice, aid); code(t, err) != "APPROVAL_UNAVAILABLE" {
		t.Error("allowed action rendered for approval")
	}
	e.svc.Actions = nil
	if _, err := e.svc.Contract(ctx, alice, aid); code(t, err) != "STATE_STORE_UNAVAILABLE" {
		t.Error("unwired action source did not fail closed")
	}
}

func TestIntentAcknowledgement(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	e.intent.result = &IntentResult{IntentCheckID: uuid.NewString(), IntentCheckStatus: "completed", Overall: "divergent",
		Findings: []Finding{{FindingID: "f2"}, {FindingID: "f1"}}}
	if _, err := e.approve(t, alice, aid, []string{"f1"}); code(t, err) != "INTENT_ACK_REQUIRED" {
		t.Error("partial acknowledgement accepted")
	}
	if _, err := e.approve(t, alice, aid, []string{"f1", "f2", "f3"}); code(t, err) != "INTENT_ACK_REQUIRED" {
		t.Error("superset acknowledgement accepted")
	}
	out, err := e.approve(t, alice, aid, []string{"f2", "f1", "f1"})
	if err != nil {
		t.Fatal(err)
	}
	var acked []string
	var intentID *string
	e.pool.QueryRow(ctx, `SELECT acknowledged_findings, intent_check_id::text FROM identity.approvals WHERE approval_id = $1`, out.ApprovalID).Scan(&acked, &intentID)
	if strings.Join(acked, ",") != "f1,f2" || intentID == nil || *intentID != e.intent.result.IntentCheckID {
		t.Fatalf("stored %v %v", acked, intentID)
	}
}

func TestConcurrentApprovalsOneWins(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	var reqs []ApproveRequest
	for i := 0; i < 6; i++ {
		ct, _ := e.svc.Contract(ctx, alice, aid)
		reqs = append(reqs, ApproveRequest{ActionID: aid, DisplayedContractDigest: ct.ContractDigest, Nonce: ct.Nonce})
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for _, r := range reqs {
		wg.Add(1)
		go func(r ApproveRequest) {
			defer wg.Done()
			if _, err := e.svc.Approve(ctx, fresh(alice), r); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}(r)
	}
	wg.Wait()
	var n int
	e.pool.QueryRow(ctx, `SELECT count(*) FROM identity.approvals WHERE action_id = $1`, aid).Scan(&n)
	if wins != 1 || n != 1 {
		t.Fatalf("wins %d rows %d", wins, n)
	}
}

func TestRevokeRoles(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	out, err := e.approve(t, alice, aid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Revoke(ctx, bob, out.ApprovalID); code(t, err) != "SESSION_BINDING_INVALID" {
		t.Fatal("other user revoked")
	}
	r, err := e.svc.Revoke(ctx, ops, out.ApprovalID)
	if err != nil || r.RevokeReason != "operator_revoked" {
		t.Fatalf("operator revoke %+v %v", r, err)
	}
	if e.audit.count("approval_revoked") != 1 {
		t.Fatal("approval_revoked missing")
	}
	for _, ev := range e.audit.events {
		if ev.Type == "approval_revoked" && (ev.ActionID != aid || ev.Tenant != alice.Tenant || ev.WorkloadID != "agent-exec/agent-runtime") {
			t.Fatalf("revoked query context %+v", ev)
		}
	}
}

func TestSessionRevokeEndsApprovals(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	sid, aid := e.claimedSession(t, alice)
	out, err := e.approve(t, alice, aid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.sess.Revoke(ctx, alice, sid, "done"); err != nil {
		t.Fatal(err)
	}
	var reason string
	e.pool.QueryRow(ctx, `SELECT revoke_reason FROM identity.approvals WHERE approval_id = $1`, out.ApprovalID).Scan(&reason)
	if reason != "session_ended" || e.audit.count("approval_revoked") != 1 {
		t.Fatalf("reason %q, events %d", reason, e.audit.count("approval_revoked"))
	}
}

func TestPending(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	sid, aid := e.claimedSession(t, alice)
	e.claimedSession(t, bob)
	out, err := e.svc.PendingFor(ctx, alice, sid)
	if err != nil || len(out) != 1 || out[0].ActionID != aid {
		t.Fatalf("pending %+v %v", out, err)
	}
	if _, err := e.svc.PendingFor(ctx, bob, sid); code(t, err) != "SESSION_BINDING_INVALID" {
		t.Fatal("other user listed pending actions")
	}
}

func TestPolicyChangeRevocation(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, a1 := e.claimedSession(t, alice)
	_, a2 := e.claimedSession(t, alice)
	e.actions.mu.Lock()
	x := e.actions.m[a2]
	x.DisclosureFields = []string{"summary", "title"}
	e.actions.m[a2] = x
	e.actions.mu.Unlock()
	keep, err := e.approve(t, alice, a1, nil)
	if err != nil {
		t.Fatal(err)
	}
	drop, err := e.approve(t, alice, a2, nil)
	if err != nil {
		t.Fatal(err)
	}
	call := func(epoch int64, kind string, allowed []string) ([]string, error) {
		rows, err := e.pool.Query(ctx, `SELECT approval_id::text FROM identity.revoke_approvals_for_policy_change($1, $2, $3)`, epoch, kind, allowed)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			rows.Scan(&id)
			ids = append(ids, id)
		}
		return ids, rows.Err()
	}
	if ids, err := call(8, "targets", []string{"summary"}); err != nil || len(ids) != 0 {
		t.Fatalf("other patch kind revoked %v %v", ids, err)
	}
	if ids, err := call(7, "receiver.allowed_disclosure_fields", []string{"summary"}); err != nil || len(ids) != 0 {
		t.Fatalf("same epoch revoked %v %v", ids, err)
	}
	if _, err := call(8, "receiver.allowed_disclosure_fields", nil); err == nil {
		t.Fatal("NULL allowed_fields accepted")
	}
	ids, err := call(8, "receiver.allowed_disclosure_fields", []string{"summary"})
	if err != nil || len(ids) != 1 || ids[0] != drop.ApprovalID {
		t.Fatalf("revoked %v %v", ids, err)
	}
	if again, _ := call(8, "receiver.allowed_disclosure_fields", []string{"summary"}); len(again) != 0 {
		t.Fatal("second call revoked again")
	}
	var reason *string
	e.pool.QueryRow(ctx, `SELECT revoke_reason FROM identity.approvals WHERE approval_id = $1`, keep.ApprovalID).Scan(&reason)
	if reason != nil {
		t.Fatal("subset approval revoked")
	}
}

// The approval row must be written from the same action the contract digest
// covers, even if the action changes right after it was read.
func TestApprovalUsesTheRenderedAction(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	ct, err := e.svc.Contract(ctx, alice, aid)
	if err != nil {
		t.Fatal(err)
	}
	e.actions.mu.Lock()
	before := e.actions.reads
	e.actions.onRead = func(id string) {
		e.actions.mu.Lock()
		a := e.actions.m[id]
		a.DisclosureFields = []string{"summary", "title"}
		e.actions.m[id] = a
		e.actions.onRead = nil
		e.actions.mu.Unlock()
	}
	e.actions.mu.Unlock()
	out, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: ct.ContractDigest, Nonce: ct.Nonce})
	if err != nil {
		t.Fatal(err)
	}
	if reads := e.actions.reads - before; reads != 1 {
		t.Fatalf("approval read the action %d times", reads)
	}
	var fields []string
	e.pool.QueryRow(ctx, `SELECT disclosure_fields FROM identity.approvals WHERE approval_id = $1`, out.ApprovalID).Scan(&fields)
	if strings.Join(fields, ",") != "summary" {
		t.Fatalf("approval stored %v, contract showed [summary]", fields)
	}
}

// txPolicy is a TxPolicySource that proves it ran inside the approval
// transaction and reports the epoch of the row it matched.
type txPolicy struct {
	p      sessions.Policy
	epoch  int64
	inTx   *bool
	called *int
}

func (s txPolicy) Policy(context.Context) (sessions.Policy, error) {
	return sessions.Policy{}, errors.New("transactional callers must use PolicyIn")
}

func (s txPolicy) PolicyIn(ctx context.Context, q sessions.Querier) (sessions.Policy, error) {
	*s.called++
	if _, ok := q.(pgx.Tx); ok {
		var level string
		if err := q.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&level); err != nil {
			return sessions.Policy{}, err
		}
		*s.inTx = true
	}
	p := s.p
	p.Epoch = s.epoch
	return p, nil
}

// #146 review: the contract's snapshot and the approval's policy_epoch must
// come from one active_policy read. A newer epoch seen by ActiveEpoch inside
// the approval transaction is a version mismatch, never a re-labelled approval.
func TestApprovalEpochMatchesRenderedSnapshot(t *testing.T) {
	ctx := context.Background()
	e := setup(t)
	_, aid := e.claimedSession(t, alice)
	base := e.svc.Policy.(staticPolicy).p
	var inTx bool
	var calls int
	e.svc.Policy = txPolicy{p: base, epoch: 6, inTx: &inTx, called: &calls}
	c, err := e.svc.Contract(ctx, alice, aid)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: c.ContractDigest, Nonce: c.Nonce})
	if code(t, err) != "POLICY_VERSION_MISMATCH" {
		t.Fatalf("epoch 6 snapshot approved under epoch 7: %v", err)
	}
	if !inTx || calls < 2 {
		t.Fatalf("policy was not read through the transaction: inTx=%v calls=%d", inTx, calls)
	}
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM identity.approvals WHERE action_id = $1`, aid).Scan(&n); err != nil || n != 0 {
		t.Fatalf("mismatched approval stored: %d %v", n, err)
	}
	if e.audit.count("approval_granted") != 0 {
		t.Fatal("approval_granted recorded for a mismatched epoch")
	}
	// Same epoch in the rendered snapshot and the approval transaction.
	e.svc.Policy = txPolicy{p: base, epoch: 7, inTx: &inTx, called: &calls}
	c, err = e.svc.Contract(ctx, alice, aid)
	if err != nil {
		t.Fatal(err)
	}
	out, err := e.svc.Approve(ctx, fresh(alice), ApproveRequest{ActionID: aid, DisplayedContractDigest: c.ContractDigest, Nonce: c.Nonce})
	if err != nil || out.PolicyEpoch != 7 {
		t.Fatalf("matching epoch rejected: %+v %v", out, err)
	}
}
