//go:build integration

package dispatch

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"net/url"
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
)

// Run against an empty database; the test applies migrations/*.up.sql:
//
//	DATABASE_URL=postgres://... go test -tags integration ./services/coordinator/internal/dispatch/
//
// The service pool runs as coordinator_app (SET ROLE), so every query also
// checks the migration's grants. Fixtures use the admin pool.

const (
	adapterSAN  = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-adapter/pod/p1"
	adapterNode = "11111111-1111-4111-8111-111111111111"
	adapterBoot = "boot-1"
	certSerial  = "0abc01"
	catalogD    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	opaRev      = "rev-7"
)

type env struct {
	admin   *pgxpool.Pool
	svc     *Service
	adapter Adapter
	dec     *fakeDecisions
	health  *fakeHealth
	audit   *recorder
	policy  *fakePolicy
	session string
}

var migrated sync.Once

func setup(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	migrated.Do(func() {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT to_regclass('coordinator.reservations') IS NOT NULL`).Scan(&exists); err != nil || exists {
			return
		}
		if _, err := admin.Exec(ctx, `DO $$ BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_health_writer') THEN CREATE ROLE control_health_writer NOLOGIN; END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN CREATE ROLE gateway_app NOLOGIN; END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'timeline_app') THEN CREATE ROLE timeline_app NOLOGIN; END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'broker_reader') THEN CREATE ROLE broker_reader NOLOGIN; END IF;
        END $$`); err != nil {
			t.Fatal(err)
		}
		files, _ := filepath.Glob("../../../../migrations/*.up.sql")
		sort.Strings(files)
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if _, err := admin.Exec(ctx, string(b)); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
		}
	})
	sess := uuid.NewString()
	if _, err := admin.Exec(ctx, `
TRUNCATE coordinator.attempt_observations, coordinator.activation_probes, coordinator.dispatch_permits,
    coordinator.attempts, coordinator.reservations, identity.approval_nonces, identity.approvals,
    identity.issue_candidate_counters, identity.issue_candidates, identity.service_session_counters, identity.session_tokens,
    identity.service_sessions, identity.session_budgets, identity.sessions, identity.issued_certificates,
    identity.registered_workloads CASCADE;
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal) VALUES
    ('agent-exec', 'agent-runtime', 'runtime', NULL, NULL),
    ('agent-adapters', 'receiver-adapter', 'adapter', 'receiver', NULL),
    ('agent-adapters', 'model-adapter', 'adapter', 'model', NULL),
    ('agent-observe', 'policy-proposer', 'service', NULL, 'policy-proposer');`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
INSERT INTO identity.issued_certificates (serial, san_uri, namespace, ksa, pod_uid, node_uid, boot_id, issued_at, expires_at)
VALUES ($1, $2, 'agent-adapters', 'receiver-adapter', gen_random_uuid(), $3, $4, now(), now() + interval '1 day')`,
		certSerial, adapterSAN, adapterNode, adapterBoot); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
INSERT INTO identity.sessions (session_id, authenticated_actor, tenant, workload_id, task_statement, allowed_operation_ids,
    state, claim_code_digest, claim_expires_at, created_at, expires_at, max_expires_at)
VALUES ($1, 'google:u1', 'hackathon', 'agent-exec/agent-runtime', 'task', '{receiver.submit}',
    'claimed', '\x00', now(), now(), now() + interval '30 minutes', now() + interval '8 hours')`, sess); err != nil {
		t.Fatal(err)
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET ROLE coordinator_app")
		return err
	}
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)

	e := &env{admin: admin, session: sess, dec: &fakeDecisions{m: map[string]Decision{}},
		health: &fakeHealth{boot: NodeBoot{BootID: adapterBoot, State: "ready"}}, audit: &recorder{},
		policy: &fakePolicy{a: ActivePolicy{Epoch: 7, CatalogDigest: catalogD, ExpectedOPARevision: opaRev}}}
	e.svc = &Service{Pool: app, Policy: e.policy, Decisions: e.dec, Health: e.health, Audit: e.audit}
	e.adapter, err = e.svc.Authenticate(ctx, leaf(t, certSerial, adapterSAN))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func leaf(t *testing.T, serialHex, san string) *x509.Certificate {
	t.Helper()
	b, err := hex.DecodeString(serialHex)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{SerialNumber: new(big.Int).SetBytes(b), URIs: []*url.URL{u}}
}

// ---- fakes ------------------------------------------------------------------

type fakePolicy struct {
	mu sync.Mutex
	a  ActivePolicy
}

func (f *fakePolicy) LockActivePolicy(context.Context, pgx.Tx) (ActivePolicy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.a, nil
}

type fakeDecisions struct {
	mu sync.Mutex
	m  map[string]Decision
}

func (f *fakeDecisions) Decision(_ context.Context, _ pgx.Tx, id string) (Decision, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.m[id]
	if !ok {
		return Decision{}, ErrNotFound
	}
	return d, nil
}

func (f *fakeDecisions) put(d Decision) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[d.DecisionID] = d
}

type fakeHealth struct {
	mu       sync.Mutex
	holds    []Hold
	boot     NodeBoot
	leaseErr error
	// activation is the open policy_activation hold LockActivationHold
	// returns; nil means none. activationErr overrides it.
	activation    *Hold
	activationErr error
}

func (f *fakeHealth) LockActivationHold(context.Context, pgx.Tx, string) (Hold, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.activationErr != nil {
		return Hold{}, f.activationErr
	}
	if f.activation == nil {
		return Hold{}, ErrNotFound
	}
	return *f.activation, nil
}

func (f *fakeHealth) LockHolds(context.Context, pgx.Tx, HoldScope) ([]Hold, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holds, nil
}

func (f *fakeHealth) LockNodeBoot(context.Context, pgx.Tx, string) (NodeBoot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boot, nil
}

func (f *fakeHealth) CheckLeases(context.Context, pgx.Tx, string, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.leaseErr
}

type recorder struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (r *recorder) Append(_ context.Context, _ pgx.Tx, ev Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
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

// ---- fixtures ---------------------------------------------------------------

func digest(c byte) string { return strings.Repeat(string(c), 64) }

// approval inserts an unused approval for a new action and returns an allow
// decision for it.
func (e *env) approval(t *testing.T) Decision {
	t.Helper()
	action, approval := uuid.NewString(), uuid.NewString()
	if _, err := e.admin.Exec(context.Background(), `
INSERT INTO identity.approvals (approval_id, revision, approval_kind, action_id, authenticated_actor, session_id,
    contract_digest, displayed_contract_digest, allowed_operation, canonical_target, disclosure_fields,
    max_actions, policy_epoch, contract_version, created_at, expires_at)
VALUES ($1, 1, 'action', $2, 'google:u1', $3, $4, $4, 'receiver.submit', '{}', '{summary}', 1, 7, '1', now(), now() + interval '5 minutes')`,
		approval, action, e.session, digest('d')); err != nil {
		t.Fatal(err)
	}
	d := Decision{DecisionID: uuid.NewString(), RequestID: uuid.NewString(), ActionID: action, ActionDigest: digest('a'),
		AdapterID: "receiver", Verdict: "allow", DecisionBasis: "approval", ApprovalID: approval,
		PolicyEpoch: 7, OPABundleRevision: opaRev, CatalogDigest: catalogD, ExpiresAt: time.Now().Add(time.Minute),
		SessionID: e.session, WorkloadID: "agent-exec/agent-runtime", OperationID: "receiver.submit", TargetID: "receiver-primary"}
	e.dec.put(d)
	return d
}

// again is a new decision for the same action (a :reevaluate).
func (e *env) again(d Decision) Decision {
	d.DecisionID, d.RequestID = uuid.NewString(), uuid.NewString()
	e.dec.put(d)
	return d
}

func reqFor(d Decision) ReserveRequest {
	return ReserveRequest{DecisionID: d.DecisionID, ActionID: d.ActionID, RequestID: d.RequestID, ActionDigest: d.ActionDigest,
		WireBodyDigest: digest('b'), PolicyEpoch: d.PolicyEpoch, CatalogDigest: d.CatalogDigest}
}

func checkFor(p *Permit) CheckRequest {
	return CheckRequest{AttemptID: p.AttemptID, ActionDigest: p.ActionDigest, PolicyEpoch: p.PolicyEpoch, WireBodyDigest: p.WireBodyDigest}
}

func (e *env) scalar(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.admin.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) used(t *testing.T, d Decision) int {
	return e.scalar(t, `SELECT used_actions FROM identity.approvals WHERE approval_id = $1`, d.ApprovalID)
}

func (e *env) rows(t *testing.T) int {
	return e.scalar(t, `SELECT (SELECT count(*) FROM coordinator.reservations) + (SELECT count(*) FROM coordinator.attempts)
    + (SELECT count(*) FROM coordinator.dispatch_permits)`)
}

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if err == nil {
		return ""
	}
	return "untyped: " + err.Error()
}

// ---- tests ------------------------------------------------------------------

func TestReserveAndClaim(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	d := e.approval(t)
	p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
	if err != nil {
		t.Fatal(err)
	}
	if p.RequestID != d.RequestID || p.AdapterID != "receiver" || p.WireBodyDigest != digest('b') || p.ClaimedAt != nil {
		t.Fatalf("permit %+v", p)
	}
	if ttl := time.Until(p.ExpiresAt); ttl <= 0 || ttl > PermitTTL+2*time.Second {
		t.Fatalf("permit ttl %v", ttl)
	}
	if e.used(t, d) != 1 || e.audit.count("attempt_planned") != 1 {
		t.Fatal("approval not consumed or attempt_planned missing")
	}
	got, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p))
	if err != nil || !got.ExecutionAllowed {
		t.Fatalf("check: %v %+v", err, got)
	}
	if e.scalar(t, `SELECT count(*) FROM coordinator.reservations r JOIN coordinator.attempts a USING (reservation_id)
WHERE r.state = 'committed' AND a.state = 'claimed' AND a.claimed_at IS NOT NULL`) != 1 {
		t.Fatal("claim did not commit the reservation and claim the attempt")
	}
	if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); code(err) != "PERMIT_INVALID" {
		t.Fatalf("second check: %v", err)
	}
	// A claimed attempt cannot be released.
	if _, err := e.svc.release(ctx, p.AttemptID, ByAdapter, []string{"CREDENTIAL_UNAVAILABLE"}, &e.adapter); code(err) != "PERMIT_INVALID" {
		t.Fatalf("release after claim: %v", err)
	}
	if e.used(t, d) != 1 {
		t.Fatal("budget restored after claim")
	}
}

func TestConcurrentReservationsOneWins(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	d := e.approval(t)
	decisions := []Decision{d}
	for i := 1; i < 20; i++ {
		decisions = append(decisions, e.again(d))
	}
	var wg sync.WaitGroup
	errs := make([]error, len(decisions))
	for i, dd := range decisions {
		wg.Add(1)
		go func(i int, dd Decision) {
			defer wg.Done()
			_, errs[i] = e.svc.Reserve(ctx, e.adapter, reqFor(dd))
		}(i, dd)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch code(err) {
		case "":
			ok++
		case "PERMIT_INVALID":
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	if ok != 1 || e.used(t, d) != 1 || e.rows(t) != 3 || e.audit.count("attempt_planned") != 1 {
		t.Fatalf("ok=%d used=%d rows=%d planned=%d", ok, e.used(t, d), e.rows(t), e.audit.count("attempt_planned"))
	}
}

func TestReplayReturnsSamePermit(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	d := e.approval(t)
	var wg sync.WaitGroup
	ids := make([]string, 20)
	errs := make([]error, 20)
	for i := range ids {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
			errs[i] = err
			if p != nil {
				ids[i] = p.PermitID
			}
		}(i)
	}
	wg.Wait()
	for i := range ids {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Fatalf("replay %d: %v %s vs %s", i, errs[i], ids[i], ids[0])
		}
	}
	if e.used(t, d) != 1 || e.rows(t) != 3 {
		t.Fatal("replay consumed budget or added rows")
	}
	// Another wire body is not a replay.
	r := reqFor(d)
	r.WireBodyDigest = digest('e')
	if _, err := e.svc.Reserve(ctx, e.adapter, r); code(err) != "PERMIT_INVALID" {
		t.Fatalf("different wire body: %v", err)
	}
}

func TestReserveRejectsWithoutChange(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	cases := map[string]struct {
		mod  func(*Decision, *ReserveRequest)
		env  func()
		want string
	}{
		"expired":        {mod: func(d *Decision, _ *ReserveRequest) { d.ExpiresAt = time.Now().Add(-time.Second) }, want: "DECISION_EXPIRED"},
		"stale epoch":    {mod: func(d *Decision, r *ReserveRequest) { d.PolicyEpoch, r.PolicyEpoch = 6, 6 }, want: "POLICY_EPOCH_STALE"},
		"opa revision":   {mod: func(d *Decision, _ *ReserveRequest) { d.OPABundleRevision = "rev-6" }, want: "POLICY_EPOCH_STALE"},
		"catalog":        {mod: func(d *Decision, r *ReserveRequest) { d.CatalogDigest, r.CatalogDigest = digest('f'), digest('f') }, want: "CATALOG_DIGEST_MISMATCH"},
		"deny":           {mod: func(d *Decision, _ *ReserveRequest) { d.Verdict = "deny" }, want: "PERMIT_INVALID"},
		"other adapter":  {mod: func(d *Decision, _ *ReserveRequest) { d.AdapterID = "model" }, want: "RESOURCE_NOT_FOUND"},
		"request digest": {mod: func(_ *Decision, r *ReserveRequest) { r.ActionDigest = digest('9') }, want: "ACTION_DIGEST_MISMATCH"},
		"request epoch":  {mod: func(_ *Decision, r *ReserveRequest) { r.PolicyEpoch = 8 }, want: "POLICY_EPOCH_STALE"},
		"unregistered probe": {mod: func(d *Decision, _ *ReserveRequest) {
			d.DecisionBasis, d.ServiceSessionID, d.ActivationProbeID = "activation_probe", uuid.NewString(), uuid.NewString()
		}, env: func() { e.health.holds = []Hold{{HoldID: "h1", Reason: "policy_activation"}} }, want: "HOLD_ACTIVE"},
		"activation hold":  {env: func() { e.health.holds = []Hold{{HoldID: "h1", Reason: "policy_activation"}} }, want: "HOLD_ACTIVE"},
		"missing approval": {mod: func(d *Decision, _ *ReserveRequest) { d.ApprovalID = uuid.NewString() }, want: "APPROVAL_UNAVAILABLE"},
		"hold":             {env: func() { e.health.holds = []Hold{{HoldID: "h1", Reason: "drift"}} }, want: "HOLD_ACTIVE"},
		"boot":             {env: func() { e.health.boot = NodeBoot{BootID: "boot-0", State: "ready"} }, want: "CONTROL_HEALTH_UNAVAILABLE"},
		"not ready": {env: func() { e.health.boot = NodeBoot{BootID: adapterBoot, State: "preparing"} },
			want: "CONTROL_HEALTH_UNAVAILABLE"},
		"lease":   {env: func() { e.health.leaseErr = errors.New("lease expired") }, want: "CONTROL_HEALTH_UNAVAILABLE"},
		"audit":   {env: func() { e.audit.err = errors.New("audit down") }, want: "STATE_STORE_UNAVAILABLE"},
		"revoked": {env: func() { e.admin.Exec(ctx, `UPDATE identity.sessions SET state = 'revoked'`) }, want: "APPROVAL_UNAVAILABLE"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e.health.holds, e.health.boot, e.health.leaseErr, e.audit.err = nil, NodeBoot{BootID: adapterBoot, State: "ready"}, nil, nil
			if _, err := e.admin.Exec(ctx, `UPDATE identity.sessions SET state = 'claimed'`); err != nil {
				t.Fatal(err)
			}
			d := e.approval(t)
			r := reqFor(d)
			if c.mod != nil {
				c.mod(&d, &r)
				e.dec.put(d)
			}
			if c.env != nil {
				c.env()
			}
			if _, err := e.svc.Reserve(ctx, e.adapter, r); code(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
			if e.rows(t) != 0 || e.scalar(t, `SELECT coalesce(sum(used_actions), 0)::int FROM identity.approvals`) != 0 {
				t.Fatal("a refused reservation left state behind")
			}
		})
	}
}

func TestReleaseRestoresOnce(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	d := e.approval(t)
	p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
	if err != nil {
		t.Fatal(err)
	}
	reasons := []string{"CREDENTIAL_UNAVAILABLE"}
	// Concurrent adapter releases: one restore.
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r, err := e.svc.release(ctx, p.AttemptID, ByAdapter, reasons, &e.adapter); err != nil || r.State != "released" {
				t.Errorf("release: %v %+v", err, r)
			}
		}()
	}
	wg.Wait()
	if e.used(t, d) != 0 || e.audit.count("attempt_released") != 1 {
		t.Fatalf("used=%d released events=%d", e.used(t, d), e.audit.count("attempt_released"))
	}
	if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); code(err) != "PERMIT_INVALID" {
		t.Fatalf("check after release: %v", err)
	}
	// Another adapter cannot see the attempt.
	other := e.adapter
	other.AdapterID = "model"
	if _, err := e.svc.release(ctx, p.AttemptID, ByAdapter, reasons, &other); code(err) != "RESOURCE_NOT_FOUND" {
		t.Fatalf("other adapter: %v", err)
	}
	// A new decision reserves the released action again and consumes again.
	p2, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.again(d)))
	if err != nil {
		t.Fatal(err)
	}
	if p2.ReservationID != p.ReservationID || p2.AttemptID == p.AttemptID || e.used(t, d) != 1 {
		t.Fatalf("re-reserve: %+v used=%d", p2, e.used(t, d))
	}
}

func TestSweeperReleasesExpiredOnly(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	expired, fresh := e.approval(t), e.approval(t)
	pe, err := e.svc.Reserve(ctx, e.adapter, reqFor(expired))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(fresh)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `UPDATE coordinator.dispatch_permits SET expires_at = now() - interval '1 second' WHERE permit_id = $1`,
		pe.PermitID); err != nil {
		t.Fatal(err)
	}
	// The sweeper races an adapter release of the same attempt.
	var wg sync.WaitGroup
	var sr SweepResult
	wg.Add(2)
	go func() { defer wg.Done(); sr, _ = e.svc.Sweep(ctx) }()
	go func() {
		defer wg.Done()
		_, _ = e.svc.release(ctx, pe.AttemptID, ByAdapter, []string{"PERMIT_INVALID"}, &e.adapter)
	}()
	wg.Wait()
	if sr.Failed != 0 || e.used(t, expired) != 0 || e.used(t, fresh) != 1 || e.audit.count("attempt_released") != 1 {
		t.Fatalf("sweep %+v used=%d/%d events=%d", sr, e.used(t, expired), e.used(t, fresh), e.audit.count("attempt_released"))
	}
	if r, err := e.svc.Sweep(ctx); err != nil || r.Candidates != 0 {
		t.Fatalf("second sweep: %+v %v", r, err)
	}
}

func TestCheckRechecks(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	cases := map[string]struct {
		before func(p *Permit, c *CheckRequest)
		want   string
	}{
		"body":    {before: func(_ *Permit, c *CheckRequest) { c.WireBodyDigest = digest('e') }, want: "PERMIT_INVALID"},
		"attempt": {before: func(_ *Permit, c *CheckRequest) { c.AttemptID = uuid.NewString() }, want: "PERMIT_INVALID"},
		"expired": {before: func(p *Permit, _ *CheckRequest) {
			e.admin.Exec(ctx, `UPDATE coordinator.dispatch_permits SET expires_at = now() - interval '1 second' WHERE permit_id = $1`, p.PermitID)
		}, want: "PERMIT_INVALID"},
		"epoch": {before: func(*Permit, *CheckRequest) { e.policy.a.Epoch = 8 }, want: "POLICY_EPOCH_STALE"},
		"decision expired": {before: func(p *Permit, _ *CheckRequest) {
			d, _ := e.dec.Decision(ctx, nil, p.DecisionID)
			d.ExpiresAt = time.Now().Add(-time.Second)
			e.dec.put(d)
		}, want: "DECISION_EXPIRED"},
		"decision deny": {before: func(p *Permit, _ *CheckRequest) {
			d, _ := e.dec.Decision(ctx, nil, p.DecisionID)
			d.Verdict = "deny"
			e.dec.put(d)
		}, want: "PERMIT_INVALID"},
		"approval revoked": {before: func(p *Permit, _ *CheckRequest) {
			e.admin.Exec(ctx, `UPDATE identity.approvals SET revoked_at = now(), revoke_reason = 'user_revoked'
WHERE action_id = $1`, p.ActionID)
		}, want: "PERMIT_INVALID"},
		"hold":    {before: func(*Permit, *CheckRequest) { e.health.holds = []Hold{{HoldID: "h", Reason: "drift"}} }, want: "HOLD_ACTIVE"},
		"session": {before: func(*Permit, *CheckRequest) { e.admin.Exec(ctx, `UPDATE identity.sessions SET state = 'revoked'`) }, want: "PERMIT_INVALID"},
		"node": {before: func(*Permit, *CheckRequest) {
			e.admin.Exec(ctx, `UPDATE coordinator.attempts SET adapter_node_uid = gen_random_uuid()`)
		}, want: "PERMIT_INVALID"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e.policy.a.Epoch, e.health.holds = 7, nil
			e.admin.Exec(ctx, `UPDATE identity.sessions SET state = 'claimed'`)
			p, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.approval(t)))
			if err != nil {
				t.Fatal(err)
			}
			cr := checkFor(p)
			c.before(p, &cr)
			if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, cr); code(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
			if e.scalar(t, `SELECT count(*) FROM coordinator.dispatch_permits WHERE permit_id = $1 AND claimed_at IS NULL`, p.PermitID) != 1 {
				t.Fatal("refused check claimed the permit")
			}
		})
	}
}

func TestStandingRuleAndServiceBudgets(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if _, err := e.admin.Exec(ctx, `INSERT INTO identity.session_budgets (session_id, standing_rule_id, max_actions, expires_at)
VALUES ($1, 'standing.k8s_read.v1', 1, now() + interval '30 minutes')`, e.session); err != nil {
		t.Fatal(err)
	}
	standing := func() Decision {
		d := Decision{DecisionID: uuid.NewString(), RequestID: uuid.NewString(), ActionID: uuid.NewString(), ActionDigest: digest('a'),
			AdapterID: "receiver", Verdict: "allow", DecisionBasis: "standing_rule", StandingRuleID: "standing.k8s_read.v1",
			PolicyEpoch: 7, OPABundleRevision: opaRev, CatalogDigest: catalogD, ExpiresAt: time.Now().Add(time.Minute),
			SessionID: e.session, WorkloadID: "agent-exec/agent-runtime", OperationID: "k8s.pods.list", TargetID: "k8s-agent-targets"}
		e.dec.put(d)
		return d
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(standing())); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(standing())); code(err) != "SESSION_BUDGET_EXHAUSTED" {
		t.Fatalf("second standing: %v", err)
	}

	svcSess := uuid.NewString()
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.service_sessions (service_session_id, caller_principal, authenticated_actor, profile, tenant, issue_id,
    state, created_at, expires_at)
VALUES ($1, 'policy-proposer', 'service:agent-observe/policy-proposer', 'policy_proposal', 'hackathon', gen_random_uuid(),
    'active', now(), now() + interval '15 minutes')`, svcSess); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO identity.service_session_counters (service_session_id, counter, max_value)
VALUES ($1, 'model', 1), ($1, 'read_tools', 6)`, svcSess); err != nil {
		t.Fatal(err)
	}
	service := func(op string) Decision {
		d := Decision{DecisionID: uuid.NewString(), RequestID: uuid.NewString(), ActionID: uuid.NewString(), ActionDigest: digest('a'),
			AdapterID: "receiver", Verdict: "allow", DecisionBasis: "service_scope", ServiceSessionID: svcSess,
			PolicyEpoch: 7, OPABundleRevision: opaRev, CatalogDigest: catalogD, ExpiresAt: time.Now().Add(time.Minute),
			OperationID: op, TargetID: "agent-platform-gemini"}
		e.dec.put(d)
		return d
	}
	p, err := e.svc.Reserve(ctx, e.adapter, reqFor(service("model.generate")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(service("model.generate"))); code(err) != "TOOL_BUDGET_EXHAUSTED" {
		t.Fatalf("model over budget: %v", err)
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(service("receiver.submit"))); code(err) != "TOOL_BUDGET_EXHAUSTED" {
		t.Fatalf("operation without a counter: %v", err)
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(service("evidence.audit.query"))); err != nil {
		t.Fatalf("read tool: %v", err)
	}
	if _, err := e.svc.release(ctx, p.AttemptID, ByAdapter, []string{"HOLD_ACTIVE"}, &e.adapter); err != nil {
		t.Fatal(err)
	}
	if e.scalar(t, `SELECT used_value FROM identity.service_session_counters WHERE service_session_id = $1 AND counter = 'model'`, svcSess) != 0 {
		t.Fatal("service counter not restored")
	}
	// A session without a candidate uses its own counters only.
	if e.scalar(t, `SELECT count(*) FROM identity.issue_candidate_counters`) != 0 {
		t.Fatal("a session without a candidate touched candidate counters")
	}
}

// ---- candidate counters ------------------------------------------------------

// candidateSession inserts a policy_proposal service session for a candidate
// the way identity's CreateService does (services/identity/internal/sessions,
// not importable here): the candidate row and its counter rows at 0 on the
// first session, and the session's own counters with used_value 0 (nothing
// copied from earlier sessions).
func (e *env) candidateSession(t *testing.T, issue, cand string, model int) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.issue_candidates (issue_id, candidate_id, created_at) VALUES ($1, $2, now()) ON CONFLICT DO NOTHING;`,
		issue, cand); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.issue_candidate_counters (issue_id, candidate_id, counter, used_value)
VALUES ($1, $2, 'model', 0), ($1, $2, 'read_tools', 0) ON CONFLICT DO NOTHING`, issue, cand); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.service_sessions (service_session_id, caller_principal, authenticated_actor, profile, tenant, issue_id,
    candidate_id, state, created_at, expires_at)
VALUES ($1, 'policy-proposer', 'service:agent-observe/policy-proposer', 'policy_proposal', 'hackathon', $2, $3,
    'active', now(), now() + interval '15 minutes')`, id, issue, cand); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO identity.service_session_counters (service_session_id, counter, max_value, used_value)
VALUES ($1, 'model', $2, 0), ($1, 'read_tools', 2, 0)`, id, model); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *env) serviceDecision(sess, op string) Decision {
	d := Decision{DecisionID: uuid.NewString(), RequestID: uuid.NewString(), ActionID: uuid.NewString(), ActionDigest: digest('a'),
		AdapterID: "receiver", Verdict: "allow", DecisionBasis: "service_scope", ServiceSessionID: sess,
		PolicyEpoch: 7, OPABundleRevision: opaRev, CatalogDigest: catalogD, ExpiresAt: time.Now().Add(time.Minute),
		OperationID: op, TargetID: "agent-platform-gemini"}
	e.dec.put(d)
	return d
}

func (e *env) reserveModel(t *testing.T, sess string) *Permit {
	t.Helper()
	p, err := e.svc.Reserve(context.Background(), e.adapter, reqFor(e.serviceDecision(sess, "model.generate")))
	if err != nil {
		t.Fatalf("reserve on %s: %v", sess, err)
	}
	return p
}

func (e *env) mustExhaust(t *testing.T, sess string) {
	t.Helper()
	if _, err := e.svc.Reserve(context.Background(), e.adapter, reqFor(e.serviceDecision(sess, "model.generate"))); code(err) != "TOOL_BUDGET_EXHAUSTED" {
		t.Fatalf("reserve on %s: %v, want TOOL_BUDGET_EXHAUSTED", sess, err)
	}
}

func (e *env) candUsed(t *testing.T, issue, cand string) int {
	return e.scalar(t, `SELECT used_value FROM identity.issue_candidate_counters
WHERE issue_id = $1 AND candidate_id = $2 AND counter = 'model'`, issue, cand)
}

func (e *env) sessUsed(t *testing.T, sess string) int {
	return e.scalar(t, `SELECT used_value FROM identity.service_session_counters WHERE service_session_id = $1 AND counter = 'model'`, sess)
}

func (e *env) expireSession(t *testing.T, sess string) {
	t.Helper()
	if _, err := e.admin.Exec(context.Background(), `
UPDATE identity.service_sessions SET expires_at = statement_timestamp() - interval '1 second' WHERE service_session_id = $1`, sess); err != nil {
		t.Fatal(err)
	}
}

// checkBooks asserts that every candidate counter is the sum of its
// sessions' own uses.
func (e *env) checkBooks(t *testing.T) {
	t.Helper()
	if bad := e.scalar(t, `
SELECT count(*) FROM identity.issue_candidate_counters cc
WHERE cc.used_value <> (
    SELECT coalesce(sum(sc.used_value), 0) FROM identity.service_session_counters sc
    JOIN identity.service_sessions s USING (service_session_id)
    WHERE s.issue_id = cc.issue_id AND s.candidate_id = cc.candidate_id AND sc.counter = cc.counter)`); bad != 0 {
		t.Fatalf("%d candidate counters differ from the sum of their sessions", bad)
	}
}

// Rina's case at the coordinator: A uses the candidate's whole model budget
// with its last permits unclaimed, A expires, B is issued for the same
// candidate, then A's permits are released (adapter outcome and permit-expiry
// sweeper). The uses return to the candidate counter, so B can use them.
func TestCandidateLateReleaseAfterReissue(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	const n = 3
	issue, cand := uuid.NewString(), uuid.NewString()
	a := e.candidateSession(t, issue, cand, n)
	var permits []*Permit
	for i := 0; i < n; i++ {
		permits = append(permits, e.reserveModel(t, a))
	}
	if _, err := e.svc.Check(ctx, e.adapter, permits[0].PermitID, checkFor(permits[0])); err != nil {
		t.Fatal(err)
	}
	e.mustExhaust(t, a)
	if e.candUsed(t, issue, cand) != n || e.sessUsed(t, a) != n {
		t.Fatalf("after A: candidate %d, A %d", e.candUsed(t, issue, cand), e.sessUsed(t, a))
	}
	e.expireSession(t, a)

	b := e.candidateSession(t, issue, cand, n)
	e.mustExhaust(t, b) // the candidate is at n, B's own row at 0
	if e.sessUsed(t, b) != 0 {
		t.Fatal("refused reservation on B left a use")
	}

	// Credential failure before the claim of A's last permit.
	last := permits[n-1]
	if _, err := e.svc.release(ctx, last.AttemptID, ByAdapter, []string{"CREDENTIAL_UNAVAILABLE"}, &e.adapter); err != nil {
		t.Fatal(err)
	}
	if e.candUsed(t, issue, cand) != n-1 || e.sessUsed(t, a) != n-1 {
		t.Fatalf("after release: candidate %d, A %d", e.candUsed(t, issue, cand), e.sessUsed(t, a))
	}
	// A duplicate release returns the stored result and restores nothing.
	if r, err := e.svc.release(ctx, last.AttemptID, ByAdapter, []string{"CREDENTIAL_UNAVAILABLE"}, &e.adapter); err != nil || r.State != "released" {
		t.Fatalf("duplicate release: %v %+v", err, r)
	}
	if e.candUsed(t, issue, cand) != n-1 || e.sessUsed(t, a) != n-1 {
		t.Fatalf("duplicate release restored again: candidate %d, A %d", e.candUsed(t, issue, cand), e.sessUsed(t, a))
	}

	// A's second permit expires unclaimed; the sweeper releases it.
	if _, err := e.admin.Exec(ctx, `UPDATE coordinator.dispatch_permits SET expires_at = now() - interval '1 second' WHERE permit_id = $1`,
		permits[n-2].PermitID); err != nil {
		t.Fatal(err)
	}
	if r, err := e.svc.Sweep(ctx); err != nil || r.Released != 1 || r.Failed != 0 {
		t.Fatalf("sweep: %+v %v", r, err)
	}
	if r, err := e.svc.Sweep(ctx); err != nil || r.Candidates != 0 {
		t.Fatalf("second sweep: %+v %v", r, err)
	}
	if e.candUsed(t, issue, cand) != n-2 || e.sessUsed(t, a) != n-2 {
		t.Fatalf("after sweep: candidate %d, A %d", e.candUsed(t, issue, cand), e.sessUsed(t, a))
	}
	e.checkBooks(t)

	// B gets exactly the two uses back, then the candidate is spent again.
	e.reserveModel(t, b)
	e.reserveModel(t, b)
	e.mustExhaust(t, b)
	if e.candUsed(t, issue, cand) != n || e.sessUsed(t, a) != n-2 || e.sessUsed(t, b) != 2 {
		t.Fatalf("end: candidate %d, A %d, B %d", e.candUsed(t, issue, cand), e.sessUsed(t, a), e.sessUsed(t, b))
	}
	e.checkBooks(t)
	if got := e.audit.count("attempt_released"); got != 2 {
		t.Fatalf("%d attempt_released events", got)
	}
}

// Concurrent reservations on a live candidate session never pass the
// candidate's usage over the session maximum.
func TestCandidateConcurrentReservations(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	issue, cand := uuid.NewString(), uuid.NewString()
	a := e.candidateSession(t, issue, cand, 4)
	e.reserveModel(t, a)
	e.reserveModel(t, a)
	e.expireSession(t, a)
	b := e.candidateSession(t, issue, cand, 4)
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.svc.Reserve(ctx, e.adapter, reqFor(e.serviceDecision(b, "model.generate")))
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch code(err) {
		case "":
			ok++
		case "TOOL_BUDGET_EXHAUSTED":
		default:
			t.Errorf("unexpected: %v", err)
		}
	}
	if ok != 2 || e.candUsed(t, issue, cand) != 4 || e.sessUsed(t, b) != 2 {
		t.Fatalf("ok=%d candidate %d B %d", ok, e.candUsed(t, issue, cand), e.sessUsed(t, b))
	}
	e.checkBooks(t)
}

// Two candidates of one issue have separate counters.
func TestCandidateCountersIndependent(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	issue, c1, c2 := uuid.NewString(), uuid.NewString(), uuid.NewString()
	s1, s2 := e.candidateSession(t, issue, c1, 1), e.candidateSession(t, issue, c2, 1)
	p1 := e.reserveModel(t, s1)
	e.mustExhaust(t, s1)
	e.reserveModel(t, s2)
	e.mustExhaust(t, s2)
	if _, err := e.svc.release(ctx, p1.AttemptID, ByAdapter, []string{"HOLD_ACTIVE"}, &e.adapter); err != nil {
		t.Fatal(err)
	}
	if u1, u2 := e.candUsed(t, issue, c1), e.candUsed(t, issue, c2); u1 != 0 || u2 != 1 {
		t.Fatalf("candidates %d %d", u1, u2)
	}
	e.mustExhaust(t, s2)
	e.reserveModel(t, s1)
	e.checkBooks(t)
}

// A candidate session whose candidate counter row is missing is a
// state-store fault, not a spent budget, and leaves nothing behind.
func TestCandidateCounterRowMissing(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	issue, cand := uuid.NewString(), uuid.NewString()
	a := e.candidateSession(t, issue, cand, 2)
	if _, err := e.admin.Exec(ctx, `DELETE FROM identity.issue_candidate_counters WHERE issue_id = $1 AND counter = 'model'`, issue); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.serviceDecision(a, "model.generate"))); code(err) != "STATE_STORE_UNAVAILABLE" {
		t.Fatalf("got %v", err)
	}
	if e.rows(t) != 0 || e.sessUsed(t, a) != 0 {
		t.Fatal("a refused reservation left state behind")
	}
}

// A release whose candidate counter has no use to give back rolls the whole
// release back: the attempt stays planned and the session keeps its use.
func TestCandidateRestoreBooks(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	issue, cand := uuid.NewString(), uuid.NewString()
	a := e.candidateSession(t, issue, cand, 2)
	p := e.reserveModel(t, a)
	if _, err := e.admin.Exec(ctx, `UPDATE identity.issue_candidate_counters SET used_value = 0 WHERE issue_id = $1`, issue); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.release(ctx, p.AttemptID, ByAdapter, []string{"CREDENTIAL_UNAVAILABLE"}, &e.adapter); code(err) != "STATE_STORE_UNAVAILABLE" {
		t.Fatalf("got %v", err)
	}
	if e.sessUsed(t, a) != 1 || e.scalar(t, `SELECT count(*) FROM coordinator.attempts WHERE attempt_id = $1 AND state = 'planned'`, p.AttemptID) != 1 {
		t.Fatal("failed release changed state")
	}
}

func TestAuthenticate(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if e.adapter.AdapterID != "receiver" || e.adapter.NodeUID != adapterNode || e.adapter.BootID != adapterBoot {
		t.Fatalf("adapter %+v", e.adapter)
	}
	for name, c := range map[string]*x509.Certificate{
		"unknown serial": leaf(t, "0abc02", adapterSAN),
		"other SAN":      leaf(t, certSerial, "spiffe://agentarium.internal/ns/agent-adapters/sa/model-adapter"),
	} {
		if _, err := e.svc.Authenticate(ctx, c); code(err) != "AUTH_REQUIRED" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.admin.Exec(ctx, `UPDATE identity.issued_certificates SET revoked_at = now()`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, leaf(t, certSerial, adapterSAN)); code(err) != "AUTH_REQUIRED" {
		t.Fatalf("revoked: %v", err)
	}
}

func TestLockTimeout(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	d := e.approval(t)
	tx, err := e.admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT 1 FROM identity.approvals WHERE approval_id = $1 FOR UPDATE`, d.ApprovalID); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(d)); code(err) != "LOCK_TIMEOUT" {
		t.Fatalf("got %v", err)
	}
	if el := time.Since(start); el < time.Second || el > 5*time.Second {
		t.Fatalf("waited %v", el)
	}
}
