//go:build integration

package dispatch

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---- fixtures ---------------------------------------------------------------

const releaserSAN = "spiffe://agentarium.internal/ns/agent-release/sa/releaser"

// claimed reserves and claims a permit for a new approval action.
func (e *env) claimed(t *testing.T) (*Permit, Decision) {
	t.Helper()
	ctx := context.Background()
	d := e.approval(t)
	p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); err != nil {
		t.Fatal(err)
	}
	return p, d
}

func fullObs(id string) Observation {
	o := obsFor(id)
	fin, at, pr := "2026-10-15T10:00:00.2Z", "2026-10-15T10:00:01Z", "req-1"
	o.SendFinishedAt, o.ResponseAt, o.ProviderRequestID = &fin, &at, &pr
	return o
}

func (e *env) state(t *testing.T, attemptID string) string {
	t.Helper()
	var s string
	if err := e.admin.QueryRow(context.Background(), `SELECT state FROM coordinator.attempts WHERE attempt_id = $1`, attemptID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	if err == nil {
		return ""
	}
	return "other: " + err.Error()
}

// execRole runs sql as role and commits; it returns the first column of the
// first row as text, or the error.
func (e *env) execRole(t *testing.T, role, sql string, args ...any) (string, error) {
	t.Helper()
	ctx := context.Background()
	var out string
	err := pgx.BeginFunc(ctx, e.admin, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
			return err
		}
		var v *string
		if err := tx.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
			return err
		}
		if v != nil {
			out = *v
		}
		return nil
	})
	return out, err
}

type releaser struct {
	leaf    *x509.Certificate
	token   string
	session string
	change  string
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// releaser makes a releaser certificate and an activation_probe service
// session with a probe_actions budget of 4 and its token.
func (e *env) releaser(t *testing.T) releaser {
	t.Helper()
	ctx := context.Background()
	r := releaser{session: uuid.NewString(), change: uuid.NewString()}
	serial := "5a" + randHex(7)
	r.leaf = leaf(t, serial, releaserSAN)
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	r.token = base64.RawURLEncoding.EncodeToString(b)
	digest := sha256.Sum256([]byte(r.token))
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal)
VALUES ('agent-release', 'releaser', 'service', NULL, 'releaser') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.issued_certificates (serial, san_uri, namespace, ksa, pod_uid, issued_at, expires_at)
VALUES ($1, $2, 'agent-release', 'releaser', gen_random_uuid(), now(), now() + interval '1 day')`, serial, releaserSAN); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `
INSERT INTO identity.service_sessions (service_session_id, caller_principal, authenticated_actor, profile, tenant, change_id,
    state, created_at, expires_at)
VALUES ($1, 'releaser', 'service:agent-release/releaser', 'activation_probe', 'hackathon', $2, 'active', now(), now() + interval '10 minutes')`,
		r.session, r.change); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO identity.service_session_counters (service_session_id, counter, max_value)
VALUES ($1, 'probe_actions', 4)`, r.session); err != nil {
		t.Fatal(err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO identity.session_tokens (token_digest, service_session_id, bound_identity, issued_at)
VALUES ($1, $2, $3, now())`, digest[:], r.session, releaserSAN); err != nil {
		t.Fatal(err)
	}
	return r
}

func (e *env) caller(t *testing.T, r releaser) ServiceCaller {
	t.Helper()
	c, err := e.svc.AuthenticateService(context.Background(), r.leaf, r.token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// register registers a probe for r with key against epoch.
func (e *env) register(t *testing.T, r releaser, key string, epoch int64) string {
	t.Helper()
	out, _, err := e.svc.RegisterProbe(context.Background(), e.caller(t, r), ProbeRequest{ChangeID: r.change, ClientRequestKey: key, TargetEpoch: epoch})
	if err != nil {
		t.Fatal(err)
	}
	return out.ActivationProbeID
}

func (e *env) bind(t *testing.T, sess, key, action string) (string, error) {
	return e.execRole(t, "gateway_app", `SELECT coordinator.bind_activation_probe_action($1, $2, $3)::text`, sess, key, action)
}

// probeDecision is an allow decision for a new action bound to a new probe
// of r (registered against epoch).
func (e *env) probeDecision(t *testing.T, r releaser, epoch int64) Decision {
	t.Helper()
	key := "probe-" + randHex(6)
	probeID := e.register(t, r, key, epoch)
	action := uuid.NewString()
	if _, err := e.bind(t, r.session, key, action); err != nil {
		t.Fatal(err)
	}
	d := Decision{DecisionID: uuid.NewString(), RequestID: uuid.NewString(), ActionID: action, ActionDigest: digest('a'),
		AdapterID: "receiver", Verdict: "allow", DecisionBasis: "activation_probe", ServiceSessionID: r.session,
		ActivationProbeID: probeID, PolicyEpoch: 7, OPABundleRevision: opaRev, CatalogDigest: catalogD,
		ExpiresAt: time.Now().Add(time.Minute), OperationID: "receiver.submit", TargetID: "receiver-probe"}
	e.dec.put(d)
	return d
}

func (e *env) probeUsed(t *testing.T, r releaser) int {
	return e.scalar(t, `SELECT used_value FROM identity.service_session_counters WHERE service_session_id = $1 AND counter = 'probe_actions'`, r.session)
}

// ---- outcome ----------------------------------------------------------------

func TestOutcomeTransitions(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	type step struct {
		transition string
		reasons    []string
		want       string // reason code, "" for success
	}
	paths := map[string][]step{
		"dispatched then response": {{"dispatched", nil, ""}, {"response_received", nil, ""}},
		"direct response":          {{"response_received", []string{"TARGET_REJECTED"}, ""}},
		"failed":                   {{"failed", []string{"TLS_VERIFY_FAILED"}, ""}},
		"unknown":                  {{"unknown", []string{"TARGET_UNAVAILABLE"}, ""}},
		"dispatched then unknown":  {{"dispatched", nil, ""}, {"unknown", []string{"TARGET_UNAVAILABLE"}, ""}},
		"dispatched then failed":   {{"dispatched", nil, ""}, {"failed", []string{"TLS_VERIFY_FAILED"}, "PERMIT_INVALID"}},
		"response then unknown":    {{"response_received", nil, ""}, {"unknown", []string{"TARGET_UNAVAILABLE"}, "PERMIT_INVALID"}},
		"failed then dispatched":   {{"failed", []string{"TLS_VERIFY_FAILED"}, ""}, {"dispatched", nil, "PERMIT_INVALID"}},
		"unknown then response":    {{"unknown", []string{"TARGET_UNAVAILABLE"}, ""}, {"response_received", nil, "PERMIT_INVALID"}},
		"response then dispatched": {{"response_received", nil, ""}, {"dispatched", nil, "PERMIT_INVALID"}},
	}
	obsFn := map[string]func(string) Observation{
		"dispatched": obsFor, "response_received": fullObs, "failed": failedObs, "unknown": obsFor,
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			p, d := e.claimed(t)
			want := "claimed"
			for _, s := range path {
				res, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, s.transition, obsFn[s.transition](p.AttemptID), s.reasons)
				if code(err) != s.want {
					t.Fatalf("%s: got %v, want %q", s.transition, err, s.want)
				}
				if err == nil {
					want = s.transition
					if res.State != s.transition || res.BudgetRestored {
						t.Fatalf("result %+v", res)
					}
				}
				if got := e.state(t, p.AttemptID); got != want {
					t.Fatalf("state %s, want %s", got, want)
				}
			}
			if e.used(t, d) != 1 || e.scalar(t, `SELECT count(*) FROM coordinator.reservations WHERE action_id = $1 AND state = 'committed'`, d.ActionID) != 1 {
				t.Fatal("a post-claim transition touched the budget or the reservation")
			}
		})
	}
	if n := e.audit.count("dispatch_started") + e.audit.count("response_received") + e.audit.count("attempt_failed") + e.audit.count("attempt_uncertain"); n != 0 {
		t.Fatalf("coordinator appended %d TASK-05 events", n)
	}

	t.Run("before claim", func(t *testing.T) {
		p, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.approval(t)))
		if err != nil {
			t.Fatal(err)
		}
		for _, tr := range []string{"dispatched", "failed", "unknown", "response_received"} {
			o := obsFor(p.AttemptID)
			switch tr {
			case "response_received":
				o = fullObs(p.AttemptID)
			case "failed":
				o = failedObs(p.AttemptID)
			}
			if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, tr, o, []string{"TARGET_UNAVAILABLE"}); code(err) != "PERMIT_INVALID" {
				t.Fatalf("%s on planned: %v", tr, err)
			}
		}
		// released → failed
		if _, err := e.svc.release(ctx, p.AttemptID, ByAdapter, []string{"CREDENTIAL_UNAVAILABLE"}, &e.adapter); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, "failed", failedObs(p.AttemptID), []string{"TLS_VERIFY_FAILED"}); code(err) != "PERMIT_INVALID" {
			t.Fatalf("failed on released: %v", err)
		}
	})

	t.Run("caller", func(t *testing.T) {
		p, _ := e.claimed(t)
		other := e.adapter
		other.AdapterID = "model"
		if _, err := e.svc.Outcome(ctx, other, p.AttemptID, "dispatched", obsFor(p.AttemptID), nil); code(err) != "RESOURCE_NOT_FOUND" {
			t.Fatalf("other adapter: %v", err)
		}
		missing := uuid.NewString()
		if _, err := e.svc.Outcome(ctx, e.adapter, missing, "dispatched", obsFor(missing), nil); code(err) != "RESOURCE_NOT_FOUND" {
			t.Fatalf("missing attempt: %v", err)
		}
		if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, "dispatched", obsFor(uuid.NewString()), nil); code(err) != "SCHEMA_INVALID" {
			t.Fatalf("observation of another attempt: %v", err)
		}
		// failed is a failure before WroteHeaders: any send or response
		// time is refused.
		at := "2026-10-15T10:00:00.1Z"
		for name, mod := range map[string]func(*Observation){
			"send_started_at":  func(o *Observation) { o.SendStartedAt = &at },
			"send_finished_at": func(o *Observation) { o.SendFinishedAt = &at },
			"response_at":      func(o *Observation) { o.ResponseAt = &at },
		} {
			o := failedObs(p.AttemptID)
			mod(&o)
			if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, "failed", o, []string{"TLS_VERIFY_FAILED"}); code(err) != "SCHEMA_INVALID" {
				t.Fatalf("failed with %s: %v", name, err)
			}
		}
		// Correlation cannot join an unspecified or zoned address, so the
		// coordinator refuses it.
		for name, mod := range map[string]func(*Observation){
			"unspecified local_addr": func(o *Observation) { v := "0.0.0.0"; o.LocalAddr = &v },
			"unspecified peer_addr":  func(o *Observation) { v := "::"; o.PeerAddr = &v },
			"zoned local_addr":       func(o *Observation) { v := "fe80::1%eth0"; o.LocalAddr = &v },
		} {
			o := obsFor(p.AttemptID)
			mod(&o)
			if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, "dispatched", o, nil); code(err) != "SCHEMA_INVALID" {
				t.Fatalf("dispatched with %s: %v", name, err)
			}
		}
		if e.state(t, p.AttemptID) != "claimed" {
			t.Fatal("refused outcome changed the attempt")
		}
	})
}

func TestOutcomeIdempotencyAndObservation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	p, _ := e.claimed(t)
	id := p.AttemptID

	// dispatched, stored and replayed.
	r1, err := e.svc.Outcome(ctx, e.adapter, id, "dispatched", obsFor(id), nil)
	if err != nil {
		t.Fatal(err)
	}
	var local, peer, dialed, kind, pod string
	var lport, pport int
	var inode int64
	var resp *time.Time
	if err := e.admin.QueryRow(ctx, `SELECT host(local_addr), local_port, host(peer_addr), peer_port, netns_inode, host(dialed_addr),
    peer_addr_kind, pod_uid::text, response_at FROM coordinator.attempt_observations WHERE attempt_id = $1`, id).Scan(
		&local, &lport, &peer, &pport, &inode, &dialed, &kind, &pod, &resp); err != nil {
		t.Fatal(err)
	}
	if local != "10.0.0.5" || lport != 40000 || peer != "10.1.0.9" || pport != 443 || inode != 4026531992 || dialed != "10.1.0.9" ||
		kind != "service_vip" || pod != "8c1e0000-0000-4000-8000-0000000000aa" || resp != nil {
		t.Fatalf("stored %s %d %s %d %d %s %s %s %v", local, lport, peer, pport, inode, dialed, kind, pod, resp)
	}
	r2, err := e.svc.Outcome(ctx, e.adapter, id, "dispatched", obsFor(id), []string{})
	if err != nil || r2.State != r1.State {
		t.Fatalf("replay: %v %+v", err, r2)
	}
	changed := obsFor(id)
	port := int64(40001)
	changed.LocalPort = &port
	if _, err := e.svc.Outcome(ctx, e.adapter, id, "dispatched", changed, nil); code(err) != "PERMIT_INVALID" {
		t.Fatalf("replay with another observation: %v", err)
	}
	if _, err := e.svc.Outcome(ctx, e.adapter, id, "dispatched", obsFor(id), []string{"TARGET_UNAVAILABLE"}); code(err) != "PERMIT_INVALID" {
		t.Fatalf("replay with other reasons: %v", err)
	}
	// response_received may add fields but not change recorded ones.
	bad := fullObs(id)
	bad.LocalPort = &port
	if _, err := e.svc.Outcome(ctx, e.adapter, id, "response_received", bad, nil); code(err) != "PERMIT_INVALID" {
		t.Fatalf("changed recorded field: %v", err)
	}
	if _, err := e.svc.Outcome(ctx, e.adapter, id, "response_received", fullObs(id), nil); err != nil {
		t.Fatal(err)
	}
	if e.scalar(t, `SELECT count(*) FROM coordinator.attempt_observations WHERE attempt_id = $1 AND response_at IS NOT NULL
    AND send_finished_at IS NOT NULL AND provider_request_id = 'req-1' AND local_port = 40000`, id) != 1 {
		t.Fatal("response_received did not extend the observation")
	}
	if _, err := e.svc.Outcome(ctx, e.adapter, id, "response_received", fullObs(id), nil); err != nil {
		t.Fatalf("response replay: %v", err)
	}
	// A replay of the earlier transition after the later one is a conflict.
	if _, err := e.svc.Outcome(ctx, e.adapter, id, "dispatched", obsFor(id), nil); code(err) != "PERMIT_INVALID" {
		t.Fatalf("earlier transition replayed: %v", err)
	}

	// Concurrent identical reports: all succeed, one transition.
	p2, _ := e.claimed(t)
	var wg sync.WaitGroup
	errs := make([]error, 10)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.svc.Outcome(ctx, e.adapter, p2.AttemptID, "dispatched", obsFor(p2.AttemptID), nil)
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent replay: %v", err)
		}
	}

	// Concurrent contradictory reports: one transition wins, its replays
	// succeed, the other transition is refused.
	p3, _ := e.claimed(t)
	results := make([]error, 10)
	transitions := make([]string, 10)
	for i := range results {
		transitions[i] = []string{"failed", "unknown"}[i%2]
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = e.svc.Outcome(ctx, e.adapter, p3.AttemptID, transitions[i], failedObs(p3.AttemptID), []string{"TARGET_UNAVAILABLE"})
		}(i)
	}
	wg.Wait()
	final := e.state(t, p3.AttemptID)
	for i, err := range results {
		want := ""
		if transitions[i] != final {
			want = "PERMIT_INVALID"
		}
		if code(err) != want {
			t.Fatalf("%s with final %s: %v", transitions[i], final, err)
		}
	}
}

func TestOutcomeHTTP(t *testing.T) {
	e := setup(t)
	p, _ := e.claimed(t)
	mux := http.NewServeMux()
	(&Handler{Svc: e.svc}).Register(mux)
	send := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/internal/dispatch/attempts/"+p.AttemptID+"/outcome", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf(t, certSerial, adapterSAN)}}}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	obs, _ := json.Marshal(obsFor(p.AttemptID))
	for name, c := range map[string]struct {
		body string
		want int
	}{
		"no observation":      {`{"transition":"dispatched","reason_codes":[]}`, http.StatusUnprocessableEntity},
		"null observation":    {`{"transition":"dispatched","observation":null,"reason_codes":[]}`, http.StatusUnprocessableEntity},
		"unknown obs field":   {`{"transition":"dispatched","observation":{"attempt_id":"` + p.AttemptID + `","process_exec_id":"x"},"reason_codes":[]}`, http.StatusUnprocessableEntity},
		"resolved transition": {`{"transition":"resolved","observation":` + string(obs) + `,"reason_codes":[]}`, http.StatusUnprocessableEntity},
		"dispatched":          {`{"transition":"dispatched","observation":` + string(obs) + `,"reason_codes":[]}`, http.StatusOK},
	} {
		if rec := send(c.body); rec.Code != c.want {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}

// ---- sweeper case 2 ---------------------------------------------------------

func (e *env) age(t *testing.T, attemptID string) {
	t.Helper()
	if _, err := e.admin.Exec(context.Background(), `UPDATE coordinator.attempts SET claimed_at = now() - interval '61 seconds' WHERE attempt_id = $1`,
		attemptID); err != nil {
		t.Fatal(err)
	}
}

func TestSweeperOutcomeTimeout(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	silentClaimed, d1 := e.claimed(t)
	silentDispatched, d2 := e.claimed(t)
	if _, err := e.svc.Outcome(ctx, e.adapter, silentDispatched.AttemptID, "dispatched", obsFor(silentDispatched.AttemptID), nil); err != nil {
		t.Fatal(err)
	}
	fresh, _ := e.claimed(t)
	answered, _ := e.claimed(t)
	if _, err := e.svc.Outcome(ctx, e.adapter, answered.AttemptID, "response_received", fullObs(answered.AttemptID), nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*Permit{silentClaimed, silentDispatched, answered} {
		e.age(t, p.AttemptID)
	}
	r, err := e.svc.Sweep(ctx)
	if err != nil || r.Uncertain != 2 || r.Released != 0 || r.Failed != 0 || r.Candidates != 2 {
		t.Fatalf("sweep %+v %v", r, err)
	}
	for _, c := range []struct {
		p    *Permit
		want string
	}{{silentClaimed, "unknown"}, {silentDispatched, "unknown"}, {fresh, "claimed"}, {answered, "response_received"}} {
		if got := e.state(t, c.p.AttemptID); got != c.want {
			t.Fatalf("%s: %s, want %s", c.p.AttemptID, got, c.want)
		}
	}
	if e.scalar(t, `SELECT count(*) FROM coordinator.attempts WHERE state = 'unknown' AND reason_codes = '{OUTCOME_TIMEOUT}'`) != 2 {
		t.Fatal("reason_codes")
	}
	if e.used(t, d1) != 1 || e.used(t, d2) != 1 {
		t.Fatal("outcome timeout restored budget")
	}
	e.audit.mu.Lock()
	n := 0
	for _, ev := range e.audit.events {
		if ev.Type == "attempt_uncertain" {
			n++
			if ev.Payload["stage"] != "outcome_timeout" || len(ev.Payload["reason_codes"].([]string)) != 1 ||
				ev.Payload["reason_codes"].([]string)[0] != "OUTCOME_TIMEOUT" {
				t.Errorf("payload %v", ev.Payload)
			}
		}
	}
	e.audit.mu.Unlock()
	if n != 2 {
		t.Fatalf("attempt_uncertain events %d", n)
	}
	// The adapter's late report is refused; unknown is left only through
	// resolve_unknown_attempt.
	if _, err := e.svc.Outcome(ctx, e.adapter, silentDispatched.AttemptID, "response_received", fullObs(silentDispatched.AttemptID), nil); code(err) != "PERMIT_INVALID" {
		t.Fatalf("late response: %v", err)
	}
	if r, err := e.svc.Sweep(ctx); err != nil || r.Candidates != 0 {
		t.Fatalf("second sweep %+v %v", r, err)
	}
	// An audit failure rolls the transition back and counts as failed.
	stuck, _ := e.claimed(t)
	e.age(t, stuck.AttemptID)
	e.audit.mu.Lock()
	e.audit.err = errors.New("audit down")
	e.audit.mu.Unlock()
	r, err = e.svc.Sweep(ctx)
	e.audit.mu.Lock()
	e.audit.err = nil
	e.audit.mu.Unlock()
	if err != nil || r.Failed != 1 || e.state(t, stuck.AttemptID) != "claimed" {
		t.Fatalf("audit failure: %+v %v %s", r, err, e.state(t, stuck.AttemptID))
	}
}

func TestSweeperRacesOutcome(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		p, _ := e.claimed(t)
		e.age(t, p.AttemptID)
		var wg sync.WaitGroup
		var outErr error
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = e.svc.Sweep(ctx) }()
		go func() {
			defer wg.Done()
			_, outErr = e.svc.Outcome(ctx, e.adapter, p.AttemptID, "response_received", fullObs(p.AttemptID), nil)
		}()
		wg.Wait()
		switch st := e.state(t, p.AttemptID); {
		case st == "response_received" && outErr == nil:
		case st == "unknown" && code(outErr) == "PERMIT_INVALID":
		default:
			t.Fatalf("state %s with outcome %v", st, outErr)
		}
	}
}

func TestSweepBatchSharedByBothCases(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	for i := 0; i < 60; i++ {
		p, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.approval(t)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.admin.Exec(ctx, `UPDATE coordinator.dispatch_permits SET expires_at = now() - interval '1 second' WHERE permit_id = $1`, p.PermitID); err != nil {
			t.Fatal(err)
		}
		c, _ := e.claimed(t)
		e.age(t, c.AttemptID)
	}
	r, err := e.svc.Sweep(ctx)
	if err != nil || r.Candidates != SweepBatch || r.Released != 60 || r.Uncertain != SweepBatch-60 || r.Failed != 0 {
		t.Fatalf("first sweep %+v %v", r, err)
	}
	r, err = e.svc.Sweep(ctx)
	if err != nil || r.Candidates != 20 || r.Uncertain != 20 {
		t.Fatalf("second sweep %+v %v", r, err)
	}
}

// ---- activation probes ------------------------------------------------------

func TestAuthenticateService(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	r := e.releaser(t)
	c := e.caller(t, r)
	if c.ServiceSessionID != r.session || c.Profile != "activation_probe" || c.ChangeID != r.change || c.SAN != releaserSAN {
		t.Fatalf("caller %+v", c)
	}
	digest := func(tok string) []byte { d := sha256.Sum256([]byte(tok)); return d[:] }
	cases := map[string]func(r releaser) (*x509.Certificate, string){
		"wrong token":    func(r releaser) (*x509.Certificate, string) { return r.leaf, r.token + "x" },
		"empty token":    func(r releaser) (*x509.Certificate, string) { return r.leaf, "" },
		"adapter cert":   func(r releaser) (*x509.Certificate, string) { return leaf(t, certSerial, adapterSAN), r.token },
		"unknown serial": func(r releaser) (*x509.Certificate, string) { return leaf(t, "5b01", releaserSAN), r.token },
		"revoked token": func(r releaser) (*x509.Certificate, string) {
			e.admin.Exec(ctx, `UPDATE identity.session_tokens SET revoked_at = now() WHERE token_digest = $1`, digest(r.token))
			return r.leaf, r.token
		},
		"token of another SAN": func(r releaser) (*x509.Certificate, string) {
			e.admin.Exec(ctx, `UPDATE identity.session_tokens SET bound_identity = 'spiffe://agentarium.internal/ns/agent-release/sa/other' WHERE token_digest = $1`, digest(r.token))
			return r.leaf, r.token
		},
		"revoked cert": func(r releaser) (*x509.Certificate, string) {
			e.admin.Exec(ctx, `UPDATE identity.issued_certificates SET revoked_at = now() WHERE serial = $1`, hex.EncodeToString(r.leaf.SerialNumber.Bytes()))
			return r.leaf, r.token
		},
		"expired session": func(r releaser) (*x509.Certificate, string) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET expires_at = now() - interval '1 second' WHERE service_session_id = $1`, r.session)
			return r.leaf, r.token
		},
		"revoked session": func(r releaser) (*x509.Certificate, string) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET state = 'revoked' WHERE service_session_id = $1`, r.session)
			return r.leaf, r.token
		},
		"principal mismatch": func(r releaser) (*x509.Certificate, string) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET caller_principal = 'policy-proposer' WHERE service_session_id = $1`, r.session)
			return r.leaf, r.token
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			leafC, tok := mod(e.releaser(t))
			if _, err := e.svc.AuthenticateService(ctx, leafC, tok); code(err) != "AUTH_REQUIRED" {
				t.Fatalf("got %v", err)
			}
		})
	}
	t.Run("disabled workload", func(t *testing.T) {
		r := e.releaser(t)
		e.admin.Exec(ctx, `UPDATE identity.registered_workloads SET enabled = false WHERE ksa = 'releaser'`)
		defer e.admin.Exec(ctx, `UPDATE identity.registered_workloads SET enabled = true WHERE ksa = 'releaser'`)
		if _, err := e.svc.AuthenticateService(ctx, r.leaf, r.token); code(err) != "AUTH_REQUIRED" {
			t.Fatalf("got %v", err)
		}
	})
}

func TestRegisterProbe(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	r := e.releaser(t)
	c := e.caller(t, r)
	e.health.activation = &Hold{HoldID: "act", Reason: "policy_activation"}
	req := ProbeRequest{ChangeID: r.change, ClientRequestKey: "probe-key-1", TargetEpoch: 8}
	out, created, err := e.svc.RegisterProbe(ctx, c, req)
	if err != nil || !created || !isUUID(out.ActivationProbeID) {
		t.Fatalf("register: %v %+v", err, out)
	}
	var sessExp time.Time
	e.admin.QueryRow(ctx, `SELECT expires_at FROM identity.service_sessions WHERE service_session_id = $1`, r.session).Scan(&sessExp)
	if !out.ExpiresAt.Equal(sessExp) {
		t.Fatalf("expires_at %v, session %v", out.ExpiresAt, sessExp)
	}
	if e.scalar(t, `SELECT count(*) FROM coordinator.activation_probes WHERE activation_probe_id = $1 AND action_id IS NULL
    AND change_id = $2 AND service_session_id = $3 AND target_epoch = 8`, out.ActivationProbeID, r.change, r.session) != 1 {
		t.Fatal("stored row")
	}
	if e.audit.count("activation_probe_registered") != 1 {
		t.Fatal("event")
	}
	again, created, err := e.svc.RegisterProbe(ctx, c, req)
	if err != nil || created || again.ActivationProbeID != out.ActivationProbeID || e.audit.count("activation_probe_registered") != 1 {
		t.Fatalf("replay: %v %v %+v", err, created, again)
	}
	other := req
	other.TargetEpoch = 9
	if _, _, err := e.svc.RegisterProbe(ctx, c, other); code(err) != "CLIENT_KEY_BODY_CONFLICT" {
		t.Fatalf("other epoch: %v", err)
	}

	for name, cs := range map[string]struct {
		mod  func(*ProbeRequest, *ServiceCaller)
		env  func(releaser)
		want string
	}{
		"other change":  {mod: func(r *ProbeRequest, _ *ServiceCaller) { r.ChangeID = uuid.NewString() }, want: "SERVICE_SCOPE_DENIED"},
		"other profile": {mod: func(_ *ProbeRequest, c *ServiceCaller) { c.Profile = "policy_proposal" }, want: "SERVICE_SCOPE_DENIED"},
		"bad key":       {mod: func(r *ProbeRequest, _ *ServiceCaller) { r.ClientRequestKey = "short" }, want: "SCHEMA_INVALID"},
		"zero epoch":    {mod: func(r *ProbeRequest, _ *ServiceCaller) { r.TargetEpoch = 0 }, want: "SCHEMA_INVALID"},
		"no hold":       {env: func(releaser) { e.health.activation = nil }, want: "RESOURCE_NOT_FOUND"},
		"health down":   {env: func(releaser) { e.health.activationErr = errors.New("down") }, want: "CONTROL_HEALTH_UNAVAILABLE"},
		"audit down":    {env: func(releaser) { e.audit.err = errors.New("down") }, want: "STATE_STORE_UNAVAILABLE"},
		// Revoked after the (unlocked) authentication read.
		"session revoked": {env: func(r releaser) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET state = 'revoked' WHERE service_session_id = $1`, r.session)
		}, want: "AUTH_REQUIRED"},
	} {
		t.Run(name, func(t *testing.T) {
			r := e.releaser(t)
			c := e.caller(t, r)
			e.health.activation, e.health.activationErr, e.audit.err = &Hold{HoldID: "act", Reason: "policy_activation"}, nil, nil
			defer func() { e.audit.err = nil }()
			req := ProbeRequest{ChangeID: r.change, ClientRequestKey: "probe-key-2", TargetEpoch: 8}
			if cs.mod != nil {
				cs.mod(&req, &c)
			}
			if cs.env != nil {
				cs.env(r)
			}
			if _, _, err := e.svc.RegisterProbe(ctx, c, req); code(err) != cs.want {
				t.Fatalf("got %v, want %s", err, cs.want)
			}
			if e.scalar(t, `SELECT count(*) FROM coordinator.activation_probes WHERE service_session_id = $1`, r.session) != 0 {
				t.Fatal("refused registration left a row")
			}
		})
	}

	t.Run("concurrent same key", func(t *testing.T) {
		e.health.activation, e.health.activationErr = &Hold{HoldID: "act", Reason: "policy_activation"}, nil
		r := e.releaser(t)
		c := e.caller(t, r)
		before := e.audit.count("activation_probe_registered")
		var wg sync.WaitGroup
		ids := make([]string, 10)
		errs := make([]error, 10)
		for i := range ids {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				out, _, err := e.svc.RegisterProbe(ctx, c, ProbeRequest{ChangeID: r.change, ClientRequestKey: "probe-key-c", TargetEpoch: 8})
				errs[i] = err
				if out != nil {
					ids[i] = out.ActivationProbeID
				}
			}(i)
		}
		wg.Wait()
		for i := range ids {
			if errs[i] != nil || ids[i] != ids[0] {
				t.Fatalf("%d: %v %s %s", i, errs[i], ids[i], ids[0])
			}
		}
		if e.audit.count("activation_probe_registered") != before+1 ||
			e.scalar(t, `SELECT count(*) FROM coordinator.activation_probes WHERE service_session_id = $1`, r.session) != 1 {
			t.Fatal("concurrent registration made more than one row or event")
		}
	})
}

func TestRegisterProbeHTTP(t *testing.T) {
	e := setup(t)
	r := e.releaser(t)
	e.health.activation = &Hold{HoldID: "act", Reason: "policy_activation"}
	mux := http.NewServeMux()
	(&Handler{Svc: e.svc}).Register(mux)
	send := func(token string) *httptest.ResponseRecorder {
		body := `{"change_id":"` + r.change + `","client_request_key":"probe-key-h","target_epoch":8}`
		req := httptest.NewRequest(http.MethodPost, "/internal/dispatch/activation-probes", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{r.leaf}}}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := send(r.token + "x"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	first := send(r.token)
	var out ProbeResult
	if first.Code != http.StatusCreated || json.Unmarshal(first.Body.Bytes(), &out) != nil || !isUUID(out.ActivationProbeID) {
		t.Fatalf("first: %d %s", first.Code, first.Body)
	}
	if rec := send(r.token); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), out.ActivationProbeID) {
		t.Fatalf("replay: %d %s", rec.Code, rec.Body)
	}
}

func TestProbeReservation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.health.activation = &Hold{HoldID: "act", Reason: "policy_activation"}
	activation := []Hold{{HoldID: "act", Reason: "policy_activation"}}
	r := e.releaser(t)

	// A bound probe passes the policy_activation hold and consumes
	// probe_actions; the permit claim applies the same exemption.
	e.health.holds = activation
	d := e.probeDecision(t, r, 7)
	p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
	if err != nil {
		t.Fatal(err)
	}
	if e.probeUsed(t, r) != 1 || e.scalar(t, `SELECT count(*) FROM coordinator.reservations WHERE action_id = $1
    AND decision_basis = 'activation_probe' AND budget_counter = 'probe_actions' AND service_session_id = $2`, d.ActionID, r.session) != 1 {
		t.Fatal("probe reservation")
	}
	if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); err != nil {
		t.Fatalf("claim under activation hold: %v", err)
	}
	// Release restores probe_actions.
	d2 := e.probeDecision(t, r, 7)
	p2, err := e.svc.Reserve(ctx, e.adapter, reqFor(d2))
	if err != nil || e.probeUsed(t, r) != 2 {
		t.Fatalf("second probe: %v used=%d", err, e.probeUsed(t, r))
	}
	if _, err := e.svc.release(ctx, p2.AttemptID, ByAdapter, []string{"CREDENTIAL_UNAVAILABLE"}, &e.adapter); err != nil || e.probeUsed(t, r) != 1 {
		t.Fatalf("release: %v used=%d", err, e.probeUsed(t, r))
	}
	// A normal action under the same hold is refused.
	if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.approval(t))); code(err) != "HOLD_ACTIVE" {
		t.Fatalf("normal action: %v", err)
	}

	refused := map[string]struct {
		mod   func(*Decision)
		holds []Hold
		want  string
	}{
		"other hold too":  {holds: append([]Hold{{HoldID: "drift", Reason: "control_drift"}}, activation...), want: "HOLD_ACTIVE"},
		"only other hold": {holds: []Hold{{HoldID: "drift", Reason: "control_drift"}}, want: "HOLD_ACTIVE"},
		"other action": {mod: func(d *Decision) {
			d.ActionID = uuid.NewString()
		}, holds: activation, want: "HOLD_ACTIVE"},
		"other session": {mod: func(d *Decision) { d.ServiceSessionID = uuid.NewString() }, holds: activation, want: "HOLD_ACTIVE"},
		"missing probe": {mod: func(d *Decision) { d.ActivationProbeID = uuid.NewString() }, holds: activation, want: "HOLD_ACTIVE"},
		"stale epoch": {mod: func(d *Decision) {
			e.admin.Exec(ctx, `UPDATE coordinator.activation_probes SET target_epoch = 8 WHERE activation_probe_id = $1`, d.ActivationProbeID)
		}, holds: activation, want: "HOLD_ACTIVE"},
		"expired probe": {mod: func(d *Decision) {
			e.admin.Exec(ctx, `UPDATE coordinator.activation_probes SET expires_at = now() - interval '1 second' WHERE activation_probe_id = $1`, d.ActivationProbeID)
		}, holds: activation, want: "HOLD_ACTIVE"},
		"no hold, stale probe": {mod: func(d *Decision) {
			e.admin.Exec(ctx, `UPDATE coordinator.activation_probes SET target_epoch = 8 WHERE activation_probe_id = $1`, d.ActivationProbeID)
		}, want: "TOOL_BUDGET_EXHAUSTED"},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			r := e.releaser(t)
			e.health.holds = activation
			d := e.probeDecision(t, r, 7)
			if c.mod != nil {
				c.mod(&d)
				e.dec.put(d)
			}
			e.health.holds = c.holds
			if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(d)); code(err) != c.want {
				t.Fatalf("got %v, want %s", err, c.want)
			}
			if e.probeUsed(t, r) != 0 || e.scalar(t, `SELECT count(*) FROM coordinator.reservations WHERE action_id = $1`, d.ActionID) != 0 {
				t.Fatal("refused probe left state")
			}
		})
	}

	t.Run("fifth probe", func(t *testing.T) {
		r := e.releaser(t)
		e.health.holds = activation
		for i := 0; i < 4; i++ {
			if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.probeDecision(t, r, 7))); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.probeDecision(t, r, 7))); code(err) != "TOOL_BUDGET_EXHAUSTED" {
			t.Fatalf("fifth: %v", err)
		}
		if e.probeUsed(t, r) != 4 {
			t.Fatal("probe_actions")
		}
	})

	// The probe becomes unusable between reservation and claim. Without a
	// hold at claim time only the locked re-check in Check can see it
	// (PERMIT_INVALID); under the activation hold the hold exemption refuses
	// first (HOLD_ACTIVE). Either way the permit stays unclaimed.
	for name, spoil := range map[string]string{
		"expired": `UPDATE coordinator.activation_probes SET expires_at = now() - interval '1 second' WHERE activation_probe_id = $1`,
		"epoch":   `UPDATE coordinator.activation_probes SET target_epoch = 8 WHERE activation_probe_id = $1`,
		"rebound": `UPDATE coordinator.activation_probes SET action_id = gen_random_uuid() WHERE activation_probe_id = $1`,
	} {
		for _, claimHolds := range []struct {
			holds []Hold
			want  string
		}{{nil, "PERMIT_INVALID"}, {activation, "HOLD_ACTIVE"}} {
			t.Run("claim after probe "+name+" holds="+strconv.Itoa(len(claimHolds.holds)), func(t *testing.T) {
				r := e.releaser(t)
				e.health.holds = activation
				d := e.probeDecision(t, r, 7)
				p, err := e.svc.Reserve(ctx, e.adapter, reqFor(d))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.admin.Exec(ctx, spoil, d.ActivationProbeID); err != nil {
					t.Fatal(err)
				}
				e.health.holds = claimHolds.holds
				if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); code(err) != claimHolds.want {
					t.Fatalf("claim: %v, want %s", err, claimHolds.want)
				}
				if e.scalar(t, `SELECT count(*) FROM coordinator.dispatch_permits WHERE permit_id = $1 AND claimed_at IS NULL`, p.PermitID) != 1 ||
					e.state(t, p.AttemptID) != "planned" {
					t.Fatal("refused claim claimed the permit")
				}
			})
		}
	}

	t.Run("claim of a usable probe without a hold", func(t *testing.T) {
		r := e.releaser(t)
		e.health.holds = activation
		p, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.probeDecision(t, r, 7)))
		if err != nil {
			t.Fatal(err)
		}
		e.health.holds = nil
		if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); err != nil {
			t.Fatalf("claim: %v", err)
		}
	})

	t.Run("claim refused when another hold appears", func(t *testing.T) {
		r := e.releaser(t)
		e.health.holds = activation
		p, err := e.svc.Reserve(ctx, e.adapter, reqFor(e.probeDecision(t, r, 7)))
		if err != nil {
			t.Fatal(err)
		}
		e.health.holds = append([]Hold{{HoldID: "drift", Reason: "control_drift"}}, activation...)
		if _, err := e.svc.Check(ctx, e.adapter, p.PermitID, checkFor(p)); code(err) != "HOLD_ACTIVE" {
			t.Fatalf("claim: %v", err)
		}
	})

	t.Run("concurrent probes share the budget", func(t *testing.T) {
		r := e.releaser(t)
		e.health.holds = activation
		ds := make([]Decision, 8)
		for i := range ds {
			ds[i] = e.probeDecision(t, r, 7)
		}
		var wg sync.WaitGroup
		errs := make([]error, len(ds))
		for i := range ds {
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, errs[i] = e.svc.Reserve(ctx, e.adapter, reqFor(ds[i])) }(i)
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch code(err) {
			case "":
				ok++
			case "TOOL_BUDGET_EXHAUSTED":
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		if ok != 4 || e.probeUsed(t, r) != 4 {
			t.Fatalf("ok=%d used=%d", ok, e.probeUsed(t, r))
		}
	})
}

// ---- DB functions and view --------------------------------------------------

func TestBindActivationProbeAction(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	e.health.activation = &Hold{HoldID: "act", Reason: "policy_activation"}
	r := e.releaser(t)
	id := e.register(t, r, "bind-key-01", 7)
	action := uuid.NewString()

	if _, err := e.execRole(t, "coordinator_app", `SELECT coordinator.bind_activation_probe_action($1, $2, $3)::text`, r.session, "bind-key-01", action); pgCode(err) != "42501" {
		t.Fatalf("coordinator_app may execute: %v", err)
	}
	got, err := e.bind(t, r.session, "bind-key-01", action)
	if err != nil || got != id {
		t.Fatalf("first bind: %v %s", err, got)
	}
	if got, err := e.bind(t, r.session, "bind-key-01", action); err != nil || got != id {
		t.Fatalf("idempotent rebind: %v %s", err, got)
	}
	if _, err := e.bind(t, r.session, "bind-key-01", uuid.NewString()); pgCode(err) != "P0001" {
		t.Fatalf("conflicting rebind: %v", err)
	}
	if e.scalar(t, `SELECT count(*) FROM coordinator.activation_probes WHERE activation_probe_id = $1 AND action_id = $2`, id, action) != 1 {
		t.Fatal("binding changed")
	}
	// The same action cannot be bound to a second probe.
	e.register(t, r, "bind-key-02", 7)
	if _, err := e.bind(t, r.session, "bind-key-02", action); pgCode(err) != "23505" {
		t.Fatalf("second probe for the action: %v", err)
	}

	for name, c := range map[string]struct {
		prep func(r releaser, key string) (sess, k string)
	}{
		"unknown key": {func(r releaser, key string) (string, string) { return r.session, "bind-key-zz" }},
		"other session": {func(r releaser, key string) (string, string) {
			o := e.releaser(t)
			return o.session, key
		}},
		"expired probe": {func(r releaser, key string) (string, string) {
			e.admin.Exec(ctx, `UPDATE coordinator.activation_probes SET expires_at = now() - interval '1 second' WHERE service_session_id = $1`, r.session)
			return r.session, key
		}},
		"session expired": {func(r releaser, key string) (string, string) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET expires_at = now() - interval '1 second' WHERE service_session_id = $1`, r.session)
			return r.session, key
		}},
		"session revoked": {func(r releaser, key string) (string, string) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET state = 'revoked' WHERE service_session_id = $1`, r.session)
			return r.session, key
		}},
		"other profile": {func(r releaser, key string) (string, string) {
			e.admin.Exec(ctx, `UPDATE identity.service_sessions SET profile = 'discovery', change_id = NULL, snapshot_id = gen_random_uuid()
WHERE service_session_id = $1`, r.session)
			return r.session, key
		}},
		"change mismatch": {func(r releaser, key string) (string, string) {
			e.admin.Exec(ctx, `UPDATE coordinator.activation_probes SET change_id = gen_random_uuid() WHERE service_session_id = $1`, r.session)
			return r.session, key
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := e.releaser(t)
			e.register(t, r, "bind-key-03", 7)
			sess, key := c.prep(r, "bind-key-03")
			if _, err := e.bind(t, sess, key, uuid.NewString()); pgCode(err) != "P0002" {
				t.Fatalf("got %v", err)
			}
			if e.scalar(t, `SELECT count(*) FROM coordinator.activation_probes WHERE service_session_id = $1 AND action_id IS NOT NULL`, r.session) != 0 {
				t.Fatal("refused bind filled action_id")
			}
		})
	}

	t.Run("concurrent binds", func(t *testing.T) {
		r := e.releaser(t)
		id := e.register(t, r, "bind-key-04", 7)
		actions := make([]string, 10)
		errs := make([]error, 10)
		var wg sync.WaitGroup
		for i := range actions {
			actions[i] = uuid.NewString()
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, errs[i] = e.bind(t, r.session, "bind-key-04", actions[i]) }(i)
		}
		wg.Wait()
		ok := 0
		var winner string
		for i, err := range errs {
			switch pgCode(err) {
			case "":
				ok++
				winner = actions[i]
			case "P0001":
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		if ok != 1 || e.scalar(t, `SELECT count(*) FROM coordinator.activation_probes WHERE activation_probe_id = $1 AND action_id = $2`, id, winner) != 1 {
			t.Fatalf("ok=%d", ok)
		}
	})
}

func TestResolveUnknownAttempt(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	p, _ := e.claimed(t)
	if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, "unknown", obsFor(p.AttemptID), []string{"TARGET_UNAVAILABLE"}); err != nil {
		t.Fatal(err)
	}
	resolution := uuid.NewString()
	resolve := func(attempt, res string) (string, error) {
		return e.execRole(t, "timeline_app", `SELECT (r.attempt_id::text || '/' || r.action_id || '/' || r.reservation_id || '/' || r.adapter_id || '/' || r.resolution_id)
FROM coordinator.resolve_unknown_attempt($1, $2) r`, attempt, res)
	}
	if _, err := e.execRole(t, "coordinator_app", `SELECT attempt_id::text FROM coordinator.resolve_unknown_attempt($1, $2)`, p.AttemptID, resolution); pgCode(err) != "42501" {
		t.Fatalf("coordinator_app may execute: %v", err)
	}
	want := p.AttemptID + "/" + p.ActionID + "/" + p.ReservationID + "/receiver/" + resolution
	if got, err := resolve(p.AttemptID, resolution); err != nil || got != want {
		t.Fatalf("resolve: %v %s", err, got)
	}
	if e.state(t, p.AttemptID) != "resolved" {
		t.Fatal("state")
	}
	if got, err := resolve(p.AttemptID, resolution); err != nil || got != want {
		t.Fatalf("idempotent resolve: %v %s", err, got)
	}
	if _, err := resolve(p.AttemptID, uuid.NewString()); pgCode(err) != "P0001" {
		t.Fatalf("other resolution: %v", err)
	}
	claimedP, _ := e.claimed(t)
	if _, err := resolve(claimedP.AttemptID, uuid.NewString()); pgCode(err) != "P0001" {
		t.Fatalf("claimed attempt: %v", err)
	}
	if _, err := resolve(uuid.NewString(), uuid.NewString()); pgCode(err) != "P0002" {
		t.Fatalf("missing attempt: %v", err)
	}
	// resolved leaves the active partial unique index: a new attempt for the
	// action can exist; before, it could not.
	if _, err := e.admin.Exec(ctx, `INSERT INTO coordinator.attempts (attempt_id, action_id, reservation_id, adapter_id, adapter_node_uid, state, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, 'receiver', $3, 'planned', now(), now())`, p.ActionID, p.ReservationID, adapterNode); err != nil {
		t.Fatalf("new attempt after resolve: %v", err)
	}
	if _, err := e.admin.Exec(ctx, `INSERT INTO coordinator.attempts (attempt_id, action_id, reservation_id, adapter_id, adapter_node_uid, state, created_at, updated_at)
VALUES (gen_random_uuid(), $1, $2, 'receiver', $3, 'planned', now(), now())`, claimedP.ActionID, claimedP.ReservationID, adapterNode); pgCode(err) != "23505" {
		t.Fatalf("new attempt beside an active one: %v", err)
	}

	t.Run("concurrent resolutions", func(t *testing.T) {
		p, _ := e.claimed(t)
		if _, err := e.svc.Outcome(ctx, e.adapter, p.AttemptID, "unknown", obsFor(p.AttemptID), []string{"TARGET_UNAVAILABLE"}); err != nil {
			t.Fatal(err)
		}
		errs := make([]error, 8)
		var wg sync.WaitGroup
		for i := range errs {
			wg.Add(1)
			go func(i int) { defer wg.Done(); _, errs[i] = resolve(p.AttemptID, uuid.NewString()) }(i)
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch pgCode(err) {
			case "":
				ok++
			case "P0001":
			default:
				t.Fatalf("unexpected %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("ok=%d", ok)
		}
	})
}
