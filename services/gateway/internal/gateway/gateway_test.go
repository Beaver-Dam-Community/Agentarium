package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/decisions"
)

var evalNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func userCaller() Caller {
	return Caller{Kind: KindUser, SAN: "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/p1",
		Namespace: "agent-exec", KSA: "agent-runtime", SessionID: uuid.NewString(), AuthenticatedActor: "google:u1",
		Tenant: "hackathon", WorkloadID: "agent-exec/agent-runtime", NodeUID: "node-1"}
}

func serviceCaller() Caller {
	return Caller{Kind: KindService, SAN: "spiffe://agentarium.internal/ns/agent-observe/sa/policy-proposer",
		Namespace: "agent-observe", KSA: "policy-proposer", SessionID: uuid.NewString(),
		AuthenticatedActor: "service:agent-observe/policy-proposer", Tenant: "hackathon", Profile: "policy_proposal"}
}

func healthyLeases(keys []LeaseKey, artifact string) []lease {
	var out []lease
	for _, k := range keys {
		var v *string
		if k.Component == "adapter" {
			v = &artifact
		}
		out = append(out, aggregate(k.Component, []LeaseRow{{Component: k.Component, SourceID: k.Component + "-0",
			ObservedState: "healthy", LeaseUntil: evalNow.Add(10 * time.Second), ActiveVersion: v}}, evalNow))
	}
	return out
}

// inputFor normalizes body for c with the real canonical package and builds
// the OPA input the gateway would evaluate.
func inputFor(t *testing.T, p *testPolicy, c Caller, body string, ds canonical.WorkloadDataState) (opaInput, canonical.ActionEnvelope) {
	t.Helper()
	cat, err := p.loader.Current().Catalog()
	if err != nil {
		t.Fatal(err)
	}
	trusted := canonical.TrustedContext{ActionID: uuid.NewString(), RequestID: uuid.NewString(), AuthenticatedActor: c.AuthenticatedActor,
		SessionKind: c.Kind, SessionID: c.SessionID, Tenant: c.Tenant, Environment: "test", WorkloadDataState: ds}
	vs := verifiedSession{Kind: c.Kind, SessionID: c.SessionID, AuthenticatedActor: c.AuthenticatedActor, Tenant: c.Tenant,
		ExpiresAt: rfc3339(evalNow.Add(time.Hour)), AllowedOperationIDs: []string{}}
	if c.Kind == KindUser {
		w := c.WorkloadID
		trusted.WorkloadID = &w
		vs.WorkloadID, vs.State = &w, "claimed"
		vs.AllowedOperationIDs = []string{"receiver.submit", "k8s.pods.list"}
	} else {
		issue := uuid.NewString()
		vs.State = "active"
		vs.CallerPrincipal = &c.KSA
		vs.ServiceScope = &serviceScope{Profile: c.Profile, IssueID: &issue}
	}
	env, _, ne := canonical.NormalizeRaw([]byte(body), trusted, cat)
	if ne != nil {
		t.Fatalf("normalize: %v", ne)
	}
	op := cat.Operations[env.OperationID]
	return opaInput{
		Envelope: env, VerifiedSession: vs, WorkloadDataState: ds,
		ControlHealth: controlHealth{EvaluatedAt: rfc3339(evalNow), ActiveArtifactDigest: p.artifact, ActiveHolds: []Hold{},
			RequiredLeases: healthyLeases(requiredLeases(env.OperationID, op.AdapterID, env.CanonicalTarget.TargetID, c), p.artifact)},
	}, env
}

func receiverBody(session, key, email string) string {
	e := "null"
	if email != "" {
		e = `"` + email + `"`
	}
	return `{"session_id":"` + session + `","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},` +
		`"arguments":{"payload":{"summary":"weekly summary","email":` + e + `}},"client_request_key":"` + key + `"}`
}

func evidenceBody(session, key string) string {
	return `{"session_id":"` + session + `","operation_id":"evidence.action.read","requested_target":{"target_id":"evidence-api","resource_id":"` +
		uuid.NewString() + `"},"arguments":{},"client_request_key":"` + key + `"}`
}

var synthetic = canonical.WorkloadDataState{DataClassHighWater: "synthetic", DataSources: []string{}}

func TestEvaluateRealBundle(t *testing.T) {
	p := loadTestPolicy(t, "")
	ctx := context.Background()
	u := userCaller()
	s := serviceCaller()
	cases := []struct {
		name    string
		c       Caller
		body    string
		mutate  func(*opaInput)
		verdict string
		codes   []string
		basis   string
		status  int
	}{
		{"user receiver without approval", u, receiverBody(u.SessionID, "key-0001", ""), nil,
			decisions.ApprovalRequired, []string{"APPROVAL_REQUIRED"}, "", 202},
		{"user receiver with email", u, receiverBody(u.SessionID, "key-0002", "a@b.example"), nil,
			decisions.Deny, []string{"DISCLOSURE_SCOPE_DENIED"}, "", 403},
		{"service evidence read in profile", s, evidenceBody(s.SessionID, "key-0003"), nil,
			decisions.Allow, []string{}, decisions.BasisServiceScope, 202},
		{"hold blocks", s, evidenceBody(s.SessionID, "key-0004"), func(in *opaInput) {
			in.ControlHealth.ActiveHolds = []Hold{{HoldID: "h1", Scope: "global", ScopeID: "*", Reason: "export_lag"}}
		}, decisions.Deny, []string{"HOLD_ACTIVE"}, "", 503},
		{"mixed adapter version", s, evidenceBody(s.SessionID, "key-0005"), func(in *opaInput) {
			for i, l := range in.ControlHealth.RequiredLeases {
				if l.Component == "adapter" {
					m := "mixed"
					in.ControlHealth.RequiredLeases[i].ActiveVersion = &m
				}
			}
		}, decisions.Deny, []string{"CONTROL_HEALTH_UNAVAILABLE"}, "", 503},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, _ := inputFor(t, p, tc.c, tc.body, synthetic)
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			ev, err := evaluate(ctx, p.loader.Current(), in, facts{}, tc.c)
			if err != nil {
				t.Fatal(err)
			}
			d := ev.derived
			if d.Verdict != tc.verdict || !slices.Equal(nonNil(d.ReasonCodes), tc.codes) || d.DecisionBasis != tc.basis {
				t.Fatalf("got %s %v %q", d.Verdict, d.ReasonCodes, d.DecisionBasis)
			}
			if got := decisions.HTTPStatus(d.Verdict, d.ReasonCodes); got != tc.status {
				t.Fatalf("status %d, want %d", got, tc.status)
			}
			// The stored input digest is the canonical digest of the stored
			// bytes (decision_input_ref = decision_input_digest).
			if dg, _ := canonical.CanonicalDigestJSON(ev.inputJSON); dg != ev.inputDigest {
				t.Fatal("input digest does not match the stored input")
			}
			var keys map[string]json.RawMessage
			_ = json.Unmarshal(ev.inputJSON, &keys)
			if len(keys) != 5 {
				t.Fatalf("OPA input has %d keys", len(keys))
			}
		})
	}
}

func TestEvaluateRejectsBadResult(t *testing.T) {
	bad := map[string]string{
		"no result":           "package agentarium.gateway\n\nother := 1\n",
		"bad verdict":         "package agentarium.gateway\n\nresult := {\"verdict\": \"permit\", \"reason_codes\": [], \"matched_rule_ids\": [\"a.b.v1\"], \"evaluated_rule_ids\": [\"a.b.v1\"], \"decision_basis\": null}\n",
		"allow without basis": "package agentarium.gateway\n\nresult := {\"verdict\": \"allow\", \"reason_codes\": [], \"matched_rule_ids\": [\"approval.allow.v1\"], \"evaluated_rule_ids\": [\"a.b.v1\"], \"decision_basis\": null}\n",
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			p := loadTestPolicy(t, src)
			s := serviceCaller()
			in, _ := inputFor(t, p, s, evidenceBody(s.SessionID, "key-0009"), synthetic)
			_, err := evaluate(context.Background(), p.loader.Current(), in, facts{}, s)
			var e *Error
			if !errors.As(err, &e) || e.Code != "POLICY_UNAVAILABLE" || e.Status != 503 {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestAggregate(t *testing.T) {
	v1, v2 := "aaaa", "bbbb"
	rows := []LeaseRow{
		{Component: "adapter", SourceID: "a-1", ObservedState: "healthy", LeaseUntil: evalNow.Add(5 * time.Second), ActiveVersion: &v1},
		{Component: "adapter", SourceID: "a-2", ObservedState: "degraded", LeaseUntil: evalNow.Add(9 * time.Second), ActiveVersion: &v1},
		{Component: "adapter", SourceID: "a-3", ObservedState: "unhealthy", LeaseUntil: evalNow.Add(-time.Second), ActiveVersion: &v2},
	}
	l := aggregate("adapter", rows, evalNow)
	if l.ObservedState != "degraded" || *l.SourceID != "a-2" || *l.ActiveVersion != v1 || l.LeaseUntil != rfc3339(evalNow.Add(9*time.Second)) {
		t.Fatalf("aggregate = %+v", l)
	}
	rows[2].LeaseUntil = evalNow.Add(time.Second)
	if l := aggregate("adapter", rows, evalNow); l.ObservedState != "unhealthy" || *l.ActiveVersion != "mixed" {
		t.Fatalf("with a third valid replica: %+v", l)
	}
	if l := aggregate("coordinator", rows, evalNow); l.ObservedState != "unhealthy" || l.SourceID != nil {
		t.Fatalf("no replica: %+v", l)
	}
	// A lease ending exactly at evaluated_at is not valid.
	if l := aggregate("x", []LeaseRow{{Component: "x", ObservedState: "healthy", LeaseUntil: evalNow}}, evalNow); l.ObservedState != "unhealthy" {
		t.Fatalf("boundary lease: %+v", l)
	}
}

func TestRequiredLeases(t *testing.T) {
	comps := func(keys []LeaseKey) []string {
		var out []string
		for _, k := range keys {
			out = append(out, k.Component)
		}
		return out
	}
	u := requiredLeases("receiver.submit", "receiver-sender", "receiver-main", userCaller())
	if !slices.Equal(comps(u), []string{"gateway", "coordinator", "audit-db", "audit-export", "adapter", "destination-evidence", "node-sensors"}) ||
		u[4].AdapterID != "receiver-sender" || u[5].TargetID != "receiver-main" || u[6].NodeUID != "node-1" {
		t.Fatalf("user receiver: %+v", u)
	}
	s := requiredLeases("evidence.action.read", "evidence-reader", "", serviceCaller())
	if !slices.Equal(comps(s), []string{"gateway", "coordinator", "audit-db", "audit-export", "adapter"}) {
		t.Fatalf("service read: %+v", s)
	}
}

func TestParseSAN(t *testing.T) {
	ok := map[string]bool{
		"spiffe://agentarium.internal/ns/a/sa/b/pod/c": true,
		"spiffe://agentarium.internal/ns/a/sa/b":       false,
	}
	for san, pod := range ok {
		if _, _, p, err := parseSAN(san); err != nil || p != pod {
			t.Errorf("%s: pod=%v err=%v", san, p, err)
		}
	}
	for _, san := range []string{"spiffe://other/ns/a/sa/b", "spiffe://agentarium.internal/ns/a/sa/", "spiffe://agentarium.internal/ns/a/xx/b",
		"spiffe://agentarium.internal/ns/a/sa/b/pod/"} {
		if _, _, _, err := parseSAN(san); err == nil {
			t.Errorf("%s accepted", san)
		}
	}
}

func TestSubmitWithoutBundle(t *testing.T) {
	s := &Service{Bundle: nil}
	_, _, err := s.Submit(context.Background(), userCaller(), []byte(`{}`), ReadinessRef{})
	var e *Error
	if !errors.As(err, &e) || e.Code != "POLICY_UNAVAILABLE" {
		t.Fatalf("err = %v", err)
	}
}

func TestHandlerEdges(t *testing.T) {
	h := &Handler{Svc: &Service{}}
	mux := http.NewServeMux()
	h.Register(mux)
	do := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := do("POST", "/v1/actions", "{}"); w.Code != 401 || !strings.Contains(w.Body.String(), "AUTH_REQUIRED") {
		t.Fatalf("no certificate: %d %s", w.Code, w.Body)
	}
	if w := do("POST", "/v1/actions/"+uuid.NewString()+":approve", "{}"); w.Code != 404 {
		t.Fatalf("unknown verb: %d", w.Code)
	}
	var req ReevaluateRequest
	if err := strictInto([]byte(`{"expected_action_digest":"x","extra":1}`), &req); err == nil {
		t.Fatal("unknown field accepted")
	}
	if err := strictInto([]byte(`{"Expected_Action_Digest":"x"}`), &req); err == nil {
		t.Fatal("case-folded key accepted")
	}
	w := httptest.NewRecorder()
	writeError(w, unavailable("POLICY_UNAVAILABLE", "x"))
	if w.Header().Get("Retry-After") != "2" || w.Code != 503 {
		t.Fatalf("503 without Retry-After")
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if len(body) != 2 || body["request_id"] == "" {
		t.Fatalf("error body %v", body)
	}
}

// TestActionResponseDecisionBasis: decision_basis is always in the body, set
// for an allow and null otherwise (TASK-04 chapter 4, COMMON enum decision_basis).
func TestActionResponseDecisionBasis(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    decisions.Derived
		want any
	}{
		{"allow service_scope", decisions.Derived{Verdict: decisions.Allow, DecisionBasis: decisions.BasisServiceScope}, "service_scope"},
		{"allow approval", decisions.Derived{Verdict: decisions.Allow, DecisionBasis: decisions.BasisApproval}, "approval"},
		{"approval_required", decisions.Derived{Verdict: decisions.ApprovalRequired, ReasonCodes: []string{"APPROVAL_REQUIRED"}}, nil},
		{"deny", decisions.Derived{Verdict: decisions.Deny, ReasonCodes: []string{"DISCLOSURE_SCOPE_DENIED"}}, nil},
	} {
		b, err := json.Marshal(respond("r", "a", "d", tc.d))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if got, ok := m["decision_basis"]; !ok || got != tc.want {
			t.Errorf("%s: decision_basis %v (present %v), want %v; body %s", tc.name, got, ok, tc.want, b)
		}
	}
	// The answer of a :reevaluate that lost the race keeps the basis.
	basis := decisions.BasisApproval
	l := latestDecision{verdict: decisions.Allow, basis: &basis}
	if out := respond("r", "a", "d", l.derived()); out.DecisionBasis == nil || *out.DecisionBasis != decisions.BasisApproval {
		t.Errorf("latestDecision basis %v", out.DecisionBasis)
	}
}
