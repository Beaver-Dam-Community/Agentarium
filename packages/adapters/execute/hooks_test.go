package execute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// The adapter hooks (ContextMapper, ResultBuilder, ModelTurnWriter,
// Mapping.ProviderRequestID) are driven through dispatch: a real TLS target,
// an in-process coordinator and a store that mirrors the Postgres
// SavePending contract for model turns.

const (
	hookHost    = "model.test"
	hookSig     = "SECRET-THOUGHT-SIGNATURE"
	hookSession = "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	hookConv    = "7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// hookResponse is a generateContent-like body with a thought signature.
var hookResponse = `{"responseId":"resp-123","candidates":[{"finishReason":"STOP","content":{"role":"model","parts":[{"text":"hello","thoughtSignature":"` + hookSig + `"}]}}]}`

type adapterState struct{ Profile string }

// modelStub is a model-like adapter. Its fields select which hooks it has
// through the wrapper types below.
type modelStub struct {
	mu          sync.Mutex
	mapCalls    int
	ctxCalls    int
	gotState    any
	gotAux      []*AuxWriteResult
	buildErr    error
	badBody     bool
	turn        func(r transport.Result) (*ModelTurnWrite, error)
	providerID  string
	mappedState string
}

func (*modelStub) ID() string { return "model" }
func (*modelStub) Prepare(Inputs, *Bundle) (Prepared, *Rejection) {
	return Prepared{}, &Rejection{ReasonCodes: []string{ReasonPreflightMismatch}}
}
func (m *modelStub) MapResponse(transport.Result) Mapping {
	m.mu.Lock()
	m.mapCalls++
	m.mu.Unlock()
	return Mapping{ExecutionState: "accepted", ReasonCodes: []string{}, EvidenceLevel: "accepted"}
}

// withContext adds ContextMapper.
type withContext struct{ *modelStub }

func (m withContext) MapResponseWithContext(in Inputs, prep Prepared, r transport.Result) Mapping {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ctxCalls++
	m.gotState = prep.AdapterState
	state := m.mappedState
	if state == "" {
		state = "accepted"
	}
	return Mapping{ExecutionState: state, ReasonCodes: []string{}, EvidenceLevel: "accepted", ProviderRequestID: m.providerID}
}

// withBuilder adds ContextMapper and ResultBuilder.
type withBuilder struct{ withContext }

func (m withBuilder) BuildResult(in Inputs, prep Prepared, r transport.Result, mp Mapping, aux *AuxWriteResult) (json.RawMessage, bool, *string, error) {
	m.mu.Lock()
	m.gotAux = append(m.gotAux, aux)
	m.mu.Unlock()
	if m.buildErr != nil {
		return nil, false, nil, m.buildErr
	}
	if m.badBody {
		return json.RawMessage(`"scalar"`), false, nil, nil
	}
	out := map[string]any{"text": "hello"}
	if aux != nil && aux.ModelTurn != nil {
		out["conversation_id"], out["turn_index"] = aux.ModelTurn.ConversationID, aux.ModelTurn.TurnIndex
	}
	b, _ := json.Marshal(out)
	return b, false, nil, nil
}

// withTurn adds ModelTurnWriter to withBuilder.
type withTurn struct{ withBuilder }

func (m withTurn) ModelTurn(in Inputs, prep Prepared, r transport.Result, mp Mapping) (*ModelTurnWrite, error) {
	if m.turn != nil {
		return m.turn(r)
	}
	var resp struct {
		Candidates []struct {
			Content struct {
				Parts json.RawMessage `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(r.Body, &resp); err != nil || len(resp.Candidates) == 0 {
		return nil, errors.New("no candidate")
	}
	return &ModelTurnWrite{ConversationID: hookConv, RawParts: resp.Candidates[0].Content.Parts, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

// turnOnly writes turns without a ResultBuilder; New must refuse it.
type turnOnly struct{ *modelStub }

func (turnOnly) ModelTurn(Inputs, Prepared, transport.Result, Mapping) (*ModelTurnWrite, error) {
	return nil, nil
}

// hookStore mirrors store.PG for the hook paths: model turns are allocated
// per conversation inside "the transaction", BuildResult runs there, and a
// failure writes nothing (AuxWriteError).
type hookStore struct {
	mu        sync.Mutex
	saves     []PendingOutcome
	pending   map[string]PendingOutcome
	results   []ActionResult
	turns     []ModelTurnWrite
	next      map[string]int64
	states    map[string]string
	failTurns bool
}

func newHookStore() *hookStore {
	return &hookStore{pending: map[string]PendingOutcome{}, next: map[string]int64{}, states: map[string]string{}}
}

func (s *hookStore) Begin(context.Context, string, string, string) (Execution, bool, error) {
	return Execution{}, false, errors.New("unused")
}
func (s *hookStore) SetState(_ context.Context, d string, _ []string, to, _ string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[d] = to
	return true, nil
}
func (s *hookStore) Unfinished(context.Context, string) ([]Execution, error) { return nil, nil }
func (s *hookStore) SavePending(_ context.Context, p PendingOutcome, _ *DataStateRaise) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves = append(s.saves, p)
	if _, ok := s.pending[p.DecisionID]; ok {
		return nil
	}
	if p.ModelTurn != nil {
		if s.failTurns {
			return &AuxWriteError{Err: errors.New("conversation_id belongs to another session")}
		}
		idx := s.next[p.ModelTurn.ConversationID]
		r, err := p.BuildResult(AuxWriteResult{ModelTurn: &ModelTurnKey{ConversationID: p.ModelTurn.ConversationID, TurnIndex: idx}})
		if err != nil {
			return &AuxWriteError{Err: err}
		}
		s.next[p.ModelTurn.ConversationID] = idx + 1
		s.turns = append(s.turns, *p.ModelTurn)
		// What pending_outcomes keeps: no model turn, no builder.
		p.Result, p.ModelTurn, p.BuildResult = &r, nil, nil
	}
	s.pending[p.DecisionID] = p
	return nil
}
func (s *hookStore) Pending(_ context.Context, d string) (PendingOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[d]
	if !ok {
		return p, ErrNotFound
	}
	return p, nil
}
func (s *hookStore) InsertResult(_ context.Context, r ActionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(r.ResultDigest) != 64 || len(r.ResultBody) == 0 {
		return fmt.Errorf("result violates the table checks: %q", r.ResultDigest)
	}
	s.results = append(s.results, r)
	return nil
}
func (s *hookStore) EventID(_ context.Context, _, _, c string) (string, error) { return c, nil }

type hookCoord struct {
	mu       sync.Mutex
	outcomes []OutcomeRequest
}

func (c *hookCoord) Reserve(context.Context, ReserveRequest) (Permit, error) {
	return Permit{}, errors.New("unused")
}
func (c *hookCoord) Check(context.Context, string, CheckRequest) (CheckResult, error) {
	return CheckResult{ExecutionAllowed: true}, nil
}
func (c *hookCoord) Outcome(_ context.Context, _ string, req OutcomeRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.outcomes = append(c.outcomes, req)
	return nil
}

type hookAudit struct {
	mu     sync.Mutex
	events []Event
}

func (a *hookAudit) Emit(_ context.Context, ev Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
	return nil
}

type hookTLS struct {
	cert tls.Certificate
	pool *x509.CertPool
}

func (m hookTLS) ClientCertificate() (*tls.Certificate, error) { c := m.cert; return &c, nil }
func (m hookTLS) RootCAs(string) (*x509.CertPool, error)       { return m.pool, nil }

type hookResolver struct{}

func (hookResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == hookHost {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type hookRig struct {
	t     *testing.T
	store *hookStore
	coord *hookCoord
	audit *hookAudit
	logs  *strings.Builder
	eng   *Engine
	port  string
	tls   hookTLS
	body  string
}

func newHookRig(t *testing.T, a Adapter) *hookRig {
	t.Helper()
	ca := testpki.NewCA(t, "cluster")
	leaf := ca.Issue(t, []string{hookHost}, nil, nil)
	client := ca.Issue(t, nil, nil, []string{"spiffe://agentarium.internal/ns/agent-adapters/sa/model"})
	h := &hookRig{t: t, store: newHookStore(), coord: &hookCoord{}, audit: &hookAudit{}, logs: &strings.Builder{},
		tls: hookTLS{cert: client.TLS, pool: ca.Pool}, body: hookResponse}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, h.body)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.TLS}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, h.port, _ = net.SplitHostPort(srv.Listener.Addr().String())
	var err error
	h.eng, err = New(Config{
		Adapter: a, Store: h.store, Coordinator: h.coord, Auditor: h.audit, TLS: h.tls,
		Credential: CredentialStrategy{Kind: CredentialNone},
		Transport:  transport.Config{Resolver: hookResolver{}, Netns: func() *uint64 { v := uint64(4026531840); return &v }},
		PodUID:     "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f", RetryBackoff: time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(&syncWriter{b: h.logs}, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type syncWriter struct {
	mu sync.Mutex
	b  *strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// run dispatches one attempt for a fresh decision and returns it.
func (h *hookRig) run() (decisionID, attemptID string) {
	h.t.Helper()
	body := []byte(`{"contents":[]}`)
	plan := canonical.WirePlan{
		Method: "POST", OriginID: "https://" + hookHost + ":" + h.port, Route: "/v1/models/m:generateContent",
		SafeHeaders: map[string]string{"User-Agent": "agentarium-test", "Content-Type": "application/json"},
		BodyBytes:   body, WireBodyDigest: canonical.WireBodyDigest(body), ResponseLimit: 65536, Timeout: 5 * time.Second,
		ExpectedTLSName: hookHost, AllowedCIDRs: []string{"127.0.0.0/8"},
	}
	prep := Prepared{Plan: plan, CARef: "cluster", ResponseDataClass: "internal", AdapterState: adapterState{Profile: "agent"}}
	decisionID, attemptID = newUUID(), newUUID()
	in := Inputs{
		Decision: Decision{DecisionID: decisionID, ActionID: newUUID(), RequestID: newUUID()},
		Envelope: canonical.ActionEnvelope{SessionKind: "service", SessionID: hookSession, CanonicalTarget: canonical.CanonicalTarget{TargetID: "agent-platform"}},
	}
	permit := Permit{PermitID: newUUID(), AttemptID: attemptID, WireBodyDigest: plan.WireBodyDigest}
	h.eng.dispatch(context.Background(), h.eng.log, in, prep, DataStateKey{ServiceSessionID: hookSession}, permit)
	return decisionID, attemptID
}

func (h *hookRig) final() OutcomeRequest {
	h.coord.mu.Lock()
	defer h.coord.mu.Unlock()
	return h.coord.outcomes[len(h.coord.outcomes)-1]
}

func (h *hookRig) event(typ string) *Event {
	h.audit.mu.Lock()
	defer h.audit.mu.Unlock()
	for _, e := range h.audit.events {
		if e.Type == typ {
			ev := e
			return &ev
		}
	}
	return nil
}

// noSignature fails if the thought signature reached anything but the model
// turn: recovery records, results, outcomes, events or logs.
func (h *hookRig) noSignature() {
	h.t.Helper()
	check := func(what string, v any) {
		b, err := json.Marshal(v)
		if err != nil {
			h.t.Fatalf("%s: %v", what, err)
		}
		if strings.Contains(string(b), hookSig) {
			h.t.Errorf("thought signature in %s: %s", what, b)
		}
	}
	h.store.mu.Lock()
	for _, p := range h.store.pending {
		check("pending_outcomes", p)
	}
	check("action_results", h.store.results)
	h.store.mu.Unlock()
	check("outcomes", h.coord.outcomes)
	check("events", h.audit.events)
	if strings.Contains(h.logs.String(), hookSig) {
		h.t.Errorf("thought signature in the log: %s", h.logs.String())
	}
}

func TestDefaultPathKeepsRedactedBody(t *testing.T) {
	m := &modelStub{}
	h := newHookRig(t, m)
	d, _ := h.run()
	if m.mapCalls != 1 {
		t.Fatalf("MapResponse calls %d", m.mapCalls)
	}
	if h.store.states[d] != StateCompleted || len(h.store.results) != 1 || !strings.Contains(string(h.store.results[0].ResultBody), hookSig) {
		t.Fatalf("an adapter without ResultBuilder must keep the redacted raw body: %s %+v", h.store.states[d], h.store.results)
	}
	if o := h.final(); o.Observation.ProviderRequestID != nil {
		t.Fatalf("provider_request_id without a mapping value: %v", *o.Observation.ProviderRequestID)
	}
}

func TestContextMapperAndProviderRequestID(t *testing.T) {
	m := &modelStub{providerID: "resp-123"}
	h := newHookRig(t, withContext{m})
	d, at := h.run()
	if m.mapCalls != 0 || m.ctxCalls != 1 || m.gotState != (adapterState{Profile: "agent"}) {
		t.Fatalf("MapResponse %d, MapResponseWithContext %d, AdapterState %#v", m.mapCalls, m.ctxCalls, m.gotState)
	}
	o := h.final()
	if o.Transition != TransitionResponseReceived || o.Observation.ProviderRequestID == nil || *o.Observation.ProviderRequestID != "resp-123" {
		t.Fatalf("outcome %+v", o)
	}
	p := h.store.pending[d]
	if p.Observation.ProviderRequestID == nil || *p.Observation.ProviderRequestID != "resp-123" {
		t.Fatal("recovery record observation without provider_request_id")
	}
	ev := h.event("response_received")
	if ev == nil || ev.AttemptID != at {
		t.Fatal("no response_received event")
	}
	if id, ok := ev.Payload["provider_request_id"].(*string); !ok || id == nil || *id != "resp-123" {
		t.Fatalf("event payload provider_request_id %#v", ev.Payload["provider_request_id"])
	}

	// An unrecordable value is dropped, not truncated.
	for _, bad := range []string{strings.Repeat("r", MaxProviderRequestID+1), "resp 1", "resp\n1", "résp"} {
		m.providerID = bad
		h.run()
		if o := h.final(); o.Observation.ProviderRequestID != nil {
			t.Fatalf("provider_request_id %q recorded as %q", bad, *o.Observation.ProviderRequestID)
		}
	}
	m.providerID = strings.Repeat("r", MaxProviderRequestID)
	h.run()
	if o := h.final(); o.Observation.ProviderRequestID == nil {
		t.Fatal("256-byte provider_request_id dropped")
	}
}

func TestResultBuilderWithoutTurn(t *testing.T) {
	m := &modelStub{}
	h := newHookRig(t, withBuilder{withContext{m}})
	d, _ := h.run()
	if h.store.states[d] != StateCompleted || len(h.store.results) != 1 {
		t.Fatalf("state %s results %d", h.store.states[d], len(h.store.results))
	}
	r := h.store.results[0]
	if string(r.ResultBody) != `{"text":"hello"}` || r.ExecutionState != "accepted" || r.DataClass != "internal" {
		t.Fatalf("result %+v %s", r, r.ResultBody)
	}
	if want, _ := canonical.CanonicalDigestJSON(r.ResultBody); r.ResultDigest != want {
		t.Fatalf("result_digest %s want %s", r.ResultDigest, want)
	}
	if len(m.gotAux) != 1 || m.gotAux[0] != nil {
		t.Fatalf("aux without a model turn: %v", m.gotAux)
	}
	h.noSignature()
}

func TestResultBuilderWithModelTurn(t *testing.T) {
	m := &modelStub{providerID: "resp-123"}
	h := newHookRig(t, withTurn{withBuilder{withContext{m}}})
	for i := 0; i < 3; i++ {
		d, at := h.run()
		if h.store.states[d] != StateCompleted {
			t.Fatalf("%d: state %s", i, h.store.states[d])
		}
		r := h.store.results[i]
		want := fmt.Sprintf(`{"conversation_id":%q,"text":"hello","turn_index":%d}`, hookConv, i)
		if r.AttemptID != at || string(r.ResultBody) != want {
			t.Fatalf("%d: result body %s want %s", i, r.ResultBody, want)
		}
		turn := h.store.turns[i]
		if turn.ActionID != r.ActionID || turn.SessionKey != hookSession || !strings.Contains(string(turn.RawParts), hookSig) {
			t.Fatalf("%d: model turn %s raw %s", i, turn, turn.RawParts)
		}
	}
	// The engine handed SavePending the turn and the builder, not a result.
	for _, p := range h.store.saves {
		if p.ModelTurn == nil || p.BuildResult == nil || p.Result != nil {
			t.Fatalf("SavePending got %+v", p)
		}
	}
	// The turn's String/LogValue hide the raw parts.
	if s := fmt.Sprintf("%v %+v %#v", h.store.turns[0], h.store.turns[0], h.store.turns[0]); strings.Contains(s, hookSig) {
		t.Fatalf("formatted model turn shows raw parts: %s", s)
	}
	h.noSignature()
}

func TestConservativeResult(t *testing.T) {
	cases := map[string]struct {
		setup     func(*modelStub, *hookRig)
		wantTurns int
	}{
		"builder error": {setup: func(m *modelStub, _ *hookRig) { m.buildErr = errors.New("unparseable candidate") }},
		"scalar body":   {setup: func(m *modelStub, _ *hookRig) { m.badBody = true }},
		"turn error": {setup: func(m *modelStub, _ *hookRig) {
			m.turn = func(transport.Result) (*ModelTurnWrite, error) { return nil, errors.New("no candidate") }
		}},
		"raw parts not an array": {setup: func(m *modelStub, _ *hookRig) {
			m.turn = func(transport.Result) (*ModelTurnWrite, error) {
				return &ModelTurnWrite{ConversationID: hookConv, RawParts: json.RawMessage(`{"thoughtSignature":"` + hookSig + `"}`), ExpiresAt: time.Now().Add(time.Hour)}, nil
			}
		}},
		"other session": {setup: func(m *modelStub, _ *hookRig) {
			m.turn = func(transport.Result) (*ModelTurnWrite, error) {
				return &ModelTurnWrite{ConversationID: hookConv, SessionKey: newUUID(), RawParts: json.RawMessage(`[]`), ExpiresAt: time.Now().Add(time.Hour)}, nil
			}
		}},
		"no expiry": {setup: func(m *modelStub, _ *hookRig) {
			m.turn = func(transport.Result) (*ModelTurnWrite, error) {
				return &ModelTurnWrite{ConversationID: hookConv, RawParts: json.RawMessage(`[]`)}, nil
			}
		}},
		"store refuses the turn": {setup: func(_ *modelStub, h *hookRig) { h.store.failTurns = true }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m := &modelStub{}
			h := newHookRig(t, withTurn{withBuilder{withContext{m}}})
			c.setup(m, h)
			d, at := h.run()
			if h.store.states[d] != StateCompleted || len(h.store.results) != 1 {
				t.Fatalf("state %s results %d", h.store.states[d], len(h.store.results))
			}
			r := h.store.results[0]
			if r.AttemptID != at || string(r.ResultBody) != "null" || r.ExecutionState != "failed" || r.EvidenceLevel != "accepted" ||
				r.ResultDigest != canonical.SHA256Hex([]byte("null")) || r.Truncated || r.TruncationReason != nil {
				t.Fatalf("result %+v %s", r, r.ResultBody)
			}
			if len(h.store.turns) != c.wantTurns {
				t.Fatalf("turns %d", len(h.store.turns))
			}
			if p := h.store.pending[d]; p.ModelTurn != nil || p.BuildResult != nil || p.Transition != TransitionResponseReceived {
				t.Fatalf("recovery record %+v", p)
			}
			if o := h.final(); o.Transition != TransitionResponseReceived {
				t.Fatalf("outcome %+v", o)
			}
			h.noSignature()
		})
	}
	// A mapped failure stays failed; the conservative result never raises a
	// state.
	m := &modelStub{mappedState: "unknown", buildErr: errors.New("x")}
	h := newHookRig(t, withBuilder{withContext{m}})
	h.run()
	if r := h.store.results[0]; r.ExecutionState != "unknown" || string(r.ResultBody) != "null" {
		t.Fatalf("result %+v", r)
	}
}

func TestBuilderTruncationRules(t *testing.T) {
	reason := "limit_bytes"
	empty := ""
	res := ActionResult{}
	if err := setBody(&res, json.RawMessage(`{}`), false, &reason); err == nil {
		t.Fatal("truncation_reason without truncated accepted")
	}
	if err := setBody(&res, json.RawMessage(`{}`), true, nil); err == nil {
		t.Fatal("truncated without truncation_reason accepted")
	}
	if err := setBody(&res, json.RawMessage(`{}`), true, &empty); err == nil {
		t.Fatal("empty truncation_reason accepted")
	}
	if err := setBody(&res, json.RawMessage(`{"a":1,"a":2}`), false, nil); err == nil {
		t.Fatal("duplicate keys accepted")
	}
	res = ActionResult{ResultBody: json.RawMessage("null")}
	if err := setBody(&res, nil, true, &reason); err != nil || !res.Truncated || *res.TruncationReason != reason || string(res.ResultBody) != "null" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestModelTurnWriterNeedsResultBuilder(t *testing.T) {
	if _, err := New(Config{Adapter: turnOnly{&modelStub{}}, Store: newHookStore(), Credential: CredentialStrategy{Kind: CredentialNone},
		PodUID: "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"}); err == nil {
		t.Fatal("ModelTurnWriter without ResultBuilder accepted")
	}
}

// truncStub has no ResultBuilder: its mapping's truncation is stored.
type truncStub struct {
	*modelStub
	truncated bool
	reason    string
}

func (s truncStub) MapResponse(transport.Result) Mapping {
	return Mapping{ExecutionState: "accepted", ReasonCodes: []string{}, EvidenceLevel: "accepted", Truncated: s.truncated, TruncationReason: s.reason}
}

func TestMappingTruncation(t *testing.T) {
	h := newHookRig(t, truncStub{modelStub: &modelStub{}, truncated: true, reason: "continue"})
	h.body = `{"metadata":{"continue":"abc"},"items":[]}`
	h.run()
	r := h.store.results[0]
	if !r.Truncated || r.TruncationReason == nil || *r.TruncationReason != "continue" || r.ExecutionState != "accepted" || string(r.ResultBody) != h.body {
		t.Fatalf("result %+v %s", r, r.ResultBody)
	}
	// Default mapping: not truncated.
	h = newHookRig(t, truncStub{modelStub: &modelStub{}})
	h.run()
	if r := h.store.results[0]; r.Truncated || r.TruncationReason != nil {
		t.Fatalf("result %+v", r)
	}
	// An invalid pair is a mapping error: conservative result.
	for _, bad := range []truncStub{{truncated: true}, {reason: "continue"}} {
		bad.modelStub = &modelStub{}
		h := newHookRig(t, bad)
		h.run()
		r := h.store.results[0]
		if r.Truncated || r.TruncationReason != nil || r.ExecutionState != "failed" || string(r.ResultBody) != "null" {
			t.Fatalf("%v/%q: result %+v %s", bad.truncated, bad.reason, r, r.ResultBody)
		}
	}
}

func TestPreflightServiceSessionBinding(t *testing.T) {
	e, err := New(Config{Adapter: &modelStub{}, Store: newHookStore(), Credential: CredentialStrategy{Kind: CredentialNone},
		PodUID: "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		decision string
		want     bool
	}{
		"same":          {hookSession, false},
		"missing":       {"", true},
		"other session": {newUUID(), true},
		"upper case":    {strings.ToUpper(hookSession), true},
	} {
		in := Inputs{Decision: Decision{ServiceSessionID: c.decision},
			Envelope: canonical.ActionEnvelope{SessionKind: "service", SessionID: hookSession}}
		_, key, rej, err := e.preflight(context.Background(), "", "", in, &Bundle{})
		if err != nil || rej == nil {
			t.Fatalf("%s: %v %v", name, rej, err)
		}
		got := false
		for _, f := range rej.ComparedFields {
			got = got || f == "service_session_id"
		}
		if got != c.want || (c.want && key.ServiceSessionID != "") || (!c.want && key.ServiceSessionID != hookSession) {
			t.Fatalf("%s: compared %v key %+v", name, rej.ComparedFields, key)
		}
	}
	// A user session is not bound by service_session_id.
	w := "agent-runtime-0"
	in := Inputs{Envelope: canonical.ActionEnvelope{SessionKind: "user", SessionID: hookSession, WorkloadID: &w}}
	_, _, rej, _ := e.preflight(context.Background(), "", "", in, &Bundle{})
	for _, f := range rej.ComparedFields {
		if f == "service_session_id" {
			t.Fatal("user session compared on service_session_id")
		}
	}
}
