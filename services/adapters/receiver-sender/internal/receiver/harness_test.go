package receiver_test

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/receiver"
)

const (
	receiverHost = "receiver.agent-targets.svc"
	receiverSAN  = "spiffe://agentarium.internal/ns/agent-targets/sa/receiver"
	adapterSAN   = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
	apiKeyHeader = receiver.KeyHeader
	apiKeyValue  = "c3ludGhldGljLXJlY2VpdmVyLWtleS0wMDAwMDAwMDA" // 32 bytes, unpadded base64url
	bundleID     = "bundle-1"
)

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// opLog is one ordered log shared by the store and the coordinator, so the
// commit order can be asserted.
type opLog struct {
	mu  sync.Mutex
	ops []string
}

func (l *opLog) add(s string) {
	l.mu.Lock()
	l.ops = append(l.ops, s)
	l.mu.Unlock()
}

func (l *opLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ops...)
}

// ---- in-memory execute.Store ------------------------------------------------

type memStore struct {
	mu         sync.Mutex
	log        *opLog
	rows       map[string]execute.Execution
	pending    map[string]execute.PendingOutcome
	results    map[string]execute.ActionResult
	data       map[execute.DataStateKey]string
	eventIDs   map[string]string
	failSave   bool
	failResult int // remaining InsertResult failures
}

var rank = map[string]int{"none": 0, "synthetic": 1, "internal": 2, "confidential": 3}

func newMemStore(log *opLog) *memStore {
	return &memStore{log: log, rows: map[string]execute.Execution{}, pending: map[string]execute.PendingOutcome{},
		results: map[string]execute.ActionResult{}, data: map[execute.DataStateKey]string{}, eventIDs: map[string]string{}}
}

func (s *memStore) Begin(_ context.Context, d, a, ad string) (execute.Execution, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[d]; ok {
		return r, false, nil
	}
	r := execute.Execution{DecisionID: d, ActionID: a, AdapterID: ad, State: execute.StateReceived, UpdatedAt: time.Now()}
	s.rows[d] = r
	return r, true, nil
}

func (s *memStore) SetState(_ context.Context, d string, from []string, to, attempt string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rows[d]
	if !ok || !slices.Contains(from, r.State) {
		return false, nil
	}
	r.State = to
	if attempt != "" {
		r.AttemptID = attempt
	}
	s.rows[d] = r
	s.log.add("state:" + to)
	return true, nil
}

func (s *memStore) Unfinished(_ context.Context, ad string) ([]execute.Execution, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []execute.Execution
	for _, r := range s.rows {
		if r.AdapterID == ad && (r.State == execute.StateReceived || r.State == execute.StateReserved) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *memStore) SavePending(_ context.Context, p execute.PendingOutcome, raise *execute.DataStateRaise) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failSave {
		return errors.New("db down")
	}
	if raise != nil {
		if rank[raise.DataClass] >= rank[s.data[raise.Key]] {
			s.data[raise.Key] = raise.DataClass
		}
		s.log.add("raise:" + raise.DataClass)
	}
	if _, ok := s.pending[p.DecisionID]; !ok {
		s.pending[p.DecisionID] = p
	}
	s.log.add("pending:" + p.Transition)
	return nil
}

func (s *memStore) Pending(_ context.Context, d string) (execute.PendingOutcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[d]
	if !ok {
		return p, execute.ErrNotFound
	}
	return p, nil
}

func (s *memStore) InsertResult(_ context.Context, r execute.ActionResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failResult > 0 {
		s.failResult--
		return errors.New("db down")
	}
	// Mirror the action_results CHECKs.
	if len(r.ResultDigest) != 64 || len(r.ResultBody) == 0 {
		return fmt.Errorf("result_digest %q / result_body %q violate the table checks", r.ResultDigest, r.ResultBody)
	}
	if _, ok := s.results[r.AttemptID]; !ok {
		s.results[r.AttemptID] = r
	}
	s.log.add("result:" + r.ExecutionState)
	return nil
}

func (s *memStore) EventID(_ context.Context, d, typ, candidate string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.rows[d]; !ok {
		return "", execute.ErrNotFound
	}
	k := d + "/" + typ
	if id, ok := s.eventIDs[k]; ok {
		return id, nil
	}
	s.eventIDs[k] = candidate
	return candidate, nil
}

func (s *memStore) row(d string) execute.Execution {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rows[d]
}

// ---- fake coordinator (COMMON dispatch API over HTTP) ----------------------

type outcomeRec struct {
	Transition  string
	ReasonCodes []string
	Observation *transport.Observation
}

type fakeCoord struct {
	t   *testing.T
	log *opLog
	srv *httptest.Server

	mu            sync.Mutex
	reservations  int
	reserved      map[string]bool // action_id
	permits       map[string]string
	claimed       map[string]bool
	outcomes      map[string][]outcomeRec // attempt_id
	refuseRes     []string
	refuseCheck   []string
	failOutcome   map[string]int    // transition -> remaining 503s
	refuseOutcome map[string]int    // transition -> remaining refusals
	refuseCode    int               // status of a refusal, 409 when 0
	state         map[string]string // attempt_id -> attempt.state
	reported      map[string]string // attempt_id -> last accepted report
	reports       int
	lastAttempt   string
}

func newFakeCoord(t *testing.T, log *opLog) *fakeCoord {
	c := &fakeCoord{t: t, log: log, reserved: map[string]bool{}, permits: map[string]string{}, claimed: map[string]bool{},
		outcomes: map[string][]outcomeRec{}, failOutcome: map[string]int{}, refuseOutcome: map[string]int{},
		state: map[string]string{}, reported: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/dispatch/reservations", c.reserve)
	mux.HandleFunc("POST /internal/dispatch/permits/{permit_id}/check", c.check)
	mux.HandleFunc("POST /internal/dispatch/attempts/{attempt_id}/outcome", c.outcome)
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func writeErr(w http.ResponseWriter, status int, codes ...string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"request_id": newUUID(), "reason_codes": codes})
}

func strictBody(t *testing.T, r *http.Request, v any) bool {
	b, _ := io.ReadAll(r.Body)
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Errorf("coordinator got a non-contract body %s: %v", b, err)
		return false
	}
	return true
}

func (c *fakeCoord) reserve(w http.ResponseWriter, r *http.Request) {
	var req execute.ReserveRequest
	if !strictBody(c.t, r, &req) {
		writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.refuseRes) > 0 {
		writeErr(w, 409, c.refuseRes...)
		return
	}
	if c.reserved[req.ActionID] {
		writeErr(w, 409, "PERMIT_INVALID")
		return
	}
	c.reserved[req.ActionID] = true
	c.reservations++
	p := execute.Permit{PermitID: newUUID(), DecisionID: req.DecisionID, ActionID: req.ActionID, RequestID: req.RequestID,
		AttemptID: newUUID(), ReservationID: newUUID(), AdapterID: receiver.AdapterID, ActionDigest: req.ActionDigest,
		WireBodyDigest: req.WireBodyDigest, PolicyEpoch: req.PolicyEpoch, CatalogDigest: req.CatalogDigest,
		ExpiresAt: time.Now().Add(10 * time.Second)}
	c.permits[p.PermitID] = p.AttemptID
	c.lastAttempt = p.AttemptID
	c.log.add("reserve")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(p)
}

func (c *fakeCoord) check(w http.ResponseWriter, r *http.Request) {
	var req execute.CheckRequest
	if !strictBody(c.t, r, &req) {
		writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	id := r.PathValue("permit_id")
	if len(c.refuseCheck) > 0 {
		writeErr(w, 409, c.refuseCheck...)
		return
	}
	if c.permits[id] != req.AttemptID || c.claimed[id] {
		writeErr(w, 409, "PERMIT_INVALID")
		return
	}
	c.claimed[id] = true
	c.state[req.AttemptID] = "claimed"
	c.log.add("claim")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"permit_id": id, "attempt_id": req.AttemptID, "execution_allowed": true, "claimed_at": time.Now()})
}

// postClaim and checkObs mirror the coordinator outcome contract (TASK-03,
// services/coordinator/internal/dispatch/outcome.go on the C2 branch).
var postClaim = map[string][]string{
	"claimed":    {"dispatched", "response_received", "failed", "unknown"},
	"dispatched": {"response_received", "unknown"},
}

func checkObs(attemptID, transition string, o *transport.Observation) bool {
	if o == nil || o.AttemptID != attemptID {
		return false
	}
	all := func(ps ...bool) bool { return !slices.Contains(ps, false) }
	none := func(ps ...bool) bool { return !slices.Contains(ps, true) }
	conn := []bool{o.LocalAddr != nil, o.LocalPort != nil, o.NetnsInode != nil}
	peer := []bool{o.PeerAddr != nil, o.PeerPort != nil}
	if !(all(conn...) || none(conn...)) || !(all(peer...) || none(peer...)) || (o.PeerAddrKind != nil && o.PeerAddr == nil) {
		return false
	}
	if o.PodUID == nil || !execute.ValidUUID(*o.PodUID) || (o.NetnsInode != nil && *o.NetnsInode == 0) {
		return false
	}
	var last *time.Time
	for _, t := range []*time.Time{o.ConnectStartedAt, o.SendStartedAt, o.SendFinishedAt, o.ResponseAt} {
		if t == nil {
			continue
		}
		if last != nil && t.Before(*last) {
			return false
		}
		last = t
	}
	sent := all(conn...) && all(peer...) && o.DialedAddr != nil && o.PeerAddrKind != nil && o.ConnectStartedAt != nil && o.SendStartedAt != nil
	switch transition {
	case "dispatched":
		return sent && o.ResponseAt == nil
	case "response_received":
		return sent && o.SendFinishedAt != nil && o.ResponseAt != nil
	case "failed":
		return o.SendStartedAt == nil && o.SendFinishedAt == nil && o.ResponseAt == nil
	case "unknown":
		return o.ResponseAt == nil
	}
	return false
}

func (c *fakeCoord) outcome(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Transition  string                 `json:"transition"`
		Observation *transport.Observation `json:"observation"`
		ReasonCodes []string               `json:"reason_codes"`
	}
	if !strictBody(c.t, r, &req) {
		writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.failOutcome[req.Transition]; n > 0 {
		c.failOutcome[req.Transition] = n - 1
		writeErr(w, 503, "STATE_STORE_UNAVAILABLE")
		return
	}
	if n := c.refuseOutcome[req.Transition]; n > 0 {
		c.refuseOutcome[req.Transition] = n - 1
		if c.refuseCode == 422 {
			writeErr(w, 422, "SCHEMA_INVALID")
		} else {
			writeErr(w, 409, "PERMIT_INVALID")
		}
		return
	}
	id := r.PathValue("attempt_id")
	state := "planned"
	if c.state[id] != "" {
		state = c.state[id]
	}
	if req.ReasonCodes == nil {
		c.t.Errorf("outcome %s without reason_codes array", req.Transition)
	}
	if req.Transition == "released" {
		if state != "planned" || req.Observation != nil || len(req.ReasonCodes) == 0 {
			writeErr(w, 409, "PERMIT_INVALID")
			return
		}
		c.state[id] = "released"
		c.outcomes[id] = append(c.outcomes[id], outcomeRec{req.Transition, req.ReasonCodes, nil})
		c.log.add("outcome:released")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"attempt_id": id, "state": "released"})
		return
	}
	if (req.Transition == "failed" || req.Transition == "unknown") && len(req.ReasonCodes) == 0 {
		writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	if !checkObs(id, req.Transition, req.Observation) {
		c.t.Errorf("observation does not fit %s: %+v", req.Transition, req.Observation)
		writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	body, _ := json.Marshal([]any{req.Observation, req.ReasonCodes})
	if state == req.Transition {
		// An identical re-report returns the stored result.
		if string(body) == c.reported[id] {
			c.reports++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"attempt_id": id, "state": state})
			return
		}
		writeErr(w, 409, "PERMIT_INVALID")
		return
	}
	if !slices.Contains(postClaim[state], req.Transition) {
		writeErr(w, 409, "PERMIT_INVALID")
		return
	}
	c.state[id] = req.Transition
	c.reported[id] = string(body)
	c.reports++
	c.outcomes[id] = append(c.outcomes[id], outcomeRec{req.Transition, req.ReasonCodes, req.Observation})
	c.log.add("outcome:" + req.Transition)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"attempt_id": id, "state": req.Transition})
}

func (c *fakeCoord) transitions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, o := range c.outcomes[c.lastAttempt] {
		out = append(out, o.Transition)
	}
	return out
}

func (c *fakeCoord) last() outcomeRec {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.outcomes[c.lastAttempt]
	if len(o) == 0 {
		return outcomeRec{}
	}
	return o[len(o)-1]
}

// ---- receiver target ------------------------------------------------------

type fakeReceiver struct {
	srv     *httptest.Server
	port    string
	count   atomic.Int32
	mu      sync.Mutex
	bodies  [][]byte
	headers []http.Header
	handler atomic.Pointer[http.HandlerFunc]
	// accept is the key the receiver accepts (apiKeyValue when unset).
	accept atomic.Pointer[string]
}

func (fr *fakeReceiver) key() string {
	if k := fr.accept.Load(); k != nil {
		return *k
	}
	return apiKeyValue
}

func newFakeReceiver(t *testing.T, ca *testpki.CA) *fakeReceiver {
	fr := &fakeReceiver{}
	// A TASK-03 service certificate: the receiver's URI SAN only, no DNS
	// name (agentarium-trust targets are verified by expected_uri_san).
	leaf := ca.Issue(t, nil, nil, []string{receiverSAN})
	fr.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.count.Add(1)
		b, _ := io.ReadAll(r.Body)
		fr.mu.Lock()
		fr.bodies = append(fr.bodies, b)
		fr.headers = append(fr.headers, r.Header.Clone())
		fr.mu.Unlock()
		if len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].URIs[0].String() != adapterSAN {
			writeErr(w, 401, "AUTH_REQUIRED")
			return
		}
		// TASK-08 receiver key check: after the SAN, before any write.
		if r.Header.Get(receiver.KeyHeader) != fr.key() {
			writeErr(w, 401, "RECEIVER_KEY_INVALID")
			return
		}
		if h := fr.handler.Load(); h != nil {
			(*h)(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = fmt.Fprintf(w, `{"receipt_attempt_id":%q,"effect_id":%q,"action_key":%q,"wire_body_digest":%q,"body_bytes":%d}`,
			newUUID(), newUUID(), r.Header.Get("Idempotency-Key"), canonical.SHA256Hex(b), len(b))
	}))
	fr.srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.TLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool}
	fr.srv.StartTLS()
	t.Cleanup(fr.srv.Close)
	_, fr.port, _ = net.SplitHostPort(fr.srv.Listener.Addr().String())
	return fr
}

func (fr *fakeReceiver) respond(h http.HandlerFunc) { fr.handler.Store(&h) }

// ---- other dependencies ---------------------------------------------------

type inputs struct {
	mu sync.Mutex
	in map[string]execute.Inputs
}

func (s *inputs) Load(_ context.Context, d, a string) (execute.Inputs, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.in[d]
	if !ok || in.Decision.ActionID != a {
		return in, execute.ErrNotFound
	}
	return in, nil
}

type bundles struct{ b *execute.Bundle }

func (s bundles) Current(context.Context) (*execute.Bundle, error) { return s.b, nil }

type auditor struct {
	mu      sync.Mutex
	events  []execute.Event
	fail    map[string]int
	lostAck map[string]int
}

func (a *auditor) Emit(_ context.Context, ev execute.Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail[ev.Type] > 0 {
		// The audit store is unavailable: nothing recorded.
		a.fail[ev.Type]--
		return errors.New("audit unavailable")
	}
	a.events = append(a.events, ev)
	if a.lostAck[ev.Type] > 0 {
		// Committed, but the adapter never learns it (crash after the audit
		// append).
		a.lostAck[ev.Type]--
		return errors.New("audit ack lost")
	}
	return nil
}

func (a *auditor) types() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.events {
		out = append(out, e.Type)
	}
	return out
}

func (a *auditor) find(typ string) *execute.Event {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.events {
		if e.Type == typ {
			ev := e
			return &ev
		}
	}
	return nil
}

type broker struct {
	calls atomic.Int32
	fail  bool
	// header and value override the answer when set.
	header, value string
}

func (b *broker) Resolve(_ context.Context, attemptID, adapterID, binding string) (execute.Credential, error) {
	b.calls.Add(1)
	if b.fail || adapterID != receiver.AdapterID || binding != "receiver-api-key" || attemptID == "" {
		return execute.Credential{}, &execute.RemoteError{Status: 503, ReasonCodes: []string{"CREDENTIAL_UNAVAILABLE"}}
	}
	c := execute.Credential{SecretVersion: "3", HeaderName: apiKeyHeader, HeaderValue: apiKeyValue, ExpiresAt: time.Now().Add(time.Minute)}
	if b.header != "" {
		c.HeaderName = b.header
	}
	if b.value != "" {
		c.HeaderValue = b.value
	}
	return c, nil
}

type tlsMat struct {
	cert tls.Certificate
	pool *x509.CertPool
}

func (m tlsMat) ClientCertificate() (*tls.Certificate, error) { c := m.cert; return &c, nil }
func (m tlsMat) RootCAs(ref string) (*x509.CertPool, error) {
	if ref != "agentarium-trust" {
		return nil, fmt.Errorf("unexpected ca_ref %s", ref)
	}
	return m.pool, nil
}

type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _ string, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// ---- harness ---------------------------------------------------------------

type harness struct {
	t        *testing.T
	log      *opLog
	store    *memStore
	coord    *fakeCoord
	recv     *fakeReceiver
	inputs   *inputs
	bundle   *execute.Bundle
	audit    *auditor
	broker   *broker
	resolver resolver
	engine   *execute.Engine
	cfg      execute.Config
	cat      canonical.Catalog
}

// useStore rebuilds the engine with another execute.Store (the Postgres
// store in the integration tests).
func (h *harness) useStore(s execute.Store) {
	h.t.Helper()
	cfg := h.cfg
	cfg.Store = s
	e, err := execute.New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.engine = e
}

type option func(*canonical.Catalog)

func withResponseClass(c string) option {
	return func(cat *canonical.Catalog) {
		op := cat.Operations[canonical.OpReceiverSubmit]
		op.ResponseDataClass = c
		cat.Operations[canonical.OpReceiverSubmit] = op
	}
}

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	ca := testpki.NewCA(t, "agentarium-trust")
	h := &harness{t: t, log: &opLog{}, audit: &auditor{fail: map[string]int{}, lostAck: map[string]int{}}, broker: &broker{}, inputs: &inputs{in: map[string]execute.Inputs{}}}
	h.store = newMemStore(h.log)
	h.coord = newFakeCoord(t, h.log)
	h.recv = newFakeReceiver(t, ca)
	h.resolver = resolver{receiverHost: {netip.MustParseAddr("127.0.0.1")}}

	_, file, _, _ := runtime.Caller(0)
	cat, err := canonical.LoadCatalogDir(filepath.Join(filepath.Dir(file), "..", "..", "..", "..", "..", "packages", "canonical", "testdata", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	tg := cat.Targets["receiver-primary"]
	tg.Origin = "https://" + receiverHost + ":" + h.recv.port
	tg.AllowedCIDRs = []string{"127.0.0.0/8"}
	cat.Targets["receiver-primary"] = tg
	for _, o := range opts {
		o(&cat)
	}
	if cat.CatalogDigest, err = cat.ComputeDigest(); err != nil {
		t.Fatal(err)
	}
	h.cat = cat
	h.bundle = &execute.Bundle{
		BundleID: bundleID, ArtifactDigest: strings.Repeat("a", 64), Catalog: cat,
		ReceiverAllowedFields: []string{"summary"},
		AdapterConstraints: map[string]execute.AdapterConstraint{receiver.AdapterID: {
			MaxRequestBytes: 65536, MaxResponseBytes: 65536, AllowedRouteIDs: []string{"submissions-v1"}}},
	}
	client := ca.Issue(t, nil, nil, []string{adapterSAN})
	h.cfg = execute.Config{
		Adapter: receiver.Adapter{}, Store: h.store, Inputs: h.inputs, Bundles: bundles{h.bundle},
		Coordinator: &execute.HTTPCoordinator{BaseURL: h.coord.srv.URL, Client: h.coord.srv.Client()},
		Credential:  execute.CredentialStrategy{Kind: execute.CredentialBroker}, Credentials: h.broker, TLS: tlsMat{cert: client.TLS, pool: ca.Pool}, Auditor: h.audit,
		Transport:    transport.Config{Resolver: h.resolver, Netns: func() *uint64 { v := uint64(4026531840); return &v }},
		PodUID:       "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f",
		RetryBackoff: time.Millisecond,
	}
	h.engine, err = execute.New(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// action stores an approved receiver.submit action and returns its decision ID.
func (h *harness) action(payload string) (decisionID, actionID string) {
	h.t.Helper()
	w := "agent-runtime-0"
	actionID, decisionID = newUUID(), newUUID()
	raw := `{"session_id":"51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},"arguments":{"payload":` + payload + `},"client_request_key":"req-00000001"}`
	env, content, nerr := canonical.NormalizeRaw([]byte(raw), canonical.TrustedContext{
		ActionID: actionID, RequestID: newUUID(), AuthenticatedActor: "user:alice@example.com", SessionKind: "user",
		SessionID: "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d", WorkloadID: &w, Tenant: "hackathon", Environment: "test",
	}, h.cat)
	if nerr != nil {
		h.t.Fatal(nerr)
	}
	h.inputs.mu.Lock()
	h.inputs.in[decisionID] = execute.Inputs{
		Decision: execute.Decision{DecisionID: decisionID, RequestID: env.RequestID, ActionID: actionID, ActionDigest: env.ActionDigest,
			AdapterID: receiver.AdapterID, Verdict: "allow", PolicyBundleID: bundleID, PolicyEpoch: 7, CatalogDigest: env.CatalogDigest,
			ExpiresAt: time.Now().Add(10 * time.Second)},
		Envelope: env, Content: content,
	}
	h.inputs.mu.Unlock()
	return decisionID, actionID
}

func (h *harness) mutate(decisionID string, f func(*execute.Inputs)) {
	h.inputs.mu.Lock()
	defer h.inputs.mu.Unlock()
	in := h.inputs.in[decisionID]
	f(&in)
	h.inputs.in[decisionID] = in
}

func (h *harness) run(decisionID, actionID string) execute.Execution {
	h.t.Helper()
	if _, _, err := h.engine.Submit(context.Background(), decisionID, actionID); err != nil {
		h.t.Fatal(err)
	}
	h.engine.Wait()
	return h.store.row(decisionID)
}
