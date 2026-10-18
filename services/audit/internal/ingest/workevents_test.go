package ingest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const (
	testGateway = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	testRuntime = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/11111111-1111-4111-8111-111111111111"
	testSource  = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"
)

type recordingStore struct {
	events []Event
	raws   [][]byte
	ack    Ack
	err    error
}

func (s *recordingStore) Append(_ context.Context, e Event, raw []byte) (Ack, error) {
	s.events = append(s.events, e)
	s.raws = append(s.raws, raw)
	if s.err != nil {
		return Ack{}, s.err
	}
	a := s.ack
	if a.EventID == "" {
		a = Ack{EventID: e.EventID, Result: "created", ReceivedAt: time.Unix(1700000000, 0).UTC()}
	}
	return a, nil
}

func validWorkEvent() WorkEventRequest {
	actor := "user:alice@example.com"
	root := "exec-1"
	gen := int64(7)
	epoch := int64(3)
	return WorkEventRequest{
		Context: WorkEventContext{SessionID: "22222222-2222-4222-8222-222222222222", Tenant: "tenant-a", WorkloadID: "agent-exec/agent-runtime", AuthenticatedActor: &actor},
		Check: WorkEventCheck{
			CheckID: "33333333-3333-4333-8333-333333333333", WorkRunID: "44444444-4444-4444-8444-444444444444",
			SessionID: "22222222-2222-4222-8222-222222222222", WorkloadID: "agent-exec/agent-runtime", CallerIdentity: testRuntime,
			RuntimeProcessEpoch: "55555555-5555-4555-8555-555555555555", WorkerInstanceID: "66666666-6666-4666-8666-666666666666",
			WorkerBindingID: "77777777-7777-4777-8777-777777777777", RootExecID: &root,
			InstanceBinding: json.RawMessage(`{"pod_uid":"p","node_uid":"n"}`), SensorGeneration: &gen, PolicyEpoch: &epoch,
			State: "ready", AuditEventRef: "88888888-8888-4888-8888-888888888888",
		},
		Event: WorkEvent{
			EventID: "99999999-9999-4999-8999-999999999999", EventType: "agent_work_start_requested",
			SourceVersion: "runtime-v1", SourceTime: "2026-10-18T00:00:00Z",
			SafePayload: WorkEventPayload{
				WorkRunID: "44444444-4444-4444-8444-444444444444", CheckID: "33333333-3333-4333-8333-333333333333",
				RuntimeProcessEpoch: "55555555-5555-4555-8555-555555555555", WorkerInstanceID: "66666666-6666-4666-8666-666666666666",
				WorkerBindingID: "77777777-7777-4777-8777-777777777777",
			},
		},
	}
}

func tlsFor(san string) *tls.ConnectionState {
	u, _ := url.Parse(san)
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
}

func postWork(t *testing.T, h http.Handler, peer string, forwarded []string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, WorkEventsPath, bytes.NewReader(body))
	if peer != "" {
		r.TLS = tlsFor(peer)
	}
	for _, f := range forwarded {
		r.Header.Add(PeerIdentityHeader, f)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func reasonCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var env struct {
		ReasonCodes []string `json:"reason_codes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	if len(env.ReasonCodes) == 0 {
		return ""
	}
	return env.ReasonCodes[0]
}

func TestWorkEventStoredWithServerIdentity(t *testing.T) {
	store := &recordingStore{}
	h := WorkEventsHandler{GatewaySAN: testGateway, Store: store}
	w := postWork(t, h, testGateway, []string{testRuntime}, mustJSON(t, validWorkEvent()))
	if w.Code != 201 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	var ack Ack
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil || ack.Result != "created" || ack.EventID != validWorkEvent().Event.EventID || ack.ReceivedAt.IsZero() {
		t.Fatalf("ack %+v %v", ack, err)
	}
	if len(store.events) != 1 {
		t.Fatal("not stored once")
	}
	e := store.events[0]
	if e.SourceID != testSource || e.Tenant != "tenant-a" || *e.SessionID != "22222222-2222-4222-8222-222222222222" ||
		*e.WorkloadID != "agent-exec/agent-runtime" || e.SourceEpoch != "55555555-5555-4555-8555-555555555555" ||
		e.SourceSequence != nil || *e.PolicyEpoch != 3 || *e.AuthenticatedActor != "user:alice@example.com" {
		t.Fatalf("server fields %+v", e)
	}
	if string(e.SafePayload["session_id"]) != `"22222222-2222-4222-8222-222222222222"` || string(e.SafePayload["caller_identity"]) != `"`+testRuntime+`"` ||
		string(e.SafePayload["sensor_generation"]) != "7" || string(e.SafePayload["root_exec_id"]) != `"exec-1"` {
		t.Fatalf("payload %v", e.SafePayload)
	}
	if _, ok := e.SafePayload["outcome"]; ok {
		t.Fatal("absent outcome stored")
	}
	if len(e.EvidenceRefs) != 1 || string(e.EvidenceRefs[0]) != `"88888888-8888-4888-8888-888888888888"` {
		t.Fatalf("evidence %s", e.EvidenceRefs)
	}
	digest, err := canonical.PayloadDigest(store.raws[0])
	if err != nil || digest != e.PayloadDigest {
		t.Fatal("payload digest not recomputable")
	}
	// Deterministic: the same request builds byte-identical events.
	postWork(t, h, testGateway, []string{testRuntime}, mustJSON(t, validWorkEvent()))
	if !bytes.Equal(store.raws[0], store.raws[1]) {
		t.Fatal("retry built a different event")
	}
}

func TestWorkEventAckMapping(t *testing.T) {
	cases := []struct {
		ack    Ack
		err    error
		status int
		code   string
	}{
		{ack: Ack{EventID: validWorkEvent().Event.EventID, Result: "duplicate", ReceivedAt: time.Now()}, status: 200},
		{ack: Ack{EventID: validWorkEvent().Event.EventID, Result: "conflict"}, status: 409, code: "EVENT_ID_CONFLICT"},
		{err: ErrForbidden, status: 403},
		{err: errors.New("db down"), status: 503, code: "STATE_STORE_UNAVAILABLE"},
		{ack: Ack{EventID: "other", Result: "created", ReceivedAt: time.Now()}, status: 503, code: "STATE_STORE_UNAVAILABLE"},
	}
	for _, c := range cases {
		h := WorkEventsHandler{GatewaySAN: testGateway, Store: &recordingStore{ack: c.ack, err: c.err}}
		w := postWork(t, h, testGateway, []string{testRuntime}, mustJSON(t, validWorkEvent()))
		if w.Code != c.status || reasonCode(t, w) != c.code {
			t.Fatalf("%+v: %d %s", c, w.Code, w.Body)
		}
	}
}

func TestWorkEventRejectsCallers(t *testing.T) {
	body := mustJSON(t, validWorkEvent())
	for name, c := range map[string]struct {
		peer      string
		forwarded []string
		status    int
	}{
		"no client certificate": {"", []string{testRuntime}, 401},
		"other service":         {"spiffe://agentarium.internal/ns/agent-control/sa/coordinator", []string{testRuntime}, 403},
		"runtime direct":        {testRuntime, []string{testRuntime}, 401},
		"no forwarded identity": {testGateway, nil, 403},
		"two forwarded values":  {testGateway, []string{testRuntime, testRuntime}, 403},
		"non-runtime namespace": {testGateway, []string{"spiffe://agentarium.internal/ns/agent-control/sa/coordinator"}, 403},
		"malformed forwarded":   {testGateway, []string{"spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/x/y"}, 403},
		"other runtime pod":     {testGateway, []string{"spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/other"}, 403},
	} {
		store := &recordingStore{}
		w := postWork(t, WorkEventsHandler{GatewaySAN: testGateway, Store: store}, c.peer, c.forwarded, body)
		if w.Code != c.status || len(store.events) != 0 {
			t.Fatalf("%s: %d stored=%d", name, w.Code, len(store.events))
		}
	}
	w := postWork(t, WorkEventsHandler{Store: &recordingStore{}}, testGateway, []string{testRuntime}, body)
	if w.Code != 403 {
		t.Fatalf("unconfigured gateway SAN: %d", w.Code)
	}
}

func TestWorkEventBindingAndSchema(t *testing.T) {
	mutate := map[string]struct {
		f      func(*WorkEventRequest)
		status int
		code   string
	}{
		"session":         {func(r *WorkEventRequest) { r.Context.SessionID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"workload":        {func(r *WorkEventRequest) { r.Context.WorkloadID = "agent-exec/other" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"caller":          {func(r *WorkEventRequest) { r.Check.CallerIdentity = testSource + "/pod/other" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"check id":        {func(r *WorkEventRequest) { r.Event.SafePayload.CheckID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"work run":        {func(r *WorkEventRequest) { r.Event.SafePayload.WorkRunID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"epoch":           {func(r *WorkEventRequest) { r.Event.SafePayload.RuntimeProcessEpoch = "x" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"worker":          {func(r *WorkEventRequest) { r.Event.SafePayload.WorkerInstanceID = "x" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"binding":         {func(r *WorkEventRequest) { r.Event.SafePayload.WorkerBindingID = "x" }, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"pending":         {func(r *WorkEventRequest) { r.Check.State = "pending" }, 503, "WORK_READINESS_EXPIRED"},
		"readiness event": {func(r *WorkEventRequest) { r.Event.EventType = "work_readiness_passed" }, 422, "SCHEMA_INVALID"},
		"other event":     {func(r *WorkEventRequest) { r.Event.EventType = "request_received" }, 422, "SCHEMA_INVALID"},
		"bad state":       {func(r *WorkEventRequest) { r.Check.State = "ok" }, 422, "SCHEMA_INVALID"},
		"bad event id":    {func(r *WorkEventRequest) { r.Event.EventID = "x" }, 422, "SCHEMA_INVALID"},
		"no version":      {func(r *WorkEventRequest) { r.Event.SourceVersion = "" }, 422, "SCHEMA_INVALID"},
		"no tenant":       {func(r *WorkEventRequest) { r.Context.Tenant = "" }, 422, "SCHEMA_INVALID"},
		"bad time":        {func(r *WorkEventRequest) { r.Event.SourceTime = "yesterday" }, 422, "SCHEMA_INVALID"},
		"empty outcome":   {func(r *WorkEventRequest) { s := ""; r.Event.SafePayload.Outcome = &s }, 422, "SCHEMA_INVALID"},
		"array binding":   {func(r *WorkEventRequest) { r.Check.InstanceBinding = json.RawMessage(`[]`) }, 422, "SCHEMA_INVALID"},
		"bad audit ref":   {func(r *WorkEventRequest) { r.Check.AuditEventRef = "ref" }, 422, "SCHEMA_INVALID"},
		"slash epoch": {func(r *WorkEventRequest) {
			r.Check.RuntimeProcessEpoch = "a/b"
			r.Event.SafePayload.RuntimeProcessEpoch = "a/b"
		}, 422, "SCHEMA_INVALID"},
		"finished w/ reason": {func(r *WorkEventRequest) {
			o, rs := "succeeded", "done"
			r.Event.EventType, r.Event.SafePayload.Outcome, r.Event.SafePayload.Reason = "agent_work_finished", &o, &rs
		}, 201, ""},
		"null binding": {func(r *WorkEventRequest) {
			r.Check.InstanceBinding = json.RawMessage(`null`)
			r.Check.SensorGeneration = nil
		}, 201, ""},
	}
	for name, c := range mutate {
		req := validWorkEvent()
		c.f(&req)
		store := &recordingStore{}
		w := postWork(t, WorkEventsHandler{GatewaySAN: testGateway, Store: store}, testGateway, []string{testRuntime}, mustJSON(t, req))
		if w.Code != c.status || reasonCode(t, w) != c.code {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		if (c.status == 201) != (len(store.events) == 1) {
			t.Fatalf("%s: stored=%d", name, len(store.events))
		}
	}
}

func TestDecodeWorkEventStrict(t *testing.T) {
	good := string(mustJSON(t, validWorkEvent()))
	if _, err := DecodeWorkEvent([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"unknown top":       strings.Replace(good, `"context":`, `"extra":1,"context":`, 1),
		"session in event":  strings.Replace(good, `"event_type":`, `"session_id":"x","event_type":`, 1),
		"payload state":     strings.Replace(good, `"work_run_id":"44444444-4444-4444-8444-444444444444","check_id"`, `"work_run_id":"44444444-4444-4444-8444-444444444444","state":"ready","check_id"`, 1),
		"case variant":      strings.Replace(good, `"tenant":`, `"Tenant":`, 1),
		"duplicate key":     strings.Replace(good, `"tenant":"tenant-a"`, `"tenant":"tenant-a","tenant":"tenant-b"`, 1),
		"missing nullable":  strings.Replace(good, `"root_exec_id":"exec-1",`, ``, 1),
		"missing binding":   strings.Replace(good, `"instance_binding":{"pod_uid":"p","node_uid":"n"},`, ``, 1),
		"null outcome":      strings.Replace(good, `"worker_binding_id":"77777777-7777-4777-8777-777777777777"}}`, `"worker_binding_id":"77777777-7777-4777-8777-777777777777","outcome":null}}`, 1),
		"float generation":  strings.Replace(good, `"sensor_generation":7`, `"sensor_generation":7.0`, 1),
		"trailing":          good + `{}`,
		"received_at in ev": strings.Replace(good, `"event_type":`, `"received_at":"2020-01-01T00:00:00Z","event_type":`, 1),
	} {
		if raw == good {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := DecodeWorkEvent([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestRuntimeSource(t *testing.T) {
	for san, want := range map[string]string{
		testRuntime: testSource,
		testSource:  testSource,
		"spiffe://agentarium.internal/ns/agent-control/sa/gateway":    "",
		"spiffe://agentarium.internal/ns/agent-exec/sa/":              "",
		"spiffe://agentarium.internal/ns/agent-exec/sa/rt/pod/":       "",
		"spiffe://agentarium.internal/ns/agent-exec/sa/rt?x=1":        "",
		"spiffe://evil.example/ns/agent-exec/sa/agent-runtime":        "",
		"spiffe://agentarium.internal/ns/agent-exec/sa/rt/pod/a/b":    "",
		"spiffe://agentarium.internal/ns/agent-exec/sa/r%2Ft/pod/abc": "",
	} {
		got, _, ok := RuntimeSource(san)
		if got != want || ok != (want != "") {
			t.Fatalf("%s: %q %v", san, got, ok)
		}
	}
}
