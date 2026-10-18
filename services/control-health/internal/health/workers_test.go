package health

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testRuntimeSAN = "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/8d0f2c39-5d0b-4b0e-9a5e-0c5f0d1e2a3b"

type fakeWorkers struct {
	calls          []string
	caller         string
	session        string
	requestSession string
	err            error
}

func (f *fakeWorkers) note(op, caller, session string) {
	f.calls = append(f.calls, op)
	f.caller, f.session = caller, session
}
func (f *fakeWorkers) RegisterWorker(_ context.Context, _ Peer, c, s string, req WorkerRegistration) (WorkerBinding, error) {
	f.note("register", c, s)
	f.requestSession = req.SessionID
	return WorkerBinding{State: "pending"}, f.err
}
func (f *fakeWorkers) GetWorker(_ context.Context, _ Peer, c, s, _ string) (WorkerBinding, error) {
	f.note("get_worker", c, s)
	return WorkerBinding{}, f.err
}
func (f *fakeWorkers) CloseWorker(_ context.Context, _ Peer, c, s, _ string, _ WorkerClose) (WorkerBinding, error) {
	f.note("close", c, s)
	return WorkerBinding{}, f.err
}
func (f *fakeWorkers) ReportWorkerObservation(context.Context, Peer, WorkerObservationResult) (EvidenceAck, error) {
	f.note("worker_result", "", "")
	return EvidenceAck{Result: "created"}, f.err
}
func (f *fakeWorkers) RequestReadiness(_ context.Context, _ Peer, c, s string, req ReadinessRequest) (ReadinessCheck, error) {
	f.note("check", c, s)
	f.requestSession = req.SessionID
	return ReadinessCheck{State: "pending"}, f.err
}
func (f *fakeWorkers) GetReadiness(_ context.Context, _ Peer, c, s, _ string) (ReadinessCheck, error) {
	f.note("get_check", c, s)
	return ReadinessCheck{}, f.err
}
func (f *fakeWorkers) ReportPodObservation(context.Context, Peer, PodObservationResult) (EvidenceAck, error) {
	f.note("pod_result", "", "")
	return EvidenceAck{Result: "existing"}, f.err
}

func peerState(san string) *tls.ConnectionState {
	u, _ := url.Parse(san)
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}, SerialNumber: big.NewInt(1)}}}}
}

func registrationBody() map[string]any {
	return map[string]any{"session_id": "aaaaaaaa-1111-4111-8111-11111111111b", "worker_instance_id": "22222222-2222-4222-8222-222222222222",
		"runtime_process_epoch":    "33333333-3333-4333-8333-333333333333",
		"supervisor_process_hint":  map[string]any{"local_pid": 1, "pid_ns_inode": 9, "start_ticks": 5},
		"worker_process_hint":      map[string]any{"local_pid": 2, "pid_ns_inode": 9, "start_ticks": 6},
		"isolation_profile_digest": strings.Repeat("a", 64), "controls_report": map[string]any{}}
}

func publicRegistrationBody() map[string]any {
	b := registrationBody()
	delete(b, "session_id")
	return b
}

func TestWorkerRoutesForwardedIdentity(t *testing.T) {
	gateway := peerState("spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway")
	id := "4444aaaa-4444-4444-8444-44444444444b"
	sess := "4444aaaa-4444-4444-8444-44444444444c"
	for _, tc := range []struct {
		name, method, path string
		header             []string
		session            []string
		body               any
		status             int
		call               string
	}{
		{"register", "POST", "/internal/control-health/session-workers", []string{testRuntimeSAN}, []string{sess}, publicRegistrationBody(), 202, "register"},
		{"body session forbidden", "POST", "/internal/control-health/session-workers", []string{testRuntimeSAN}, []string{sess}, registrationBody(), 422, ""},
		{"check", "POST", "/internal/control-health/work-readiness/checks", []string{testRuntimeSAN}, []string{sess}, map[string]any{"work_run_id": id, "runtime_process_epoch": id, "checkpoint": "start", "worker_instance_id": id, "worker_binding_id": id}, 202, "check"},
		{"get worker", "GET", "/internal/control-health/session-workers/" + id, []string{testRuntimeSAN}, []string{sess}, nil, 200, "get_worker"},
		{"close", "POST", "/internal/control-health/session-workers/" + id + ":close", []string{testRuntimeSAN}, []string{sess}, map[string]any{"reason": "done", "evidence_refs": []string{}}, 200, "close"},
		{"get check", "GET", "/internal/control-health/work-readiness/checks/" + id, []string{testRuntimeSAN}, []string{sess}, nil, 200, "get_check"},
		{"no forwarded identity", "GET", "/internal/control-health/work-readiness/checks/" + id, nil, []string{sess}, nil, 422, ""},
		{"two forwarded identities", "GET", "/internal/control-health/work-readiness/checks/" + id, []string{testRuntimeSAN, testRuntimeSAN}, []string{sess}, nil, 422, ""},
		{"service SAN forwarded", "GET", "/internal/control-health/work-readiness/checks/" + id, []string{"spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"}, []string{sess}, nil, 422, ""},
		{"no forwarded session", "GET", "/internal/control-health/work-readiness/checks/" + id, []string{testRuntimeSAN}, nil, nil, 422, ""},
		{"two forwarded sessions", "GET", "/internal/control-health/work-readiness/checks/" + id, []string{testRuntimeSAN}, []string{sess, sess}, nil, 422, ""},
		{"non-canonical session", "GET", "/internal/control-health/work-readiness/checks/" + id, []string{testRuntimeSAN}, []string{strings.ToUpper(sess)}, nil, 422, ""},
		{"non-canonical id", "GET", "/internal/control-health/work-readiness/checks/" + strings.ToUpper(id), []string{testRuntimeSAN}, []string{sess}, nil, 422, ""},
		{"identity on a node route", "POST", "/internal/control-health/pod-observation-results", []string{testRuntimeSAN}, nil, map[string]any{}, 403, ""},
		{"session on a node route", "POST", "/internal/control-health/pod-observation-results", nil, []string{sess}, map[string]any{}, 403, ""},
		{"unknown field", "POST", "/internal/control-health/work-readiness/checks", []string{testRuntimeSAN}, []string{sess}, map[string]any{"session_id": id, "extra": 1}, 422, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeWorkers{}
			raw, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(raw))
			req.TLS = gateway
			for _, v := range tc.header {
				req.Header.Add(PeerIdentityHeader, v)
			}
			for _, v := range tc.session {
				req.Header.Add(PeerSessionHeader, v)
			}
			rec := httptest.NewRecorder()
			Handler{Workers: f}.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("HTTP %d %s", rec.Code, rec.Body.String())
			}
			if (tc.call == "register" || tc.call == "check") && f.requestSession != sess {
				t.Fatalf("request session %q does not match authenticated header", f.requestSession)
			}
			if tc.call == "" && len(f.calls) != 0 || tc.call != "" && (len(f.calls) != 1 || f.calls[0] != tc.call || f.caller != testRuntimeSAN || f.session != sess) {
				t.Fatalf("backend calls %v caller %q session %q", f.calls, f.caller, f.session)
			}
		})
	}
}

func TestWorkerRouteErrors(t *testing.T) {
	gateway := peerState("spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway")
	for _, tc := range []struct {
		err    error
		status int
		code   string
	}{
		{Coded(403, CodeReadinessMismatch), 403, CodeReadinessMismatch},
		{Coded(503, CodeWorkerNotReady), 503, CodeWorkerNotReady},
		{ErrNotFound, 404, "RESOURCE_NOT_FOUND"},
		{ErrForbidden, 403, ""},
		{context.DeadlineExceeded, 503, CodeHealthUnavailable},
	} {
		req := httptest.NewRequest("GET", "/internal/control-health/work-readiness/checks/44444444-4444-4444-8444-444444444444", nil)
		req.TLS = gateway
		req.Header.Set(PeerIdentityHeader, testRuntimeSAN)
		req.Header.Set(PeerSessionHeader, "44444444-4444-4444-8444-444444444445")
		rec := httptest.NewRecorder()
		Handler{Workers: &fakeWorkers{err: tc.err}}.ServeHTTP(rec, req)
		var out struct {
			ReasonCodes []string `json:"reason_codes"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != tc.status || (tc.code != "" && (len(out.ReasonCodes) != 1 || out.ReasonCodes[0] != tc.code)) {
			t.Fatalf("%v: HTTP %d %s", tc.err, rec.Code, rec.Body.String())
		}
	}
	// Without a worker backend the routes are unavailable, never ready.
	req := httptest.NewRequest("GET", "/internal/control-health/work-readiness/checks/44444444-4444-4444-8444-444444444444", nil)
	req.TLS = gateway
	rec := httptest.NewRecorder()
	Handler{}.ServeHTTP(rec, req)
	if rec.Code != 503 {
		t.Fatalf("unwired: %d", rec.Code)
	}
}

func TestDecodeWorkerBodies(t *testing.T) {
	good := registrationBody()
	raw, _ := json.Marshal(good)
	if _, err := DecodeWorkerRegistration(raw); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"same hints": func(m map[string]any) { m["worker_process_hint"] = m["supervisor_process_hint"] },
		"zero pid": func(m map[string]any) {
			m["worker_process_hint"] = map[string]any{"local_pid": 0, "pid_ns_inode": 9, "start_ticks": 6}
		},
		"digest":          func(m map[string]any) { m["isolation_profile_digest"] = "x" },
		"controls array":  func(m map[string]any) { m["controls_report"] = []int{} },
		"missing epoch":   func(m map[string]any) { delete(m, "runtime_process_epoch") },
		"uppercase uuid":  func(m map[string]any) { m["session_id"] = strings.ToUpper(m["session_id"].(string)) },
		"caller host pid": func(m map[string]any) { m["host_pid"] = 4 },
		"null controls":   func(m map[string]any) { m["controls_report"] = nil },
	} {
		m := registrationBody()
		mutate(m)
		raw, _ := json.Marshal(m)
		if _, err := DecodeWorkerRegistration(raw); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	check := map[string]any{"session_id": "11111111-1111-4111-8111-111111111111", "work_run_id": "55555555-5555-4555-8555-555555555555",
		"runtime_process_epoch": "33333333-3333-4333-8333-333333333333", "checkpoint": "start",
		"worker_instance_id": "22222222-2222-4222-8222-222222222222", "worker_binding_id": "66666666-6666-4666-8666-666666666666"}
	raw, _ = json.Marshal(check)
	if _, err := DecodeReadinessRequest(raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{{"checkpoint": "anything"}, {"instance_binding": map[string]any{}}, {"root_exec_id": "caller-chosen"}} {
		m := map[string]any{}
		for k, v := range check {
			m[k] = v
		}
		for k, v := range bad {
			m[k] = v
		}
		raw, _ := json.Marshal(m)
		if _, err := DecodeReadinessRequest(raw); err == nil {
			t.Fatalf("readiness request %v accepted", bad)
		}
	}
	if _, _, _, ok := RuntimeSAN("spiffe://agentarium.internal/ns/agent-control/sa/agent-runtime/pod/8d0f2c39-5d0b-4b0e-9a5e-0c5f0d1e2a3b"); ok {
		t.Fatal("non agent-exec Pod SAN accepted as runtime")
	}
}

func TestBindPeerSessionRejectsUntrustedBodySession(t *testing.T) {
	session := "aaaaaaaa-1111-4111-8111-11111111111b"
	for _, raw := range []string{`{"session_id":null}`, `{"Session_ID":"spoof"}`, `{"x":1,"x":2}`, `null`, `[]`, `{} {}`} {
		if _, err := bindPeerSession([]byte(raw), session); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
