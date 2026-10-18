package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	weRunID   = "66666666-6666-4666-8666-666666666666"
	weEpoch   = "77777777-7777-4777-8777-777777777777"
	weWorker  = "88888888-8888-4888-8888-888888888888"
	weEventID = "99999999-9999-4999-8999-999999999999"
	weAuditID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
)

func weBody() string {
	return `{"event_id":"` + weEventID + `","event_type":"agent_work_start_requested","source_version":"runtime-v1",` +
		`"source_time":"2026-10-18T00:00:00Z","safe_payload":{"work_run_id":"` + weRunID + `","check_id":"` + relayCheckID +
		`","runtime_process_epoch":"` + weEpoch + `","worker_instance_id":"` + weWorker + `","worker_binding_id":"` + relayBindingID + `"}}`
}

// weCheck is a control-health GET answer with extra fields the relay drops.
func weCheck(session, caller string) string {
	return `{"check_id":"` + relayCheckID + `","work_run_id":"` + weRunID + `","checkpoint":"start","session_id":"` + session +
		`","workload_id":"agent-exec/agent-runtime","caller_identity":"` + caller + `","runtime_process_epoch":"` + weEpoch +
		`","worker_instance_id":"` + weWorker + `","worker_binding_id":"` + relayBindingID + `","root_exec_id":"exec-1",` +
		`"worker_evidence_refs":["k1"],"instance_binding":{"pod_uid":"p","node_uid":"n"},"sensor_generation":3,"rule_hash":"r",` +
		`"policy_epoch":5,"challenge_id":null,"challenge_evidence_refs":[],"state":"ready","reason_codes":[],` +
		`"created_at":"2026-10-18T00:00:00Z","checked_at":"2026-10-18T00:00:01Z","expires_at":"2026-10-18T00:00:04Z",` +
		`"audit_event_ref":"` + weAuditID + `","remaining_valid_ms":2000}`
}

const weAck = `{"event_id":"` + weEventID + `","result":"created","received_at":"2026-10-18T00:00:02Z"}`

func TestRelayWorkEvents(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	rt := e.client(t, relayRuntimeSAN)
	check := weCheck(relaySessionA, relayRuntimeSAN)
	e.health.reply = func(s runtimeRelaySeen) (int, string, http.Header) {
		if s.peerSession != relaySessionA {
			return 403, `{"reason_codes":["WORK_READINESS_BINDING_MISMATCH"]}`, nil
		}
		return 200, check, nil
	}
	e.audit.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 201, weAck, nil }
	tokA := map[string]string{"Authorization": "Bearer tok-a", PeerIdentityHeader: relaySpoof, "X-Agentarium-Peer-Session": relaySessionB}

	a := e.do(t, rt, "POST", "/v1/runtime/work-events", weBody(), tokA)
	if a.status != 201 || string(a.body) != weAck {
		t.Fatalf("work event = %d %s", a.status, a.body)
	}
	h := e.health.got()
	if len(h) != 1 || h[0].method != "GET" || h[0].path != internalChecks+"/"+relayCheckID || len(h[0].peer) != 1 || h[0].peer[0] != relayRuntimeSAN || h[0].auth != "" || h[0].peerSession != relaySessionA {
		t.Fatalf("check read %+v", h)
	}
	got := e.audit.got()
	if len(got) != 1 {
		t.Fatalf("audit calls %d", len(got))
	}
	s := got[0]
	if s.method != "POST" || s.path != internalWorkEvents || len(s.peer) != 1 || s.peer[0] != relayRuntimeSAN || s.auth != "" ||
		s.client != gatewayTestSAN || s.contentType != "application/json" || len(s.peerSession) != 0 {
		t.Fatalf("audit forwarded %+v", s)
	}
	var fwd struct {
		Context map[string]json.RawMessage `json:"context"`
		Check   map[string]json.RawMessage `json:"check"`
		Event   json.RawMessage            `json:"event"`
	}
	if err := json.Unmarshal(s.body, &fwd); err != nil {
		t.Fatal(err)
	}
	if string(fwd.Context["session_id"]) != `"`+relaySessionA+`"` || string(fwd.Context["tenant"]) != `"tenant-a"` ||
		string(fwd.Context["workload_id"]) != `"agent-exec/agent-runtime"` || string(fwd.Context["authenticated_actor"]) != `"user:alice@example.com"` {
		t.Fatalf("context %s", s.body)
	}
	if string(fwd.Check["caller_identity"]) != `"`+relayRuntimeSAN+`"` || string(fwd.Check["audit_event_ref"]) != `"`+weAuditID+`"` ||
		string(fwd.Check["instance_binding"]) != `{"pod_uid":"p","node_uid":"n"}` || string(fwd.Check["state"]) != `"ready"` ||
		string(fwd.Check["sensor_generation"]) != "3" || string(fwd.Check["policy_epoch"]) != "5" || len(fwd.Check) != 14 {
		t.Fatalf("check %s", s.body)
	}
	if _, ok := fwd.Check["remaining_valid_ms"]; ok {
		t.Fatal("time-varying field forwarded")
	}
	if string(fwd.Event) != weBody() {
		t.Fatalf("event changed: %s", fwd.Event)
	}

	// TASK-07 answers pass through: duplicate, conflict, 403, 503.
	for _, c := range []struct {
		status int
		body   string
		retry  string
	}{
		{200, `{"event_id":"` + weEventID + `","result":"duplicate","received_at":"2026-10-18T00:00:02Z"}`, ""},
		{409, `{"request_id":"r","reason_codes":["EVENT_ID_CONFLICT"]}`, ""},
		{403, `{"request_id":"r","reason_codes":[]}`, ""},
		{503, `{"request_id":"r","reason_codes":["STATE_STORE_UNAVAILABLE"]}`, "2"},
	} {
		e.audit.reply = func(runtimeRelaySeen) (int, string, http.Header) { return c.status, c.body, nil }
		a := e.do(t, rt, "POST", "/v1/runtime/work-events", weBody(), tokA)
		if a.status != c.status || string(a.body) != c.body || a.header.Get("Retry-After") != c.retry {
			t.Errorf("audit %d = %d %s", c.status, a.status, a.body)
		}
	}
	// audit-writer 401 rejects the gateway's own connection.
	e.audit.reply = func(runtimeRelaySeen) (int, string, http.Header) {
		return 401, `{"request_id":"r","reason_codes":["AUTH_REQUIRED"]}`, nil
	}
	if a := e.do(t, rt, "POST", "/v1/runtime/work-events", weBody(), tokA); a.status != 503 || a.codes(t)[0] != "STATE_STORE_UNAVAILABLE" {
		t.Errorf("audit 401 = %d %s", a.status, a.body)
	}
}

func TestRelayWorkEventsRefused(t *testing.T) {
	e := newRuntimeRelayEnv(t)
	rt := e.client(t, relayRuntimeSAN)
	check := weCheck(relaySessionA, relayRuntimeSAN)
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 200, check, nil }
	tokA := map[string]string{"Authorization": "Bearer tok-a"}
	body := weBody()
	repl := func(old, new string) string {
		t.Helper()
		if !strings.Contains(body, old) {
			t.Fatalf("no %q", old)
		}
		return strings.Replace(body, old, new, 1)
	}
	for name, c := range map[string]struct {
		client *http.Client
		body   string
		h      map[string]string
		status int
		code   string
	}{
		"no token":         {rt, body, nil, 401, "AUTH_REQUIRED"},
		"service session":  {rt, body, map[string]string{"Authorization": "Bearer tok-svc"}, 401, "AUTH_REQUIRED"},
		"non-exec caller":  {e.client(t, controlSAN), body, tokA, 401, "AUTH_REQUIRED"},
		"session in body":  {rt, repl(`"event_type"`, `"session_id":"`+relaySessionB+`","event_type"`), tokA, 422, "SCHEMA_INVALID"},
		"session payload":  {rt, repl(`"work_run_id"`, `"session_id":"`+relaySessionB+`","work_run_id"`), tokA, 422, "SCHEMA_INVALID"},
		"tenant in body":   {rt, repl(`"event_type"`, `"tenant":"x","event_type"`), tokA, 422, "SCHEMA_INVALID"},
		"source in body":   {rt, repl(`"event_type"`, `"source_id":"x","event_type"`), tokA, 422, "SCHEMA_INVALID"},
		"state in payload": {rt, repl(`"work_run_id"`, `"state":"ready","work_run_id"`), tokA, 422, "SCHEMA_INVALID"},
		"case variant":     {rt, repl(`"event_type"`, `"Event_Type"`), tokA, 422, "SCHEMA_INVALID"},
		"duplicate key":    {rt, repl(`"event_type":"agent_work_start_requested"`, `"event_type":"agent_work_start_requested","event_type":"x"`), tokA, 422, "SCHEMA_INVALID"},
		"null outcome":     {rt, repl(`"worker_binding_id":"`+relayBindingID+`"}`, `"worker_binding_id":"`+relayBindingID+`","outcome":null}`), tokA, 422, "SCHEMA_INVALID"},
		"bad check id":     {rt, repl(relayCheckID, "not-a-uuid"), tokA, 422, "SCHEMA_INVALID"},
		"other work run":   {rt, repl(weRunID, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), tokA, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"other epoch":      {rt, repl(weEpoch, "x"), tokA, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"other worker":     {rt, repl(weWorker, "x"), tokA, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"other binding":    {rt, repl(`"worker_binding_id":"`+relayBindingID, `"worker_binding_id":"x`), tokA, 403, "WORK_READINESS_BINDING_MISMATCH"},
		"query string":     {rt, body, tokA, 422, "SCHEMA_INVALID"},
	} {
		path := "/v1/runtime/work-events"
		if name == "query string" {
			path += "?x=1"
		}
		n := len(e.audit.got())
		a := e.do(t, c.client, "POST", path, c.body, c.h)
		if a.status != c.status || a.codes(t)[0] != c.code {
			t.Errorf("%s = %d %s, want %d %s", name, a.status, a.body, c.status, c.code)
		}
		if len(e.audit.got()) != n {
			t.Fatalf("%s reached audit-writer", name)
		}
	}
	// A check of another session, caller or workload never reaches audit.
	for name, chk := range map[string]string{
		"other session":  weCheck(relaySessionB, relayRuntimeSAN),
		"other caller":   weCheck(relaySessionA, revokedSAN),
		"other workload": strings.Replace(check, `"agent-exec/agent-runtime"`, `"agent-exec/other"`, 1),
		"other check":    strings.Replace(check, `"check_id":"`+relayCheckID, `"check_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc`, 1),
	} {
		e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 200, chk, nil }
		if a := e.do(t, rt, "POST", "/v1/runtime/work-events", body, tokA); a.status != 403 || a.codes(t)[0] != "WORK_READINESS_BINDING_MISMATCH" {
			t.Errorf("%s = %d %s", name, a.status, a.body)
		}
	}
	// Unknown check and control-health failures.
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) {
		return 404, `{"request_id":"r","reason_codes":["RESOURCE_NOT_FOUND"]}`, nil
	}
	if a := e.do(t, rt, "POST", "/v1/runtime/work-events", body, tokA); a.status != 404 {
		t.Errorf("unknown check = %d %s", a.status, a.body)
	}
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 200, `nope`, nil }
	if a := e.do(t, rt, "POST", "/v1/runtime/work-events", body, tokA); a.status != 503 || a.codes(t)[0] != "CONTROL_HEALTH_UNAVAILABLE" {
		t.Errorf("invalid check = %d %s", a.status, a.body)
	}
	if len(e.audit.got()) != 0 {
		t.Fatal("refused work event reached audit-writer")
	}
	// audit-writer unreachable.
	e.health.reply = func(runtimeRelaySeen) (int, string, http.Header) { return 200, check, nil }
	e.audit.srv.Close()
	if a := e.do(t, rt, "POST", "/v1/runtime/work-events", body, tokA); a.status != 503 || a.codes(t)[0] != "STATE_STORE_UNAVAILABLE" || a.header.Get("Retry-After") != "2" {
		t.Errorf("audit down = %d %s", a.status, a.body)
	}
}
