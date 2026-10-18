package dispatch

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutesNeedClientCertificate(t *testing.T) {
	mux := http.NewServeMux()
	(&Handler{Svc: &Service{}}).Register(mux)
	for _, path := range []string{
		"/internal/dispatch/reservations",
		"/internal/dispatch/permits/8c1e0000-0000-4000-8000-000000000001/check",
		"/internal/dispatch/attempts/8c1e0000-0000-4000-8000-000000000001/outcome",
		"/internal/dispatch/activation-probes",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(rec, req)
		var body errorBody
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusUnauthorized || len(body.ReasonCodes) != 1 || body.ReasonCodes[0] != "AUTH_REQUIRED" {
			t.Errorf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
}

func TestStrictBody(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":  `{"transition":"released","reason_codes":["HOLD_ACTIVE"],"extra":1}`,
		"case variant":   `{"Transition":"released","reason_codes":["HOLD_ACTIVE"]}`,
		"duplicate key":  `{"transition":"released","transition":"released","reason_codes":["HOLD_ACTIVE"]}`,
		"nested unknown": `{"decision_id":"x","policy_epoch":1,"catalog_digest":{"a":1}}`,
	} {
		var v OutcomeRequest
		if name == "nested unknown" {
			var r ReserveRequest
			if strictInto([]byte(body), &r) == nil {
				t.Errorf("%s accepted", name)
			}
			continue
		}
		if strictInto([]byte(body), &v) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestValidation(t *testing.T) {
	if !isUUID("8c1e0000-0000-4000-8000-000000000001") || isUUID("8C1E0000-0000-4000-8000-000000000001") || isUUID("x") {
		t.Fatal("isUUID")
	}
	if !isDigest(strings.Repeat("a", 64)) || isDigest(strings.Repeat("A", 64)) || isDigest("ab") {
		t.Fatal("isDigest")
	}
	for codes, want := range map[string]bool{
		"CREDENTIAL_UNAVAILABLE":                 true,
		"HOLD_ACTIVE,PERMIT_INVALID":             true,
		"":                                       false,
		"HOLD_ACTIVE,HOLD_ACTIVE":                false,
		"TARGET_UNAVAILABLE":                     false, // a post-claim failure
		"credential_unavailable":                 false,
		"PERMIT_INVALID,LOCK_TIMEOUT,NOT_A_CODE": false,
	} {
		var list []string
		if codes != "" {
			list = strings.Split(codes, ",")
		}
		if validReleaseReasons(list) != want {
			t.Errorf("%q: want %v", codes, want)
		}
	}
}

func TestCounterFor(t *testing.T) {
	for op, want := range map[string]string{
		"model.generate":       "model",
		"evidence.audit.query": "read_tools",
		"discovery.snapshot":   "snapshot_reads",
		"receiver.submit":      "",
		"k8s.pods.list":        "",
	} {
		if got := counterFor(op); got != want {
			t.Errorf("%s: %q, want %q", op, got, want)
		}
	}
}

func TestBudgetForProbe(t *testing.T) {
	b, err := budgetFor(Decision{DecisionBasis: "activation_probe", ServiceSessionID: "s", ActivationProbeID: "p"})
	if err != nil || b.Counter == nil || *b.Counter != "probe_actions" || b.exhaustedCode() != "TOOL_BUDGET_EXHAUSTED" {
		t.Fatalf("probe: %+v %v", b, err)
	}
	for _, d := range []Decision{
		{DecisionBasis: "activation_probe", ServiceSessionID: "s"},
		{DecisionBasis: "activation_probe", ActivationProbeID: "p"},
		{DecisionBasis: "approval"},
	} {
		if _, err := budgetFor(d); err == nil {
			t.Fatalf("%+v accepted", d)
		}
	}
}

func obsFor(id string) Observation {
	s := func(v string) *string { return &v }
	n := func(v int64) *int64 { return &v }
	return Observation{AttemptID: id, LocalAddr: s("10.0.0.5"), LocalPort: n(40000), PeerAddr: s("10.1.0.9"), PeerPort: n(443),
		NetnsInode: n(4026531992), DialedAddr: s("10.1.0.9"), PeerAddrKind: s("service_vip"),
		PodUID: s("8c1e0000-0000-4000-8000-0000000000aa"), ConnectStartedAt: s("2026-10-15T10:00:00.000001Z"),
		SendStartedAt: s("2026-10-15T10:00:00.1Z")}
}

// failedObs is a failure after connect and before WroteHeaders (TLS): the
// socket is known, nothing was sent.
func failedObs(id string) Observation {
	o := obsFor(id)
	o.SendStartedAt = nil
	return o
}

func TestCheckObservation(t *testing.T) {
	const id = "8c1e0000-0000-4000-8000-000000000001"
	s := func(v string) *string { return &v }
	n := func(v int64) *int64 { return &v }
	full := obsFor(id)
	full.SendFinishedAt, full.ResponseAt = s("2026-10-15T10:00:00.2Z"), s("2026-10-15T10:00:01Z")
	cases := []struct {
		name, transition string
		mod              func(*Observation)
		want             bool
	}{
		{"dispatched", "dispatched", nil, true},
		{"dispatched without send_started_at", "dispatched", func(o *Observation) { o.SendStartedAt = nil }, false},
		{"dispatched without dialed_addr", "dispatched", func(o *Observation) { o.DialedAddr = nil }, false},
		{"dispatched with response_at", "dispatched", func(o *Observation) { o.ResponseAt = s("2026-10-15T10:00:01Z") }, false},
		{"response_received", "response_received", func(o *Observation) { *o = full }, true},
		{"response_received without response_at", "response_received", nil, false},
		{"other attempt", "dispatched", func(o *Observation) { o.AttemptID = "8c1e0000-0000-4000-8000-000000000002" }, false},
		{"bad addr", "dispatched", func(o *Observation) { o.LocalAddr = s("10.0.0") }, false},
		{"zoned addr", "dispatched", func(o *Observation) { o.LocalAddr = s("fe80::1%eth0") }, false},
		{"zoned peer addr", "dispatched", func(o *Observation) { o.PeerAddr = s("fe80::2%eth0") }, false},
		{"unspecified local v4", "dispatched", func(o *Observation) { o.LocalAddr = s("0.0.0.0") }, false},
		{"unspecified local v6", "dispatched", func(o *Observation) { o.LocalAddr = s("::") }, false},
		{"unspecified peer v4", "dispatched", func(o *Observation) { o.PeerAddr = s("0.0.0.0") }, false},
		{"unspecified peer v6", "dispatched", func(o *Observation) { o.PeerAddr = s("::") }, false},
		{"unspecified v4-mapped peer", "dispatched", func(o *Observation) { o.PeerAddr = s("::ffff:0.0.0.0") }, false},
		{"unspecified dialed addr", "dispatched", func(o *Observation) { o.DialedAddr = s("0.0.0.0") }, false},
		{"unspecified local on failed", "failed", func(o *Observation) { *o = failedObs(id); o.LocalAddr = s("0.0.0.0") }, false},
		{"unspecified local on unknown", "unknown", func(o *Observation) { o.LocalAddr = s("::") }, false},
		{"ipv6 addrs", "dispatched", func(o *Observation) { o.LocalAddr, o.PeerAddr, o.DialedAddr = s("fd00::5"), s("fd00::9"), s("fd00::9") }, true},
		{"send before connect", "dispatched", func(o *Observation) { o.SendStartedAt = s("2026-10-15T10:00:00Z") }, false},
		{"port 0", "dispatched", func(o *Observation) { o.PeerPort = n(0) }, false},
		{"port too big", "dispatched", func(o *Observation) { o.PeerPort = n(65536) }, false},
		{"inode 0", "dispatched", func(o *Observation) { o.NetnsInode = n(0) }, false},
		{"kind", "dispatched", func(o *Observation) { o.PeerAddrKind = s("pod") }, false},
		{"pod uid", "dispatched", func(o *Observation) { o.PodUID = s("x") }, false},
		{"time", "dispatched", func(o *Observation) { o.SendStartedAt = s("yesterday") }, false},
		{"backwards", "dispatched", func(o *Observation) { o.SendStartedAt = s("2026-10-15T09:00:00Z") }, false},
		{"digest", "dispatched", func(o *Observation) { o.WireBodyDigest = s("AB") }, false},
		{"empty provider id", "dispatched", func(o *Observation) { o.ProviderRequestID = s("") }, false},
		{"failed before connect", "failed", func(o *Observation) {
			*o = Observation{AttemptID: id, PodUID: s("8c1e0000-0000-4000-8000-0000000000aa"), DialedAddr: s("10.1.0.9")}
		}, true},
		{"failed after connect", "failed", func(o *Observation) { *o = failedObs(id) }, true},
		{"failed with half a tuple", "failed", func(o *Observation) { *o = failedObs(id); o.LocalPort = nil }, false},
		{"failed with send_started_at", "failed", func(o *Observation) { *o = failedObs(id); o.SendStartedAt = s("2026-10-15T10:00:00.1Z") }, false},
		{"failed with send_finished_at", "failed", func(o *Observation) { *o = failedObs(id); o.SendFinishedAt = s("2026-10-15T10:00:00.2Z") }, false},
		{"failed with response_at", "failed", func(o *Observation) { *o = failedObs(id); o.ResponseAt = s("2026-10-15T10:00:01Z") }, false},
		{"failed with dispatched observation", "failed", nil, false},
		{"failed with response", "failed", func(o *Observation) { *o = full }, false},
		{"failed without pod", "failed", func(o *Observation) { *o = failedObs(id); o.PodUID = nil }, false},
		{"unknown after restart", "unknown", func(o *Observation) {
			*o = Observation{AttemptID: id, PodUID: s("8c1e0000-0000-4000-8000-0000000000aa")}
		}, true},
		{"unknown with response", "unknown", func(o *Observation) { *o = full }, false},
		{"kind without peer", "unknown", func(o *Observation) { o.PeerAddr, o.PeerPort = nil, nil }, false},
	}
	for _, c := range cases {
		o := obsFor(id)
		if c.mod != nil {
			c.mod(&o)
		}
		if _, ok := checkObservation(id, c.transition, o); ok != c.want {
			t.Errorf("%s: got %v", c.name, ok)
		}
	}
}

func TestObservationKeeps(t *testing.T) {
	const id = "8c1e0000-0000-4000-8000-000000000001"
	d, _ := checkObservation(id, "dispatched", obsFor(id))
	full := obsFor(id)
	at, fin := "2026-10-15T10:00:01Z", "2026-10-15T10:00:00.2Z"
	full.ResponseAt, full.SendFinishedAt = &at, &fin
	r, ok := checkObservation(id, "response_received", full)
	if !ok || !d.keeps(r) || r.keeps(d) || d.equal(r) {
		t.Fatal("dispatched → response_received superset")
	}
	other := obsFor(id)
	port := int64(40001)
	other.LocalPort = &port
	o, _ := checkObservation(id, "dispatched", other)
	if d.keeps(o) {
		t.Fatal("a changed local_port was kept")
	}
	// Sub-microsecond differences are below PostgreSQL's precision.
	nano := obsFor(id)
	ns := "2026-10-15T10:00:00.100000400Z"
	nano.SendStartedAt = &ns
	if n, _ := checkObservation(id, "dispatched", nano); !n.equal(d) {
		t.Fatal("microsecond truncation")
	}
}

func TestOutcomeReasons(t *testing.T) {
	for _, c := range []struct {
		transition string
		codes      []string
		want       bool
	}{
		{"dispatched", nil, true},
		{"response_received", []string{"TARGET_REJECTED"}, true},
		{"failed", nil, false},
		{"failed", []string{"TLS_VERIFY_FAILED"}, true},
		{"unknown", []string{}, false},
		{"unknown", []string{"TARGET_UNAVAILABLE", "TARGET_UNAVAILABLE"}, false},
		{"failed", []string{"NOT_A_CODE"}, false},
	} {
		if validOutcomeReasons(c.transition, c.codes) != c.want {
			t.Errorf("%s %v: want %v", c.transition, c.codes, c.want)
		}
	}
}
