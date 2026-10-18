package health

import (
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

func TestHoldRequestBoundary(t *testing.T) {
	valid := `{"scope":"node","scope_id":"11111111-1111-4111-8111-111111111111","reason":"sensor_degraded","evidence_refs":[]}`
	if _, err := DecodeHoldRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`null`, `[]`, `{"scope":"global"}`,
		`{"scope":"global","scope_id":"*","reason":"db_unavailable","evidence_refs":null}`,
		`{"scope":"global","scope_id":"*","reason":"db_unavailable","evidence_refs":[null]}`,
		`{"scope":"global","scope_id":"*","reason":"db_unavailable","evidence_refs":[""]}`,
		`{"scope":"global","scope_id":"*","reason":"sensor_degraded","evidence_refs":[]}`,
		`{"scope":"global","scope_id":"*","reason":"risk_event","evidence_refs":[]}`,
		`{"scope":"global","scope_id":"*","reason":"operator_stop","evidence_refs":[]}`,
		`{"scope":"global","scope_id":"*","reason":"db_unavailable","evidence_refs":[],"requester":"forged"}`,
		`{"Scope":"global","scope_id":"*","reason":"db_unavailable","evidence_refs":[]}`,
		`{"scope":"global","scope":"node","scope_id":"*","reason":"db_unavailable","evidence_refs":[]}`,
		valid + ` {}`,
	} {
		if _, err := DecodeHoldRequest([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	var denied map[string]any
	raw, err := json.Marshal(HoldAck{Decision: "rejected", ReasonCodes: []string{CodeHoldRequestDenied}})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &denied); err != nil {
		t.Fatal(err)
	}
	if len(denied) != 3 || denied["hold_id"] != nil {
		t.Fatal(string(raw))
	}
}

func TestReasonOwnerIsNotArbitraryRequester(t *testing.T) {
	for reason, owner := range map[string]string{"sensor_degraded": "node-sensors", "db_unavailable": "audit-db", "export_lag": "audit-export", "start_unknown": "start-coordinator", "policy_activation": "releaser", "control_drift": "control-health", "lease_expired": "control-health", "probe_failed": "destination-evidence"} {
		if got := HoldOwner(reason, "destination-evidence"); got != owner {
			t.Fatalf("%s: %s", reason, got)
		}
	}
}

func TestProbeHoldControllerOwnership(t *testing.T) {
	for _, component := range []string{"control-health", "destination-evidence"} {
		if got := HoldOwner("probe_failed", component); got != component {
			t.Fatalf("%s owns %s", component, got)
		}
	}
}

type ownedBackend struct {
	Backend
	err error
}

func (b ownedBackend) OwnedHolds(context.Context, Peer, string) (OwnedHolds, error) {
	return OwnedHolds{Holds: []Hold{}}, b.err
}

func TestOwnedHoldsHTTP(t *testing.T) {
	for _, c := range []struct {
		query string
		err   error
		code  int
		body  string
	}{
		{"owner_component=audit-export", nil, 200, `{"holds":[]}`},
		{"", nil, 422, "SCHEMA_INVALID"},
		{"owner_component=a&owner_component=b", nil, 422, "SCHEMA_INVALID"},
		{"owner_component=audit-export&x=1", nil, 422, "SCHEMA_INVALID"},
		{"owner_component=other", ErrForbidden, 403, CodeHoldRequestDenied},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/internal/holds?"+c.query, nil)
		r.TLS = testPeerTLS(t)
		Handler{Backend: ownedBackend{err: c.err}}.ServeHTTP(w, r)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.body) {
			t.Fatalf("%q: %d %s", c.query, w.Code, w.Body.String())
		}
	}
}

func testPeerTLS(t *testing.T) *tls.ConnectionState {
	t.Helper()
	u, _ := url.Parse("spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter")
	cert := &x509.Certificate{SerialNumber: big.NewInt(7), URIs: []*url.URL{u}}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
}

func TestRiskEventHoldRequest(t *testing.T) {
	ok := `{"scope":"workload","scope_id":"agent-exec/runtime","reason":"risk_event","reason_detail":"protected_path_write","evidence_refs":["kernel_event:1"]}`
	if h, err := DecodeHoldRequest([]byte(ok)); err != nil || h.ReasonDetail == nil || *h.ReasonDetail != "protected_path_write" {
		t.Fatalf("%+v %v", h, err)
	}
	for name, body := range map[string]string{
		"missing detail": `{"scope":"workload","scope_id":"agent-exec/runtime","reason":"risk_event","evidence_refs":["kernel_event:1"]}`,
		"null detail":    `{"scope":"workload","scope_id":"agent-exec/runtime","reason":"risk_event","reason_detail":null,"evidence_refs":["kernel_event:1"]}`,
		"unknown detail": `{"scope":"workload","scope_id":"agent-exec/runtime","reason":"risk_event","reason_detail":"other","evidence_refs":["kernel_event:1"]}`,
		"no evidence":    `{"scope":"workload","scope_id":"agent-exec/runtime","reason":"risk_event","reason_detail":"protected_path_write","evidence_refs":[]}`,
		"node scope":     `{"scope":"node","scope_id":"6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f","reason":"risk_event","reason_detail":"protected_path_write","evidence_refs":["k"]}`,
		"detail on lag":  `{"scope":"global","scope_id":"*","reason":"export_lag","reason_detail":"protected_path_write","evidence_refs":[]}`,
		"extra field":    `{"scope":"global","scope_id":"*","reason":"export_lag","owner":"x","evidence_refs":[]}`,
	} {
		if _, err := DecodeHoldRequest([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
