package inputs

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

const (
	actionID  = "0b7c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"
	requestID = "1c8d3e4f-5a6b-4d7e-9f80-1b2c3d4e5f60"
	sessionID = "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
)

// normalized returns a receiver.submit envelope and content as the gateway
// would store them (TASK-02 Normalize over the test catalog).
func normalized(t *testing.T, service bool) (canonical.ActionEnvelope, canonical.Content) {
	t.Helper()
	cat, err := canonical.LoadCatalogDir("../../canonical/testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	tc := canonical.TrustedContext{
		ActionID: actionID, RequestID: requestID, AuthenticatedActor: "user:alice@example.com", SessionKind: "user",
		SessionID: sessionID, Tenant: "hackathon", Environment: "test",
		WorkloadDataState: canonical.WorkloadDataState{DataClassHighWater: "synthetic", DataSources: []string{"receiver-primary"}},
	}
	if service {
		tc.SessionKind, tc.AuthenticatedActor = "service", "spiffe://agentarium.internal/ns/agent-control/sa/policy-proposer"
	} else {
		w := "agent-runtime-0"
		tc.WorkloadID = &w
	}
	raw := `{"session_id":"` + sessionID + `","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},"arguments":{"payload":{"summary":"synthetic summary","email":null}},"client_request_key":"req-00000001"}`
	env, content, nerr := canonical.NormalizeRaw([]byte(raw), tc, cat)
	if nerr != nil {
		t.Fatal(nerr)
	}
	return env, content
}

func TestDecodeEnvelope(t *testing.T) {
	for _, service := range []bool{false, true} {
		env, _ := normalized(t, service)
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := decodeEnvelope(env.ActionID, raw)
		if err != nil {
			t.Fatalf("service=%v: %v", service, err)
		}
		if !reflect.DeepEqual(got, env) {
			t.Fatalf("service=%v:\n got %+v\nwant %+v", service, got, env)
		}
		// The decoded envelope still digests to the stored action_digest.
		if ad, err := canonical.ActionDigest(got.HashObject()); err != nil || ad != env.ActionDigest {
			t.Fatalf("action_digest %s, want %s (%v)", ad, env.ActionDigest, err)
		}
		if service != (got.WorkloadID == nil) {
			t.Fatalf("service=%v workload_id %v", service, got.WorkloadID)
		}
	}
}

func TestDecodeEnvelopeWithoutContent(t *testing.T) {
	env, _ := normalized(t, false)
	env.ContentDigest, env.ContentRef, env.Bytes = nil, nil, 0
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeEnvelope(env.ActionID, raw)
	if err != nil || got.ContentDigest != nil || got.ContentRef != nil {
		t.Fatalf("got %+v err=%v", got, err)
	}
}

// The database keeps the envelope jsonb equal to the typed columns but does
// not check the shape of the canonical_target and limits values;
// decodeEnvelope rejects whatever does not decode strictly.
func TestDecodeEnvelopeRejects(t *testing.T) {
	env, _ := normalized(t, false)
	full, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	with := func(key, value string) []byte {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(full, &m); err != nil {
			t.Fatal(err)
		}
		if value == "" {
			delete(m, key)
		} else {
			m[key] = json.RawMessage(value)
		}
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, raw := range map[string][]byte{
		"not an object":          []byte(`null`),
		"empty object":           []byte(`{}`),
		"missing limits":         with("limits", ""),
		"unknown key":            with("x", `1`),
		"duplicate keys":         append([]byte(`{"tenant":"x",`), full[1:]...),
		"string as number":       with("bytes", `"12"`),
		"target null":            with("canonical_target", `null`),
		"target missing route":   with("canonical_target", `{"target_id":"receiver-primary"}`),
		"target unknown key":     with("canonical_target", `{"target_id":"receiver-primary","route_id":"submissions-v1","x":"y"}`),
		"limits null":            with("limits", `null`),
		"limits fraction":        with("limits", `{"max_bytes":1.5}`),
		"limits array":           with("limits", `[1]`),
		"disclosure not strings": with("disclosure_fields", `[1]`),
	} {
		if _, err := decodeEnvelope(actionID, raw); !errors.Is(err, ErrInconsistent) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDecisionFromRow(t *testing.T) {
	exp := time.Date(2026, 10, 15, 12, 0, 10, 0, time.UTC)
	s := func(v string) *string { return &v }
	epoch := int64(7)
	allow := decisionRow{
		DecisionID: "2d9e4f50-6b7c-4e8f-a091-2c3d4e5f6071", RequestID: requestID, ActionID: actionID,
		ActionDigest: s(strings.Repeat("e", 64)), AdapterID: s("receiver-sender"), Verdict: "allow",
		PolicyBundleID: "bundle-1", PolicyEpoch: &epoch, CatalogDigest: strings.Repeat("c", 64), ExpiresAt: exp,
	}
	want := execute.Decision{
		DecisionID: allow.DecisionID, RequestID: requestID, ActionID: actionID, ActionDigest: strings.Repeat("e", 64),
		AdapterID: "receiver-sender", Verdict: "allow", PolicyBundleID: "bundle-1", PolicyEpoch: 7,
		CatalogDigest: strings.Repeat("c", 64), ExpiresAt: exp,
	}
	if got := allow.decision(); got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// A normalize-stage deny has no action_digest, adapter_id or epoch.
	deny := allow
	deny.ActionDigest, deny.AdapterID, deny.PolicyEpoch, deny.Verdict = nil, nil, nil, "deny"
	want.ActionDigest, want.AdapterID, want.PolicyEpoch, want.Verdict = "", "", 0, "deny"
	if got := deny.decision(); got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	// A service session decision carries service_session_id.
	svc := allow
	svc.ServiceSessionID = s("7a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d")
	if got := svc.decision(); got.ServiceSessionID != *svc.ServiceSessionID {
		t.Fatalf("service_session_id %q", got.ServiceSessionID)
	}
}

func TestContentFromRow(t *testing.T) {
	env, content := normalized(t, false)
	r := contentRow{ContentDigest: content.ContentDigest, Tenant: content.Tenant, ActionID: content.ActionID,
		AdapterID: content.AdapterID, ContentBytes: content.ContentBytes}
	got := r.content()
	if !reflect.DeepEqual(got, content) {
		t.Fatalf("got %+v want %+v", got, content)
	}
	if err := canonical.VerifyContent(env, got); err != nil {
		t.Fatal(err)
	}
	// The row is mapped as stored: a row of another action with the same
	// bytes does not verify.
	r.ActionID = requestID
	if err := canonical.VerifyContent(env, r.content()); err == nil {
		t.Fatal("content of another action verified")
	}
}

func TestLoadRejectsNonUUIDWithoutQuery(t *testing.T) {
	s := &PG{AdapterID: "receiver-sender"} // nil pool: a query would panic
	for _, ids := range [][2]string{{"x", actionID}, {actionID, "x"}, {strings.ToUpper(actionID), actionID}} {
		if _, err := s.Load(t.Context(), ids[0], ids[1]); !errors.Is(err, execute.ErrNotFound) {
			t.Errorf("%v: %v", ids, err)
		}
	}
	if _, err := (&PG{}).Load(t.Context(), actionID, actionID); err == nil || errors.Is(err, execute.ErrNotFound) {
		t.Errorf("empty AdapterID: %v", err)
	}
}
