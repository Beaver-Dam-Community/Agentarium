package prepare_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/prepare"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

func catalog(t *testing.T) canonical.Catalog {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	c, err := canonical.LoadCatalogDir(filepath.Join(filepath.Dir(file), "..", "..", "canonical", "testdata", "catalog"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func normalize(t *testing.T, cat canonical.Catalog, payload string) (canonical.ActionEnvelope, canonical.Content) {
	t.Helper()
	w := "agent-runtime-0"
	raw := `{"session_id":"51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d","operation_id":"receiver.submit","requested_target":{"target_id":"receiver-primary"},"arguments":{"payload":` + payload + `},"client_request_key":"req-00000001"}`
	env, content, nerr := canonical.NormalizeRaw([]byte(raw), canonical.TrustedContext{
		ActionID: "8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f", RequestID: "0f9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d6c",
		AuthenticatedActor: "user:alice@example.com", SessionKind: "user", SessionID: "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
		WorkloadID: &w, Tenant: "hackathon", Environment: "test",
	}, cat)
	if nerr != nil {
		t.Fatal(nerr)
	}
	return env, content
}

func TestReceiverPlan(t *testing.T) {
	cat := catalog(t)
	env, content := normalize(t, cat, `{"summary":"3 pods restarted","email":null}`)
	plan, op, tg, m := prepare.ReceiverPlan(env, content, cat)
	if m != nil {
		t.Fatal(m)
	}
	if string(plan.BodyBytes) != `{"email":null,"summary":"3 pods restarted"}` || plan.WireBodyDigest != *env.ContentDigest {
		t.Fatalf("body %s digest %s", plan.BodyBytes, plan.WireBodyDigest)
	}
	if plan.Method != "POST" || plan.Route != op.RouteTemplate || plan.OriginID != tg.Origin || plan.ExpectedTLSName != tg.ExpectedTLSName {
		t.Fatalf("plan %+v", plan)
	}
	if plan.SafeHeaders["Idempotency-Key"] != env.ActionID || plan.SafeHeaders["User-Agent"] == "" {
		t.Fatalf("safe headers %v", plan.SafeHeaders)
	}
	for k := range plan.SafeHeaders {
		if k == "Authorization" || k == "Traceparent" || k == "Baggage" {
			t.Fatalf("header %s must not be in the plan", k)
		}
	}
}

func TestReceiverPlanRejectsChanges(t *testing.T) {
	cat := catalog(t)
	env, content := normalize(t, cat, `{"summary":"3 pods restarted","email":null}`)

	cases := map[string]struct {
		mut  func(*canonical.ActionEnvelope, *canonical.Content, *canonical.Catalog)
		code string
	}{
		"body changed after approval": {func(_ *canonical.ActionEnvelope, c *canonical.Content, _ *canonical.Catalog) {
			c.ContentBytes = []byte(`{"email":null,"summary":"4 pods restarted"}`)
		}, prepare.ReasonContentDigestMismatch},
		"target changed": {func(e *canonical.ActionEnvelope, _ *canonical.Content, _ *canonical.Catalog) {
			e.CanonicalTarget.TargetID = "no-such-receiver"
		}, prepare.ReasonPreflightMismatch},
		"route changed": {func(e *canonical.ActionEnvelope, _ *canonical.Content, _ *canonical.Catalog) {
			e.CanonicalTarget.RouteID = "other-route"
		}, prepare.ReasonPreflightMismatch},
		"disclosure narrower than payload": {func(e *canonical.ActionEnvelope, c *canonical.Content, _ *canonical.Catalog) {
			e.DisclosureFields = []string{}
		}, prepare.ReasonPreflightMismatch},
		"catalog changed": {func(_ *canonical.ActionEnvelope, _ *canonical.Content, cat *canonical.Catalog) {
			cat.CatalogDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		}, prepare.ReasonCatalogDigestMismatch},
		"content of another action": {func(_ *canonical.ActionEnvelope, c *canonical.Content, _ *canonical.Catalog) {
			c.ActionID = "00000000-0000-4000-8000-000000000000"
		}, prepare.ReasonContentDigestMismatch},
		"bytes differ": {func(e *canonical.ActionEnvelope, _ *canonical.Content, _ *canonical.Catalog) {
			e.Bytes++
		}, prepare.ReasonPreflightMismatch},
	}
	for name, tc := range cases {
		e, c := env, content
		e.DisclosureFields = append([]string(nil), env.DisclosureFields...)
		c.ContentBytes = append([]byte(nil), content.ContentBytes...)
		ct := cat
		tc.mut(&e, &c, &ct)
		if _, _, _, m := prepare.ReceiverPlan(e, c, ct); m == nil || m.ReasonCode != tc.code {
			t.Errorf("%s: got %v, want %s", name, m, tc.code)
		}
	}
}

func TestReceiverPolicy(t *testing.T) {
	cat := catalog(t)
	env, content := normalize(t, cat, `{"summary":"3 pods restarted","email":"a@b.example"}`)
	plan, op, _, m := prepare.ReceiverPlan(env, content, cat)
	if m != nil {
		t.Fatal(m)
	}
	ok := prepare.ReceiverPolicy{AllowedDisclosureFields: []string{"email", "summary"}, MaxRequestBytes: 65536, MaxResponseBytes: 512, AllowedRouteIDs: []string{op.RouteID}}
	got, m := prepare.CheckReceiverPolicy(plan, env, op, ok)
	if m != nil || got.ResponseLimit != 512 {
		t.Fatalf("%v limit %d", m, got.ResponseLimit)
	}
	for name, pol := range map[string]prepare.ReceiverPolicy{
		"email not allowed": {AllowedDisclosureFields: []string{"summary"}, MaxRequestBytes: 65536, MaxResponseBytes: 512, AllowedRouteIDs: []string{op.RouteID}},
		"route not allowed": {AllowedDisclosureFields: []string{"email", "summary"}, MaxRequestBytes: 65536, MaxResponseBytes: 512},
		"too large":         {AllowedDisclosureFields: []string{"email", "summary"}, MaxRequestBytes: 10, MaxResponseBytes: 512, AllowedRouteIDs: []string{op.RouteID}},
		"no constraint":     {AllowedDisclosureFields: []string{"email", "summary"}, AllowedRouteIDs: []string{op.RouteID}},
	} {
		if _, m := prepare.CheckReceiverPolicy(plan, env, op, pol); m == nil || m.ReasonCode != prepare.ReasonPreflightMismatch {
			t.Errorf("%s: %v", name, m)
		}
	}
}
