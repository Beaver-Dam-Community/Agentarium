package decisions

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func decode(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

const approvalAllow = `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "decision_basis": "approval",
 "evaluated_rule_ids": ["approval.binding.v1", "approval.usable.v1", "catalog.digest_match.v1", "session.binding.v1"]}`

func TestParseResultAccepts(t *testing.T) {
	cases := map[string]string{
		"approval allow": approvalAllow,
		"standing allow": `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.k8s_read.v1"], "decision_basis": "standing_rule", "evaluated_rule_ids": ["session.binding.v1", "standing.k8s_read.v1"]}`,
		"probe allow": `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["probe.activation.v1", "hold.activation_probe_exempt.v1"], "decision_basis": "activation_probe",
			"evaluated_rule_ids": ["hold.activation_probe_exempt.v1", "probe.activation.v1"]}`,
		"service allow":     `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["service.scope_allow.v1"], "decision_basis": "service_scope", "evaluated_rule_ids": ["service.scope_allow.v1"]}`,
		"approval required": `{"verdict": "approval_required", "reason_codes": ["APPROVAL_REQUIRED"], "matched_rule_ids": ["approval.required_default.v1"], "decision_basis": null, "evaluated_rule_ids": ["session.binding.v1"]}`,
		"deny":              `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE", "SESSION_BINDING_INVALID"], "matched_rule_ids": ["hold.blocking.v1", "session.binding.v1"], "decision_basis": null, "evaluated_rule_ids": ["hold.blocking.v1", "session.binding.v1"]}`,
	}
	for name, s := range cases {
		if _, err := ParseResult(decode(t, s)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseResultRejects(t *testing.T) {
	cases := map[string]string{
		"not object":           `["allow"]`,
		"missing key":          `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"]}`,
		"extra key":            `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null, "x": 1}`,
		"bad verdict":          `{"verdict": "permit", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": null}`,
		"empty matched":        `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": [], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null}`,
		"empty evaluated":      `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": [], "decision_basis": null}`,
		"bad rule id":          `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["HoldBlocking"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null}`,
		"duplicate rule id":    `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1", "hold.blocking.v1"], "decision_basis": null}`,
		"allow without basis":  `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": null}`,
		"deny with basis":      `{"verdict": "deny", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": "approval"}`,
		"allow with codes":     `{"verdict": "allow", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "approval"}`,
		"deny without codes":   `{"verdict": "deny", "reason_codes": [], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null}`,
		"deny unknown code":    `{"verdict": "deny", "reason_codes": ["NOT_A_CODE"], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null}`,
		"approval_req code":    `{"verdict": "approval_required", "reason_codes": ["HOLD_ACTIVE"], "matched_rule_ids": ["approval.required_default.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": null}`,
		"bad basis":            `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "operator"}`,
		"basis rule mismatch":  `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.k8s_read.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "approval"}`,
		"probe as standing":    `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["probe.activation.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "standing_rule"}`,
		"service extra rule":   `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["service.scope_allow.v1", "hold.activation_probe_exempt.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "service_scope"}`,
		"numeric verdict":      `{"verdict": 1, "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "approval"}`,
		"non-string code":      `{"verdict": "deny", "reason_codes": [1], "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null}`,
		"basis wrong type":     `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["approval.allow.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": 3}`,
		"codes not an array":   `{"verdict": "deny", "reason_codes": "HOLD_ACTIVE", "matched_rule_ids": ["hold.blocking.v1"], "evaluated_rule_ids": ["hold.blocking.v1"], "decision_basis": null}`,
		"standing exempt":      `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.k8s_read.v1", "hold.activation_probe_exempt.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "standing_rule"}`,
		"standing extra rules": `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.k8s_read.v1", "session.binding.v1"], "evaluated_rule_ids": ["a.b.v1"], "decision_basis": "standing_rule"}`,
	}
	for name, s := range cases {
		_, err := ParseResult(decode(t, s))
		if !errors.Is(err, ErrSchema) {
			t.Errorf("%s: err = %v, want ErrSchema", name, err)
		}
	}
	if _, err := ParseResult(nil); !errors.Is(err, ErrSchema) {
		t.Errorf("nil result: %v", err)
	}
}

func mustParse(t *testing.T, s string) Result {
	t.Helper()
	r, err := ParseResult(decode(t, s))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDerive(t *testing.T) {
	r := mustParse(t, approvalAllow)
	d, err := Derive(r, Facts{ApprovalID: "a1"})
	if err != nil || d.DecisionBasis != BasisApproval || d.ApprovalID != "a1" || d.StandingRuleID != "" || d.ServiceSessionID != "" {
		t.Fatalf("approval: %+v %v", d, err)
	}
	if _, err := Derive(r, Facts{}); err == nil {
		t.Error("approval basis without approval id was accepted")
	}

	st := mustParse(t, `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.k8s_read.v1"], "decision_basis": "standing_rule", "evaluated_rule_ids": ["standing.k8s_read.v1"]}`)
	d, err = Derive(st, Facts{})
	if err != nil || d.StandingRuleID != "standing.k8s_read.v1" || d.ApprovalID != "" {
		t.Fatalf("standing: %+v %v", d, err)
	}

	pr := mustParse(t, `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["probe.activation.v1", "hold.activation_probe_exempt.v1"], "decision_basis": "activation_probe", "evaluated_rule_ids": ["probe.activation.v1"]}`)
	d, err = Derive(pr, Facts{ServiceSessionID: "s1", ActivationProbeID: "p1"})
	if err != nil || d.StandingRuleID != RuleProbeActivation || d.ActivationProbeID != "p1" || d.ServiceSessionID != "s1" {
		t.Fatalf("probe: %+v %v", d, err)
	}
	if _, err := Derive(pr, Facts{ServiceSessionID: "s1"}); err == nil {
		t.Error("probe basis without probe row was accepted")
	}
	// Without a hold the probe matches only probe.activation.v1; the probe
	// row is still recorded.
	nohold := mustParse(t, `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["probe.activation.v1"], "decision_basis": "activation_probe", "evaluated_rule_ids": ["probe.activation.v1"]}`)
	d, err = Derive(nohold, Facts{ServiceSessionID: "s1", ActivationProbeID: "p1"})
	if err != nil || d.ActivationProbeID != "p1" || d.StandingRuleID != RuleProbeActivation {
		t.Fatalf("probe without hold: %+v %v", d, err)
	}
	if _, err := Derive(nohold, Facts{ServiceSessionID: "s1"}); err == nil {
		t.Error("probe basis without probe row (no hold) was accepted")
	}

	sv := mustParse(t, `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["service.scope_allow.v1"], "decision_basis": "service_scope", "evaluated_rule_ids": ["service.scope_allow.v1"]}`)
	if _, err := Derive(sv, Facts{}); err == nil {
		t.Error("service_scope for a user session was accepted")
	}
	ar := mustParse(t, `{"verdict": "approval_required", "reason_codes": ["APPROVAL_REQUIRED"], "matched_rule_ids": ["approval.required_default.v1"], "decision_basis": null, "evaluated_rule_ids": ["session.binding.v1"]}`)
	if _, err := Derive(ar, Facts{ServiceSessionID: "s1"}); err == nil {
		t.Error("approval_required for a service session was accepted")
	}
	d, err = Derive(ar, Facts{})
	if err != nil || d.DecisionBasis != "" || len(d.GatewayAddedRuleIDs) != 0 || d.GatewayAddedRuleIDs == nil {
		t.Fatalf("approval_required: %+v %v", d, err)
	}
}

func TestEscalateIntent(t *testing.T) {
	st := mustParse(t, `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.model_synthetic.v1"], "decision_basis": "standing_rule", "evaluated_rule_ids": ["standing.model_synthetic.v1"]}`)
	d, _ := Derive(st, Facts{})
	e := EscalateIntent(d, IntentCompleted, IntentDivergent)
	if e.Verdict != ApprovalRequired || e.DecisionBasis != "" || !e.IntentEscalated ||
		!slices.Equal(e.ReasonCodes, []string{ReasonApprovalRequired, ReasonIntentEscalated}) ||
		!slices.Equal(e.GatewayAddedRuleIDs, []string{RuleIntentEscalation}) ||
		!slices.Equal(e.MatchedRuleIDs, []string{"standing.model_synthetic.v1", RuleIntentEscalation}) ||
		e.RegoResult.Verdict != Allow || e.StandingRuleID != "" {
		t.Fatalf("escalated: %+v", e)
	}
	// The standing rule is kept only in the Rego result (and matched_rule_ids).
	if !slices.Equal(e.RegoResult.MatchedRuleIDs, []string{"standing.model_synthetic.v1"}) {
		t.Fatalf("rego matched rules: %v", e.RegoResult.MatchedRuleIDs)
	}
	if err := AssertNotLooser(e); err != nil {
		t.Fatal(err)
	}
	// The original is untouched.
	if d.Verdict != Allow || len(d.GatewayAddedRuleIDs) != 0 || d.StandingRuleID != "standing.model_synthetic.v1" {
		t.Fatalf("original changed: %+v", d)
	}
	for _, c := range []struct{ status, overall string }{
		{IntentCompleted, "unclear"}, {IntentCompleted, "consistent"}, {"not_run", IntentDivergent}, {"not_run", ""},
	} {
		if got := EscalateIntent(d, c.status, c.overall); got.Verdict != Allow || got.IntentEscalated {
			t.Errorf("%v escalated", c)
		}
	}
	// Approval, service and non-allow decisions never change.
	ap, _ := Derive(mustParse(t, approvalAllow), Facts{ApprovalID: "a1"})
	if got := EscalateIntent(ap, IntentCompleted, IntentDivergent); got.Verdict != Allow {
		t.Error("approval allow escalated")
	}
	sd := d
	sd.ServiceSessionID = "s1"
	if got := EscalateIntent(sd, IntentCompleted, IntentDivergent); got.Verdict != Allow {
		t.Error("service standing allow escalated")
	}
}

func TestAssertNotLooser(t *testing.T) {
	ar := mustParse(t, `{"verdict": "approval_required", "reason_codes": ["APPROVAL_REQUIRED"], "matched_rule_ids": ["approval.required_default.v1"], "decision_basis": null, "evaluated_rule_ids": ["session.binding.v1"]}`)
	d, _ := Derive(ar, Facts{})
	looser := d
	looser.Verdict = Allow
	if err := AssertNotLooser(looser); err == nil {
		t.Error("approval_required -> allow passed")
	}
	if err := AssertNotLooser(d); err != nil {
		t.Error(err)
	}
	st := mustParse(t, `{"verdict": "allow", "reason_codes": [], "matched_rule_ids": ["standing.k8s_read.v1"], "decision_basis": "standing_rule", "evaluated_rule_ids": ["standing.k8s_read.v1"]}`)
	a, _ := Derive(st, Facts{})
	a.GatewayAddedRuleIDs = []string{RuleIntentEscalation}
	if err := AssertNotLooser(a); err == nil {
		t.Error("allow with gateway-added rule passed")
	}
}

func TestHTTPStatus(t *testing.T) {
	cases := []struct {
		verdict string
		codes   []string
		want    int
	}{
		{Allow, nil, 202},
		{ApprovalRequired, []string{"APPROVAL_REQUIRED"}, 202},
		{Deny, []string{"SESSION_BINDING_INVALID"}, 403},
		{Deny, []string{"SESSION_BINDING_INVALID", "HOLD_ACTIVE"}, 503},
		{Deny, []string{"APPROVAL_UNAVAILABLE", "TARGET_SCOPE_DENIED"}, 409},
		{Deny, []string{"SCHEMA_INVALID", "CONTENT_PATTERN_DENIED"}, 403},
		{Deny, []string{"SCHEMA_INVALID"}, 422},
		{Deny, []string{"CATALOG_DIGEST_MISMATCH", "CONTROL_HEALTH_UNAVAILABLE", "DATA_CLASS_DENIED"}, 503},
		{Deny, []string{"NOT_A_CODE", "SESSION_BINDING_INVALID"}, 503},
		{Deny, nil, 503},
		{Deny, []string{"APPROVAL_REQUIRED"}, 503},
	}
	for _, c := range cases {
		if got := HTTPStatus(c.verdict, c.codes); got != c.want {
			t.Errorf("%s %v = %d, want %d", c.verdict, c.codes, got, c.want)
		}
	}
	for code := range regoDenyCodes {
		if !KnownReason(code) {
			t.Errorf("rego code %s missing from the dictionary", code)
		}
	}
	if got := SortedCodes([]string{"B", "A", "B"}); !slices.Equal(got, []string{"A", "B"}) {
		t.Errorf("SortedCodes = %v", got)
	}
}
