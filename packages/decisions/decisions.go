// Package decisions checks the result of the gateway Rego policy and derives
// the GatewayDecision fields from it (TASK-04 3.2, 3.3, chapter 6; COMMON policy
// decision contract).
//
//   - ParseResult checks the OPA result object against a strict schema. Any
//     deviation is an error; the gateway answers it with 503
//     POLICY_UNAVAILABLE and stores nothing.
//   - Derive fills decision_basis, standing_rule_id, approval_id,
//     service_session_id and activation_probe_id from the result and the
//     facts the gateway gave to OPA.
//   - EscalateIntent applies the only change the gateway may make after Rego:
//     a standing-rule allow becomes approval_required when the intent check
//     is divergent. AssertNotLooser guards that direction.
//   - HTTPStatus picks the response status from the reason codes.
package decisions

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
)

// Verdicts (COMMON enum verdict).
const (
	Allow            = "allow"
	ApprovalRequired = "approval_required"
	Deny             = "deny"
)

// Decision bases (COMMON enum decision_basis).
const (
	BasisApproval        = "approval"
	BasisStandingRule    = "standing_rule"
	BasisServiceScope    = "service_scope"
	BasisActivationProbe = "activation_probe"
)

// Rule IDs the gateway reads or adds.
const (
	RuleApprovalAllow        = "approval.allow.v1"
	RuleServiceScopeAllow    = "service.scope_allow.v1"
	RuleApprovalRequired     = "approval.required_default.v1"
	RuleProbeActivation      = "probe.activation.v1"
	RuleProbeExempt          = "hold.activation_probe_exempt.v1"
	RuleIntentEscalation     = "intent.divergence_escalation.v1"
	ReasonApprovalRequired   = "APPROVAL_REQUIRED"
	ReasonIntentEscalated    = "INTENT_DIVERGENCE_ESCALATED"
	ReasonPolicyUnavailable  = "POLICY_UNAVAILABLE"
	ReasonVersionMismatch    = "POLICY_VERSION_MISMATCH"
	ReasonStateStore         = "STATE_STORE_UNAVAILABLE"
	ReasonServiceScopeDenied = "SERVICE_SCOPE_DENIED"
)

// reasonHTTP is the HTTP column of the COMMON reason code dictionary.
// OUTCOME_TIMEOUT has no HTTP status and is not listed.
var reasonHTTP = map[string]int{
	"AUTH_REQUIRED":                    401,
	"CLAIM_CODE_INVALID":               403,
	"SESSION_BINDING_INVALID":          403,
	"ENDPOINT_NOT_REGISTERED":          403,
	"SERVICE_SCOPE_DENIED":             403,
	"TARGET_SCOPE_DENIED":              403,
	"DISCLOSURE_SCOPE_DENIED":          403,
	"CONTENT_PATTERN_DENIED":           403,
	"DATA_CLASS_DENIED":                403,
	"APPROVAL_REQUIRED":                202,
	"INTENT_DIVERGENCE_ESCALATED":      202,
	"INTENT_ACK_REQUIRED":              422,
	"PERMISSION_WIDENING_ACK_REQUIRED": 422,
	"LOCK_TIMEOUT":                     503,
	"APPROVAL_INVALID":                 403,
	"APPROVAL_UNAVAILABLE":             409,
	"SESSION_BUDGET_EXHAUSTED":         409,
	"CONTEXT_INCOMPLETE":               403,
	"POLICY_UNAVAILABLE":               503,
	"POLICY_VERSION_MISMATCH":          503,
	"POLICY_EPOCH_STALE":               409,
	"CATALOG_DIGEST_MISMATCH":          409,
	"DECISION_EXPIRED":                 409,
	"HOLD_ACTIVE":                      503,
	"CONTROL_HEALTH_UNAVAILABLE":       503,
	"POD_OBSERVATION_NOT_READY":        503,
	"WORK_READINESS_EXPIRED":           503,
	"WORK_READINESS_BINDING_MISMATCH":  403,
	"CLIENT_KEY_BODY_CONFLICT":         409,
	"PREFLIGHT_MISMATCH":               409,
	"CONTENT_DIGEST_MISMATCH":          409,
	"DESTINATION_NOT_ALLOWED":          403,
	"TLS_VERIFY_FAILED":                502,
	"CREDENTIAL_UNAVAILABLE":           503,
	"PERMIT_INVALID":                   409,
	"RESPONSE_TOO_LARGE":               502,
	"TARGET_REJECTED":                  502,
	"TARGET_UNAVAILABLE":               503,
	"MODEL_BLOCKED":                    502,
	"TARGET_IDENTITY_CHANGED":          409,
	"EVENT_ID_CONFLICT":                409,
	"TARGET_KEY_BODY_CONFLICT":         409,
	"TOOL_NOT_REGISTERED":              403,
	"TOOL_BUDGET_EXHAUSTED":            409,
	"MODEL_OUTPUT_TRUNCATED":           502,
	"MODEL_SCHEMA_INVALID":             422,
	"STARTUP_GUARD_UNAVAILABLE":        503,
	"SCHEMA_INVALID":                   422,
	"ACTION_DIGEST_MISMATCH":           409,
	"RESOURCE_NOT_FOUND":               404,
	"STATE_STORE_UNAVAILABLE":          503,
	"BODY_TOO_LARGE":                   413,
	"RATE_LIMITED":                     429,
}

// regoDenyCodes are the codes decision.rego can put in a deny result.
var regoDenyCodes = map[string]bool{
	"CONTEXT_INCOMPLETE":         true,
	"ENDPOINT_NOT_REGISTERED":    true,
	"CATALOG_DIGEST_MISMATCH":    true,
	"SESSION_BINDING_INVALID":    true,
	"TARGET_SCOPE_DENIED":        true,
	"DISCLOSURE_SCOPE_DENIED":    true,
	"DATA_CLASS_DENIED":          true,
	"SERVICE_SCOPE_DENIED":       true,
	"APPROVAL_INVALID":           true,
	"APPROVAL_UNAVAILABLE":       true,
	"HOLD_ACTIVE":                true,
	"CONTROL_HEALTH_UNAVAILABLE": true,
}

// ruleID is <area>.<rule>.v<number> (COMMON policy decision contract).
var ruleID = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+\.v[0-9]+$`)

// statusRank orders statuses for a response with several codes: 503 > 409 >
// 403 > 422 (TASK-04 3.1, COMMON). Codes outside these four rank below them.
var statusRank = map[int]int{503: 4, 409: 3, 403: 2, 422: 1}

// HTTPStatus returns the status of a response carrying codes. allow and
// approval_required are 202; a deny picks the highest-ranked status of its
// codes. An unknown code makes the response 503, so a typo never turns into
// a weaker status.
func HTTPStatus(verdict string, codes []string) int {
	if verdict == Allow || verdict == ApprovalRequired {
		return http.StatusAccepted
	}
	best, bestRank := 0, -1
	for _, c := range codes {
		s, ok := reasonHTTP[c]
		if !ok {
			return http.StatusServiceUnavailable
		}
		if r := statusRank[s]; r > bestRank {
			best, bestRank = s, r
		}
	}
	if best == 0 || best == http.StatusAccepted {
		return http.StatusServiceUnavailable
	}
	return best
}

// KnownReason reports whether code is in the COMMON reason code dictionary.
func KnownReason(code string) bool {
	_, ok := reasonHTTP[code]
	return ok
}

// Result is the gateway Rego result (TASK-04 3.2 `result`).
type Result struct {
	Verdict          string   `json:"verdict"`
	ReasonCodes      []string `json:"reason_codes"`
	MatchedRuleIDs   []string `json:"matched_rule_ids"`
	EvaluatedRuleIDs []string `json:"evaluated_rule_ids"`
	DecisionBasis    *string  `json:"decision_basis"`
}

// RegoResult is GatewayDecision.rego_result.
type RegoResult struct {
	Verdict        string   `json:"verdict"`
	ReasonCodes    []string `json:"reason_codes"`
	MatchedRuleIDs []string `json:"matched_rule_ids"`
}

// ErrSchema marks a result that does not fit the strict schema.
var ErrSchema = errors.New("decisions: rego result schema")

func schemaErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSchema, fmt.Sprintf(format, a...))
}

// ParseResult checks the value of one OPA expression (the decoded JSON value
// of data.agentarium.gateway.result) and returns it as a Result.
func ParseResult(v any) (Result, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return Result{}, schemaErr("result is %T, not an object", v)
	}
	want := []string{"verdict", "reason_codes", "matched_rule_ids", "evaluated_rule_ids", "decision_basis"}
	if len(m) != len(want) {
		return Result{}, schemaErr("result has %d keys, want %d", len(m), len(want))
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return Result{}, schemaErr("result has no %q", k)
		}
	}
	var r Result
	var err error
	if r.Verdict, ok = m["verdict"].(string); !ok {
		return Result{}, schemaErr("verdict is not a string")
	}
	if r.ReasonCodes, err = stringList(m["reason_codes"], "reason_codes"); err != nil {
		return Result{}, err
	}
	if r.MatchedRuleIDs, err = stringList(m["matched_rule_ids"], "matched_rule_ids"); err != nil {
		return Result{}, err
	}
	if r.EvaluatedRuleIDs, err = stringList(m["evaluated_rule_ids"], "evaluated_rule_ids"); err != nil {
		return Result{}, err
	}
	switch b := m["decision_basis"].(type) {
	case nil:
	case string:
		r.DecisionBasis = &b
	default:
		return Result{}, schemaErr("decision_basis is %T", b)
	}
	return r, r.Check()
}

func stringList(v any, name string) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, schemaErr("%s is %T, not an array", name, v)
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, schemaErr("%s has a %T element", name, e)
		}
		out = append(out, s)
	}
	return out, nil
}

// Check enforces the meaning rules of a Rego result (TASK-04 3.2 decision
// meaning tests, COMMON Rego result and decision rules):
//   - verdict and decision_basis are enum values; decision_basis is set
//     exactly when the verdict is allow;
//   - matched_rule_ids and evaluated_rule_ids are non-empty, duplicate-free
//     rule IDs;
//   - allow has no reason codes; approval_required has exactly
//     APPROVAL_REQUIRED; deny has one or more codes decision.rego can give;
//   - the matched rule agrees with the basis.
func (r Result) Check() error {
	switch r.Verdict {
	case Allow, ApprovalRequired, Deny:
	default:
		return schemaErr("verdict %q", r.Verdict)
	}
	if len(r.MatchedRuleIDs) == 0 || len(r.EvaluatedRuleIDs) == 0 {
		return schemaErr("matched_rule_ids and evaluated_rule_ids must be non-empty")
	}
	for _, l := range [][]string{r.MatchedRuleIDs, r.EvaluatedRuleIDs} {
		seen := map[string]bool{}
		for _, id := range l {
			if !ruleID.MatchString(id) {
				return schemaErr("rule_id %q", id)
			}
			if seen[id] {
				return schemaErr("duplicate rule_id %q", id)
			}
			seen[id] = true
		}
	}
	basis := ""
	if r.DecisionBasis != nil {
		basis = *r.DecisionBasis
		switch basis {
		case BasisApproval, BasisStandingRule, BasisServiceScope, BasisActivationProbe:
		default:
			return schemaErr("decision_basis %q", basis)
		}
	}
	if (r.Verdict == Allow) != (r.DecisionBasis != nil) {
		return schemaErr("decision_basis must be set exactly for allow")
	}
	switch r.Verdict {
	case Allow:
		if len(r.ReasonCodes) != 0 {
			return schemaErr("allow with reason codes %v", r.ReasonCodes)
		}
		switch basis {
		case BasisApproval:
			if r.MatchedRuleIDs[0] != RuleApprovalAllow {
				return schemaErr("approval allow matched %v", r.MatchedRuleIDs)
			}
		case BasisServiceScope:
			if !slices.Equal(r.MatchedRuleIDs, []string{RuleServiceScopeAllow}) {
				return schemaErr("service_scope allow matched %v", r.MatchedRuleIDs)
			}
		case BasisActivationProbe:
			if r.MatchedRuleIDs[0] != RuleProbeActivation {
				return schemaErr("activation_probe allow matched %v", r.MatchedRuleIDs)
			}
		case BasisStandingRule:
			if r.MatchedRuleIDs[0] == RuleProbeActivation || !hasPrefix(r.MatchedRuleIDs[0], "standing.") {
				return schemaErr("standing_rule allow matched %v", r.MatchedRuleIDs)
			}
		}
		// Only an activation probe can carry the hold exemption (decision.rego
		// probe_exempt requires standing_rule_id = probe.activation.v1).
		for _, id := range r.MatchedRuleIDs[1:] {
			if id != RuleProbeExempt || basis != BasisActivationProbe {
				return schemaErr("allow matched %v", r.MatchedRuleIDs)
			}
		}
	case ApprovalRequired:
		if !slices.Equal(r.ReasonCodes, []string{ReasonApprovalRequired}) {
			return schemaErr("approval_required with reason codes %v", r.ReasonCodes)
		}
	case Deny:
		if len(r.ReasonCodes) == 0 {
			return schemaErr("deny without reason codes")
		}
		for _, c := range r.ReasonCodes {
			if !regoDenyCodes[c] {
				return schemaErr("deny reason code %q", c)
			}
		}
	}
	return nil
}

func hasPrefix(s, p string) bool { return len(s) > len(p) && s[:len(p)] == p }

// Facts are the input values the derived IDs come from: the approval
// snapshot, the service session and the activation probe row the gateway put
// into the OPA input. Empty means absent.
type Facts struct {
	ApprovalID        string
	ServiceSessionID  string // set for a service-session request
	ActivationProbeID string
}

// Derived is the part of GatewayDecision the gateway computes from the Rego
// result (TASK-04 3.2 derivation table).
type Derived struct {
	Verdict             string
	ReasonCodes         []string
	DecisionBasis       string // empty = null
	StandingRuleID      string
	ApprovalID          string
	ServiceSessionID    string
	ActivationProbeID   string
	MatchedRuleIDs      []string // rego matched ∪ gateway_added
	EvaluatedRuleIDs    []string
	RegoResult          RegoResult
	GatewayAddedRuleIDs []string
	IntentEscalated     bool
}

// Derive turns a checked Result into the decision fields. It fails when the
// basis needs an ID the facts do not have, so a decision never names an
// approval or probe the input did not contain.
func Derive(r Result, f Facts) (Derived, error) {
	if err := r.Check(); err != nil {
		return Derived{}, err
	}
	d := Derived{
		Verdict:             r.Verdict,
		ReasonCodes:         slices.Clone(r.ReasonCodes),
		MatchedRuleIDs:      slices.Clone(r.MatchedRuleIDs),
		EvaluatedRuleIDs:    slices.Clone(r.EvaluatedRuleIDs),
		RegoResult:          RegoResult{Verdict: r.Verdict, ReasonCodes: slices.Clone(r.ReasonCodes), MatchedRuleIDs: slices.Clone(r.MatchedRuleIDs)},
		GatewayAddedRuleIDs: []string{},
		ServiceSessionID:    f.ServiceSessionID,
	}
	if r.DecisionBasis != nil {
		d.DecisionBasis = *r.DecisionBasis
	}
	// A service session cannot be approved (COMMON): its only outcomes are
	// allow and deny.
	if r.Verdict == ApprovalRequired && f.ServiceSessionID != "" {
		return Derived{}, schemaErr("approval_required for a service session")
	}
	switch d.DecisionBasis {
	case BasisApproval:
		if f.ApprovalID == "" || f.ServiceSessionID != "" {
			return Derived{}, schemaErr("approval basis without a user approval snapshot")
		}
		d.ApprovalID = f.ApprovalID
	case BasisStandingRule:
		d.StandingRuleID = r.MatchedRuleIDs[0]
	case BasisActivationProbe:
		if f.ActivationProbeID == "" || f.ServiceSessionID == "" {
			return Derived{}, schemaErr("activation_probe basis without a probe row")
		}
		d.StandingRuleID = r.MatchedRuleIDs[0]
	case BasisServiceScope:
		if f.ServiceSessionID == "" {
			return Derived{}, schemaErr("service_scope basis for a user session")
		}
	}
	// activation_probe_id is recorded when the probe exemption matched
	// (TASK-04 3.2 derivation table) and for every activation_probe allow, because the
	// reservation reads the probe row's target_epoch through it (COMMON reservation
	// transaction). The two rules agree: the exemption only matches on the
	// probe path.
	if d.DecisionBasis == BasisActivationProbe || slices.Contains(r.MatchedRuleIDs, RuleProbeExempt) {
		if f.ActivationProbeID == "" {
			return Derived{}, schemaErr("probe exemption matched without a probe row")
		}
		d.ActivationProbeID = f.ActivationProbeID
	}
	return d, nil
}

// Intent check results (COMMON IntentCheckResult).
const (
	IntentCompleted = "completed"
	IntentDivergent = "divergent"
)

// EscalateIntent applies an intent check result to a derived decision
// (TASK-04 3.3 effects, COMMON). Only a user-session standing-rule allow with a
// completed, divergent check changes: it becomes approval_required with
// reason codes [APPROVAL_REQUIRED, INTENT_DIVERGENCE_ESCALATED], decision_basis
// null, standing_rule_id empty and gateway_added_rule_ids
// [intent.divergence_escalation.v1] (TASK-04 3.3: decision_basis null,
// standing_rule_id not recorded). The original standing rule stays only in
// matched_rule_ids and in rego_result, which keeps the original allow. Every
// other input is returned unchanged.
func EscalateIntent(d Derived, status, overall string) Derived {
	if d.Verdict != Allow || d.DecisionBasis != BasisStandingRule || d.ServiceSessionID != "" ||
		status != IntentCompleted || overall != IntentDivergent {
		return d
	}
	e := d
	e.Verdict = ApprovalRequired
	e.ReasonCodes = []string{ReasonApprovalRequired, ReasonIntentEscalated}
	e.DecisionBasis = ""
	e.StandingRuleID = ""
	e.GatewayAddedRuleIDs = []string{RuleIntentEscalation}
	e.MatchedRuleIDs = union(d.RegoResult.MatchedRuleIDs, e.GatewayAddedRuleIDs)
	e.IntentEscalated = true
	return e
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, v := range b {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

var strictness = map[string]int{Allow: 0, ApprovalRequired: 1, Deny: 2}

// AssertNotLooser checks that the final verdict is at least as strict as the
// Rego verdict (TASK-04 3.3: intent check can never create an allow or lower
// a deny/approval_required). On failure the gateway stores the Rego decision.
func AssertNotLooser(final Derived) error {
	f, ok1 := strictness[final.Verdict]
	r, ok2 := strictness[final.RegoResult.Verdict]
	if !ok1 || !ok2 || f < r {
		return fmt.Errorf("decisions: final verdict %q is looser than rego verdict %q", final.Verdict, final.RegoResult.Verdict)
	}
	if final.Verdict == Allow && len(final.GatewayAddedRuleIDs) > 0 {
		return errors.New("decisions: gateway-added rule on an allow")
	}
	return nil
}

// SortedCodes returns codes sorted and de-duplicated.
func SortedCodes(codes []string) []string {
	out := slices.Clone(codes)
	sort.Strings(out)
	return slices.Compact(out)
}
