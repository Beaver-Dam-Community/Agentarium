package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/decisions"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// evaluation is one OPA evaluation and what the decision row needs from it.
type evaluation struct {
	inputJSON   []byte // the OPA input as evaluated (decision_inputs.sanitized_input)
	inputDigest string // canonical digest of inputJSON (decision_input_digest)
	derived     decisions.Derived
	intent      IntentResult
}

var policyUnavailable = unavailable("POLICY_UNAVAILABLE", "policy evaluation failed")

// evaluate runs the snapshot's prepared query on in with a 500 ms timeout
// (TASK-04 chapter 3 step 5), checks the result against the strict schema and
// derives the decision fields. An empty result set, a schema deviation or a
// timeout is 503 POLICY_UNAVAILABLE; the caller stores nothing.
func evaluate(ctx context.Context, snap *policyloader.Snapshot, in opaInput, f facts, c Caller) (evaluation, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return evaluation{}, fmt.Errorf("gateway: OPA input: %w", err)
	}
	digest, err := canonical.CanonicalDigestJSON(raw)
	if err != nil {
		return evaluation{}, fmt.Errorf("gateway: OPA input digest: %w", err)
	}
	// Parse the exact bytes that are hashed and stored, so OPA sees the same
	// value (integers stay integers).
	value, err := ast.ValueFromReader(bytes.NewReader(raw))
	if err != nil {
		return evaluation{}, fmt.Errorf("gateway: OPA input value: %w", err)
	}
	ectx, cancel := context.WithTimeout(ctx, EvalTimeout)
	defer cancel()
	rs, err := snap.Prepared().Eval(ectx, rego.EvalParsedInput(value))
	if err != nil || len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return evaluation{}, policyUnavailable
	}
	res, err := decisions.ParseResult(rs[0].Expressions[0].Value)
	if err != nil {
		return evaluation{}, policyUnavailable
	}
	df := decisions.Facts{ApprovalID: f.approvalID}
	if c.Kind == KindService {
		df.ServiceSessionID = c.SessionID
		// An approval never applies to a service session (Rego denies it).
		df.ApprovalID = ""
	}
	if f.probe != nil {
		df.ActivationProbeID = f.probe.ActivationProbeID
	}
	d, err := decisions.Derive(res, df)
	if err != nil {
		return evaluation{}, policyUnavailable
	}
	return evaluation{inputJSON: raw, inputDigest: digest, derived: d, intent: IntentResult{Status: "not_run"}}, nil
}

// applyIntent runs the standing-rule intent check when it applies (TASK-04
// 3.3): a user-session standing-rule allow of an operation whose catalog
// entry sets intent_check_on_standing_rule. It waits at most IntentTimeout;
// an error or timeout is not_run and keeps the Rego verdict. The result can
// only make the verdict stricter; if the assert fails the Rego decision is
// kept and the error logged.
func (s *Service) applyIntent(ctx context.Context, ev *evaluation, op canonical.CatalogOperation, c Caller, env canonical.ActionEnvelope) {
	d := ev.derived
	if c.Kind != KindUser || d.Verdict != decisions.Allow || d.DecisionBasis != decisions.BasisStandingRule || !op.IntentCheckOnStandingRule {
		return
	}
	ictx, cancel := context.WithTimeout(ctx, IntentTimeout)
	defer cancel()
	r, err := s.intent().Check(ictx, IntentRequest{ActionID: env.ActionID, SessionID: c.SessionID, Envelope: env})
	if err != nil || (r.Status != decisions.IntentCompleted && r.Status != "not_run") {
		ev.intent = IntentResult{Status: "not_run"}
		return
	}
	ev.intent = r
	e := decisions.EscalateIntent(d, r.Status, r.Overall)
	if err := decisions.AssertNotLooser(e); err != nil {
		s.log().Error("intent escalation assert failed; storing the Rego decision", "action_id", env.ActionID, "err", err)
		return
	}
	ev.derived = e
}
