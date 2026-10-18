package sessions

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/policyloader"
)

// SnapshotPolicy adapts the existing signature-verifying bundle loader to the
// session and approval PolicySource (TASK-03 standing rule/session budgets).
// The installer still has to wire an authorized loader; this adapter neither
// fetches a policy itself nor creates an initial policy or epoch.
type SnapshotPolicy struct {
	Loader      *policyloader.Loader
	Active      ActivePolicyReader
	Environment string
	// DB serves Policy(ctx) callers that hold no transaction (session
	// creation). Transactional callers use PolicyIn with their own tx.
	DB Querier
}

// ActiveBundle is the existing COMMON active_policy tuple needed to identify
// the activated snapshot. It is read from trusted server state, not a caller.
type ActiveBundle struct {
	ScopeID             string
	BundleID            string
	ArtifactDigest      string
	ExpectedOPARevision string
	Epoch               int64
}

// ActivePolicyReader reads the environment's active_policy row, bundle and
// epoch together, through the caller's Querier. Implementations must use one
// plain SELECT: identity_app has SELECT only, so FOR SHARE fails with 42501,
// and a second pool connection inside a transaction can exhaust the pool.
// A desired_bundle reader is not a substitute. This port does not create or
// activate a policy.
type ActivePolicyReader interface {
	ActivePolicy(ctx context.Context, q Querier, environment string) (ActiveBundle, error)
}

var (
	_ PolicySource   = SnapshotPolicy{}
	_ TxPolicySource = SnapshotPolicy{}
)

// Policy reads the active row through s.DB, for callers without a transaction.
func (s SnapshotPolicy) Policy(ctx context.Context) (Policy, error) {
	if s.DB == nil {
		return Policy{}, ErrPolicyUnavailable
	}
	return s.PolicyIn(ctx, s.DB)
}

// PolicyIn reads the active row through q (normally the caller's tx) and
// returns the matched snapshot with that row's epoch.
func (s SnapshotPolicy) PolicyIn(ctx context.Context, q Querier) (Policy, error) {
	if err := ctx.Err(); err != nil {
		return Policy{}, err
	}
	if s.Loader == nil || s.Active == nil || s.Environment == "" || q == nil {
		return Policy{}, ErrPolicyUnavailable
	}
	// Capture once: a concurrent reload must not mix a catalog from one
	// signed bundle with standing-rule budgets from another.
	snapshot := s.Loader.Current()
	if snapshot == nil {
		return Policy{}, ErrPolicyUnavailable
	}
	active, err := s.Active.ActivePolicy(ctx, q, s.Environment)
	if err != nil {
		return Policy{}, fmt.Errorf("%w: active policy: %v", ErrPolicyUnavailable, err)
	}
	if active.ScopeID == "" || active.BundleID == "" {
		return Policy{}, fmt.Errorf("%w: no active policy row", ErrPolicyUnavailable)
	}
	if active.ScopeID != s.Environment || active.BundleID != snapshot.BundleID() ||
		active.ArtifactDigest != snapshot.ArtifactDigest() || active.ExpectedOPARevision != snapshot.Revision() {
		return Policy{}, ErrPolicyVersionMismatch
	}
	if active.Epoch <= 0 {
		return Policy{}, fmt.Errorf("%w: active policy has no epoch", ErrPolicyUnavailable)
	}
	catalog, err := snapshot.Catalog()
	if err != nil {
		return Policy{}, fmt.Errorf("%w: catalog: %v", ErrPolicyUnavailable, err)
	}
	data, err := snapshot.Data()
	if err != nil {
		return Policy{}, fmt.Errorf("%w: bundle data: %v", ErrPolicyUnavailable, err)
	}
	raw, err := json.Marshal(data["standing_rules"])
	if err != nil {
		return Policy{}, fmt.Errorf("%w: standing rules: %v", ErrPolicyUnavailable, err)
	}
	// Consume only the identity fields. Limits, profile, disclosure_fields and
	// data_profile belong to the existing full rule; they are not unknown
	// caller fields and must not be rejected or used to widen session scope.
	var rules map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rules); err != nil || rules == nil {
		return Policy{}, fmt.Errorf("%w: invalid standing_rules object", ErrPolicyUnavailable)
	}
	result := Policy{Catalog: catalog, StandingRules: make(map[string]StandingRule, len(rules)), Epoch: active.Epoch}
	for id, fields := range rules {
		var rule StandingRule
		var budget *int
		// Decode exact keys individually: encoding/json's case-insensitive
		// struct matching must not turn an unknown key into a budget field.
		for key, value := range map[string]any{
			"standing_rule_id": &rule.StandingRuleID,
			"session_kind":     &rule.SessionKind,
			"operation_ids":    &rule.OperationIDs,
			"target_pattern":   &rule.TargetPattern,
			"session_budget":   &budget,
		} {
			if err := json.Unmarshal(fields[key], value); err != nil {
				return Policy{}, fmt.Errorf("%w: invalid standing-rule field", ErrPolicyUnavailable)
			}
		}
		if id == "" || rule.StandingRuleID != id ||
			(rule.SessionKind != "user" && rule.SessionKind != "service") ||
			len(rule.OperationIDs) == 0 || rule.TargetPattern == "" || budget == nil || *budget < 0 || int64(*budget) > canonical.MaxSafeInteger {
			return Policy{}, fmt.Errorf("%w: invalid standing rule", ErrPolicyUnavailable)
		}
		if _, err := path.Match(rule.TargetPattern, ""); err != nil {
			return Policy{}, fmt.Errorf("%w: invalid target pattern", ErrPolicyUnavailable)
		}
		for _, operation := range rule.OperationIDs {
			if operation == "" {
				return Policy{}, fmt.Errorf("%w: empty standing-rule operation", ErrPolicyUnavailable)
			}
		}
		rule.SessionBudget = *budget
		result.StandingRules[id] = rule
	}
	return result, nil
}
