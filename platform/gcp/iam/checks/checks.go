package checks

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ExecNamespace is the namespace whose principals must never receive a grant.
const ExecNamespace = "agent-exec"

// Rule identifiers reported in Violation.Rule.
const (
	RuleExecGrant          = "EXEC_PRINCIPAL_GRANT"
	RuleWholePoolGrant     = "WHOLE_POOL_GRANT"
	RuleUnresolvedSelector = "UNRESOLVED_WORKLOAD_PRINCIPAL"
	RuleCrossEnvPool       = "CROSS_ENV_POOL"
)

// Env identifies the environment whose policies are checked.
type Env struct {
	// ProjectID of this environment; its pool is ProjectID + ".svc.id.goog".
	ProjectID string
	// ProjectNumber is optional; when set, principal URIs on a GKE pool must use it.
	ProjectNumber string
	// CrossEnv lists the only grants to another environment's principals that
	// pass (TASK-06 3.3, #97), and only for policies read with CheckAsset.
	// Build it with CrossEnvAllowlist.
	CrossEnv []CrossEnvGrant
}

// WorkloadPool returns the GKE workload identity pool of the environment.
func (e Env) WorkloadPool() string { return e.ProjectID + ".svc.id.goog" }

// Violation is one forbidden member found in a policy.
type Violation struct {
	Rule   string
	Role   string
	Member string
	Detail string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s role=%s member=%s: %s", v.Rule, v.Role, v.Member, v.Detail)
}

const (
	iamPrefix         = "iam.googleapis.com/"
	principalPrefix   = "principal://" + iamPrefix
	principalSetPfx   = "principalSet://" + iamPrefix
	serviceAcctPrefix = "serviceAccount:"
	gkePoolSuffix     = ".svc.id.goog"
)

var poolRef = regexp.MustCompile(`(?i)[a-z0-9][a-z0-9-]*\.svc\.id\.goog`)

// Check returns every violation in the policy for the given environment.
// No cross-environment grant is exempt because the resource is unknown.
func Check(p *Policy, env Env) ([]Violation, error) { return checkResource(p, env, "", "") }

// checkResource is Check for the policy of an exported resource. A member
// whose resource, asset type, role and exact member string match env.CrossEnv
// in an unconditioned binding is exempt from CROSS_ENV_POOL only; every other
// rule still applies to it.
func checkResource(p *Policy, env Env, resource, assetType string) ([]Violation, error) {
	if env.ProjectID == "" {
		return nil, errors.New("project ID is required")
	}
	own := strings.ToLower(env.WorkloadPool())
	var out []Violation
	for _, b := range p.Bindings {
		for _, raw := range b.Members {
			m := normalizeMember(raw)
			exempt := crossEnvExempt(env, resource, assetType, b, raw)
			for _, v := range checkMember(m, env) {
				if exempt && v.Rule == RuleCrossEnvPool {
					continue
				}
				v.Role, v.Member = b.Role, raw
				out = append(out, v)
			}
			if exempt {
				continue
			}
			for _, ref := range foreignPools(raw, own) {
				out = append(out, Violation{RuleCrossEnvPool, b.Role, raw, "references workload pool " + ref})
			}
		}
		if b.Condition != nil {
			text := b.Condition.Title + "\n" + b.Condition.Description + "\n" + b.Condition.Expression
			for _, ref := range foreignPools(text, own) {
				out = append(out, Violation{RuleCrossEnvPool, b.Role, "(condition)", "condition references workload pool " + ref})
			}
		}
	}
	return out, nil
}

// normalizeMember strips the deleted: prefix and ?uid= suffix IAM adds to
// members whose identity was deleted; the grant is still reported.
func normalizeMember(m string) string {
	m = strings.TrimPrefix(m, "deleted:")
	if i := strings.Index(m, "?uid="); i >= 0 {
		m = m[:i]
	}
	return m
}

func foreignPools(s, own string) []string {
	var refs []string
	for _, ref := range poolRef.FindAllString(s, -1) {
		if strings.ToLower(ref) != own {
			refs = append(refs, ref)
		}
	}
	return refs
}

func checkMember(m string, env Env) []Violation {
	switch {
	case strings.HasPrefix(m, principalPrefix):
		return checkWorkloadURI(strings.TrimPrefix(m, principalPrefix), false, env)
	case strings.HasPrefix(m, principalSetPfx):
		return checkWorkloadURI(strings.TrimPrefix(m, principalSetPfx), true, env)
	case strings.HasPrefix(m, serviceAcctPrefix) && strings.Contains(m, "["):
		return checkLegacyMember(strings.TrimPrefix(m, serviceAcctPrefix))
	}
	return nil
}

// checkWorkloadURI handles
// projects/NUMBER/locations/global/workloadIdentityPools/POOL/SELECTOR.
func checkWorkloadURI(rest string, set bool, env Env) []Violation {
	parts := strings.SplitN(rest, "/", 7)
	if len(parts) < 6 || parts[0] != "projects" || parts[4] != "workloadIdentityPools" {
		return nil // workforce pools and other identity sources are out of scope
	}
	number, pool := parts[1], parts[5]
	if !strings.HasSuffix(strings.ToLower(pool), gkePoolSuffix) {
		return nil // not a GKE workload pool
	}
	var out []Violation
	if env.ProjectNumber != "" && number != env.ProjectNumber {
		out = append(out, Violation{Rule: RuleCrossEnvPool, Detail: "principal uses project number " + number})
	}
	selector := ""
	if len(parts) == 7 {
		selector = parts[6]
	}
	if set {
		return append(out, checkPrincipalSet(selector)...)
	}
	return append(out, checkPrincipal(selector)...)
}

func checkPrincipal(selector string) []Violation {
	if ns, _, ok := parseSubject(selector); ok {
		if ns == ExecNamespace {
			return []Violation{{Rule: RuleExecGrant, Detail: "grant to a KSA in " + ExecNamespace}}
		}
		return nil
	}
	// kubernetes.serviceaccount.uid/UID and other selectors cannot be mapped to a
	// namespace from the policy alone, so they fail closed.
	return []Violation{{Rule: RuleUnresolvedSelector, Detail: "principal selector does not name a namespace: " + selector}}
}

func checkPrincipalSet(selector string) []Violation {
	switch {
	case selector == "*":
		return []Violation{{Rule: RuleWholePoolGrant, Detail: "grant to every identity in the workload pool"}}
	case strings.HasPrefix(selector, "kubernetes.cluster/"):
		return []Violation{{Rule: RuleWholePoolGrant, Detail: "grant to every workload in a cluster, including " + ExecNamespace}}
	case strings.HasPrefix(selector, "namespace/"):
		if strings.TrimPrefix(selector, "namespace/") == ExecNamespace {
			return []Violation{{Rule: RuleExecGrant, Detail: "grant to every KSA in " + ExecNamespace}}
		}
		return nil
	}
	return []Violation{{Rule: RuleUnresolvedSelector, Detail: "principalSet selector does not name a namespace: " + selector}}
}

// parseSubject parses subject/ns/NAMESPACE/sa/KSA.
func parseSubject(selector string) (ns, ksa string, ok bool) {
	p := strings.Split(selector, "/")
	if len(p) != 5 || p[0] != "subject" || p[1] != "ns" || p[3] != "sa" || p[2] == "" || p[4] == "" {
		return "", "", false
	}
	return p[2], p[4], true
}

// checkLegacyMember handles serviceAccount:POOL[NAMESPACE/KSA].
func checkLegacyMember(s string) []Violation {
	open := strings.Index(s, "[")
	if !strings.HasSuffix(strings.ToLower(s[:open]), gkePoolSuffix) {
		return nil
	}
	inner := strings.TrimSuffix(s[open+1:], "]")
	ns, _, found := strings.Cut(inner, "/")
	if !found || !strings.HasSuffix(s, "]") {
		return []Violation{{Rule: RuleUnresolvedSelector, Detail: "malformed workload identity member"}}
	}
	if ns == ExecNamespace {
		return []Violation{{Rule: RuleExecGrant, Detail: "grant to a KSA in " + ExecNamespace}}
	}
	return nil
}
