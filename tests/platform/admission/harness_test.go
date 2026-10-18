package admission

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	admv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/apiserver/pkg/admission"
	plugincel "k8s.io/apiserver/pkg/admission/plugin/cel"
	"k8s.io/apiserver/pkg/admission/plugin/policy/validating"
	"k8s.io/apiserver/pkg/admission/plugin/webhook/matchconditions"
	celconfig "k8s.io/apiserver/pkg/apis/cel"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/cel/environment"
	psapi "k8s.io/pod-security-admission/api"
	pspolicy "k8s.io/pod-security-admission/policy"
)

// minCompat is the lowest Kubernetes minor the lock allows
// (gke.kubernetes_minor >= 1.33, TASK-01 4). Policies are compiled and
// evaluated with the CEL environment of that compatibility version.
var minCompat = version.MajorMinor(1, 33)

// cluster is an offline stand-in for the admission chain of one API server:
// the rendered Namespaces (PSA labels), the ValidatingAdmissionPolicies with
// their bindings, and the param ConfigMaps.
type cluster struct {
	namespaces map[string]*corev1.Namespace
	policies   map[string]*admv1.ValidatingAdmissionPolicy
	validators map[string]validating.Validator
	bindings   []*admv1.ValidatingAdmissionPolicyBinding
	configMaps map[string]*corev1.ConfigMap
	psa        pspolicy.Evaluator
}

func newCluster(t *testing.T, values map[string]string) *cluster {
	t.Helper()
	c := &cluster{
		namespaces: map[string]*corev1.Namespace{},
		policies:   map[string]*admv1.ValidatingAdmissionPolicy{},
		validators: map[string]validating.Validator{},
		configMaps: map[string]*corev1.ConfigMap{},
	}
	for _, d := range loadAll(t, values) {
		switch o := d.obj.(type) {
		case *corev1.Namespace:
			// The API server adds this label to every Namespace.
			if o.Labels == nil {
				o.Labels = map[string]string{}
			}
			o.Labels[corev1.LabelMetadataName] = o.Name
			c.namespaces[o.Name] = o
		case *admv1.ValidatingAdmissionPolicy:
			c.policies[o.Name] = o
			v := compilePolicy(o, environment.MustBaseEnvSet(minCompat))
			if err := v.CompileError(); err != nil {
				t.Fatalf("policy %s: compile: %v", o.Name, err)
			}
			c.validators[o.Name] = v
		case *admv1.ValidatingAdmissionPolicyBinding:
			c.bindings = append(c.bindings, o)
		case *corev1.ConfigMap:
			c.configMaps[o.Namespace+"/"+o.Name] = o
		}
	}
	for _, b := range c.bindings {
		if _, ok := c.policies[b.Spec.PolicyName]; !ok {
			t.Fatalf("binding %s references missing policy %s", b.Name, b.Spec.PolicyName)
		}
	}
	for name := range c.policies {
		found := false
		for _, b := range c.bindings {
			found = found || b.Spec.PolicyName == name
		}
		if !found {
			t.Fatalf("policy %s has no binding", name)
		}
	}
	e, err := pspolicy.NewEvaluator(pspolicy.DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.psa = e
	return c
}

// compilePolicy mirrors the unexported compilePolicy in
// k8s.io/apiserver/pkg/admission/plugin/policy/validating/plugin.go, using
// the given CEL environment instead of the library's default version.
func compilePolicy(p *admv1.ValidatingAdmissionPolicy, envSet *environment.EnvSet) validating.Validator {
	hasParam := p.Spec.ParamKind != nil
	optionalVars := plugincel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: true}
	exprVars := plugincel.OptionalVariableDeclarations{HasParams: hasParam, HasAuthorizer: false}
	compiler, err := plugincel.NewCompositedCompiler(envSet)
	if err != nil {
		return validating.NewValidator(nil, nil, nil, nil, p.Spec.FailurePolicy, err)
	}
	vars := make([]plugincel.NamedExpressionAccessor, len(p.Spec.Variables))
	for i, v := range p.Spec.Variables {
		vars[i] = &validating.Variable{Name: v.Name, Expression: v.Expression}
	}
	compiler.CompileAndStoreVariables(vars, optionalVars, environment.StoredExpressions)
	var matcher matchconditions.Matcher
	if len(p.Spec.MatchConditions) > 0 {
		acc := make([]plugincel.ExpressionAccessor, len(p.Spec.MatchConditions))
		for i := range p.Spec.MatchConditions {
			acc[i] = (*matchconditions.MatchCondition)(&p.Spec.MatchConditions[i])
		}
		matcher = matchconditions.NewMatcher(compiler.CompileCondition(acc, optionalVars, environment.StoredExpressions),
			p.Spec.FailurePolicy, "policy", "validate", p.Name)
	}
	validations := make([]plugincel.ExpressionAccessor, len(p.Spec.Validations))
	messages := make([]plugincel.ExpressionAccessor, len(p.Spec.Validations))
	for i, v := range p.Spec.Validations {
		validations[i] = &validating.ValidationCondition{Expression: v.Expression, Message: v.Message, Reason: v.Reason}
		if v.MessageExpression != "" {
			messages[i] = &validating.MessageExpressionCondition{MessageExpression: v.MessageExpression}
		}
	}
	return validating.NewValidator(
		compiler.CompileCondition(validations, optionalVars, environment.StoredExpressions),
		matcher,
		compiler.CompileCondition(nil, optionalVars, environment.StoredExpressions),
		compiler.CompileCondition(messages, exprVars, environment.StoredExpressions),
		p.Spec.FailurePolicy,
		nil,
	)
}

type req struct {
	op          admission.Operation
	namespace   string
	name        string
	resource    string // "pods", "nodes" or "jobs" (batch)
	subresource string
	obj, old    runtime.Object
	username    string
}

// result lists every reason the request would be refused: PSA violations as
// "PSA:<check>" and VAP denials as "<policy>:<message>". VAP evaluation
// errors (failurePolicy Fail) appear as "<policy>:ERROR:<detail>".
type result []string

func (r result) has(s string) bool {
	for _, x := range r {
		if x == s {
			return true
		}
	}
	return false
}

func (c *cluster) admit(t *testing.T, r req) result {
	t.Helper()
	var out result
	gvr := schema.GroupVersionResource{Version: "v1", Resource: r.resource}
	var gvk schema.GroupVersionKind
	switch r.resource {
	case "pods":
		gvk = schema.GroupVersionKind{Version: "v1", Kind: "Pod"}
		out = append(out, c.podSecurity(t, r)...)
	case "nodes":
		gvk = schema.GroupVersionKind{Version: "v1", Kind: "Node"}
	case "jobs":
		gvr.Group = "batch"
		gvk = schema.GroupVersionKind{Group: "batch", Version: "v1", Kind: "Job"}
	default:
		t.Fatalf("unsupported resource %s", r.resource)
	}
	username := r.username
	if username == "" {
		username = "platform-test"
	}
	attrs := admission.NewAttributesRecord(r.obj, r.old, gvk, r.namespace, r.name, gvr, r.subresource, r.op, nil, false,
		&user.DefaultInfo{Name: username})
	va := &admission.VersionedAttributes{
		Attributes:         attrs,
		VersionedKind:      gvk,
		VersionedObject:    admission.NewLazyObject(r.obj),
		VersionedOldObject: admission.NewLazyObject(r.old),
	}
	ns := c.namespaces[r.namespace]
	for _, b := range c.bindings {
		p := c.policies[b.Spec.PolicyName]
		if !matchesRules(p.Spec.MatchConstraints, r) || !c.matchesNamespace(t, b.Spec.MatchResources, r.namespace) {
			continue
		}
		var params runtime.Object
		if b.Spec.ParamRef != nil {
			cm, ok := c.configMaps[b.Spec.ParamRef.Namespace+"/"+b.Spec.ParamRef.Name]
			if !ok {
				out = append(out, p.Name+":PARAM_NOT_FOUND")
				continue
			}
			params = cm
		}
		res := c.validators[p.Name].Validate(context.Background(), gvr, va, params, ns, celconfig.RuntimeCELCostBudget, nil)
		for _, d := range res.Decisions {
			switch {
			case d.Evaluation == validating.EvalError:
				out = append(out, p.Name+":ERROR:"+d.Message)
			case d.Action == validating.ActionDeny:
				out = append(out, p.Name+":"+d.Message)
			}
		}
	}
	sort.Strings(out)
	return out
}

// matchesRules implements the subset of matchConstraints used here:
// resourceRules on the core group with operations and resource/subresource.
func matchesRules(m *admv1.MatchResources, r req) bool {
	full := r.resource
	if r.subresource != "" {
		full += "/" + r.subresource
	}
	for _, rule := range m.ResourceRules {
		opOK := false
		for _, op := range rule.Operations {
			opOK = opOK || string(op) == string(r.op) || op == admv1.OperationAll
		}
		resOK := false
		for _, res := range rule.Resources {
			resOK = resOK || res == full
		}
		if opOK && resOK {
			return true
		}
	}
	return false
}

func (c *cluster) matchesNamespace(t *testing.T, m *admv1.MatchResources, namespace string) bool {
	t.Helper()
	// namespaceSelector does not constrain cluster-scoped objects.
	if m == nil || m.NamespaceSelector == nil || namespace == "" {
		return true
	}
	sel, err := metav1.LabelSelectorAsSelector(m.NamespaceSelector)
	if err != nil {
		t.Fatal(err)
	}
	ns, ok := c.namespaces[namespace]
	if !ok {
		t.Fatalf("unknown namespace %s", namespace)
	}
	return sel.Matches(labels.Set(ns.Labels))
}

// podSecurity evaluates the Namespace's enforce level with the PSA library.
// PSA does not evaluate pods/ephemeralcontainers UPDATE checks on unchanged
// specs the same way the plugin does; only CREATE is evaluated here.
func (c *cluster) podSecurity(t *testing.T, r req) []string {
	t.Helper()
	if r.op != admission.Create || r.subresource != "" {
		return nil
	}
	ns := c.namespaces[r.namespace]
	lvl, err := psapi.ParseLevel(ns.Labels[psapi.EnforceLevelLabel])
	if err != nil {
		t.Fatal(err)
	}
	ver, err := psapi.ParseVersion(ns.Labels[psapi.EnforceVersionLabel])
	if err != nil {
		t.Fatal(err)
	}
	pod := r.obj.(*corev1.Pod)
	var out []string
	for _, cr := range c.psa.EvaluatePod(psapi.LevelVersion{Level: lvl, Version: ver}, &pod.ObjectMeta, &pod.Spec) {
		if !cr.Allowed {
			out = append(out, "PSA:"+cr.ForbiddenReason)
		}
	}
	return out
}

func expectExactly(t *testing.T, got result, want ...string) {
	t.Helper()
	w := append(result(nil), want...)
	sort.Strings(w)
	if strings.Join(got, "\n") != strings.Join(w, "\n") {
		t.Errorf("admission result:\n  got  %s\n  want %s", fmtResult(got), fmtResult(w))
	}
}

func fmtResult(r result) string {
	if len(r) == 0 {
		return "[allowed]"
	}
	return fmt.Sprintf("%q", []string(r))
}

// Policies must also compile in the CEL environment of the library's default
// compatibility version (newer than the lock minimum).
func TestPoliciesCompileAtDefaultCompatibility(t *testing.T) {
	envSet := environment.MustBaseEnvSet(environment.DefaultCompatibilityVersion())
	for _, d := range loadAll(t, sampleRender()) {
		if p, ok := d.obj.(*admv1.ValidatingAdmissionPolicy); ok {
			if err := compilePolicy(p, envSet).CompileError(); err != nil {
				t.Errorf("policy %s: %v", p.Name, err)
			}
		}
	}
}
