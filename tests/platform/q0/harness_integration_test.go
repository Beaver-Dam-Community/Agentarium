//go:build integration

// Q0 probes against a real cluster. Run with:
//
//	KUBECONFIG=... Q0_RUN_ID=... Q0_OUT_DIR=evidence/gcp/runs \
//	  go test -tags integration -run TestQ0 -v ./tests/platform/q0/
//
// Inputs (each probe group is skipped, and its rows stay not_run, when its
// inputs are absent):
//
//	KUBECONFIG                platform test account; needs serviceaccounts/token create
//	                          for the probed SAs and dry-run create/patch.
//	Q0_RUNTIME_POD_JSON       known-good agent-runtime Pod manifest (rendered from deploy/)
//	Q0_PROBE_POD_JSON         known-good probe-runner Pod manifest
//	Q0_FIXTURE_POD_JSON       known-good start-fixture Pod manifest
//	Q0_STIMULI_JSONL          Stimulus lines written by the probe runner
//	Q0_EVENTS_JSONL           ObservedEvent lines exported from audit.kernel_events
//	Q0_INJECTION_JSONL        InjectionEvidence lines from the 3.4.1 injection runs
//	Q0_ATTESTATIONS_JSONL     Attestation lines for node-level checks
//	Q0_RUN_ID, Q0_IMPLEMENTATION_COMMIT, Q0_IMAGE_DIGEST, Q0_ENVIRONMENT_MANIFEST
//
// Placement and node-readiness permission probes use dryRun=All only; the
// API server runs admission (PSA, VAP) without persisting anything.
package q0

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	roleLabel     = "node-restriction.kubernetes.io/agentarium-role"
	poolSelector  = roleLabel + " in (exec,control)"
	startTaintKey = "agentarium.io/observe-not-ready"
	scopeInvalid  = "NODE_READINESS_SCOPE_INVALID"
	nameLabel     = "app.kubernetes.io/name"
)

var dryRun = []string{metav1.DryRunAll}

func TestQ0(t *testing.T) {
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("KUBECONFIG not set: Q0 probes need a real cluster")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	rows := Catalog()
	var probes []ProbeRecord
	var latencies []time.Duration

	t.Run("compatibility", func(t *testing.T) { probeCompatibility(ctx, t, client, rows) })
	t.Run("attestations", func(t *testing.T) { applyAttestations(t, rows) })
	t.Run("placement", func(t *testing.T) { probePlacement(ctx, t, client, rows) })
	t.Run("permissions", func(t *testing.T) { probePermissions(ctx, t, cfg, client, rows) })
	t.Run("runtime_observation", func(t *testing.T) { probes = append(probes, probeRuntimeObservation(t, rows)...) })
	t.Run("startup_guard_injection", func(t *testing.T) { latencies = probeInjection(t, rows) })

	runID := os.Getenv("Q0_RUN_ID")
	if runID == "" {
		runID = fmt.Sprintf("q0-local-%d", time.Now().Unix())
	}
	rep := BuildReport(RunMeta{
		ImplementationCommit: envPtr("Q0_IMPLEMENTATION_COMMIT"),
		ImageDigest:          envPtr("Q0_IMAGE_DIGEST"),
		EnvironmentManifest:  envPtr("Q0_ENVIRONMENT_MANIFEST"),
		RunID:                &runID,
	}, rows, probes, latencies)

	out := os.Getenv("Q0_OUT_DIR")
	if out == "" {
		out = t.TempDir()
	}
	dir := filepath.Join(out, runID)
	if err := rep.Write(dir); err != nil {
		t.Fatal(err)
	}
	inv := rep.Summary.Invariants
	t.Logf("Q0 run %s written to %s: status=%s", runID, dir, rep.Summary.Status)
	if inv != nil {
		t.Logf("platform gate=%s failed=%v pending=%v", inv.PlatformGate.Status, inv.PlatformGate.FailedRows, inv.PlatformGate.PendingRows)
		t.Logf("startup_guard_gate active=%v startup_capture=%s", inv.StartupGuardOn, *rep.Summary.StartupCapture)
		if inv.PlatformGate.Status == StatusFail {
			t.Errorf("MVP platform gate failed: unsupported rows %v", inv.PlatformGate.FailedRows)
		}
	}
}

func envPtr(k string) *string {
	if v := os.Getenv(k); v != "" {
		return &v
	}
	return nil
}

func readJSONL[T any](t *testing.T, env string) ([]T, bool) {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("%s: %v", env, err)
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var v T
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil {
			t.Fatalf("%s line %d: %v", env, n, err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("%s: %v", env, err)
	}
	return out, true
}

func readPod(t *testing.T, env string) (*corev1.Pod, bool) {
	t.Helper()
	path := os.Getenv(env)
	if path == "" {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v", env, err)
	}
	var p corev1.Pod
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatalf("%s: %v", env, err)
	}
	p.Name, p.GenerateName, p.ResourceVersion, p.UID = "", "q0-", "", ""
	return &p, true
}

func setRow(rows []Row, id string, o Outcome, refs []string, lim ...string) {
	r := FindRow(rows, id)
	r.Outcome = o
	r.EvidenceRefs = append(r.EvidenceRefs, refs...)
	r.Limitations = append(r.Limitations, lim...)
}

// ---- compatibility ----

func probeCompatibility(ctx context.Context, t *testing.T, c kubernetes.Interface, rows []Row) {
	nodes, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: poolSelector})
	if err != nil {
		setRow(rows, "compat.node_inventory", OutcomeUnknown, nil, "node list failed: "+err.Error())
		return
	}
	if len(nodes.Items) == 0 {
		setRow(rows, "compat.node_inventory", OutcomeUnknown, nil, "no exec/control pool nodes found")
		return
	}
	out := OutcomePass
	var refs []string
	for _, n := range nodes.Items {
		ni := n.Status.NodeInfo
		t.Logf("node %s pool=%s os=%q kernel=%s runtime=%s kubelet=%s", n.Name, n.Labels[roleLabel],
			ni.OSImage, ni.KernelVersion, ni.ContainerRuntimeVersion, ni.KubeletVersion)
		refs = append(refs, fmt.Sprintf("k8s:nodes/%s@%s", n.Name, n.ResourceVersion))
		if ni.KernelVersion == "" || !strings.HasPrefix(ni.ContainerRuntimeVersion, "containerd://") ||
			!strings.Contains(ni.OSImage, "Container-Optimized OS") {
			out = OutcomeFail
		}
	}
	setRow(rows, "compat.node_inventory", out, refs,
		"kernel/runtime versions come from kubelet self-report (Node status)")
}

func applyAttestations(t *testing.T, rows []Row) {
	atts, ok := readJSONL[Attestation](t, "Q0_ATTESTATIONS_JSONL")
	if !ok {
		t.Skip("Q0_ATTESTATIONS_JSONL not set: node-level compatibility rows stay not_run")
	}
	for _, a := range atts {
		r := FindRow(rows, a.RowID)
		if r == nil || r.Area == AreaRuntimeObservation || r.Area == AreaStartupGuard {
			t.Errorf("attestation for %q is not accepted; measured rows come from probe data", a.RowID)
			continue
		}
		ApplyAttestation(r, a)
	}
}

// ---- placement ----

func isRejected(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsInvalid(err)
}

func dryRunCreate(ctx context.Context, c kubernetes.Interface, p *corev1.Pod) error {
	ns := p.Namespace
	if ns == "" {
		ns = "agent-exec"
	}
	_, err := c.CoreV1().Pods(ns).Create(ctx, p, metav1.CreateOptions{DryRun: dryRun})
	return err
}

func probePlacement(ctx context.Context, t *testing.T, c kubernetes.Interface, rows []Row) {
	probeExecPodsPlacement(ctx, t, c, rows)

	runtimePod, ok := readPod(t, "Q0_RUNTIME_POD_JSON")
	if !ok {
		t.Skip("Q0_RUNTIME_POD_JSON not set: admission placement rows stay not_run")
	}
	if err := dryRunCreate(ctx, c, runtimePod); err != nil {
		lim := "control: known-good runtime Pod was rejected, rejections cannot be attributed: " + err.Error()
		for _, id := range []string{"placement.control_pool_selector", "placement.host_network", "placement.privileged",
			"placement.runtime_class", "placement.start_taint_toleration", "placement.node_name"} {
			setRow(rows, id, OutcomeUnknown, nil, lim)
		}
		return
	}

	nodeName := ""
	if nodes, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: roleLabel + "=exec"}); err == nil && len(nodes.Items) > 0 {
		nodeName = nodes.Items[0].Name
	}
	mutations := map[string]func(p *corev1.Pod){
		"placement.control_pool_selector": func(p *corev1.Pod) {
			if p.Spec.NodeSelector == nil {
				p.Spec.NodeSelector = map[string]string{}
			}
			p.Spec.NodeSelector[roleLabel] = "control"
		},
		"placement.host_network": func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"placement.privileged": func(p *corev1.Pod) {
			priv := true
			if p.Spec.Containers[0].SecurityContext == nil {
				p.Spec.Containers[0].SecurityContext = &corev1.SecurityContext{}
			}
			p.Spec.Containers[0].SecurityContext.Privileged = &priv
		},
		"placement.runtime_class": func(p *corev1.Pod) {
			rc := "q0-unapproved"
			p.Spec.RuntimeClassName = &rc
		},
		"placement.start_taint_toleration": func(p *corev1.Pod) {
			p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{
				Key: startTaintKey, Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule})
		},
		"placement.node_name": func(p *corev1.Pod) {
			if nodeName == "" {
				p.Spec.NodeName = "q0-nonexistent-node"
			} else {
				p.Spec.NodeName = nodeName
			}
		},
	}
	for id, mutate := range mutations {
		p := runtimePod.DeepCopy()
		mutate(p)
		recordRejection(t, rows, id, dryRunCreate(ctx, c, p))
	}

	probePod, okProbe := readPod(t, "Q0_PROBE_POD_JSON")
	fixturePod, okFixture := readPod(t, "Q0_FIXTURE_POD_JSON")
	if okProbe {
		if err := dryRunCreate(ctx, c, probePod); err != nil {
			setRow(rows, "placement.profile_runtime_label_probe_image", OutcomeUnknown, nil, "control probe Pod rejected: "+err.Error())
			setRow(rows, "placement.profile_probe_label_runtime_sa", OutcomeUnknown, nil, "control probe Pod rejected: "+err.Error())
		} else {
			p := runtimePod.DeepCopy()
			p.Spec.Containers[0].Image = probePod.Spec.Containers[0].Image
			recordRejection(t, rows, "placement.profile_runtime_label_probe_image", dryRunCreate(ctx, c, p))
			p = probePod.DeepCopy()
			p.Spec.ServiceAccountName = "agent-runtime"
			recordRejection(t, rows, "placement.profile_probe_label_runtime_sa", dryRunCreate(ctx, c, p))
		}
	}
	if okFixture {
		if err := dryRunCreate(ctx, c, fixturePod); err != nil {
			setRow(rows, "placement.profile_fixture_restart_always", OutcomeUnknown, nil, "control fixture Pod rejected: "+err.Error())
		} else {
			p := fixturePod.DeepCopy()
			p.Spec.RestartPolicy = corev1.RestartPolicyAlways
			recordRejection(t, rows, "placement.profile_fixture_restart_always", dryRunCreate(ctx, c, p))
		}
	}
}

func recordRejection(t *testing.T, rows []Row, id string, err error) {
	switch {
	case err == nil:
		setRow(rows, id, OutcomeFail, nil, "dry-run create was admitted")
	case isRejected(err):
		t.Logf("%s rejected: %v", id, err)
		setRow(rows, id, OutcomePass, []string{"k8s:dry-run:" + id})
	default:
		setRow(rows, id, OutcomeUnknown, nil, "unexpected error: "+err.Error())
	}
}

// probeExecPodsPlacement compares actual agent-exec Pods with their nodes.
// probe-runner may run on nodes with the start taint (TASK-01 3.2).
func probeExecPodsPlacement(ctx context.Context, t *testing.T, c kubernetes.Interface, rows []Row) {
	const id = "placement.no_exec_pod_on_control_or_unready"
	pods, err := c.CoreV1().Pods("agent-exec").List(ctx, metav1.ListOptions{})
	if err != nil {
		setRow(rows, id, OutcomeUnknown, nil, "pod list failed: "+err.Error())
		return
	}
	checked, out := 0, OutcomePass
	var refs []string
	for _, p := range pods.Items {
		if p.Spec.NodeName == "" {
			continue
		}
		n, err := c.CoreV1().Nodes().Get(ctx, p.Spec.NodeName, metav1.GetOptions{})
		if err != nil {
			continue
		}
		checked++
		tainted := false
		for _, tn := range n.Spec.Taints {
			if tn.Key == startTaintKey {
				tainted = true
			}
		}
		if n.Labels[roleLabel] != "exec" || (tainted && p.Labels[nameLabel] != "probe-runner") {
			out = OutcomeFail
			refs = append(refs, fmt.Sprintf("k8s:pods/agent-exec/%s@%s", p.Name, n.Name))
			t.Logf("exec Pod %s on node %s (pool=%s, start taint=%v)", p.Name, n.Name, n.Labels[roleLabel], tainted)
		}
	}
	if checked == 0 {
		setRow(rows, id, OutcomeUnknown, nil, "no scheduled agent-exec Pods to compare")
		return
	}
	setRow(rows, id, out, refs)
}

// ---- permissions ----

func saClient(ctx context.Context, admin kubernetes.Interface, base *rest.Config, ns, sa string) (kubernetes.Interface, error) {
	exp := int64(600)
	tr, err := admin.CoreV1().ServiceAccounts(ns).CreateToken(ctx, sa,
		&authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &exp}}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}
	cfg := rest.AnonymousClientConfig(base)
	cfg.BearerToken = tr.Status.Token
	return kubernetes.NewForConfig(cfg)
}

type check struct {
	name  string
	allow bool // expected outcome: true = allowed, false = forbidden
	call  func(ctx context.Context, c kubernetes.Interface) error
}

func runChecks(ctx context.Context, t *testing.T, c kubernetes.Interface, checks []check) (Outcome, []string) {
	out := OutcomePass
	var lim []string
	for _, ch := range checks {
		err := ch.call(ctx, c)
		switch {
		case ch.allow && err == nil, !ch.allow && apierrors.IsForbidden(err):
			t.Logf("%s: as expected (%v)", ch.name, err)
		case ch.allow && apierrors.IsForbidden(err), !ch.allow && err == nil:
			out = OutcomeFail
			lim = append(lim, fmt.Sprintf("%s: unexpected result (err=%v)", ch.name, err))
		default:
			if out != OutcomeFail {
				out = OutcomeUnknown
			}
			lim = append(lim, fmt.Sprintf("%s: undetermined: %v", ch.name, err))
		}
	}
	return out, lim
}

func probePermissions(ctx context.Context, t *testing.T, base *rest.Config, admin kubernetes.Interface, rows []Row) {
	nodes, err := admin.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: poolSelector})
	if err != nil || len(nodes.Items) == 0 {
		t.Skipf("no pool nodes for permission probes: %v", err)
	}
	target := nodes.Items[0]
	for _, n := range nodes.Items {
		if hasTaint(&n, startTaintKey) {
			target = n
			break
		}
	}

	if c, err := saClient(ctx, admin, base, "agent-exec", "agent-runtime"); err != nil {
		setRow(rows, "permissions.exec_sa_no_management_api", OutcomeUnknown, nil, "token request failed: "+err.Error())
	} else {
		out, lim := runChecks(ctx, t, c, []check{
			{"list pods", false, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.CoreV1().Pods("agent-exec").List(ctx, metav1.ListOptions{})
				return err
			}},
			{"create pod", false, func(ctx context.Context, c kubernetes.Interface) error {
				p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{GenerateName: "q0-"},
					Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "q0.invalid/none"}}}}
				_, err := c.CoreV1().Pods("agent-exec").Create(ctx, p, metav1.CreateOptions{DryRun: dryRun})
				return err
			}},
			{"list secrets", false, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.CoreV1().Secrets("agent-exec").List(ctx, metav1.ListOptions{})
				return err
			}},
			{"list namespaces", false, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
				return err
			}},
			{"patch node", false, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.CoreV1().Nodes().Patch(ctx, target.Name, types.MergePatchType,
					[]byte(`{"metadata":{"labels":{"q0.agentarium.io/probe":"x"}}}`), metav1.PatchOptions{DryRun: dryRun})
				return err
			}},
			{"create rolebinding", false, func(ctx context.Context, c kubernetes.Interface) error {
				rb := &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{GenerateName: "q0-"},
					RoleRef:  rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
					Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "agent-runtime", Namespace: "agent-exec"}}}
				_, err := c.RbacV1().RoleBindings("agent-exec").Create(ctx, rb, metav1.CreateOptions{DryRun: dryRun})
				return err
			}},
		})
		setRow(rows, "permissions.exec_sa_no_management_api", out, []string{"k8s:token:agent-exec/agent-runtime"}, lim...)
	}

	if c, err := saClient(ctx, admin, base, "agent-observe", "drift-probe"); err != nil {
		setRow(rows, "permissions.drift_probe_read_only", OutcomeUnknown, nil, "token request failed: "+err.Error())
	} else {
		out, lim := runChecks(ctx, t, c, []check{
			{"list secrets", false, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.CoreV1().Secrets("agent-control").List(ctx, metav1.ListOptions{})
				return err
			}},
			{"create VAP", false, func(ctx context.Context, c kubernetes.Interface) error {
				vap := &admissionv1.ValidatingAdmissionPolicy{ObjectMeta: metav1.ObjectMeta{GenerateName: "q0-"},
					Spec: admissionv1.ValidatingAdmissionPolicySpec{
						Validations: []admissionv1.Validation{{Expression: "true"}},
						MatchConstraints: &admissionv1.MatchResources{ResourceRules: []admissionv1.NamedRuleWithOperations{{
							RuleWithOperations: admissionv1.RuleWithOperations{
								Operations: []admissionv1.OperationType{admissionv1.Create},
								Rule:       admissionv1.Rule{APIGroups: []string{""}, APIVersions: []string{"v1"}, Resources: []string{"configmaps"}},
							}}}}}}
				_, err := c.AdmissionregistrationV1().ValidatingAdmissionPolicies().Create(ctx, vap, metav1.CreateOptions{DryRun: dryRun})
				return err
			}},
			{"list VAPs", true, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, metav1.ListOptions{})
				return err
			}},
			{"list nodes", true, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
				return err
			}},
			{"list networkpolicies", true, func(ctx context.Context, c kubernetes.Interface) error {
				_, err := c.NetworkingV1().NetworkPolicies("agent-exec").List(ctx, metav1.ListOptions{})
				return err
			}},
		})
		setRow(rows, "permissions.drift_probe_read_only", out, []string{"k8s:token:agent-observe/drift-probe"}, lim...)
	}

	c, err := saClient(ctx, admin, base, "agent-control", "node-readiness")
	if err != nil {
		for _, id := range []string{"permissions.node_readiness_start_taint", "permissions.node_readiness_other_taint",
			"permissions.node_readiness_label", "permissions.node_readiness_unschedulable"} {
			setRow(rows, id, OutcomeUnknown, nil, "token request failed: "+err.Error())
		}
		return
	}
	probeNodeReadinessScope(ctx, t, c, &target, rows)
}

func hasTaint(n *corev1.Node, key string) bool {
	for _, t := range n.Spec.Taints {
		if t.Key == key {
			return true
		}
	}
	return false
}

func jsonPatch(ctx context.Context, c kubernetes.Interface, node string, ops []map[string]any) error {
	b, err := json.Marshal(ops)
	if err != nil {
		return err
	}
	_, err = c.CoreV1().Nodes().Patch(ctx, node, types.JSONPatchType, b, metav1.PatchOptions{DryRun: dryRun})
	return err
}

func probeNodeReadinessScope(ctx context.Context, t *testing.T, c kubernetes.Interface, n *corev1.Node, rows []Row) {
	rv := map[string]any{"op": "test", "path": "/metadata/resourceVersion", "value": n.ResourceVersion}

	// Allowed: change only the start taint (remove it if present, else add it).
	var startOps []map[string]any
	lim := ""
	idx := -1
	for i, tn := range n.Spec.Taints {
		if tn.Key == startTaintKey {
			idx = i
		}
	}
	if idx >= 0 {
		startOps = []map[string]any{rv, {"op": "remove", "path": fmt.Sprintf("/spec/taints/%d", idx)}}
	} else {
		lim = "no pool node had the start taint; probed adding it instead of removing it"
		taint := map[string]any{"key": startTaintKey, "value": "true", "effect": "NoSchedule"}
		if len(n.Spec.Taints) == 0 {
			startOps = []map[string]any{rv, {"op": "add", "path": "/spec/taints", "value": []any{taint}}}
		} else {
			startOps = []map[string]any{rv, {"op": "add", "path": "/spec/taints/-", "value": taint}}
		}
	}
	switch err := jsonPatch(ctx, c, n.Name, startOps); {
	case err == nil:
		setRow(rows, "permissions.node_readiness_start_taint", OutcomePass, []string{"k8s:dry-run:nodes/" + n.Name}, nonEmpty(lim)...)
	case apierrors.IsForbidden(err) || apierrors.IsInvalid(err):
		setRow(rows, "permissions.node_readiness_start_taint", OutcomeFail, nil, "start taint change rejected: "+err.Error())
	default:
		setRow(rows, "permissions.node_readiness_start_taint", OutcomeUnknown, nil, err.Error())
	}

	other := map[string]any{"key": "q0.agentarium.io/other", "value": "x", "effect": "NoSchedule"}
	var otherOps []map[string]any
	if len(n.Spec.Taints) == 0 {
		otherOps = []map[string]any{rv, {"op": "add", "path": "/spec/taints", "value": []any{other}}}
	} else {
		otherOps = []map[string]any{rv, {"op": "add", "path": "/spec/taints/-", "value": other}}
	}
	newRole := "control"
	if n.Labels[roleLabel] == "control" {
		newRole = "exec"
	}
	labelPath := "/metadata/labels/" + strings.ReplaceAll(strings.ReplaceAll(roleLabel, "~", "~0"), "/", "~1")

	for id, ops := range map[string][]map[string]any{
		"permissions.node_readiness_other_taint":   otherOps,
		"permissions.node_readiness_label":         {rv, {"op": "replace", "path": labelPath, "value": newRole}},
		"permissions.node_readiness_unschedulable": {rv, {"op": "add", "path": "/spec/unschedulable", "value": !n.Spec.Unschedulable}},
	} {
		err := jsonPatch(ctx, c, n.Name, ops)
		switch {
		case err == nil:
			setRow(rows, id, OutcomeFail, nil, "dry-run patch was admitted")
		case strings.Contains(err.Error(), scopeInvalid):
			t.Logf("%s rejected: %v", id, err)
			setRow(rows, id, OutcomePass, []string{"k8s:dry-run:nodes/" + n.Name})
		default:
			setRow(rows, id, OutcomeUnknown, nil, "rejected without "+scopeInvalid+": "+err.Error())
		}
	}
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// ---- runtime observation ----

// requiredEventTypes per stimulus kind (TASK-10 3.2 answer probe table).
// SPEC-QUESTION: TASK-10 names file hooks (security_file_open, openat) while
// COMMON KernelEvent uses event_type file_open; file stimuli therefore only
// require at least one expected event and rely on the runner's list.
var requiredEventTypes = map[string][]string{
	"process": {"process_exec", "process_exit"},
	"tcp":     {"tcp_connect", "tcp_state"},
	"file":    {},
}

var kindRow = map[string]string{"process": "runtime.process", "tcp": "runtime.tcp", "file": "runtime.protected_path"}

func probeRuntimeObservation(t *testing.T, rows []Row) []ProbeRecord {
	stimuli, ok1 := readJSONL[Stimulus](t, "Q0_STIMULI_JSONL")
	events, ok2 := readJSONL[ObservedEvent](t, "Q0_EVENTS_JSONL")
	if !ok1 || !ok2 {
		t.Skip("Q0_STIMULI_JSONL and Q0_EVENTS_JSONL are both required: runtime rows stay not_run")
	}
	byKind := map[string][]Stimulus{}
	for _, s := range stimuli {
		if _, ok := kindRow[s.Kind]; !ok {
			t.Errorf("stimulus %s has unknown kind %q", s.StimulusID, s.Kind)
			continue
		}
		if !coversRequired(s) {
			// An incomplete answer key cannot count as observed or missed.
			s.TruthAvailable = false
		}
		byKind[s.Kind] = append(byKind[s.Kind], s)
	}
	var all []ProbeRecord
	for kind, id := range kindRow {
		recs, tally := CountStimuli(byKind[kind], events)
		r := FindRow(rows, id)
		if len(byKind[kind]) == 0 {
			r.Outcome = OutcomeNotRun
			continue
		}
		ApplyObservation(r, tally)
		r.EvidenceRefs = append(r.EvidenceRefs, "file:"+os.Getenv("Q0_STIMULI_JSONL"), "file:"+os.Getenv("Q0_EVENTS_JSONL"))
		t.Logf("%s: pass=%d fail=%d unknown=%d", id, tally.Pass, tally.Fail, tally.Unknown)
		all = append(all, recs...)
	}
	return all
}

func coversRequired(s Stimulus) bool {
	if len(s.Expected) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, e := range s.Expected {
		have[e.EventType] = true
	}
	for _, ty := range requiredEventTypes[s.Kind] {
		if !have[ty] {
			return false
		}
	}
	return true
}

// ---- startup_guard_gate failure injection ----

func probeInjection(t *testing.T, rows []Row) []time.Duration {
	samples, ok := readJSONL[InjectionEvidence](t, "Q0_INJECTION_JSONL")
	if !ok {
		t.Skip("Q0_INJECTION_JSONL not set: injection rows stay not_run, startup_guard_gate inactive")
	}
	byRow := map[string][]InjectionEvidence{}
	var lat []time.Duration
	for _, s := range samples {
		if r := FindRow(rows, s.RowID); r == nil || r.Area != AreaStartupGuard {
			t.Errorf("injection evidence for unknown row %q", s.RowID)
			continue
		}
		byRow[s.RowID] = append(byRow[s.RowID], s)
		if s.StartLatencyMS != nil {
			lat = append(lat, time.Duration(*s.StartLatencyMS*float64(time.Millisecond)))
		}
	}
	for _, id := range InjectionRowIDs {
		ApplyInjection(FindRow(rows, id), byRow[id])
	}
	return lat
}
