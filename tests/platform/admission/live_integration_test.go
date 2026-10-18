//go:build integration

// Live admission test against a real cluster (TASK-01 7: placement bypass, exec
// profile separation subset). Run with:
//
//	KUBECONFIG=... ADMISSION_TARGET_IMAGE=<region>-docker.pkg.dev/<project>/agentarium/admission-sleeper@sha256:<digest> \
//	  ADMISSION_OUT=evidence/gcp/runs/<run_id>/admission.json \
//	  go test -tags integration -run TestLiveAdmission -v ./tests/platform/admission/
//
// Preconditions: deploy/gcp/base is applied, and the rendered values put
// ADMISSION_TARGET_IMAGE in AGENT_TARGETS_IMAGES and AGENT_ADAPTERS_IMAGES
// (so the adapter toleration rule is reached after the image rule) while
// RUNTIME_IMAGE, PROBE_IMAGES and FIXTURE_IMAGES stay empty (fail closed).
//
// One allowed Pod is created for real in agent-targets and must reach Running
// on a control node; it and its ServiceAccount are deleted afterwards. Every
// forbidden variant is submitted with dryRun=All, so admission (PSA, VAP) runs
// and nothing is persisted.
package admission

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	liveSA       = "admission-probe"
	roleLabelKey = "node-restriction.kubernetes.io/agentarium-role"
	startTaint   = "agentarium.io/observe-not-ready"
)

type liveResult struct {
	Case      string `json:"case"`
	Namespace string `json:"namespace"`
	Expected  string `json:"expected"`
	Observed  string `json:"observed"`
	Outcome   string `json:"outcome"` // passed | failed
}

type liveReport struct {
	Test       string       `json:"test"`
	StartedAt  string       `json:"started_at"`
	Server     string       `json:"server"`
	Image      string       `json:"image"`
	Results    []liveResult `json:"results"`
	Passed     int          `json:"passed"`
	Failed     int          `json:"failed"`
	NotRun     []string     `json:"not_run"`
	FinishedAt string       `json:"finished_at"`
}

func basePod(ns, image string) *corev1.Pod {
	f := false
	t := true
	uid := int64(65532)
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "admission-probe-",
			Namespace:    ns,
			Labels:       map[string]string{"app.kubernetes.io/name": liveSA},
		},
		Spec: corev1.PodSpec{
			ServiceAccountName:           liveSA,
			AutomountServiceAccountToken: &f,
			SchedulerName:                "default-scheduler",
			NodeSelector:                 map[string]string{roleLabelKey: "control"},
			Tolerations: []corev1.Toleration{{
				Key: startTaint, Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule,
			}},
			RestartPolicy: corev1.RestartPolicyNever,
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   &t,
				RunAsUser:      &uid,
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{{
				Name:  "sleeper",
				Image: image,
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &f,
					ReadOnlyRootFilesystem:   &t,
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{"cpu": resource.MustParse("10m"), "memory": resource.MustParse("16Mi")},
					Limits:   corev1.ResourceList{"cpu": resource.MustParse("50m"), "memory": resource.MustParse("32Mi")},
				},
			}},
		},
	}
}

func TestLiveAdmission(t *testing.T) {
	image := os.Getenv("ADMISSION_TARGET_IMAGE")
	if image == "" || !strings.Contains(image, "@sha256:") {
		t.Skip("ADMISSION_TARGET_IMAGE (digest reference) not set")
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		t.Fatalf("kubeconfig: %v", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	rep := &liveReport{Test: "TestLiveAdmission", StartedAt: time.Now().UTC().Format(time.RFC3339), Server: cfg.Host, Image: image}
	record := func(r liveResult) {
		if r.Outcome == "passed" {
			rep.Passed++
		} else {
			rep.Failed++
			t.Errorf("%s/%s: expected %s, observed %s", r.Namespace, r.Case, r.Expected, r.Observed)
		}
		rep.Results = append(rep.Results, r)
	}
	defer func() {
		rep.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		writeLiveReport(t, rep)
	}()

	// The ServiceAccount admission plugin runs before PSA and VAP, so every
	// namespace under test needs the SA for the rejection to come from policy.
	for _, ns := range []string{"agent-targets", "agent-adapters", "agent-exec"} {
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: liveSA, Namespace: ns}}
		if _, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			t.Fatalf("create SA %s/%s: %v", ns, liveSA, err)
		}
		defer func(ns string) {
			_ = cs.CoreV1().ServiceAccounts(ns).Delete(context.Background(), liveSA, metav1.DeleteOptions{})
		}(ns)
	}

	// Allowed: created for real, must run on a control node.
	allowed := liveResult{Case: "allowed_control_pod", Namespace: "agent-targets", Expected: "Running on a control node"}
	pod, err := cs.CoreV1().Pods("agent-targets").Create(ctx, basePod("agent-targets", image), metav1.CreateOptions{})
	if err != nil {
		allowed.Observed, allowed.Outcome = "rejected: "+err.Error(), "failed"
		record(allowed)
	} else {
		defer func() {
			_ = cs.CoreV1().Pods("agent-targets").Delete(context.Background(), pod.Name, metav1.DeleteOptions{})
		}()
		var last *corev1.Pod
		werr := wait.PollUntilContextTimeout(ctx, 3*time.Second, 4*time.Minute, true, func(ctx context.Context) (bool, error) {
			p, err := cs.CoreV1().Pods("agent-targets").Get(ctx, pod.Name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			last = p
			return p.Status.Phase == corev1.PodRunning || p.Status.Phase == corev1.PodFailed, nil
		})
		role := ""
		if last != nil && last.Spec.NodeName != "" {
			if n, err := cs.CoreV1().Nodes().Get(ctx, last.Spec.NodeName, metav1.GetOptions{}); err == nil {
				role = n.Labels[roleLabelKey]
			}
		}
		phase := "unknown"
		if last != nil {
			phase = string(last.Status.Phase)
		}
		allowed.Observed = phase + " on role=" + role
		allowed.Outcome = "failed"
		if werr == nil && phase == string(corev1.PodRunning) && role == "control" {
			allowed.Outcome = "passed"
		}
		record(allowed)
	}

	// Forbidden: dryRun=All, admission must reject with the given marker.
	tru := true
	otherDigest := image[:strings.Index(image, "@sha256:")] + "@sha256:" + strings.Repeat("0", 64)
	tagImage := image[:strings.Index(image, "@sha256:")] + ":m0-2"
	cases := []struct {
		name, ns, marker string
		mutate           func(*corev1.Pod)
	}{
		{"privileged", "agent-targets", "PodSecurity", func(p *corev1.Pod) {
			// API validation rejects privileged with allowPrivilegeEscalation=false
			// before admission, so both are flipped.
			p.Spec.Containers[0].SecurityContext.Privileged = &tru
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = &tru
		}},
		{"host_network", "agent-targets", "PodSecurity", func(p *corev1.Pod) { p.Spec.HostNetwork = true }},
		{"tag_image", "agent-targets", "ROLE_IMAGE_NOT_ALLOWED", func(p *corev1.Pod) { p.Spec.Containers[0].Image = tagImage }},
		{"digest_not_allowed", "agent-targets", "ROLE_IMAGE_NOT_ALLOWED", func(p *corev1.Pod) { p.Spec.Containers[0].Image = otherDigest }},
		{"exec_node_selected", "agent-targets", "ROLE_PLACEMENT_INVALID", func(p *corev1.Pod) { p.Spec.NodeSelector[roleLabelKey] = "exec" }},
		{"node_name_set", "agent-targets", "ROLE_PLACEMENT_INVALID", func(p *corev1.Pod) {
			p.Spec.NodeName = "gke-agentarium-prod-control-pool-x"
		}},
		{"other_scheduler", "agent-targets", "ROLE_PLACEMENT_INVALID", func(p *corev1.Pod) { p.Spec.SchedulerName = "other-scheduler" }},
		{"label_sa_mismatch", "agent-targets", "ROLE_LABEL_OR_PRIORITY_INVALID", func(p *corev1.Pod) {
			p.Labels["app.kubernetes.io/name"] = "someone-else"
		}},
		{"runtime_priority_class", "agent-targets", "ROLE_LABEL_OR_PRIORITY_INVALID", func(p *corev1.Pod) {
			p.Spec.PriorityClassName = "agentarium-runtime"
		}},
		{"runtime_class_set", "agent-targets", "ROLE_RUNTIME_INVALID", func(p *corev1.Pod) {
			rc := "gvisor"
			p.Spec.RuntimeClassName = &rc
		}},
		{"adapter_start_taint_toleration", "agent-adapters", "ROLE_ADAPTER_BOOTSTRAP_TOLERATION_FORBIDDEN", func(p *corev1.Pod) {}},
		{"exec_pod_without_runtime_contract", "agent-exec", "denied", func(p *corev1.Pod) {
			p.Spec.Tolerations = nil
			p.Spec.NodeSelector[roleLabelKey] = "exec"
		}},
		{"exec_pod_on_control", "agent-exec", "denied", func(p *corev1.Pod) { p.Spec.Tolerations = nil }},
	}
	for _, c := range cases {
		p := basePod(c.ns, image)
		c.mutate(p)
		r := liveResult{Case: c.name, Namespace: c.ns, Expected: "rejected (" + c.marker + ")"}
		_, err := cs.CoreV1().Pods(c.ns).Create(ctx, p, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		switch {
		case err == nil:
			r.Observed, r.Outcome = "admitted", "failed"
		case strings.Contains(err.Error(), c.marker) && (apierrors.IsForbidden(err) || apierrors.IsInvalid(err)):
			r.Observed, r.Outcome = "rejected: "+err.Error(), "passed"
		default:
			r.Observed, r.Outcome = "rejected without the expected marker: "+err.Error(), "failed"
		}
		record(r)
	}

	rep.NotRun = []string{
		"exec runtime Pod Pending under the start taint (needs a CI-built RUNTIME_IMAGE)",
		"exec profile split (needs probe/fixture image digests)",
		"RBAC matrix, node-readiness gating, bootstrap order (M1+)",
	}
}

func writeLiveReport(t *testing.T, rep *liveReport) {
	b, _ := json.MarshalIndent(rep, "", "  ")
	t.Logf("report:\n%s", b)
	out := os.Getenv("ADMISSION_OUT")
	if out == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Errorf("report dir: %v", err)
		return
	}
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Errorf("write report: %v", err)
	}
}
