//go:build integration

// Live exec-profile test against a real cluster (TASK-01 3.3 admission verification,
// 7: placement bypass / exec profile separation / resource limit subset). Run with:
//
//	KUBECONFIG=... \
//	  ADMISSION_RUNTIME_IMAGE=<digest ref> ADMISSION_PROBE_IMAGE=<digest ref> ADMISSION_FIXTURE_IMAGE=<digest ref> \
//	  ADMISSION_EXEC_OUT=evidence/gcp/runs/<run_id>/admission-exec.json \
//	  go test -tags integration -run TestLiveExecProfiles -v ./tests/platform/admission/
//
// Preconditions: deploy/gcp/base is applied with RUNTIME_IMAGE, PROBE_IMAGES,
// FIXTURE_IMAGES set to these digests and PROBE_ENTRYPOINTS set to
// <probe>=/app/bin/probe-runner,<fixture>=/app/bin/start-fixture. The images
// may be stand-ins (a process that waits for SIGTERM at the fixed entrypoint);
// this test checks admission and placement only, not runtime behaviour.
//
// Real Pods: one runtime Pod (must be admitted, stay Pending under the start
// taint and count in agent-runtime-quota), one probe Pod (tolerates the start
// taint, must run on an exec node and count only in agent-probe-quota), one
// fixture Pod (cannot tolerate the start taint, must stay Pending). All are
// deleted afterwards. Every forbidden variant uses dryRun=All.
package admission

import (
	"context"
	"os"
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

const execNS = "agent-exec"

func execResources() corev1.ResourceRequirements {
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{"cpu": resource.MustParse("100m"), "memory": resource.MustParse("64Mi"), "ephemeral-storage": resource.MustParse("64Mi")},
		Limits:   corev1.ResourceList{"cpu": resource.MustParse("200m"), "memory": resource.MustParse("128Mi"), "ephemeral-storage": resource.MustParse("128Mi")},
	}
}

func execSecurity() (*corev1.PodSecurityContext, *corev1.SecurityContext) {
	t, f := true, false
	uid := int64(10001)
	return &corev1.PodSecurityContext{RunAsNonRoot: &t, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}},
		&corev1.SecurityContext{
			RunAsUser: &uid, RunAsNonRoot: &t, ReadOnlyRootFilesystem: &t, AllowPrivilegeEscalation: &f,
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		}
}

func identityVolume() corev1.Volume {
	exp := int64(600)
	return corev1.Volume{Name: "identity", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
		Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
			Audience: "agentarium-identity", ExpirationSeconds: &exp, Path: "token",
		}}},
	}}}
}

// liveRuntimePod follows the TASK-01 3.3 runtime Pod template.
func liveRuntimePod(image string) *corev1.Pod {
	f := false
	size := resource.MustParse("512Mi")
	psc, csc := execSecurity()
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "admission-runtime-", Namespace: execNS,
			Labels: map[string]string{"app.kubernetes.io/name": "agent-runtime"}},
		Spec: corev1.PodSpec{
			ServiceAccountName:           "agent-runtime",
			AutomountServiceAccountToken: &f,
			PriorityClassName:            "agentarium-runtime",
			SchedulerName:                "default-scheduler",
			NodeSelector:                 map[string]string{roleLabelKey: "exec"},
			Tolerations: []corev1.Toleration{{Key: "agentarium-role", Operator: corev1.TolerationOpEqual, Value: "exec",
				Effect: corev1.TaintEffectNoSchedule}},
			SecurityContext: psc,
			Containers: []corev1.Container{{
				Name: "agent-runtime", Image: image, Command: []string{"/app/bin/agent-runtime"},
				SecurityContext: csc, Resources: execResources(),
				VolumeMounts: []corev1.VolumeMount{
					{Name: "work", MountPath: "/work"},
					{Name: "identity", MountPath: "/run/agentarium/identity", ReadOnly: true},
				},
			}},
			Volumes: []corev1.Volume{
				{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &size}}},
				identityVolume(),
			},
		},
	}
}

// liveProbePod builds a probe-runner or start-fixture Pod (TASK-01 3.2 probe contract).
func liveProbePod(profile, image, entrypoint string) *corev1.Pod {
	f := false
	size := resource.MustParse("64Mi")
	psc, csc := execSecurity()
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "admission-" + profile + "-", Namespace: execNS,
			Labels: map[string]string{"app.kubernetes.io/name": profile}},
		Spec: corev1.PodSpec{
			ServiceAccountName:           profile,
			AutomountServiceAccountToken: &f,
			SchedulerName:                "default-scheduler",
			NodeSelector:                 map[string]string{roleLabelKey: "exec"},
			Tolerations: []corev1.Toleration{{Key: "agentarium-role", Operator: corev1.TolerationOpEqual, Value: "exec",
				Effect: corev1.TaintEffectNoSchedule}},
			RestartPolicy:   corev1.RestartPolicyNever,
			SecurityContext: psc,
			Containers: []corev1.Container{{
				Name: profile, Image: image, Command: []string{entrypoint},
				SecurityContext: csc, Resources: execResources(),
				VolumeMounts: []corev1.VolumeMount{{Name: "scratch", MountPath: "/scratch"}},
			}},
			Volumes: []corev1.Volume{{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: &size}}}},
		},
	}
	if profile == "probe-runner" {
		p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{Key: startTaint, Operator: corev1.TolerationOpEqual,
			Value: "true", Effect: corev1.TaintEffectNoSchedule})
	}
	return p
}

func TestLiveExecProfiles(t *testing.T) {
	runtimeImg, probeImg, fixtureImg := os.Getenv("ADMISSION_RUNTIME_IMAGE"), os.Getenv("ADMISSION_PROBE_IMAGE"), os.Getenv("ADMISSION_FIXTURE_IMAGE")
	for _, img := range []string{runtimeImg, probeImg, fixtureImg} {
		if !strings.Contains(img, "@sha256:") {
			t.Skip("ADMISSION_RUNTIME_IMAGE / ADMISSION_PROBE_IMAGE / ADMISSION_FIXTURE_IMAGE (digest refs) not set")
		}
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

	rep := &liveReport{Test: "TestLiveExecProfiles", StartedAt: time.Now().UTC().Format(time.RFC3339), Server: cfg.Host,
		Image: strings.Join([]string{runtimeImg, probeImg, fixtureImg}, ",")}
	record := func(r liveResult) {
		if r.Outcome == "passed" {
			rep.Passed++
		} else {
			rep.Failed++
			t.Errorf("%s/%s: expected %s, observed %s", r.Namespace, r.Case, r.Expected, r.Observed)
		}
		rep.Results = append(rep.Results, r)
	}
	t.Setenv("ADMISSION_OUT", os.Getenv("ADMISSION_EXEC_OUT"))
	defer func() {
		rep.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		writeLiveReport(t, rep)
	}()

	// ServiceAccounts the profiles name; only the ones created here are removed.
	for _, sa := range []string{"agent-runtime", "probe-runner", "start-fixture"} {
		_, err := cs.CoreV1().ServiceAccounts(execNS).Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa, Namespace: execNS}}, metav1.CreateOptions{})
		switch {
		case err == nil:
			defer func(sa string) {
				_ = cs.CoreV1().ServiceAccounts(execNS).Delete(context.Background(), sa, metav1.DeleteOptions{})
			}(sa)
		case apierrors.IsAlreadyExists(err):
		default:
			t.Fatalf("create SA %s: %v", sa, err)
		}
	}

	create := func(p *corev1.Pod) (*corev1.Pod, error) {
		return cs.CoreV1().Pods(execNS).Create(ctx, p, metav1.CreateOptions{})
	}
	var created []string
	defer func() {
		for _, n := range created {
			_ = cs.CoreV1().Pods(execNS).Delete(context.Background(), n, metav1.DeleteOptions{})
		}
	}()
	waitPod := func(name string, d time.Duration, done func(*corev1.Pod) bool) *corev1.Pod {
		var last *corev1.Pod
		_ = wait.PollUntilContextTimeout(ctx, 3*time.Second, d, true, func(ctx context.Context) (bool, error) {
			p, err := cs.CoreV1().Pods(execNS).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, nil
			}
			last = p
			return done(p), nil
		})
		return last
	}
	// GKE's scheduler message says "untolerated taint(s)" without naming the key, so
	// the start taint is attributed by checking that every exec node carries it.
	allExecNodesTainted := func() bool {
		nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: roleLabelKey + "=exec"})
		if err != nil || len(nodes.Items) == 0 {
			return false
		}
		for _, n := range nodes.Items {
			found := false
			for _, tn := range n.Spec.Taints {
				found = found || (tn.Key == startTaint && tn.Effect == corev1.TaintEffectNoSchedule)
			}
			if !found {
				return false
			}
		}
		return true
	}
	unschedulableByStartTaint := func(p *corev1.Pod) bool {
		if p.Status.Phase != corev1.PodPending || p.Spec.NodeName != "" {
			return false
		}
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable &&
				strings.Contains(c.Message, "untolerated taint") {
				return allExecNodesTainted()
			}
		}
		return false
	}
	schedMsg := func(p *corev1.Pod) string {
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodScheduled {
				return string(c.Status) + "/" + c.Reason + ": " + c.Message
			}
		}
		return "no PodScheduled condition"
	}
	quotaUsed := func(name string) string {
		q, err := cs.CoreV1().ResourceQuotas(execNS).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return "error: " + err.Error()
		}
		u := q.Status.Used["pods"]
		return u.String()
	}

	// 1. runtime Pod: admitted, Pending because of the start taint, counted in the runtime quota.
	r := liveResult{Case: "runtime_pending_under_start_taint", Namespace: execNS,
		Expected: "admitted; Pending with an untolerated observe-not-ready taint; agent-runtime-quota pods=1"}
	if p, err := create(liveRuntimePod(runtimeImg)); err != nil {
		r.Observed, r.Outcome = "rejected: "+err.Error(), "failed"
	} else {
		created = append(created, p.Name)
		last := waitPod(p.Name, time.Minute, unschedulableByStartTaint)
		time.Sleep(3 * time.Second) // quota status is updated asynchronously
		used := quotaUsed("agent-runtime-quota")
		r.Observed = "phase=" + string(last.Status.Phase) + " node=" + last.Spec.NodeName + " runtime-quota pods=" + used + " scheduled=" + schedMsg(last)
		r.Outcome = "failed"
		if unschedulableByStartTaint(last) && used == "1" {
			r.Outcome = "passed"
		}
	}
	record(r)

	// 2. probe Pod: tolerates the start taint, runs on an exec node, counted only in agent-probe-quota.
	r = liveResult{Case: "probe_runs_before_readiness", Namespace: execNS,
		Expected: "Running on an exec node; agent-probe-quota pods>=1; agent-runtime-quota pods unchanged (1)"}
	if p, err := create(liveProbePod("probe-runner", probeImg, "/app/bin/probe-runner")); err != nil {
		r.Observed, r.Outcome = "rejected: "+err.Error(), "failed"
	} else {
		created = append(created, p.Name)
		last := waitPod(p.Name, 3*time.Minute, func(p *corev1.Pod) bool { return p.Status.Phase != corev1.PodPending })
		role := ""
		if last.Spec.NodeName != "" {
			if n, err := cs.CoreV1().Nodes().Get(ctx, last.Spec.NodeName, metav1.GetOptions{}); err == nil {
				role = n.Labels[roleLabelKey]
			}
		}
		time.Sleep(3 * time.Second)
		pu, ru := quotaUsed("agent-probe-quota"), quotaUsed("agent-runtime-quota")
		r.Observed = "phase=" + string(last.Status.Phase) + " role=" + role + " probe-quota pods=" + pu + " runtime-quota pods=" + ru
		r.Outcome = "failed"
		if last.Status.Phase == corev1.PodRunning && role == "exec" && pu != "0" && ru == "1" {
			r.Outcome = "passed"
		}
	}
	record(r)

	// 3. fixture Pod: no start-taint toleration allowed, stays Pending.
	r = liveResult{Case: "fixture_pending_under_start_taint", Namespace: execNS, Expected: "admitted; Pending with an untolerated observe-not-ready taint"}
	if p, err := create(liveProbePod("start-fixture", fixtureImg, "/app/bin/start-fixture")); err != nil {
		r.Observed, r.Outcome = "rejected: "+err.Error(), "failed"
	} else {
		created = append(created, p.Name)
		last := waitPod(p.Name, time.Minute, unschedulableByStartTaint)
		r.Observed = "phase=" + string(last.Status.Phase) + " node=" + last.Spec.NodeName + " scheduled=" + schedMsg(last)
		r.Outcome = "failed"
		if unschedulableByStartTaint(last) {
			r.Outcome = "passed"
		}
	}
	record(r)

	// Forbidden variants (dryRun=All). The marker is the expected policy message.
	tru := true
	otherDigest := runtimeImg[:strings.Index(runtimeImg, "@sha256:")] + "@sha256:" + strings.Repeat("0", 64)
	big := resource.MustParse("1Gi")
	cases := []struct {
		name, marker string
		pod          func() *corev1.Pod
	}{
		{"runtime_privileged", "PodSecurity", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Containers[0].SecurityContext.Privileged = &tru
			p.Spec.Containers[0].SecurityContext.AllowPrivilegeEscalation = &tru
			return p
		}},
		{"runtime_on_control", "EXEC_PLACEMENT_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.NodeSelector[roleLabelKey] = "control"
			return p
		}},
		{"runtime_secret_volume", "EXEC_SECRET_OR_VOLUME_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Volumes[0] = corev1.Volume{Name: "work", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "x"}}}
			return p
		}},
		{"runtime_other_digest", "EXEC_IMAGE_OR_ENTRYPOINT_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Containers[0].Image = otherDigest
			return p
		}},
		{"runtime_probe_image", "EXEC_IMAGE_OR_ENTRYPOINT_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Containers[0].Image = probeImg
			return p
		}},
		{"runtime_token_automount", "EXEC_IDENTITY_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.AutomountServiceAccountToken = &tru
			return p
		}},
		{"runtime_other_audience", "EXEC_SECRET_OR_VOLUME_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Volumes[1].Projected.Sources[0].ServiceAccountToken.Audience = "kubernetes"
			return p
		}},
		{"runtime_large_work_dir", "EXEC_SECRET_OR_VOLUME_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Volumes[0].EmptyDir.SizeLimit = &big
			return p
		}},
		{"runtime_runtime_class", "EXEC_RUNTIME_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			rc := "gvisor"
			p.Spec.RuntimeClassName = &rc
			return p
		}},
		{"runtime_start_taint_toleration", "EXEC_TOLERATION_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{Key: startTaint, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule})
			return p
		}},
		{"runtime_second_container", "EXEC_CONTAINER_SET_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			c := p.Spec.Containers[0]
			c.Name = "sidecar"
			p.Spec.Containers = append(p.Spec.Containers, c)
			return p
		}},
		{"probe_label_with_runtime_sa", "EXEC_ROLE_LABEL_INVALID", func() *corev1.Pod {
			p := liveProbePod("probe-runner", probeImg, "/app/bin/probe-runner")
			p.Spec.ServiceAccountName = "agent-runtime"
			return p
		}},
		{"probe_with_runtime_image", "PROBE_IMAGE_OR_ENTRYPOINT_INVALID", func() *corev1.Pod {
			return liveProbePod("probe-runner", runtimeImg, "/app/bin/agent-runtime")
		}},
		{"probe_wrong_entrypoint", "PROBE_IMAGE_OR_ENTRYPOINT_INVALID", func() *corev1.Pod {
			return liveProbePod("probe-runner", probeImg, "/bin/sh")
		}},
		{"fixture_restart_always", "FIXTURE_RESTART_POLICY_INVALID", func() *corev1.Pod {
			p := liveProbePod("start-fixture", fixtureImg, "/app/bin/start-fixture")
			p.Spec.RestartPolicy = corev1.RestartPolicyAlways
			return p
		}},
		{"fixture_start_taint_toleration", "PROBE_TOLERATION_INVALID", func() *corev1.Pod {
			p := liveProbePod("start-fixture", fixtureImg, "/app/bin/start-fixture")
			p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{Key: startTaint, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule})
			return p
		}},
		{"unknown_profile_label", "EXEC_ROLE_LABEL_INVALID", func() *corev1.Pod {
			p := liveRuntimePod(runtimeImg)
			// The SA stays agent-runtime so the ServiceAccount admission plugin
			// does not reject first; only the profile label is unknown.
			p.Labels["app.kubernetes.io/name"] = "debug-shell"
			return p
		}},
	}
	for _, c := range cases {
		res := liveResult{Case: c.name, Namespace: execNS, Expected: "rejected (" + c.marker + ")"}
		_, err := cs.CoreV1().Pods(execNS).Create(ctx, c.pod(), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		switch {
		case err == nil:
			res.Observed, res.Outcome = "admitted", "failed"
		case strings.Contains(err.Error(), c.marker):
			res.Observed, res.Outcome = "rejected: "+err.Error(), "passed"
		default:
			res.Observed, res.Outcome = "rejected without the expected marker: "+err.Error(), "failed"
		}
		record(res)
	}

	// "resources removed": LimitRange defaulting runs before the VAP (SPEC-QUESTION in
	// deploy/gcp/base/namespaces/agent-exec-resources.yaml); record what happens.
	p := liveRuntimePod(runtimeImg)
	p.Spec.Containers[0].Resources = corev1.ResourceRequirements{}
	_, err = cs.CoreV1().Pods(execNS).Create(ctx, p, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	obs := "admitted (LimitRange defaulted the resources)"
	if err != nil {
		obs = "rejected: " + err.Error()
	}
	rep.NotRun = append(rep.NotRun,
		"runtime_resources_removed: recorded only, observed="+obs,
		"NRI bypass annotation (forbiddenAnnotationKeys comes from the Q0 runtime profile; empty here)",
		"ephemeral container add (needs a running runtime Pod)",
		"rollout within 10 minutes (needs the runtime Deployment, TASK-15)")
}
