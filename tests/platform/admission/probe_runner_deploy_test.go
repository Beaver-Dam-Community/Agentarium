package admission

import (
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
)

// TASK-10 3.2 answer probe runner and its tcp target (deploy/gcp/base/probe-runner).
const (
	probeRunnerEntrypoint = "/probe/bin/probe-runner"
	probeSinkImage        = reg + "probe-sink@" + digestA
)

func probeRunnerValues() map[string]string {
	v := deployValues()
	v["PROBE_RUNNER_IMAGE"], v["PROBE_SINK_IMAGE"] = probeImage, probeSinkImage
	v["PROBE_SINK_CLUSTER_IP"] = "10.30.0.23"
	v["PROBE_ENTRYPOINTS"] = v["PROBE_ENTRYPOINTS"] + "," + probeImage + "=" + probeRunnerEntrypoint
	v["AGENT_TARGETS_IMAGES"] += "," + probeSinkImage
	return v
}

// daemonSetPods turns every DaemonSet of a rendered List into the Pod the
// DaemonSet controller would create: node affinity on one node name and the
// automatic not-ready/unreachable/pressure tolerations without seconds.
func daemonSetPods(t *testing.T, file string, values map[string]string) []*corev1.Pod {
	t.Helper()
	var pods []*corev1.Pod
	for _, raw := range renderedItems(t, file, values) {
		var head listItem
		if err := json.Unmarshal(raw, &head); err != nil || head.Kind != "DaemonSet" {
			continue
		}
		var d appsv1.DaemonSet
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		p := &corev1.Pod{ObjectMeta: d.Spec.Template.ObjectMeta, Spec: *d.Spec.Template.Spec.DeepCopy()}
		p.TypeMeta.APIVersion, p.TypeMeta.Kind = "v1", "Pod"
		p.Name, p.Namespace = d.Name+"-0", d.Namespace
		p.Spec.RestartPolicy = corev1.RestartPolicyAlways
		p.Spec.Affinity = &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchFields: []corev1.NodeSelectorRequirement{
				{Key: "metadata.name", Operator: corev1.NodeSelectorOpIn, Values: []string{"gke-node-1"}}}}}}}}
		for _, key := range []string{"node.kubernetes.io/not-ready", "node.kubernetes.io/unreachable"} {
			p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{Key: key, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute})
		}
		for _, key := range []string{"node.kubernetes.io/disk-pressure", "node.kubernetes.io/memory-pressure", "node.kubernetes.io/pid-pressure", "node.kubernetes.io/unschedulable"} {
			p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{Key: key, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule})
		}
		pods = append(pods, p)
	}
	return pods
}

func probeRunnerPod(t *testing.T, values map[string]string, namespace string) *corev1.Pod {
	t.Helper()
	for _, p := range daemonSetPods(t, "deploy/gcp/base/probe-runner/probe-runner.yaml", values) {
		if p.Namespace == namespace {
			return p
		}
	}
	t.Fatalf("no probe-runner DaemonSet in %s", namespace)
	return nil
}

// Both runners and the sink pass their Namespace contracts and Pod Security
// as rendered (TASK-01 3.2, TASK-10 3.2).
func TestProbeRunnerDeploymentsAdmitted(t *testing.T) {
	values := probeRunnerValues()
	c := newCluster(t, values)
	runners := daemonSetPods(t, "deploy/gcp/base/probe-runner/probe-runner.yaml", values)
	if len(runners) != 2 {
		t.Fatalf("got %d DaemonSets, want agent-exec and agent-adapters", len(runners))
	}
	for _, p := range runners {
		t.Run(p.Namespace+"/"+p.Name, func(t *testing.T) { expectExactly(t, c.admit(t, create(p.Namespace, p))) })
	}
	sinks := deploymentPods(t, "deploy/gcp/base/probe-runner/probe-sink.yaml", values)
	if len(sinks) != 1 || sinks[0].Namespace != "agent-targets" {
		t.Fatalf("want one agent-targets probe-sink Deployment, got %d", len(sinks))
	}
	t.Run("agent-targets/probe-sink", func(t *testing.T) { expectExactly(t, c.admit(t, create("agent-targets", sinks[0]))) })

	exec := probeRunnerPod(t, values, "agent-exec")
	if got := envValue(exec, "AGENTARIUM_REPORT_URL"); got != "https://10.30.0.20:8443" {
		t.Fatalf("agent-exec runner must report through the gateway ClusterIP, got %q", got)
	}
	if got := envValue(exec, "AGENTARIUM_PROBE_SINK"); got != "10.30.0.23:8443" {
		t.Fatalf("agent-exec runner must dial the sink ClusterIP without DNS, got %q", got)
	}
	if pem := envValue(exec, "AGENTARIUM_TRUST_BUNDLE_PEM"); !strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----\n") {
		t.Fatalf("trust bundle env is not PEM text: %q", pem)
	}
}

// An agent-exec probe runner with anything beyond the rendered contract is
// refused (TASK-01 3.2 agent-exec-probe-contract).
func TestProbeRunnerExtraPrivilegesRejected(t *testing.T) {
	values := probeRunnerValues()
	c := newCluster(t, values)
	base := probeRunnerPod(t, values, "agent-exec")
	cases := []struct {
		name   string
		mutate func(*corev1.Pod)
		want   []string
	}{
		{"args", func(p *corev1.Pod) { p.Spec.Containers[0].Args = []string{"--report-url=https://evil"} },
			[]string{"agent-exec-probe-contract:PROBE_IMAGE_OR_ENTRYPOINT_INVALID"}},
		{"other entrypoint", func(p *corev1.Pod) { p.Spec.Containers[0].Command = []string{"/probe/bin/marker"} },
			[]string{"agent-exec-probe-contract:PROBE_IMAGE_OR_ENTRYPOINT_INVALID"}},
		{"hostPath volume", func(p *corev1.Pod) { p.Spec.Volumes = append(p.Spec.Volumes, hostPathVol("proc", "/proc")) },
			[]string{"agent-exec-probe-contract:PROBE_VOLUME_INVALID", "PSA:restricted volume types"}},
		{"env from a Secret", func(p *corev1.Pod) {
			p.Spec.Containers[0].Env = append(p.Spec.Containers[0].Env, corev1.EnvVar{Name: "X", ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "s"}, Key: "k"}}})
		}, []string{"agent-exec-probe-contract:PROBE_VOLUME_INVALID"}},
		{"root user", func(p *corev1.Pod) {
			p.Spec.SecurityContext.RunAsUser = ptr.To[int64](0)
			p.Spec.Containers[0].SecurityContext.RunAsUser = ptr.To[int64](0)
		}, []string{"agent-exec-probe-contract:PROBE_VOLUME_INVALID", "PSA:runAsUser=0"}},
		{"privileged", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true) },
			[]string{"PSA:privileged"}},
		{"added capability", func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"DAC_OVERRIDE"}
		}, []string{"PSA:unrestricted capabilities"}},
		{"hostPID", func(p *corev1.Pod) { p.Spec.HostPID = true }, []string{"PSA:host namespaces"}},
		{"control pool placement", func(p *corev1.Pod) { p.Spec.NodeSelector[roleLabel] = "control" },
			[]string{"agent-exec-probe-contract:PROBE_PLACEMENT_INVALID"}},
		{"extra toleration", func(p *corev1.Pod) {
			p.Spec.Tolerations = append(p.Spec.Tolerations, corev1.Toleration{Key: "agentarium-role", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule})
		}, []string{"agent-exec-probe-contract:PROBE_TOLERATION_INVALID"}},
		{"token automount", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = ptr.To(true) },
			[]string{"agent-exec-probe-contract:PROBE_IDENTITY_INVALID"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base.DeepCopy()
			tc.mutate(p)
			expectExactly(t, c.admit(t, create("agent-exec", p)), tc.want...)
		})
	}
	t.Run("image not on PROBE_IMAGES", func(t *testing.T) {
		v := probeRunnerValues()
		v["PROBE_RUNNER_IMAGE"] = probeSinkImage
		p := probeRunnerPod(t, v, "agent-exec")
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-probe-contract:PROBE_IMAGE_OR_ENTRYPOINT_INVALID")
	})
	t.Run("adapters runner image missing from its Namespace list", func(t *testing.T) {
		v := probeRunnerValues()
		v["AGENT_ADAPTERS_IMAGES"] = strings.ReplaceAll(v["AGENT_ADAPTERS_IMAGES"], probeImage+",", "")
		p := probeRunnerPod(t, v, "agent-adapters")
		expectExactly(t, newCluster(t, v).admit(t, create("agent-adapters", p)), "agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
	})
	t.Run("adapters non-probe workload with the start taint", func(t *testing.T) {
		p := probeRunnerPod(t, values, "agent-adapters")
		p.Spec.ServiceAccountName, p.Labels["app.kubernetes.io/name"] = "receiver-sender", "receiver-sender"
		expectExactly(t, c.admit(t, create("agent-adapters", p)), "agent-role-contract:ROLE_ADAPTER_BOOTSTRAP_TOLERATION_FORBIDDEN")
	})
}
