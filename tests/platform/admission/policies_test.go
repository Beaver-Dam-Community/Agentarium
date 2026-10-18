package admission

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/utils/ptr"
)

// ---- fixtures ---------------------------------------------------------------

const (
	roleLabel     = "node-restriction.kubernetes.io/agentarium-role"
	startTaintKey = "agentarium.io/observe-not-ready"
)

func restrictedContainer(name, image, command string) corev1.Container {
	return corev1.Container{
		Name:    name,
		Image:   image,
		Command: []string{command},
		SecurityContext: &corev1.SecurityContext{
			RunAsUser:                ptr.To[int64](10001),
			RunAsNonRoot:             ptr.To(true),
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	}
}

func execToleration() corev1.Toleration {
	return corev1.Toleration{Key: "agentarium-role", Operator: corev1.TolerationOpEqual, Value: "exec", Effect: corev1.TaintEffectNoSchedule}
}

// defaultTolerationSeconds is what the DefaultTolerationSeconds admission
// plugin adds before validation.
func defaultTolerationSeconds() []corev1.Toleration {
	return []corev1.Toleration{
		{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](300)},
		{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute, TolerationSeconds: ptr.To[int64](300)},
	}
}

// runtimePod is the TASK-01 3.3 Pod template with the fields the API server
// defaults or mutating plugins add before ValidatingAdmissionPolicy runs.
func runtimePod() *corev1.Pod {
	c := restrictedContainer("agent-runtime", runtimeImage, "/app/bin/agent-runtime")
	c.Resources = corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("512Mi"),
			corev1.ResourceEphemeralStorage: resource.MustParse("256Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("2Gi"),
			corev1.ResourceEphemeralStorage: resource.MustParse("2Gi"),
		},
	}
	c.VolumeMounts = []corev1.VolumeMount{
		{Name: "work", MountPath: "/work"},
		{Name: "identity", MountPath: "/run/agentarium/identity", ReadOnly: true},
	}
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: "agent-runtime-0", Namespace: "agent-exec", Labels: map[string]string{"app.kubernetes.io/name": "agent-runtime"}},
		Spec: corev1.PodSpec{
			ServiceAccountName:           "agent-runtime",
			AutomountServiceAccountToken: ptr.To(false),
			PriorityClassName:            "agentarium-runtime",
			SchedulerName:                "default-scheduler",
			RestartPolicy:                corev1.RestartPolicyAlways,
			NodeSelector:                 map[string]string{roleLabel: "exec"},
			Tolerations:                  append([]corev1.Toleration{execToleration()}, defaultTolerationSeconds()...),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{c},
			Volumes: []corev1.Volume{
				{Name: "work", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("512Mi"))}}},
				{Name: "identity", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
						Audience: "agentarium-identity", ExpirationSeconds: ptr.To[int64](600), Path: "token",
					}}},
				}}},
			},
		},
	}
}

// probePod builds a TASK-10 probe runner Pod as the DaemonSet controller
// would create it (auto tolerations without tolerationSeconds), or a start
// fixture Pod (restartPolicy Never).
func probePod(profile string) *corev1.Pod {
	image, entry := probeImage, probeEntrypoint
	if profile == "start-fixture" {
		image, entry = fixtureImage, fixtureEntry
	}
	p := &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: profile + "-0", Namespace: "agent-exec", Labels: map[string]string{"app.kubernetes.io/name": profile}},
		Spec: corev1.PodSpec{
			ServiceAccountName:           profile,
			AutomountServiceAccountToken: ptr.To(false),
			SchedulerName:                "default-scheduler",
			RestartPolicy:                corev1.RestartPolicyAlways,
			NodeSelector:                 map[string]string{roleLabel: "exec"},
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{restrictedContainer(profile, image, entry)},
			Volumes: []corev1.Volume{
				{Name: "scratch", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("64Mi"))}}},
			},
		},
	}
	if profile == "probe-runner" {
		p.Spec.Tolerations = []corev1.Toleration{
			execToleration(),
			{Key: startTaintKey, Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule},
			{Key: "node.kubernetes.io/not-ready", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
			{Key: "node.kubernetes.io/unreachable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoExecute},
			{Key: "node.kubernetes.io/disk-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			{Key: "node.kubernetes.io/memory-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			{Key: "node.kubernetes.io/pid-pressure", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
			{Key: "node.kubernetes.io/unschedulable", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule},
		}
	} else {
		p.Spec.RestartPolicy = corev1.RestartPolicyNever
		p.Spec.Tolerations = append([]corev1.Toleration{execToleration()}, defaultTolerationSeconds()...)
	}
	return p
}

// rolePod is a control-pool service Pod for agent-role-contract.
func rolePod(namespace, ksa, image string) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: ksa + "-0", Namespace: namespace, Labels: map[string]string{"app.kubernetes.io/name": ksa}},
		Spec: corev1.PodSpec{
			ServiceAccountName: ksa,
			SchedulerName:      "default-scheduler",
			RestartPolicy:      corev1.RestartPolicyAlways,
			NodeSelector:       map[string]string{roleLabel: "control"},
			Tolerations:        defaultTolerationSeconds(),
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr.To(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			Containers: []corev1.Container{restrictedContainer(ksa, image, "/app/bin/"+ksa)},
		},
	}
}

func startTaintToleration() corev1.Toleration {
	return corev1.Toleration{Key: startTaintKey, Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule}
}

func hostPathVol(name, path string) corev1.Volume {
	return corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: path}}}
}

// sensorPod is a privileged hostNetwork/hostPID agent-sensors DaemonSet Pod.
func sensorPod(ksa, image string, vols []corev1.Volume, mounts []corev1.VolumeMount) *corev1.Pod {
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: ksa + "-0", Namespace: "agent-sensors", Labels: map[string]string{"app.kubernetes.io/name": ksa}},
		Spec: corev1.PodSpec{
			ServiceAccountName: ksa,
			SchedulerName:      "default-scheduler",
			RestartPolicy:      corev1.RestartPolicyAlways,
			HostNetwork:        true,
			HostPID:            true,
			Tolerations:        []corev1.Toleration{execToleration(), startTaintToleration()},
			Containers: []corev1.Container{{
				Name: ksa, Image: image, VolumeMounts: mounts,
				SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
			}},
			Volumes: vols,
		},
	}
}

// recorderPod is the TASK-09 3.6 lifecycle-recorder Pod: the containerd
// socket only in containerd-proxy, cgroup (read-only) and spool in the
// recorder, the spool in the spool-owner init container, no hostNetwork.
func recorderPod() *corev1.Pod {
	p := sensorPod("lifecycle-recorder", recorderImage,
		[]corev1.Volume{hostPathVol("containerd", "/run/containerd/containerd.sock"), hostPathVol("cgroup", "/sys/fs/cgroup"), hostPathVol("spool", "/var/lib/agentarium/lifecycle-spool"),
			{Name: "proxy", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{Medium: corev1.StorageMediumMemory}}}},
		[]corev1.VolumeMount{{Name: "containerd", MountPath: "/run/containerd/containerd.sock"}, {Name: "proxy", MountPath: "/run/agentarium-containerd"}})
	p.Spec.HostNetwork, p.Spec.HostPID = false, false
	p.Spec.Containers[0].Name = "containerd-proxy"
	p.Spec.Containers[0].SecurityContext = unprivileged()
	nonRoot := unprivileged()
	nonRoot.RunAsNonRoot = ptr.To(true)
	p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "lifecycle-recorder", Image: recorderImage, SecurityContext: nonRoot,
		VolumeMounts: []corev1.VolumeMount{{Name: "cgroup", MountPath: "/host/sys/fs/cgroup", ReadOnly: true}, {Name: "spool", MountPath: "/var/lib/agentarium/lifecycle-spool"}, {Name: "proxy", MountPath: "/run/agentarium-containerd"}}})
	chown := unprivileged()
	chown.Capabilities.Add = []corev1.Capability{"CHOWN"}
	p.Spec.InitContainers = []corev1.Container{{Name: "spool-owner", Image: recorderImage, SecurityContext: chown,
		VolumeMounts: []corev1.VolumeMount{{Name: "spool", MountPath: "/var/lib/agentarium/lifecycle-spool"}}}}
	return p
}

func tetragonPod() *corev1.Pod {
	var vols []corev1.Volume
	var mounts []corev1.VolumeMount
	for i, p := range tetragonHostPaths {
		name := string(rune('a'+i)) + "-host"
		vols = append(vols, hostPathVol(name, p))
		// /sys/fs/cgroup is read-only for every container (lifecycle rule).
		mounts = append(mounts, corev1.VolumeMount{Name: name, MountPath: "/host" + p, ReadOnly: p == "/sys/fs/cgroup"})
	}
	p := sensorPod("tetragon", tetragonImage, vols, mounts)
	var exporterMounts []corev1.VolumeMount
	for i, path := range tetragonHostPaths {
		switch path {
		case "/var/run/cilium/tetragon":
			exporterMounts = append(exporterMounts, corev1.VolumeMount{Name: mounts[i].Name, MountPath: path, ReadOnly: true})
		case "/var/lib/agentarium/sensor-spool":
			exporterMounts = append(exporterMounts, corev1.VolumeMount{Name: mounts[i].Name, MountPath: path})
		case "/proc", "/sys/fs/cgroup":
			// Node nonce responder host reads (TASK-01 3.2.1): all three
			// options explicit.
			exporterMounts = append(exporterMounts, hostReadMount(mounts[i].Name, "/host"+path))
		}
	}
	p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "exporter", Image: exporterImage, VolumeMounts: exporterMounts, SecurityContext: unprivileged()})
	return p
}

// hostReadMount is the exporter's host /proc or /sys/fs/cgroup mount:
// readOnly, recursiveReadOnly Enabled, mountPropagation None.
func hostReadMount(name, path string) corev1.VolumeMount {
	return corev1.VolumeMount{Name: name, MountPath: path, ReadOnly: true,
		RecursiveReadOnly: ptr.To(corev1.RecursiveReadOnlyEnabled), MountPropagation: ptr.To(corev1.MountPropagationNone)}
}

// unprivileged is the securityContext every non-tetragon container of the
// tetragon Pod must carry (no privileged, no escalation, no added caps).
func unprivileged() *corev1.SecurityContext {
	return &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}}
}

func netpolPod(logReadOnly bool) *corev1.Pod {
	return sensorPod("netpol-collector", netpolImage,
		[]corev1.Volume{hostPathVol("policy-log", "/var/log/network"), hostPathVol("spool", "/var/lib/agentarium/netpol-spool")},
		[]corev1.VolumeMount{
			{Name: "policy-log", MountPath: "/var/log/network", ReadOnly: logReadOnly},
			{Name: "spool", MountPath: "/var/lib/agentarium/netpol-spool"},
		})
}

func create(ns string, p *corev1.Pod) req {
	return req{op: admission.Create, namespace: ns, name: p.Name, resource: "pods", obj: p}
}

// ---- section 7 "placement bypass (Admission)" and the 3.3 admission variants

func TestExecRuntimeContract(t *testing.T) {
	c := newCluster(t, sampleRender())
	guarded := sampleRender()
	guarded["GUARDED_RUNTIME_ENABLED"] = "true"
	cg := newCluster(t, guarded)

	t.Run("valid runtime Pod", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-exec", runtimePod())))
	})

	cases := []struct {
		name   string
		mutate func(*corev1.Pod)
		want   []string
	}{
		{"control pool nodeSelector", func(p *corev1.Pod) { p.Spec.NodeSelector[roleLabel] = "control" },
			[]string{"agent-exec-contract:EXEC_PLACEMENT_INVALID"}},
		{"direct nodeName", func(p *corev1.Pod) { p.Spec.NodeName = "gke-control-1" },
			[]string{"agent-exec-contract:EXEC_PLACEMENT_INVALID"}},
		{"other scheduler", func(p *corev1.Pod) { p.Spec.SchedulerName = "custom" },
			[]string{"agent-exec-contract:EXEC_PLACEMENT_INVALID"}},
		{"hostNetwork", func(p *corev1.Pod) { p.Spec.HostNetwork = true },
			[]string{"PSA:host namespaces"}},
		{"privileged", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.Privileged = ptr.To(true) },
			[]string{"PSA:privileged"}},
		{"runtimeClass outside allowlist", func(p *corev1.Pod) { p.Spec.RuntimeClassName = ptr.To("gvisor") },
			[]string{"agent-exec-contract:EXEC_RUNTIME_INVALID"}},
		{"agentarium-guarded without gate record", func(p *corev1.Pod) { p.Spec.RuntimeClassName = ptr.To("agentarium-guarded") },
			[]string{"agent-exec-contract:EXEC_RUNTIME_INVALID"}},
		{"start taint toleration", func(p *corev1.Pod) { p.Spec.Tolerations = append(p.Spec.Tolerations, startTaintToleration()) },
			[]string{"agent-exec-contract:EXEC_TOLERATION_INVALID"}},
		{"not-ready toleration over 300s", func(p *corev1.Pod) { p.Spec.Tolerations[1].TolerationSeconds = ptr.To[int64](301) },
			[]string{"agent-exec-contract:EXEC_TOLERATION_INVALID"}},
		{"Secret volume", func(p *corev1.Pod) {
			p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "s", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "x"}}})
		}, []string{"agent-exec-contract:EXEC_SECRET_OR_VOLUME_INVALID"}},
		{"other image digest", func(p *corev1.Pod) { p.Spec.Containers[0].Image = reg + "runtime@" + digestD },
			[]string{"agent-exec-contract:EXEC_IMAGE_OR_ENTRYPOINT_INVALID"}},
		{"token automount", func(p *corev1.Pod) { p.Spec.AutomountServiceAccountToken = ptr.To(true) },
			[]string{"agent-exec-contract:EXEC_IDENTITY_INVALID"}},
		{"other projected token audience", func(p *corev1.Pod) {
			p.Spec.Volumes[1].Projected.Sources[0].ServiceAccountToken.Audience = "https://kubernetes.default.svc"
		}, []string{"agent-exec-contract:EXEC_SECRET_OR_VOLUME_INVALID"}},
		{"NRI bypass annotation", func(p *corev1.Pod) { p.Annotations = map[string]string{nriAnnotationKey: "true"} },
			[]string{"agent-exec-contract:EXEC_ANNOTATION_FORBIDDEN"}},
		{"resources removed (VAP only, before LimitRanger defaulting)", func(p *corev1.Pod) { p.Spec.Containers[0].Resources = corev1.ResourceRequirements{} },
			[]string{"agent-exec-contract:EXEC_RESOURCES_REQUIRED"}},
		{"init container", func(p *corev1.Pod) {
			p.Spec.InitContainers = []corev1.Container{restrictedContainer("init", runtimeImage, "/app/bin/agent-runtime")}
		}, []string{"agent-exec-contract:EXEC_CONTAINER_SET_INVALID"}},
		{"priority class missing", func(p *corev1.Pod) { p.Spec.PriorityClassName = "" },
			[]string{"agent-exec-contract:EXEC_PRIORITY_CLASS_INVALID"}},
		{"writable rootfs", func(p *corev1.Pod) { p.Spec.Containers[0].SecurityContext.ReadOnlyRootFilesystem = ptr.To(false) },
			[]string{"agent-exec-contract:EXEC_FILESYSTEM_INVALID"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := runtimePod()
			tc.mutate(p)
			expectExactly(t, c.admit(t, create("agent-exec", p)), tc.want...)
		})
	}

	t.Run("agentarium-guarded with gate record", func(t *testing.T) {
		p := runtimePod()
		p.Spec.RuntimeClassName = ptr.To("agentarium-guarded")
		expectExactly(t, cg.admit(t, create("agent-exec", p)))
	})

	t.Run("ephemeral container added via subresource", func(t *testing.T) {
		old := runtimePod()
		p := runtimePod()
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: runtimeImage}}}
		r := req{op: admission.Update, namespace: "agent-exec", name: p.Name, resource: "pods", subresource: "ephemeralcontainers", obj: p, old: old}
		expectExactly(t, c.admit(t, r), "agent-exec-contract:EXEC_CONTAINER_SET_INVALID")
	})

	// pods/status keeps metadata changes (only spec and ownerReferences are
	// reset), so it must not relabel a Pod into another profile's
	// NetworkPolicy podSelector or add a forbidden annotation.
	statusUpdate := func(old, p *corev1.Pod) req {
		return req{op: admission.Update, namespace: "agent-exec", name: p.Name, resource: "pods", subresource: "status", obj: p, old: old}
	}
	t.Run("relabel runtime Pod via pods/status", func(t *testing.T) {
		p := runtimePod()
		p.Labels["app.kubernetes.io/name"] = "probe-runner"
		expectExactly(t, c.admit(t, statusUpdate(runtimePod(), p)),
			"agent-exec-profile:EXEC_ROLE_LABEL_INVALID", "agent-exec-profile:EXEC_STATUS_METADATA_IMMUTABLE")
	})
	t.Run("forbidden annotation via pods/status", func(t *testing.T) {
		p := runtimePod()
		p.Annotations = map[string]string{nriAnnotationKey: "true"}
		expectExactly(t, c.admit(t, statusUpdate(runtimePod(), p)), "agent-exec-profile:EXEC_STATUS_METADATA_IMMUTABLE")
	})
	t.Run("resize runtime Pod resources", func(t *testing.T) {
		old := runtimePod()
		p := runtimePod()
		p.Spec.Containers[0].Resources.Limits[corev1.ResourceCPU] = resource.MustParse("16")
		r := req{op: admission.Update, namespace: "agent-exec", name: p.Name, resource: "pods", subresource: "resize", obj: p, old: old}
		expectExactly(t, c.admit(t, r), "agent-exec-profile:EXEC_RESIZE_FORBIDDEN")
	})
	t.Run("kubelet status update of a Pod admitted under an older runtime image", func(t *testing.T) {
		old := runtimePod()
		old.Spec.Containers[0].Image = reg + "runtime@" + digestD
		p := old.DeepCopy()
		p.Status.Phase = corev1.PodRunning
		expectExactly(t, c.admit(t, statusUpdate(old, p)))
	})

	// Same rule for the role and sensors Namespaces (agent-role-status-metadata).
	roleStatus := func(ns string, old, p *corev1.Pod) req {
		return req{op: admission.Update, namespace: ns, name: p.Name, resource: "pods", subresource: "status", obj: p, old: old}
	}
	t.Run("relabel role Pod via pods/status", func(t *testing.T) {
		old := rolePod("agent-control", "policy-gateway", gatewayImage)
		p := old.DeepCopy()
		p.Labels["app.kubernetes.io/name"] = "workload-identity"
		expectExactly(t, c.admit(t, roleStatus("agent-control", old, p)), "agent-role-status-metadata:ROLE_STATUS_METADATA_IMMUTABLE")
	})
	t.Run("annotation added to a sensor Pod via pods/status", func(t *testing.T) {
		old := tetragonPod()
		p := old.DeepCopy()
		p.Annotations = map[string]string{"example.com/x": "y"}
		expectExactly(t, c.admit(t, roleStatus("agent-sensors", old, p)), "agent-role-status-metadata:ROLE_STATUS_METADATA_IMMUTABLE")
	})
	t.Run("kubelet status update of a role Pod", func(t *testing.T) {
		old := rolePod("agent-control", "policy-gateway", gatewayImage)
		p := old.DeepCopy()
		p.Status.Phase = corev1.PodRunning
		expectExactly(t, c.admit(t, roleStatus("agent-control", old, p)))
	})

	t.Run("sensor host privileges are not available in agent-exec", func(t *testing.T) {
		p := tetragonPod()
		p.Namespace = "agent-exec"
		got := c.admit(t, create("agent-exec", p))
		for _, w := range []string{"PSA:privileged", "PSA:host namespaces", "PSA:restricted volume types", "agent-exec-profile:EXEC_ROLE_LABEL_INVALID"} {
			if !got.has(w) {
				t.Errorf("missing %s in %s", w, fmtResult(got))
			}
		}
	})
}

// ---- section 7 "exec profile separation" ---------------------------------------

func TestExecProfileSeparation(t *testing.T) {
	c := newCluster(t, sampleRender())

	t.Run("valid probe runner DaemonSet Pod", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-exec", probePod("probe-runner"))))
	})
	t.Run("valid start fixture Pod", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-exec", probePod("start-fixture"))))
	})
	t.Run("runtime label with probe image", func(t *testing.T) {
		p := runtimePod()
		p.Spec.Containers[0].Image = probeImage
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-contract:EXEC_IMAGE_OR_ENTRYPOINT_INVALID")
	})
	t.Run("probe label with runtime SA", func(t *testing.T) {
		p := probePod("probe-runner")
		p.Spec.ServiceAccountName = "agent-runtime"
		expectExactly(t, c.admit(t, create("agent-exec", p)),
			"agent-exec-profile:EXEC_ROLE_LABEL_INVALID", "agent-exec-probe-contract:PROBE_IDENTITY_INVALID")
	})
	t.Run("fixture with restartPolicy Always", func(t *testing.T) {
		p := probePod("start-fixture")
		p.Spec.RestartPolicy = corev1.RestartPolicyAlways
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-probe-contract:FIXTURE_RESTART_POLICY_INVALID")
	})
	t.Run("probe runner with fixture image", func(t *testing.T) {
		p := probePod("probe-runner")
		p.Spec.Containers[0].Image = fixtureImage
		p.Spec.Containers[0].Command = []string{fixtureEntry}
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-probe-contract:PROBE_IMAGE_OR_ENTRYPOINT_INVALID")
	})
	t.Run("probe runner with mismatched image/entrypoint pair", func(t *testing.T) {
		p := probePod("probe-runner")
		p.Spec.Containers[0].Command = []string{fixtureEntry}
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-probe-contract:PROBE_IMAGE_OR_ENTRYPOINT_INVALID")
	})
	t.Run("fixture may not tolerate the start taint", func(t *testing.T) {
		p := probePod("start-fixture")
		p.Spec.Tolerations = append(p.Spec.Tolerations, startTaintToleration())
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-probe-contract:PROBE_TOLERATION_INVALID")
	})
	t.Run("probe runner may not take the runtime priority class", func(t *testing.T) {
		p := probePod("probe-runner")
		p.Spec.PriorityClassName = "agentarium-runtime"
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-probe-contract:PROBE_IDENTITY_INVALID")
	})
	t.Run("unknown profile label", func(t *testing.T) {
		p := probePod("probe-runner")
		p.Labels["app.kubernetes.io/name"] = "debug"
		p.Spec.ServiceAccountName = "debug"
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-profile:EXEC_ROLE_LABEL_INVALID")
	})
}

// ---- agent-role-contract (3.2) and the "bootstrap order" adapter rule ---------

func TestRoleContract(t *testing.T) {
	c := newCluster(t, sampleRender())

	t.Run("control service on control pool", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-control", rolePod("agent-control", "policy-gateway", gatewayImage))))
	})
	t.Run("control bootstrap Pod may tolerate the start taint", func(t *testing.T) {
		p := rolePod("agent-control", "node-readiness", gatewayImage)
		p.Spec.Tolerations = append(p.Spec.Tolerations, startTaintToleration())
		expectExactly(t, c.admit(t, create("agent-control", p)))
	})
	t.Run("adapter with start taint toleration", func(t *testing.T) {
		p := rolePod("agent-adapters", "kubernetes-reader", adapterImage)
		p.Spec.Tolerations = append(p.Spec.Tolerations, startTaintToleration())
		expectExactly(t, c.admit(t, create("agent-adapters", p)), "agent-role-contract:ROLE_ADAPTER_BOOTSTRAP_TOLERATION_FORBIDDEN")
	})
	t.Run("adapters probe runner may tolerate the start taint", func(t *testing.T) {
		p := rolePod("agent-adapters", "probe-runner", probeImage)
		p.Spec.Tolerations = append(p.Spec.Tolerations, startTaintToleration())
		expectExactly(t, c.admit(t, create("agent-adapters", p)))
	})
	t.Run("control service selecting exec pool", func(t *testing.T) {
		p := rolePod("agent-control", "policy-gateway", gatewayImage)
		p.Spec.NodeSelector[roleLabel] = "exec"
		expectExactly(t, c.admit(t, create("agent-control", p)), "agent-role-contract:ROLE_PLACEMENT_INVALID")
	})
	t.Run("image from another Namespace list", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-control", rolePod("agent-control", "policy-gateway", adapterImage))),
			"agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
	})
	t.Run("label differs from SA", func(t *testing.T) {
		p := rolePod("agent-control", "policy-gateway", gatewayImage)
		p.Spec.ServiceAccountName = "credential-broker"
		expectExactly(t, c.admit(t, create("agent-control", p)), "agent-role-contract:ROLE_LABEL_OR_PRIORITY_INVALID")
	})
	t.Run("runtime priority class outside agent-exec", func(t *testing.T) {
		p := rolePod("agent-control", "policy-gateway", gatewayImage)
		p.Spec.PriorityClassName = "agentarium-runtime"
		expectExactly(t, c.admit(t, create("agent-control", p)), "agent-role-contract:ROLE_LABEL_OR_PRIORITY_INVALID")
	})
	t.Run("missing param key fails closed", func(t *testing.T) {
		c2 := newCluster(t, sampleRender())
		delete(c2.configMaps["agent-control/agent-role-constraints"].Data, "agent-targets.images")
		got := c2.admit(t, create("agent-targets", rolePod("agent-targets", "receiver", sqlProxyImage)))
		if len(got) != 1 || !strings.HasPrefix(got[0], "agent-role-contract:ERROR:") {
			t.Errorf("want a single fail-closed evaluation error, got %s", fmtResult(got))
		}
	})
}

// ---- section 7 "node-readiness scope" ------------------------------------

func readinessNode(withStartTaint bool) *corev1.Node {
	taints := []corev1.Taint{{Key: "agentarium-role", Value: "exec", Effect: corev1.TaintEffectNoSchedule}}
	if withStartTaint {
		taints = append(taints, corev1.Taint{Key: startTaintKey, Value: "true", Effect: corev1.TaintEffectNoSchedule})
	}
	taints = append(taints, corev1.Taint{Key: "example.com/maintenance", Value: "x", Effect: corev1.TaintEffectPreferNoSchedule})
	return &corev1.Node{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Node"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        "gke-exec-1",
			Labels:      map[string]string{roleLabel: "exec", "kubernetes.io/hostname": "gke-exec-1"},
			Annotations: map[string]string{"node.alpha.kubernetes.io/ttl": "0"},
		},
		Spec: corev1.NodeSpec{Taints: taints},
	}
}

const readinessSA = "system:serviceaccount:agent-control:node-readiness"

func nodeUpdate(old, obj *corev1.Node, user string) req {
	return req{op: admission.Update, name: obj.Name, resource: "nodes", obj: obj, old: old, username: user}
}

func TestNodeReadinessScope(t *testing.T) {
	c := newCluster(t, sampleRender())

	t.Run("remove start taint", func(t *testing.T) {
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), readinessNode(false), readinessSA)))
	})
	t.Run("re-add start taint", func(t *testing.T) {
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(false), readinessNode(true), readinessSA)))
	})
	deny := "node-readiness-scope:NODE_READINESS_SCOPE_INVALID"
	t.Run("add another taint", func(t *testing.T) {
		n := readinessNode(false)
		n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: "other", Effect: corev1.TaintEffectNoSchedule})
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("change protected label", func(t *testing.T) {
		n := readinessNode(true)
		n.Labels[roleLabel] = "control"
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("change annotation", func(t *testing.T) {
		n := readinessNode(true)
		n.Annotations["x"] = "y"
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("set unschedulable", func(t *testing.T) {
		n := readinessNode(true)
		n.Spec.Unschedulable = true
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("reorder other taints", func(t *testing.T) {
		n := readinessNode(false)
		n.Spec.Taints[0], n.Spec.Taints[1] = n.Spec.Taints[1], n.Spec.Taints[0]
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	// The SA may only toggle the start taint; every other writable Node field
	// must stay as it was.
	t.Run("set ownerReferences", func(t *testing.T) {
		n := readinessNode(true)
		n.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Namespace", Name: "gone", UID: "00000000-0000-0000-0000-000000000000"}}
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("add finalizer", func(t *testing.T) {
		n := readinessNode(true)
		n.Finalizers = []string{"example.com/block-delete"}
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("set providerID and podCIDR", func(t *testing.T) {
		n := readinessNode(true)
		n.Spec.ProviderID = "gce://other-project/zone/vm"
		n.Spec.PodCIDR = "10.0.0.0/24"
		n.Spec.PodCIDRs = []string{"10.0.0.0/24"}
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, readinessSA)), deny)
	})
	t.Run("add start-key taint with NoExecute effect", func(t *testing.T) {
		n := readinessNode(false)
		n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: startTaintKey, Value: "true", Effect: corev1.TaintEffectNoExecute})
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(false), n, readinessSA)), deny)
	})
	t.Run("add start-key taint with another value", func(t *testing.T) {
		n := readinessNode(false)
		n.Spec.Taints = append(n.Spec.Taints, corev1.Taint{Key: startTaintKey, Value: "x", Effect: corev1.TaintEffectNoSchedule})
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(false), n, readinessSA)), deny)
	})
	t.Run("pre-existing non-canonical start-key taint may stay", func(t *testing.T) {
		old := readinessNode(true)
		old.Spec.Taints = append(old.Spec.Taints, corev1.Taint{Key: startTaintKey, Value: "x", Effect: corev1.TaintEffectNoExecute})
		n := old.DeepCopy()
		n.Spec.Taints = append(n.Spec.Taints[:1], n.Spec.Taints[2:]...)
		expectExactly(t, c.admit(t, nodeUpdate(old, n, readinessSA)))
	})
	// Only exec and control Nodes are in scope; system-pool Nodes never get
	// the start taint.
	t.Run("add start taint to a system-pool node", func(t *testing.T) {
		old := readinessNode(false)
		old.Labels[roleLabel] = "system"
		n := readinessNode(true)
		n.Labels[roleLabel] = "system"
		expectExactly(t, c.admit(t, nodeUpdate(old, n, readinessSA)), deny)
	})
	t.Run("add start taint to a node without the role label", func(t *testing.T) {
		old := readinessNode(false)
		delete(old.Labels, roleLabel)
		n := readinessNode(true)
		delete(n.Labels, roleLabel)
		expectExactly(t, c.admit(t, nodeUpdate(old, n, readinessSA)), deny)
	})
	t.Run("toggle start taint on a control node", func(t *testing.T) {
		old := readinessNode(true)
		old.Labels[roleLabel] = "control"
		n := readinessNode(false)
		n.Labels[roleLabel] = "control"
		expectExactly(t, c.admit(t, nodeUpdate(old, n, readinessSA)))
	})
	t.Run("change label via nodes/status", func(t *testing.T) {
		n := readinessNode(true)
		n.Labels[roleLabel] = "control"
		r := nodeUpdate(readinessNode(true), n, readinessSA)
		r.subresource = "status"
		expectExactly(t, c.admit(t, r), deny)
	})
	t.Run("kubelet nodes/status update is out of scope", func(t *testing.T) {
		n := readinessNode(true)
		n.Status.Phase = corev1.NodeRunning
		r := nodeUpdate(readinessNode(true), n, "system:node:gke-exec-1")
		r.subresource = "status"
		expectExactly(t, c.admit(t, r))
	})
	t.Run("other users are out of scope", func(t *testing.T) {
		n := readinessNode(true)
		n.Labels[roleLabel] = "control"
		expectExactly(t, c.admit(t, nodeUpdate(readinessNode(true), n, "system:serviceaccount:agent-control:policy-gateway")))
	})
}

// ---- section 7 "sensors exception" -------------------------------------------

func TestSensorsContract(t *testing.T) {
	c := newCluster(t, sampleRender())

	t.Run("tetragon with exporter sidecar and lock hostPaths", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-sensors", tetragonPod())))
	})
	t.Run("netpol-collector read-only log and spool", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-sensors", netpolPod(true))))
	})
	t.Run("lifecycle-recorder socket only in containerd-proxy", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-sensors", recorderPod())))
	})
	t.Run("lifecycle-recorder writable cgroup", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Containers[1].VolumeMounts[0].ReadOnly = false
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_HOSTPATH_NOT_READ_ONLY")
	})
	t.Run("recorder container mounts the containerd socket", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "containerd", MountPath: "/run/containerd/containerd.sock"})
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINERD_SOCKET_MOUNT_INVALID")
	})
	t.Run("renamed proxy container mounts the containerd socket", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Containers[0].Name = "proxy"
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINERD_SOCKET_MOUNT_INVALID", "agent-sensors-contract:SENSORS_RECORDER_PRIVILEGE_INVALID")
	})
	t.Run("containerd-proxy mounts another hostPath", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "spool", MountPath: "/spool"})
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINERD_SOCKET_MOUNT_INVALID", "agent-sensors-contract:SENSORS_RECORDER_PROXY_VOLUME_INVALID")
	})
	t.Run("init container mounts the containerd socket", func(t *testing.T) {
		p := recorderPod()
		p.Spec.InitContainers[0].VolumeMounts = append(p.Spec.InitContainers[0].VolumeMounts, corev1.VolumeMount{Name: "containerd", MountPath: "/run/containerd/containerd.sock"})
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINERD_SOCKET_MOUNT_INVALID")
	})
	t.Run("init container named containerd-proxy", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Containers = p.Spec.Containers[1:]
		p.Spec.InitContainers = append(p.Spec.InitContainers, corev1.Container{Name: "containerd-proxy", Image: recorderImage, SecurityContext: unprivileged(),
			VolumeMounts: []corev1.VolumeMount{{Name: "containerd", MountPath: "/run/containerd/containerd.sock"}}})
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINERD_SOCKET_MOUNT_INVALID")
	})
	t.Run("ephemeral container mounts the containerd socket", func(t *testing.T) {
		old := recorderPod()
		p := recorderPod()
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: recorderImage, SecurityContext: &corev1.SecurityContext{AllowPrivilegeEscalation: ptr.To(false), RunAsNonRoot: ptr.To(true)},
			VolumeMounts: []corev1.VolumeMount{{Name: "containerd", MountPath: "/run/containerd/containerd.sock"}}}}}
		r := req{op: admission.Update, namespace: "agent-sensors", name: p.Name, resource: "pods", subresource: "ephemeralcontainers", obj: p, old: old}
		expectExactly(t, c.admit(t, r), "agent-sensors-contract:SENSORS_CONTAINERD_SOCKET_MOUNT_INVALID")
	})
	recorderDenied := map[string]func(p *corev1.Pod){
		"hostPID":               func(p *corev1.Pod) { p.Spec.HostPID = true },
		"hostNetwork":           func(p *corev1.Pod) { p.Spec.HostNetwork = true },
		"shareProcessNamespace": func(p *corev1.Pod) { p.Spec.ShareProcessNamespace = ptr.To(true) },
		"privileged recorder":   func(p *corev1.Pod) { p.Spec.Containers[1].SecurityContext.Privileged = ptr.To(true) },
		"recorder may escalate": func(p *corev1.Pod) { p.Spec.Containers[1].SecurityContext.AllowPrivilegeEscalation = nil },
		"recorder adds SYS_PTRACE": func(p *corev1.Pod) {
			p.Spec.Containers[1].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_PTRACE"}
		},
		"recorder as root": func(p *corev1.Pod) { p.Spec.Containers[1].SecurityContext.RunAsNonRoot = nil },
		"proxy adds CHOWN": func(p *corev1.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"CHOWN"}
		},
		"spool-owner adds SYS_ADMIN": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"CHOWN", "SYS_ADMIN"}
		},
		"regular container named spool-owner": func(p *corev1.Pod) {
			p.Spec.InitContainers[0].Name = "init"
			p.Spec.Containers[1].Name = "spool-owner"
			p.Spec.Containers[1].SecurityContext.RunAsNonRoot = nil
		},
	}
	for name, mutate := range recorderDenied {
		t.Run("lifecycle-recorder Pod "+name, func(t *testing.T) {
			p := recorderPod()
			mutate(p)
			expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_RECORDER_PRIVILEGE_INVALID")
		})
	}
	t.Run("containerd-proxy mounts a projected token", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}}}}}})
		p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "token", MountPath: "/var/run/secrets/kubernetes.io/serviceaccount"})
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_RECORDER_PROXY_VOLUME_INVALID")
	})
	t.Run("runtime-guard NRI socket directory", func(t *testing.T) {
		p := sensorPod("runtime-guard", guardImage,
			[]corev1.Volume{hostPathVol("nri", "/var/run/nri")},
			[]corev1.VolumeMount{{Name: "nri", MountPath: "/var/run/nri"}})
		expectExactly(t, c.admit(t, create("agent-sensors", p)))
	})
	t.Run("netpol-collector writable /var/log/network", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-sensors", netpolPod(false))), "agent-sensors-contract:SENSORS_HOSTPATH_NOT_READ_ONLY")
	})
	t.Run("exporter writable export directory", func(t *testing.T) {
		p := tetragonPod()
		for i, m := range p.Spec.Containers[1].VolumeMounts {
			if m.MountPath == "/var/run/cilium/tetragon" {
				p.Spec.Containers[1].VolumeMounts[i].ReadOnly = false
			}
		}
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	for _, path := range []string{"/proc", "/sys/fs/cgroup"} {
		t.Run("exporter writable host "+path, func(t *testing.T) {
			p := tetragonPod()
			for i, m := range p.Spec.Containers[1].VolumeMounts {
				if m.MountPath == "/host"+path {
					p.Spec.Containers[1].VolumeMounts[i].ReadOnly = false
				}
			}
			want := []string{"agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID"}
			if path == "/sys/fs/cgroup" {
				want = append(want, "agent-sensors-contract:SENSORS_HOSTPATH_NOT_READ_ONLY")
			}
			expectExactly(t, c.admit(t, create("agent-sensors", p)), want...)
		})
	}
	// TASK-01 3.2.1: readOnly alone is not enough for host /proc and
	// /sys/fs/cgroup; every option must be explicit and exact.
	hostReadDenied := map[string]func(m *corev1.VolumeMount){
		"readOnly only":        func(m *corev1.VolumeMount) { m.RecursiveReadOnly, m.MountPropagation = nil, nil },
		"no recursiveReadOnly": func(m *corev1.VolumeMount) { m.RecursiveReadOnly = nil },
		"recursiveReadOnly IfPossible": func(m *corev1.VolumeMount) {
			m.RecursiveReadOnly = ptr.To(corev1.RecursiveReadOnlyIfPossible)
		},
		"recursiveReadOnly Disabled": func(m *corev1.VolumeMount) {
			m.RecursiveReadOnly = ptr.To(corev1.RecursiveReadOnlyDisabled)
		},
		"no mountPropagation": func(m *corev1.VolumeMount) { m.MountPropagation = nil },
		"HostToContainer propagation": func(m *corev1.VolumeMount) {
			m.MountPropagation = ptr.To(corev1.MountPropagationHostToContainer)
		},
	}
	for _, path := range []string{"/proc", "/sys/fs/cgroup"} {
		for name, mutate := range hostReadDenied {
			t.Run("exporter host "+path+" "+name, func(t *testing.T) {
				p := tetragonPod()
				for i := range p.Spec.Containers[1].VolumeMounts {
					if p.Spec.Containers[1].VolumeMounts[i].MountPath == "/host"+path {
						mutate(&p.Spec.Containers[1].VolumeMounts[i])
					}
				}
				expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
			})
		}
	}
	t.Run("ephemeral container mounts host /proc readOnly only", func(t *testing.T) {
		old := tetragonPod()
		p := tetragonPod()
		ro := p.Spec.Containers[1].VolumeMounts[0] // exporter /host/proc
		if ro.MountPath != "/host/proc" {
			t.Fatalf("fixture order changed: %s", ro.MountPath)
		}
		ro.RecursiveReadOnly, ro.MountPropagation = nil, nil
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: exporterImage, SecurityContext: unprivileged(), VolumeMounts: []corev1.VolumeMount{ro}}}}
		r := req{op: admission.Update, namespace: "agent-sensors", name: p.Name, resource: "pods", subresource: "ephemeralcontainers", obj: p, old: old}
		expectExactly(t, c.admit(t, r), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	t.Run("ephemeral container mounts host /proc with every option", func(t *testing.T) {
		old := tetragonPod()
		p := tetragonPod()
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: exporterImage, SecurityContext: unprivileged(), VolumeMounts: []corev1.VolumeMount{p.Spec.Containers[1].VolumeMounts[0]}}}}
		r := req{op: admission.Update, namespace: "agent-sensors", name: p.Name, resource: "pods", subresource: "ephemeralcontainers", obj: p, old: old}
		expectExactly(t, c.admit(t, r))
	})
	t.Run("tetragon container keeps the read-write /procRoot exception", func(t *testing.T) {
		p := tetragonPod()
		if p.Spec.Containers[0].VolumeMounts[0].ReadOnly || p.Spec.Containers[0].VolumeMounts[0].RecursiveReadOnly != nil {
			t.Fatal("fixture: tetragon /proc mount must be plain read-write")
		}
		expectExactly(t, c.admit(t, create("agent-sensors", p)))
	})
	t.Run("exporter mounts the cilium run directory", func(t *testing.T) {
		p := tetragonPod()
		ro := p.Spec.Containers[0].VolumeMounts[3] // /var/run/cilium
		ro.ReadOnly = true
		p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, ro)
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	t.Run("exporter is not given the Tetragon gRPC socket directory", func(t *testing.T) {
		p := tetragonPod()
		sock := p.Spec.Containers[0].VolumeMounts[5] // /var/run/tetragon
		sock.ReadOnly = true
		p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, sock)
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	t.Run("renamed exporter container is still limited", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[1].Name = "exporter2"
		p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, p.Spec.Containers[0].VolumeMounts[3])
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	t.Run("init container named exporter is limited", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.InitContainers = []corev1.Container{{Name: "exporter-init", Image: exporterImage, SecurityContext: unprivileged(), VolumeMounts: []corev1.VolumeMount{p.Spec.Containers[0].VolumeMounts[3]}}}
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	t.Run("ephemeral container is limited", func(t *testing.T) {
		old := tetragonPod()
		p := tetragonPod()
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: exporterImage, SecurityContext: unprivileged(), VolumeMounts: []corev1.VolumeMount{p.Spec.Containers[0].VolumeMounts[3]}}}}
		r := req{op: admission.Update, namespace: "agent-sensors", name: p.Name, resource: "pods", subresource: "ephemeralcontainers", obj: p, old: old}
		expectExactly(t, c.admit(t, r), "agent-sensors-contract:SENSORS_EXPORTER_MOUNT_INVALID")
	})
	t.Run("privileged exporter", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[1].SecurityContext.Privileged = ptr.To(true)
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINER_PRIVILEGE_INVALID")
	})
	t.Run("exporter without allowPrivilegeEscalation false", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[1].SecurityContext = nil
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINER_PRIVILEGE_INVALID")
	})
	t.Run("exporter adds SYS_ADMIN", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[1].SecurityContext.Capabilities.Add = []corev1.Capability{"SYS_ADMIN"}
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINER_PRIVILEGE_INVALID")
	})
	t.Run("privileged init container", func(t *testing.T) {
		p := tetragonPod()
		sc := unprivileged()
		sc.Privileged = ptr.To(true)
		p.Spec.InitContainers = []corev1.Container{{Name: "setup", Image: exporterImage, SecurityContext: sc}}
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_CONTAINER_PRIVILEGE_INVALID")
	})
	t.Run("second container runs the Tetragon image to remount", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[1].Image = tetragonImage
		p.Spec.Containers[1].Command = []string{"mount", "-o", "remount,rw", "/var/run/cilium/tetragon"}
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_TETRAGON_IMAGE_INVALID")
	})
	t.Run("tetragon container runs another sensor image", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[0].Image = exporterImage
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_TETRAGON_IMAGE_INVALID")
	})
	t.Run("BTF hostPath is no longer listed", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Volumes = append(p.Spec.Volumes, hostPathVol("btf", "/sys/kernel/btf"))
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_HOSTPATH_NOT_ALLOWED")
	})
	t.Run("hostPath outside the table", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Volumes = append(p.Spec.Volumes, hostPathVol("etc", "/etc"))
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_HOSTPATH_NOT_ALLOWED")
	})
	t.Run("hostPath of another sensor SA", func(t *testing.T) {
		p := recorderPod()
		p.Spec.Volumes = append(p.Spec.Volumes, hostPathVol("nri", "/var/run/nri"))
		p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "nri", MountPath: "/var/run/nri"})
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_HOSTPATH_NOT_ALLOWED")
	})
	t.Run("hostPath path variant is not normalized", func(t *testing.T) {
		p := netpolPod(true)
		p.Spec.Volumes[0].HostPath.Path = "/var/log/network/../../"
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_HOSTPATH_NOT_ALLOWED")
	})
	t.Run("image outside agent-sensors.images", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[1].Image = gatewayImage
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_IMAGE_NOT_ALLOWED")
	})
	t.Run("tag instead of digest", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.Containers[0].Image = reg + "tetragon:v1"
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_IMAGE_NOT_ALLOWED", "agent-sensors-contract:SENSORS_TETRAGON_IMAGE_INVALID")
	})
	t.Run("unapproved ephemeral container image", func(t *testing.T) {
		old := tetragonPod()
		p := tetragonPod()
		p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: reg + "busybox@" + digestD, SecurityContext: unprivileged()}}}
		r := req{op: admission.Update, namespace: "agent-sensors", name: p.Name, resource: "pods", subresource: "ephemeralcontainers", obj: p, old: old}
		expectExactly(t, c.admit(t, r), "agent-sensors-contract:SENSORS_IMAGE_NOT_ALLOWED")
	})
	t.Run("hostIPC", func(t *testing.T) {
		p := tetragonPod()
		p.Spec.HostIPC = true
		expectExactly(t, c.admit(t, create("agent-sensors", p)), "agent-sensors-contract:SENSORS_HOST_NAMESPACE_FORBIDDEN")
	})
	t.Run("unapproved SA", func(t *testing.T) {
		p := tetragonPod()
		p.Labels["app.kubernetes.io/name"] = "debug"
		p.Spec.ServiceAccountName = "debug"
		// allowedHostPaths is empty for an unknown SA, so the hostPath rule fires too.
		expectExactly(t, c.admit(t, create("agent-sensors", p)),
			"agent-sensors-contract:SENSORS_IDENTITY_INVALID", "agent-sensors-contract:SENSORS_HOSTPATH_NOT_ALLOWED")
	})
}
