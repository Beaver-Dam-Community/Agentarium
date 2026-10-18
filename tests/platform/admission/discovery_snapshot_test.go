package admission

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/utils/ptr"
)

const (
	discoveryUser  = "system:serviceaccount:agent-observe:discovery"
	snapshotKSA    = "discovery-snapshot"
	sourceDigest   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	jobControlUser = "system:serviceaccount:kube-system:job-controller"
)

// snapshotPodSpec mirrors KubernetesJobs.job_manifest in
// services/discovery/src/agentarium_discovery/clients.py.
func snapshotPodSpec() corev1.PodSpec {
	return corev1.PodSpec{
		ServiceAccountName:           snapshotKSA,
		AutomountServiceAccountToken: ptr.To(false),
		RestartPolicy:                corev1.RestartPolicyNever,
		SchedulerName:                "default-scheduler",
		NodeSelector:                 map[string]string{roleLabel: "control"},
		Tolerations:                  defaultTolerationSeconds(),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot: ptr.To(true), RunAsUser: ptr.To[int64](65532), RunAsGroup: ptr.To[int64](65532),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:  "scanner",
			Image: snapshotImage,
			Args: []string{"--language", "python", "--source-uri", "gs://" + discoveryBucket + "/sources/" + sourceDigest + ".tar.gz",
				"--source-digest", sourceDigest, "--library", "httpx", "--library-version", "0.27.0",
				"--out-root", "gs://" + discoveryBucket, "--work-dir", "/work"},
			SecurityContext: &corev1.SecurityContext{
				ReadOnlyRootFilesystem: ptr.To(true), AllowPrivilegeEscalation: ptr.To(false),
				Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
			VolumeMounts: []corev1.VolumeMount{{Name: "work", MountPath: "/work"}},
		}},
		Volumes: []corev1.Volume{{Name: "work", VolumeSource: corev1.VolumeSource{
			EmptyDir: &corev1.EmptyDirVolumeSource{SizeLimit: ptr.To(resource.MustParse("2Gi"))}}}},
	}
}

func snapshotJob(mutate func(*corev1.PodSpec)) *batchv1.Job {
	spec := snapshotPodSpec()
	if mutate != nil {
		mutate(&spec)
	}
	ksa := spec.ServiceAccountName
	return &batchv1.Job{
		TypeMeta:   metav1.TypeMeta{APIVersion: "batch/v1", Kind: "Job"},
		ObjectMeta: metav1.ObjectMeta{Name: "discovery-snapshot-01234567-abcdef", Namespace: "agent-observe"},
		Spec: batchv1.JobSpec{
			BackoffLimit: ptr.To[int32](0),
			Template: corev1.PodTemplateSpec{
				// The Job API adds these selector labels before validation.
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{
					"app.kubernetes.io/name": ksa, "batch.kubernetes.io/job-name": "discovery-snapshot-01234567-abcdef",
					"job-name": "discovery-snapshot-01234567-abcdef", "controller-uid": "11111111-1111-4111-8111-111111111111"}},
				Spec: spec,
			},
		},
	}
}

func snapshotPod(mutate func(*corev1.PodSpec)) *corev1.Pod {
	job := snapshotJob(mutate)
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-x1", Namespace: "agent-observe", Labels: job.Spec.Template.Labels},
		Spec:       job.Spec.Template.Spec,
	}
}

func execHandler() *corev1.LifecycleHandler {
	return &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-c", "id"}}}
}

func execProbe() *corev1.Probe {
	return &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"/bin/sh", "-c", "id"}}}}
}

func createJob(j *batchv1.Job, user string) req {
	return req{op: admission.Create, namespace: j.Namespace, name: j.Name, resource: "jobs", obj: j, username: user}
}

func TestDiscoverySnapshotShape(t *testing.T) {
	c := newCluster(t, sampleRender())
	const p = "discovery-snapshot-job:"

	t.Run("discovery Job as built by the service", func(t *testing.T) {
		expectExactly(t, c.admit(t, createJob(snapshotJob(nil), discoveryUser)))
	})
	t.Run("its Pod created by the job controller", func(t *testing.T) {
		pod := snapshotPod(nil)
		expectExactly(t, c.admit(t, req{op: admission.Create, namespace: "agent-observe", name: pod.Name,
			resource: "pods", obj: pod, username: jobControlUser}))
	})

	rejected := []struct {
		name   string
		mutate func(*corev1.PodSpec)
		want   []string
	}{
		{"runs as audit-writer", func(s *corev1.PodSpec) { s.ServiceAccountName = "audit-writer" },
			[]string{p + "SNAPSHOT_IDENTITY_INVALID", p + "SNAPSHOT_LABEL_INVALID"}},
		{"API token automount", func(s *corev1.PodSpec) { s.AutomountServiceAccountToken = ptr.To(true) },
			[]string{p + "SNAPSHOT_IDENTITY_INVALID"}},
		{"projected token volume", func(s *corev1.PodSpec) {
			s.Volumes = append(s.Volumes, corev1.Volume{Name: "token", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token", Audience: "agentarium-identity"}}}}}})
			s.Containers[0].VolumeMounts = append(s.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "token", MountPath: "/var/run/token"})
		}, []string{p + "SNAPSHOT_VOLUMES_INVALID"}},
		{"extra secret volume", func(s *corev1.PodSpec) {
			s.Volumes = append(s.Volumes, corev1.Volume{Name: "s", VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "x"}}})
		}, []string{p + "SNAPSHOT_VOLUMES_INVALID"}},
		{"hostPath instead of emptyDir", func(s *corev1.PodSpec) {
			s.Volumes[0].VolumeSource = corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/"}}
		},
			[]string{p + "SNAPSHOT_VOLUMES_INVALID"}},
		{"work mount elsewhere", func(s *corev1.PodSpec) { s.Containers[0].VolumeMounts[0].MountPath = "/etc" },
			[]string{p + "SNAPSHOT_VOLUMES_INVALID"}},
		{"another listed image", func(s *corev1.PodSpec) { s.Containers[0].Image = auditImage },
			[]string{p + "SNAPSHOT_IMAGE_INVALID"}},
		{"second container", func(s *corev1.PodSpec) {
			s.Containers = append(s.Containers, s.Containers[0])
			s.Containers[1].Name = "x"
		},
			[]string{p + "SNAPSHOT_IMAGE_INVALID"}},
		{"init container", func(s *corev1.PodSpec) { s.InitContainers = []corev1.Container{s.Containers[0]} },
			[]string{p + "SNAPSHOT_IMAGE_INVALID"}},
		{"command override", func(s *corev1.PodSpec) { s.Containers[0].Command = []string{"/bin/sh", "-c"} },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"environment", func(s *corev1.PodSpec) { s.Containers[0].Env = []corev1.EnvVar{{Name: "X", Value: "y"}} },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"other bucket output", func(s *corev1.PodSpec) { s.Containers[0].Args[11] = "gs://other-bucket" },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"source digest mismatch", func(s *corev1.PodSpec) { s.Containers[0].Args[5] = strings.Repeat("f", 64) },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"non-gs source", func(s *corev1.PodSpec) { s.Containers[0].Args[3] = "https://example.com/x.tar.gz" },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"flag injected as library", func(s *corev1.PodSpec) { s.Containers[0].Args[7] = "--out-root" },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"extra argument", func(s *corev1.PodSpec) { s.Containers[0].Args = append(s.Containers[0].Args, "--debug") },
			[]string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"host network", func(s *corev1.PodSpec) { s.HostNetwork = true },
			[]string{p + "SNAPSHOT_POD_INVALID"}},
		{"postStart exec hook", func(s *corev1.PodSpec) {
			s.Containers[0].Lifecycle = &corev1.Lifecycle{PostStart: execHandler()}
		}, []string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"preStop exec hook", func(s *corev1.PodSpec) {
			s.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: execHandler()}
		}, []string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"liveness exec probe", func(s *corev1.PodSpec) { s.Containers[0].LivenessProbe = execProbe() },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"readiness exec probe", func(s *corev1.PodSpec) { s.Containers[0].ReadinessProbe = execProbe() },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"startup exec probe", func(s *corev1.PodSpec) { s.Containers[0].StartupProbe = execProbe() },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"envFrom", func(s *corev1.PodSpec) {
			s.Containers[0].EnvFrom = []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "x"}}}}
		}, []string{p + "SNAPSHOT_ARGS_INVALID"}},
		{"workingDir", func(s *corev1.PodSpec) { s.Containers[0].WorkingDir = "/tmp" },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"stdin", func(s *corev1.PodSpec) { s.Containers[0].Stdin = true },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"stdinOnce", func(s *corev1.PodSpec) { s.Containers[0].StdinOnce = true },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"tty", func(s *corev1.PodSpec) { s.Containers[0].TTY = true },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"ports", func(s *corev1.PodSpec) { s.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 8080}} },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"resizePolicy", func(s *corev1.PodSpec) {
			s.Containers[0].ResizePolicy = []corev1.ContainerResizePolicy{{ResourceName: corev1.ResourceCPU, RestartPolicy: corev1.NotRequired}}
		}, []string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"container restartPolicy", func(s *corev1.PodSpec) { s.Containers[0].RestartPolicy = ptr.To(corev1.ContainerRestartPolicyAlways) },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"termination message path", func(s *corev1.PodSpec) { s.Containers[0].TerminationMessagePath = "/work/msg" },
			[]string{p + "SNAPSHOT_CONTAINER_FIELDS_INVALID"}},
		{"volumeDevices", func(s *corev1.PodSpec) {
			s.Containers[0].VolumeDevices = []corev1.VolumeDevice{{Name: "work", DevicePath: "/dev/x"}}
		}, []string{p + "SNAPSHOT_VOLUMES_INVALID"}},
		{"privileged", func(s *corev1.PodSpec) { s.Containers[0].SecurityContext.Privileged = ptr.To(true) },
			[]string{p + "SNAPSHOT_SECURITY_CONTEXT_INVALID"}},
		{"runAsUser override", func(s *corev1.PodSpec) { s.Containers[0].SecurityContext.RunAsUser = ptr.To[int64](0) },
			[]string{p + "SNAPSHOT_SECURITY_CONTEXT_INVALID"}},
		{"added capability", func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.Capabilities.Add = []corev1.Capability{"NET_RAW"}
		},
			[]string{p + "SNAPSHOT_SECURITY_CONTEXT_INVALID"}},
		{"seccomp override", func(s *corev1.PodSpec) {
			s.Containers[0].SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
		}, []string{p + "SNAPSHOT_SECURITY_CONTEXT_INVALID"}},
		{"writable root filesystem", func(s *corev1.PodSpec) { s.Containers[0].SecurityContext.ReadOnlyRootFilesystem = ptr.To(false) },
			[]string{p + "SNAPSHOT_SECURITY_CONTEXT_INVALID"}},
		{"deprecated serviceAccount differs", func(s *corev1.PodSpec) { s.DeprecatedServiceAccount = "audit-writer" },
			[]string{p + "SNAPSHOT_POD_INVALID"}},
		{"shared process namespace", func(s *corev1.PodSpec) { s.ShareProcessNamespace = ptr.To(true) },
			[]string{p + "SNAPSHOT_POD_INVALID"}},
	}
	for _, tc := range rejected {
		t.Run("Job: "+tc.name, func(t *testing.T) {
			expectExactly(t, c.admit(t, createJob(snapshotJob(tc.mutate), discoveryUser)), tc.want...)
		})
	}
	// The Pod policy applies to any creator of a discovery-snapshot Pod.
	for _, tc := range rejected {
		if tc.name == "runs as audit-writer" {
			continue
		}
		t.Run("Pod: "+tc.name, func(t *testing.T) {
			pod := snapshotPod(tc.mutate)
			got := c.admit(t, req{op: admission.Create, namespace: "agent-observe", name: pod.Name, resource: "pods", obj: pod, username: jobControlUser})
			if !strings.Contains(strings.Join(got, ","), "discovery-snapshot-pod:") {
				t.Errorf("Pod not rejected by discovery-snapshot-pod: %s", fmtResult(got))
			}
		})
	}
	t.Run("manual selector", func(t *testing.T) {
		j := snapshotJob(nil)
		j.Spec.ManualSelector = ptr.To(true)
		j.Spec.Selector = &metav1.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "audit-writer"}}
		expectExactly(t, c.admit(t, createJob(j, discoveryUser)), p+"SNAPSHOT_SELECTOR_INVALID")
	})
	t.Run("manual selector explicitly false is allowed", func(t *testing.T) {
		j := snapshotJob(nil)
		j.Spec.ManualSelector = ptr.To(false)
		expectExactly(t, c.admit(t, createJob(j, discoveryUser)))
	})
	t.Run("Job label claims another KSA", func(t *testing.T) {
		j := snapshotJob(nil)
		j.Spec.Template.Labels["app.kubernetes.io/name"] = "audit-writer"
		expectExactly(t, c.admit(t, createJob(j, discoveryUser)), p+"SNAPSHOT_LABEL_INVALID")
	})
	t.Run("another creator's snapshot-identity Job is checked too", func(t *testing.T) {
		expectExactly(t, c.admit(t, createJob(snapshotJob(func(s *corev1.PodSpec) { s.Containers[0].Image = auditImage }), "platform-test")),
			p+"SNAPSHOT_IMAGE_INVALID")
	})
	t.Run("unrelated Jobs by other creators are out of scope", func(t *testing.T) {
		j := snapshotJob(func(s *corev1.PodSpec) { s.ServiceAccountName = "audit-exporter" })
		j.Spec.Template.Labels["app.kubernetes.io/name"] = "audit-exporter"
		expectExactly(t, c.admit(t, createJob(j, "platform-test")))
	})
	t.Run("Jobs outside agent-observe are not bound", func(t *testing.T) {
		j := snapshotJob(nil)
		j.Namespace = "agent-control"
		expectExactly(t, c.admit(t, createJob(j, discoveryUser)))
	})
	t.Run("empty snapshot image fails closed", func(t *testing.T) {
		v := sampleRender()
		v["DISCOVERY_SNAPSHOT_IMAGE"] = ""
		c2 := newCluster(t, v)
		expectExactly(t, c2.admit(t, createJob(snapshotJob(nil), discoveryUser)), p+"SNAPSHOT_IMAGE_INVALID")
	})
	t.Run("missing constraints ConfigMap fails closed", func(t *testing.T) {
		c2 := newCluster(t, sampleRender())
		delete(c2.configMaps, "agent-control/discovery-snapshot-constraints")
		expectExactly(t, c2.admit(t, createJob(snapshotJob(nil), discoveryUser)), "discovery-snapshot-job:PARAM_NOT_FOUND")
	})
}

// TestDiscoverySnapshotFieldAllowlist fails when the pinned k8s.io/api gains a
// Container or SecurityContext field that the snapshot policies neither allow
// nor require to be absent, so the CEL allowlist cannot silently go stale.
func TestDiscoverySnapshotFieldAllowlist(t *testing.T) {
	policy := readFile(t, "deploy/gcp/base/admission/discovery-snapshot.yaml")
	for _, tc := range []struct {
		typ     reflect.Type
		prefix  string
		allowed []string
	}{
		{reflect.TypeOf(corev1.Container{}), "c.", []string{
			"name", "image", "args", "resources", "volumeMounts", "securityContext", "imagePullPolicy",
			// checked through variables.s.containers[0] in the args and volume rules
			"command", "env", "envFrom", "volumeDevices",
			// Not in the 1.33 schema, so has() would raise a type-check warning
			// there; API validation accepts it only with restartPolicy, which
			// the policies forbid.
			"restartPolicyRules"}},
		{reflect.TypeOf(corev1.SecurityContext{}), "c.securityContext.", nil},
	} {
		for i := 0; i < tc.typ.NumField(); i++ {
			name, _, _ := strings.Cut(tc.typ.Field(i).Tag.Get("json"), ",")
			if slices.Contains(tc.allowed, name) {
				continue
			}
			if !strings.Contains(policy, "has("+tc.prefix+name+")") &&
				!strings.Contains(policy, "has(variables.s.containers[0]."+name+")") {
				t.Errorf("%s field %q is not covered by discovery-snapshot policies", tc.typ.Name(), name)
			}
		}
	}
}
