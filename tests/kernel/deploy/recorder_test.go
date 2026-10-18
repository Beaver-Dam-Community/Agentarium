package deploy

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	recorderImage  = reg + "/lifecycle-recorder@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	proxyImage     = reg + "/containerd-proxy@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	containerdSock = "/run/containerd/containerd.sock"
)

// The lifecycle-recorder DaemonSet (TASK-09 3.6, #207) renders and is admitted
// in agent-sensors. Only the containerd-proxy container has the containerd
// socket; the recorder is non-root on the Pod network with read-only
// /sys/fs/cgroup, the spool and the proxy socket, and is the only container
// with a ServiceAccount token.
func TestLifecycleRecorderDaemonSetIsAdmitted(t *testing.T) {
	raw := string(read(t, filepath.Join(repo, "deploy/gcp/sensors/lifecycle-recorder.yaml")))
	repl := strings.NewReplacer("${LIFECYCLE_RECORDER_IMAGE}", recorderImage, "${CONTAINERD_PROXY_IMAGE}", proxyImage, "${CLUSTER_UID}", "00000000-0000-4000-8000-000000000001", "${RECORDER_VERSION}", "sample")
	var lines []string
	for _, l := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			l = repl.Replace(l)
			if strings.Contains(l, "${") {
				t.Fatalf("unknown placeholder: %s", l)
			}
		}
		lines = append(lines, l)
	}
	typed, generic := decode(t, []byte(strings.Join(lines, "\n")))
	var ds *appsv1.DaemonSet
	var cm *corev1.ConfigMap
	var sa *corev1.ServiceAccount
	for _, o := range typed {
		switch o := o.(type) {
		case *appsv1.DaemonSet:
			ds = o
		case *corev1.ConfigMap:
			cm = o
		case *corev1.ServiceAccount:
			sa = o
		}
	}
	if ds == nil || cm == nil || sa == nil || len(generic) != 2 {
		t.Fatalf("objects ds=%v cm=%v other=%d", ds != nil, cm != nil, len(generic))
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cm.Data["config.json"]), &cfg); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if strings.Join(keys, ",") != "boot_id_path,ca_file,cgroup_root,cluster_uid,collector_origin,containerd_socket,health_origin,identity_origin,identity_peer_san,spool_capacity_bytes,spool_dir,token_file,version" {
		t.Fatalf("config keys %v", keys)
	}
	spec := ds.Spec.Template.Spec
	pod := &corev1.Pod{TypeMeta: metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"}, ObjectMeta: metav1.ObjectMeta{Name: "lifecycle-recorder-x", Namespace: "agent-sensors", Labels: ds.Spec.Template.Labels}, Spec: spec}
	if spec.HostNetwork || spec.HostPID || spec.AutomountServiceAccountToken == nil || *spec.AutomountServiceAccountToken {
		t.Fatal("recorder Pod must not use hostNetwork/hostPID or automount a token")
	}
	hostPaths := map[string]string{}
	tokens := map[string]bool{}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			hostPaths[v.Name] = v.HostPath.Path
		}
		if v.Projected != nil {
			for _, src := range v.Projected.Sources {
				if src.ServiceAccountToken != nil {
					tokens[v.Name] = true
				}
			}
		}
	}
	if cm.Data["config.json"] == "" || cfg["containerd_socket"] != "/run/agentarium-containerd/containerd.sock" {
		t.Fatalf("recorder must use the proxy socket: %v", cfg["containerd_socket"])
	}
	all := append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...)
	if len(spec.Containers) != 2 || spec.Containers[0].Name != "containerd-proxy" || spec.Containers[0].Image != proxyImage || spec.Containers[1].Name != "lifecycle-recorder" {
		t.Fatalf("containers %v", spec.Containers)
	}
	for _, c := range all {
		var mounted []string
		for _, m := range c.VolumeMounts {
			if p, ok := hostPaths[m.Name]; ok {
				mounted = append(mounted, p)
			}
			if tokens[m.Name] && c.Name != "lifecycle-recorder" {
				t.Errorf("%s mounts token volume %s", c.Name, m.Name)
			}
		}
		sort.Strings(mounted)
		sc := c.SecurityContext
		switch c.Name {
		case "containerd-proxy":
			if strings.Join(mounted, ",") != containerdSock || len(sc.Capabilities.Add) != 0 || len(c.Env) != 0 {
				t.Errorf("proxy hostPaths %v caps %v env %v", mounted, sc.Capabilities.Add, c.Env)
			}
			// Dropping every capability takes CAP_DAC_OVERRIDE and
			// CAP_DAC_READ_SEARCH from UID 0, so the execute-only binary of
			// the proxy image is non-dumpable from execve (TASK-09 3.6).
			if len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" {
				t.Errorf("proxy must drop ALL capabilities: %v", sc.Capabilities.Drop)
			}
		case "lifecycle-recorder":
			if strings.Join(mounted, ",") != "/sys/fs/cgroup,/var/lib/agentarium/lifecycle-spool" || sc.RunAsUser == nil || *sc.RunAsUser == 0 || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot || len(sc.Capabilities.Add) != 0 {
				t.Errorf("recorder hostPaths %v securityContext %+v", mounted, sc)
			}
		case "spool-owner":
			if strings.Join(mounted, ",") != "/var/lib/agentarium/lifecycle-spool" || len(sc.Capabilities.Add) != 1 || sc.Capabilities.Add[0] != "CHOWN" {
				t.Errorf("spool-owner hostPaths %v caps %v", mounted, sc.Capabilities.Add)
			}
		default:
			t.Errorf("unexpected container %s", c.Name)
		}
	}
	c := newCluster(t, "", recorderImage+","+proxyImage)
	if res := c.admit(t, pod); len(res) != 0 {
		t.Fatalf("lifecycle-recorder Pod denied: %v", res)
	}
	deny := func(name string, mutate func(p *corev1.Pod)) {
		p := pod.DeepCopy()
		mutate(p)
		if res := c.admit(t, p); len(res) == 0 {
			t.Errorf("%s admitted", name)
		}
	}
	deny("writable /sys/fs/cgroup", func(p *corev1.Pod) {
		for i, m := range p.Spec.Containers[1].VolumeMounts {
			if m.Name == "cgroup" {
				p.Spec.Containers[1].VolumeMounts[i].ReadOnly = false
			}
		}
	})
	deny("socket in the recorder container", func(p *corev1.Pod) {
		p.Spec.Containers[1].VolumeMounts = append(p.Spec.Containers[1].VolumeMounts, corev1.VolumeMount{Name: "containerd", MountPath: containerdSock})
	})
	deny("socket in the init container", func(p *corev1.Pod) {
		p.Spec.InitContainers[0].VolumeMounts = append(p.Spec.InitContainers[0].VolumeMounts, corev1.VolumeMount{Name: "containerd", MountPath: containerdSock})
	})
	deny("spool in the proxy container", func(p *corev1.Pod) {
		p.Spec.Containers[0].VolumeMounts = append(p.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "spool", MountPath: "/spool"})
	})
}

// The proxy image ships /app execute-only and root-owned, so UID 0 without
// capabilities cannot read it and execve leaves the process non-dumpable before
// main runs (TASK-09 3.6; checked on Linux by
// services/lifecycle-recorder/cmd/containerd-proxy TestNonDumpableFromExec).
func TestContainerdProxyImageIsExecuteOnly(t *testing.T) {
	df := string(read(t, filepath.Join(repo, "build/docker/containerd-proxy.Dockerfile")))
	for _, want := range []string{
		"-o /out/app ./services/lifecycle-recorder/cmd/containerd-proxy",
		"COPY --from=build --chown=0:0 --chmod=0111 /out/app /app",
		`ENTRYPOINT ["/app"]`,
	} {
		if !strings.Contains(df, want) {
			t.Errorf("containerd-proxy.Dockerfile lacks %q", want)
		}
	}
}
