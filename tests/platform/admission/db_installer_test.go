package admission

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Images mirrored for the issue #123 installer Job. They are added to the
// agent-control allowlist only for the installation window.
var (
	migrateImage = reg + "migrate@" + digestC
	psqlImage    = reg + "postgres@" + digestD
)

// renderInstallerJob runs platform/gcp/scripts/render-db-installer-job.py with
// a fixture lock and in-memory migrations, and returns the Job's Pod as the
// Job controller would create it.
func renderInstallerJob(t *testing.T) *corev1.Pod {
	t.Helper()
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("r", sys.argv[1])
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
lock = {"project": {"id": "test-project", "location": "us"},
        "storage": {"cloudsql_instance": "test-project:us:agentarium"}}
out = r.render(lock, sys.argv[2], sys.argv[3], sys.argv[4], "db-installer@test-project.iam.gserviceaccount.com",
               "agentarium", "a" * 40, {"20261013161333_discovery_candidates.up.sql": "SELECT 1;"}, previous=None)
print(json.dumps(out["items"][2]))
`
	cmd := exec.Command("python3", "-c", script,
		filepath.Join(repoRoot, "platform/gcp/scripts/render-db-installer-job.py"), sqlProxyImage, migrateImage, psqlImage)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("render installer Job: %v", err)
	}
	var job batchv1.Job
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	tpl := job.Spec.Template
	pod := &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: job.Name + "-x", Namespace: job.Namespace, Labels: tpl.Labels, Annotations: tpl.Annotations},
		Spec:       tpl.Spec,
	}
	// Labels the Job controller adds, and the DefaultTolerationSeconds plugin.
	pod.Labels["batch.kubernetes.io/job-name"] = job.Name
	pod.Labels["job-name"] = job.Name
	pod.Spec.Tolerations = append(pod.Spec.Tolerations, defaultTolerationSeconds()...)
	return pod
}

func TestDBInstallerJobAdmission(t *testing.T) {
	pod := renderInstallerJob(t)
	t.Run("allowed once the installer images are allowlisted", func(t *testing.T) {
		values := sampleRender()
		values["AGENT_CONTROL_IMAGES"] += "," + migrateImage + "," + psqlImage
		expectExactly(t, newCluster(t, values).admit(t, create("agent-control", pod)))
	})
	t.Run("rejected without the allowlist addition", func(t *testing.T) {
		expectExactly(t, newCluster(t, sampleRender()).admit(t, create("agent-control", pod)),
			"agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
	})
	t.Run("rejected in another role Namespace", func(t *testing.T) {
		values := sampleRender()
		values["AGENT_CONTROL_IMAGES"] += "," + migrateImage + "," + psqlImage
		p := pod.DeepCopy()
		p.Namespace = "agent-observe"
		expectExactly(t, newCluster(t, values).admit(t, create("agent-observe", p)),
			"agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
	})
	t.Run("restricted Pod Security still applies to installer containers", func(t *testing.T) {
		values := sampleRender()
		values["AGENT_CONTROL_IMAGES"] += "," + migrateImage + "," + psqlImage
		p := pod.DeepCopy()
		p.Spec.InitContainers[2].SecurityContext.AllowPrivilegeEscalation = nil
		if got := newCluster(t, values).admit(t, create("agent-control", p)); len(got) != 1 || got[0] != "PSA:allowPrivilegeEscalation != false" {
			t.Errorf("want only the PSA allowPrivilegeEscalation violation, got %s", fmtResult(got))
		}
	})
}
