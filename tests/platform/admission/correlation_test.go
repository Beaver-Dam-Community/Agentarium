package admission

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The TASK-10 correlation Deployment (deploy/gcp/base/correlation) renders and
// its Pod template is admitted in agent-observe; an image outside the
// Namespace list is denied.
func TestCorrelationDeploymentIsAdmitted(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "deploy/gcp/base/correlation/correlation.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	values := sampleRender()
	for k, v := range map[string]string{"CORRELATION_IMAGE": correlationImage, "SQL_PROXY_IMAGE": sqlProxyImage, "CLUSTER_UID": "6f1c3a4e-8f0e-4d4c-9b55-0d9e0c1b2a3f",
		"CORRELATION_DB_GSA": "correlation-db@test-project.iam.gserviceaccount.com", "CORRELATION_DB_USER": "correlation-db@test-project.iam",
		"CORRELATION_AUDIT_SOURCE_ID": "correlation", "DB_NAME": "agentarium", "CLOUDSQL_CONNECTION_NAME": "test-project:us-central1:agentarium",
		"control_plane_endpoint": "192.0.2.1", "cloudsql_private_ip": "192.0.2.2", "node_cidr": "198.51.100.0/24"} {
		values[k] = v
	}
	var list struct{ Items []json.RawMessage }
	if err := json.Unmarshal([]byte(render(t, string(raw), values)), &list); err != nil {
		t.Fatal(err)
	}
	var deploy *appsv1.Deployment
	for _, item := range list.Items {
		var meta metav1.TypeMeta
		_ = json.Unmarshal(item, &meta)
		if meta.Kind == "Deployment" {
			deploy = &appsv1.Deployment{}
			if err := json.Unmarshal(item, deploy); err != nil {
				t.Fatal(err)
			}
		}
	}
	if deploy == nil {
		t.Fatal("no Deployment")
	}
	pod := func() *corev1.Pod {
		spec := *deploy.Spec.Template.Spec.DeepCopy()
		// Fields the API server defaults before validating admission.
		spec.Tolerations = append(spec.Tolerations, defaultTolerationSeconds()...)
		spec.RestartPolicy = corev1.RestartPolicyAlways
		return &corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
			ObjectMeta: metav1.ObjectMeta{Name: "correlation-0", Namespace: "agent-observe", Labels: deploy.Spec.Template.Labels}, Spec: spec}
	}
	c := newCluster(t, sampleRender())
	expectExactly(t, c.admit(t, create("agent-observe", pod())))
	other := pod()
	other.Spec.Containers[0].Image = adapterImage
	expectExactly(t, c.admit(t, create("agent-observe", other)), "agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
}
