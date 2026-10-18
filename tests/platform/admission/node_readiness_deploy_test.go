package admission

import (
	"encoding/json"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const nodeReadinessImage = reg + "node-readiness@" + digestA

// The node-readiness Deployment (deploy/gcp/base/node-readiness, TASK-01 3.5)
// renders and its Pod template is admitted in agent-control with the start
// taint toleration; an image outside the Namespace list is denied.
func TestNodeReadinessDeploymentAdmitted(t *testing.T) {
	values := sampleRender()
	values["AGENT_CONTROL_IMAGES"] = gatewayImage + "," + sqlProxyImage + "," + nodeReadinessImage
	values["NODE_READINESS_IMAGE"] = nodeReadinessImage
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(render(t, readFile(t, "deploy/gcp/base/node-readiness/node-readiness.yaml"), values)), &list); err != nil {
		t.Fatal(err)
	}
	var deploy *appsv1.Deployment
	for _, raw := range list.Items {
		var d appsv1.Deployment
		if json.Unmarshal(raw, &d) == nil && d.Kind == "Deployment" && d.Name == "node-readiness" {
			deploy = &d
		}
	}
	if deploy == nil {
		t.Fatal("no node-readiness Deployment")
	}
	pod := func() *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: deploy.Spec.Template.ObjectMeta, Spec: *deploy.Spec.Template.Spec.DeepCopy()}
		p.TypeMeta.APIVersion, p.TypeMeta.Kind = "v1", "Pod"
		p.Name, p.Namespace = "node-readiness-0", "agent-control"
		// Fields the API server defaults before validating admission.
		p.Spec.RestartPolicy = corev1.RestartPolicyAlways
		p.Spec.Tolerations = append(p.Spec.Tolerations, defaultTolerationSeconds()...)
		return p
	}
	c := newCluster(t, values)
	expectExactly(t, c.admit(t, create("agent-control", pod())))
	other := pod()
	other.Spec.Containers[0].Image = adapterImage
	expectExactly(t, c.admit(t, create("agent-control", other)), "agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
}
