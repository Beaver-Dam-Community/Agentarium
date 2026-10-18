package admission

import (
	"encoding/json"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const healthImage = reg + "control-health@" + digestC

// The control-health Deployment with the NodeFacts additions (#199: API token
// for Node get/list, optional startup_capture ConfigMap) must still pass the
// agent-observe role contract and Pod Security.
func TestControlHealthDeploymentAdmitted(t *testing.T) {
	values := deployValues()
	values["AGENT_OBSERVE_IMAGES"] = sqlProxyImage + "," + healthImage
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(render(t, readFile(t, "deploy/gcp/base/contact-services/contacts.yaml"), values)), &list); err != nil {
		t.Fatal(err)
	}
	var deploy *appsv1.Deployment
	for _, raw := range list.Items {
		var d appsv1.Deployment
		if json.Unmarshal(raw, &d) == nil && d.Kind == "Deployment" && d.Name == "control-health" {
			deploy = &d
		}
	}
	if deploy == nil {
		t.Fatal("no control-health Deployment")
	}
	p := &corev1.Pod{ObjectMeta: deploy.Spec.Template.ObjectMeta, Spec: *deploy.Spec.Template.Spec.DeepCopy()}
	p.TypeMeta.APIVersion, p.TypeMeta.Kind = "v1", "Pod"
	p.Name, p.Namespace = "control-health-0", "agent-observe"
	p.Spec.RestartPolicy = corev1.RestartPolicyAlways
	p.Spec.Tolerations = append(p.Spec.Tolerations, defaultTolerationSeconds()...)
	expectExactly(t, newCluster(t, values).admit(t, create("agent-observe", p)))
}
