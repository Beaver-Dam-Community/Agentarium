package admission

import (
	"encoding/json"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const brokerImage = reg + "credential-broker@" + digestC

// The credential-broker Deployment (deploy/gcp/base/credential-broker, TASK-06)
// renders and its Pod template is admitted in agent-control with the start
// taint toleration; an image outside the Namespace list is denied.
func TestBrokerDeploymentAdmitted(t *testing.T) {
	values := sampleRender()
	values["AGENT_CONTROL_IMAGES"] = gatewayImage + "," + sqlProxyImage + "," + brokerImage
	values["BROKER_IMAGE"] = brokerImage
	values["SQL_PROXY_IMAGE"] = sqlProxyImage
	values["BROKER_DB_GSA"] = "agentarium-broker-db@test-project.iam.gserviceaccount.com"
	values["BROKER_DB_USER"] = "agentarium-broker-db@test-project.iam"
	values["CLOUDSQL_CONNECTION_NAME"] = "test-project:us-central1:agentarium"
	values["DB_NAME"] = "agentarium"
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(render(t, readFile(t, "deploy/gcp/base/credential-broker/broker.yaml"), values)), &list); err != nil {
		t.Fatal(err)
	}
	var deploy *appsv1.Deployment
	for _, raw := range list.Items {
		var d appsv1.Deployment
		if json.Unmarshal(raw, &d) == nil && d.Kind == "Deployment" && d.Name == "credential-broker" {
			deploy = &d
		}
	}
	if deploy == nil {
		t.Fatal("no credential-broker Deployment")
	}
	pod := func() *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: deploy.Spec.Template.ObjectMeta, Spec: *deploy.Spec.Template.Spec.DeepCopy()}
		p.TypeMeta.APIVersion, p.TypeMeta.Kind = "v1", "Pod"
		p.Name, p.Namespace = "credential-broker-0", "agent-control"
		// Fields the API server defaults before validating admission.
		p.Spec.RestartPolicy = corev1.RestartPolicyAlways
		p.Spec.Tolerations = append(p.Spec.Tolerations, defaultTolerationSeconds()...)
		return p
	}
	c := newCluster(t, values)
	expectExactly(t, c.admit(t, create("agent-control", pod())))
	other := pod()
	for i := range other.Spec.Containers {
		if other.Spec.Containers[i].Name == "credential-broker" {
			other.Spec.Containers[i].Image = adapterImage
		}
	}
	expectExactly(t, c.admit(t, create("agent-control", other)), "agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
}
