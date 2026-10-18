package admission

import (
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// M3-1 action path images (deploy/gcp/base/action-path).
const (
	coordinatorImage    = reg + "coordinator@" + digestB
	receiverSenderImage = reg + "receiver-sender@" + digestC
	receiverImage       = reg + "receiver@" + digestD
	collectorImage      = reg + "evidence-collector@" + digestA
)

// deployValues extends sampleRender with every service placeholder of the
// contact-services and action-path manifests. Names, users and GSAs are
// fictitious; render.py derives the lock values in a real install.
func deployValues() map[string]string {
	v := sampleRender()
	for _, k := range []string{"AGENTARIUM_ENVIRONMENT", "AUDIT_DB_GSA", "AUDIT_DB_USER", "AUDIT_HEALTH_SOURCE_ID", "AUDIT_VERSION",
		"CA_POOL_ID", "SERVICE_CERTIFICATE_TEMPLATE", "CLIENT_CERTIFICATE_TEMPLATE", "CLAIM_KEY_SECRET", "CLAIM_KEY_SECRET_VERSION", "CLOUDSQL_CONNECTION_NAME", "DB_NAME", "HEALTH_DB_GSA",
		"HEALTH_DB_USER", "IDENTITY_DB_GSA", "IDENTITY_DB_USER", "OIDC_AUDIENCES", "OIDC_ALLOWED_HD", "BUNDLE_KEY_ID",
		"RELEASE_VERSION", "AGENTARIUM_TENANT", "RECEIVER_MODE", "RECEIVER_API_KEY_SECRET_OBJECTS",
		"GATEWAY_DB_GSA", "GATEWAY_DB_USER", "COORDINATOR_DB_GSA", "COORDINATOR_DB_USER",
		"RECEIVER_SENDER_DB_GSA", "RECEIVER_SENDER_DB_USER", "RECEIVER_DB_GSA", "RECEIVER_DB_USER",
		"EVIDENCE_COLLECTOR_DB_GSA", "EVIDENCE_COLLECTOR_DB_USER"} {
		v[k] = "test"
	}
	v["EVIDENCE_PROBE_ACTION_KEY"] = "00000000-0000-4000-8000-000000000001"
	v["GATEWAY_CLUSTER_IP"], v["RECEIVER_CLUSTER_IP"], v["RECEIVER_PROBE_CLUSTER_IP"] = "10.30.0.20", "10.30.0.21", "10.30.0.22"
	v["node_cidr"], v["pods_range"] = "198.51.100.0/24", "203.0.113.0/24"
	// JSON-escaped like render.py check_value(TRUST_BUNDLE_PEM).
	v["TRUST_BUNDLE_PEM"] = `-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n`
	v["IDENTITY_IMAGE"], v["AUDIT_IMAGE"], v["HEALTH_IMAGE"], v["SQL_PROXY_IMAGE"] = gatewayImage, auditImage, healthImage, sqlProxyImage
	v["GATEWAY_IMAGE"], v["COORDINATOR_IMAGE"] = gatewayImage, coordinatorImage
	v["RECEIVER_SENDER_IMAGE"], v["RECEIVER_IMAGE"], v["EVIDENCE_COLLECTOR_IMAGE"] = receiverSenderImage, receiverImage, collectorImage
	v["AGENT_CONTROL_IMAGES"] = strings.Join([]string{gatewayImage, coordinatorImage, sqlProxyImage}, ",")
	v["AGENT_ADAPTERS_IMAGES"] = strings.Join([]string{adapterImage, receiverSenderImage, probeImage, sqlProxyImage}, ",")
	v["AGENT_OBSERVE_IMAGES"] = strings.Join([]string{sqlProxyImage, snapshotImage, auditImage, healthImage, collectorImage}, ",")
	v["AGENT_TARGETS_IMAGES"] = strings.Join([]string{receiverImage, sqlProxyImage}, ",")
	return v
}

type listItem struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"metadata"`
}

func renderedItems(t *testing.T, file string, values map[string]string) []json.RawMessage {
	t.Helper()
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(render(t, readFile(t, file), values)), &list); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	return list.Items
}

// deploymentPods turns every Deployment of a rendered List into the Pod the
// ReplicaSet controller would create (name, namespace, API defaults).
func deploymentPods(t *testing.T, file string, values map[string]string) []*corev1.Pod {
	t.Helper()
	var pods []*corev1.Pod
	for _, raw := range renderedItems(t, file, values) {
		var head listItem
		if err := json.Unmarshal(raw, &head); err != nil || head.Kind != "Deployment" {
			continue
		}
		var d appsv1.Deployment
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		p := &corev1.Pod{ObjectMeta: d.Spec.Template.ObjectMeta, Spec: *d.Spec.Template.Spec.DeepCopy()}
		p.TypeMeta.APIVersion, p.TypeMeta.Kind = "v1", "Pod"
		p.Name, p.Namespace = d.Name+"-0", d.Namespace
		p.Spec.RestartPolicy = corev1.RestartPolicyAlways
		p.Spec.Tolerations = append(p.Spec.Tolerations, defaultTolerationSeconds()...)
		pods = append(pods, p)
	}
	return pods
}

// Every action path Deployment passes its role Namespace contract and Pod
// Security with the images on that Namespace's list (TASK-01 3.2).
func TestActionPathDeploymentsAdmitted(t *testing.T) {
	values := deployValues()
	c := newCluster(t, values)
	pods := deploymentPods(t, "deploy/gcp/base/action-path/services.yaml", values)
	want := map[string]string{"policy-gateway": "agent-control", "coordinator": "agent-control",
		"receiver-sender": "agent-adapters", "receiver": "agent-targets", "evidence-collector": "agent-observe"}
	if len(pods) != len(want) {
		t.Fatalf("got %d Deployments, want %d", len(pods), len(want))
	}
	for _, p := range pods {
		name := strings.TrimSuffix(p.Name, "-0")
		if want[name] != p.Namespace {
			t.Errorf("%s in %s, want %s", name, p.Namespace, want[name])
		}
		t.Run(name, func(t *testing.T) {
			expectExactly(t, c.admit(t, create(p.Namespace, p)))
		})
	}
	t.Run("image missing from its Namespace list is rejected", func(t *testing.T) {
		v := deployValues()
		v["AGENT_TARGETS_IMAGES"] = sqlProxyImage
		for _, p := range deploymentPods(t, "deploy/gcp/base/action-path/services.yaml", v) {
			if p.Namespace == "agent-targets" {
				expectExactly(t, newCluster(t, v).admit(t, create(p.Namespace, p)), "agent-role-contract:ROLE_IMAGE_NOT_ALLOWED")
			}
		}
	})
	t.Run("adapter with the start-taint toleration is rejected", func(t *testing.T) {
		for _, p := range pods {
			if p.Namespace == "agent-adapters" {
				q := p.DeepCopy()
				q.Spec.Tolerations = append(q.Spec.Tolerations, corev1.Toleration{Key: "agentarium.io/observe-not-ready", Operator: corev1.TolerationOpEqual, Value: "true", Effect: corev1.TaintEffectNoSchedule})
				expectExactly(t, c.admit(t, create(q.Namespace, q)), "agent-role-contract:ROLE_ADAPTER_BOOTSTRAP_TOLERATION_FORBIDDEN")
			}
		}
	})
}

// The contact services with the M3-1 identity/audit additions stay admitted.
func TestContactDeploymentsAdmitted(t *testing.T) {
	values := deployValues()
	c := newCluster(t, values)
	for _, p := range deploymentPods(t, "deploy/gcp/base/contact-services/contacts.yaml", values) {
		t.Run(p.Name, func(t *testing.T) { expectExactly(t, c.admit(t, create(p.Namespace, p))) })
	}
}

// The demo runtime Pod satisfies agent-exec-contract/-profile exactly as
// rendered: no args, plain env only, the two allowed volumes.
func TestActionPathRuntimePodAdmitted(t *testing.T) {
	values := deployValues()
	c := newCluster(t, values)
	var pod *corev1.Pod
	for _, raw := range renderedItems(t, "deploy/gcp/base/action-path/agent-runtime.yaml", values) {
		var head listItem
		if json.Unmarshal(raw, &head) == nil && head.Kind == "Pod" {
			pod = &corev1.Pod{}
			if err := json.Unmarshal(raw, pod); err != nil {
				t.Fatal(err)
			}
		}
	}
	if pod == nil {
		t.Fatal("no runtime Pod")
	}
	pod.Spec.Tolerations = append(pod.Spec.Tolerations, defaultTolerationSeconds()...)
	expectExactly(t, c.admit(t, create("agent-exec", pod)))
	if pem := envValue(pod, "AGENTARIUM_TRUST_BUNDLE_PEM"); !strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----\n") {
		t.Fatalf("trust bundle env is not PEM text: %q", pem)
	}
	if got := envValue(pod, "AGENTARIUM_GATEWAY_URL"); got != "https://10.30.0.20:8443" {
		t.Fatalf("runtime must dial the fixed gateway ClusterIP, got %q", got)
	}
	t.Run("an args entry is rejected", func(t *testing.T) {
		p := pod.DeepCopy()
		p.Spec.Containers[0].Args = []string{"-gateway-url=https://evil"}
		expectExactly(t, c.admit(t, create("agent-exec", p)), "agent-exec-contract:EXEC_IMAGE_OR_ENTRYPOINT_INVALID")
	})
}

func envValue(p *corev1.Pod, name string) string {
	for _, e := range p.Spec.Containers[0].Env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}
