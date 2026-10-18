package admission

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// identityPod is the workload-identity Pod from the committed contact manifest
// (TASK-06 3.3, #101), with its images replaced by digests on the sample
// agent-control list and the defaults the API server adds before admission.
func identityPod(t *testing.T) *corev1.Pod {
	t.Helper()
	raw := readFile(t, "deploy/gcp/base/contact-services/contacts.yaml")
	raw = strings.NewReplacer("${IDENTITY_IMAGE}", gatewayImage, "${SQL_PROXY_IMAGE}", sqlProxyImage).Replace(raw)
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		t.Fatal(err)
	}
	for _, item := range list.Items {
		var head struct {
			Kind     string            `json:"kind"`
			Metadata metav1.ObjectMeta `json:"metadata"`
		}
		if err := json.Unmarshal(item, &head); err != nil {
			t.Fatal(err)
		}
		if head.Kind != "Deployment" || head.Metadata.Name != "workload-identity" {
			continue
		}
		var deploy struct {
			Spec struct {
				Template corev1.PodTemplateSpec `json:"template"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(item, &deploy); err != nil {
			t.Fatal(err)
		}
		pod := &corev1.Pod{
			TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
			ObjectMeta: metav1.ObjectMeta{Name: "workload-identity-0", Namespace: "agent-control", Labels: deploy.Spec.Template.Labels},
			Spec:       deploy.Spec.Template.Spec,
		}
		pod.Spec.Tolerations = append(pod.Spec.Tolerations, defaultTolerationSeconds()...)
		return pod
	}
	t.Fatal("workload-identity Deployment not found")
	return nil
}

func TestIdentityClaimKeyCSIAdmission(t *testing.T) {
	c := newCluster(t, sampleRender())
	pod := identityPod(t)
	var csi *corev1.CSIVolumeSource
	for _, v := range pod.Spec.Volumes {
		if v.CSI != nil {
			csi = v.CSI
		}
	}
	if csi == nil || csi.Driver != "secrets-store-gke.csi.k8s.io" || csi.ReadOnly == nil || !*csi.ReadOnly ||
		csi.VolumeAttributes["secretProviderClass"] != "workload-identity-claim-key" {
		t.Fatalf("identity Pod lacks the claim key CSI volume: %+v", pod.Spec.Volumes)
	}

	t.Run("identity Pod with the Secret Manager CSI volume is admitted in agent-control", func(t *testing.T) {
		expectExactly(t, c.admit(t, create("agent-control", pod)))
	})
	t.Run("the extra gke-metadata-server nodeSelector keeps role placement valid", func(t *testing.T) {
		if pod.Spec.NodeSelector["iam.gke.io/gke-metadata-server-enabled"] != "true" ||
			pod.Spec.NodeSelector[roleLabel] != "control" {
			t.Fatalf("nodeSelector %v", pod.Spec.NodeSelector)
		}
	})
	t.Run("the same CSI volume is still rejected in agent-exec", func(t *testing.T) {
		p := runtimePod()
		p.Spec.Volumes = append(p.Spec.Volumes, corev1.Volume{Name: "claim-key", VolumeSource: corev1.VolumeSource{CSI: csi.DeepCopy()}})
		got := c.admit(t, create("agent-exec", p))
		if len(got) == 0 {
			t.Fatal("a CSI secret volume must not be admitted for the execution runtime")
		}
	})
	t.Run("a hostPath volume instead is rejected by Pod Security", func(t *testing.T) {
		p := pod.DeepCopy()
		for i := range p.Spec.Volumes {
			if p.Spec.Volumes[i].Name == "claim-key" {
				p.Spec.Volumes[i].VolumeSource = corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/secrets"}}
			}
		}
		got := c.admit(t, create("agent-control", p))
		if !strings.Contains(strings.Join(got, ","), "PSA:") {
			t.Fatalf("hostPath must be rejected by restricted PSA: %s", fmtResult(got))
		}
	})
}
