package podmeta

import (
	"net/netip"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func TestContainerReportsKubeletStatusOnlyAfterSync(t *testing.T) {
	r, err := New(Config{NodeName: node, Observed: []string{"agent-exec"}, Grace: time.Second, Retain: time.Minute, PodCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	p := testPod("agent-exec", "rt", "10000000-0000-4000-8000-000000000001", "10.0.0.5", cid('a'))
	p.Status.ContainerStatuses[0].ImageID = "registry/runtime@sha256:" + cid('e')
	p.Status.ContainerStatuses[0].State.Running = &corev1.ContainerStateRunning{}
	r.Upsert(p)
	if _, ok := r.Container(cid('a')); ok {
		t.Fatal("container reported before the initial LIST")
	}
	r.MarkSynced()
	c, ok := r.Container(cid('a'))
	if !ok || c.PodUID != "10000000-0000-4000-8000-000000000001" || !c.Observed || !c.Running || c.Deleted || c.ImageID != "registry/runtime@sha256:"+cid('e') {
		t.Fatalf("container %+v %v", c, ok)
	}
	r.Delete(p)
	if c, ok := r.Container(cid('a')); !ok || !c.Deleted {
		t.Fatalf("deleted container %+v", c)
	}
	if _, ok := r.Container(cid('b')); ok {
		t.Fatal("unknown container")
	}
}
