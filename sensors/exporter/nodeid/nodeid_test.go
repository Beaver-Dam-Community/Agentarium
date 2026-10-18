package nodeid

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestResolveRequiresMatchingBootAndBuildsEpoch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "boot_id")
	boot := "6f1d3d1c-1f5e-4a1b-9c7c-0c4f7d9e2a11"
	if err := os.WriteFile(path, []byte(boot+"\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	node := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "n1", UID: types.UID("30000000-0000-4000-8000-000000000001")}, Spec: corev1.NodeSpec{PodCIDRs: []string{"10.20.1.0/24"}}, Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{BootID: boot}}}
	id, err := Resolve(context.Background(), fake.NewSimpleClientset(node), "n1", path)
	if err != nil || id.NodeUID != string(node.UID) || id.BootID != boot || len(id.PodCIDRs) != 1 || id.PodCIDRs[0].String() != "10.20.1.0/24" {
		t.Fatalf("%+v %v", id, err)
	}
	epoch, err := Epoch(id, uuid.MustParse("40000000-0000-4000-8000-000000000002"))
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{128}$`).MatchString(epoch) || epoch[:32] != "30000000000040008000000000000001" || epoch[96:] != "40000000000040008000000000000002" {
		t.Fatalf("epoch %q %v", epoch, err)
	}
	noCIDR := node.DeepCopy()
	noCIDR.Spec.PodCIDRs = nil
	if _, err := Resolve(context.Background(), fake.NewSimpleClientset(noCIDR), "n1", path); err == nil {
		t.Fatal("node without podCIDR accepted")
	}
	node.Status.NodeInfo.BootID = "00000000-0000-4000-8000-000000000000"
	if _, err := Resolve(context.Background(), fake.NewSimpleClientset(node), "n1", path); err == nil {
		t.Fatal("stale Node bootID accepted")
	}
	if _, err := Resolve(context.Background(), fake.NewSimpleClientset(), "n1", path); err == nil {
		t.Fatal("missing Node accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not-a-uuid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBootID(path); err == nil {
		t.Fatal("invalid boot ID accepted")
	}
	if _, err := Epoch(Identity{NodeUID: "x"}, uuid.New()); err == nil {
		t.Fatal("invalid identity accepted")
	}
}
