// Package nodeid derives the exporter's node/boot identity and source epoch.
package nodeid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strings"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

type Identity struct {
	NodeUID, BootID string
	// PodCIDRs are the node's Pod ranges from Node spec.podCIDRs.
	PodCIDRs []netip.Prefix
}

// ReadBootID reads the kernel boot ID. The value is kernel-global, so the
// container view equals the host's.
func ReadBootID(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if _, err := uuid.Parse(id); err != nil {
		return "", errors.New("invalid kernel boot ID")
	}
	return id, nil
}

// Resolve reads the Node object of this exporter. The kernel boot ID must
// equal the kubelet-reported Node status bootID; a mismatch (stale status after
// a reboot or wrong node) fails closed instead of choosing one.
func Resolve(ctx context.Context, client kubernetes.Interface, nodeName, bootIDPath string) (Identity, error) {
	boot, err := ReadBootID(bootIDPath)
	if err != nil {
		return Identity{}, err
	}
	n, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return Identity{}, err
	}
	nodeUID := string(n.UID)
	if id, err := uuid.Parse(nodeUID); err != nil || id.String() != nodeUID {
		return Identity{}, errors.New("node UID is not a canonical UUID")
	}
	if n.Status.NodeInfo.BootID != boot {
		return Identity{}, errors.New("kernel boot ID differs from Node status bootID")
	}
	cidrs := n.Spec.PodCIDRs
	if len(cidrs) == 0 && n.Spec.PodCIDR != "" {
		cidrs = []string{n.Spec.PodCIDR}
	}
	var prefixes []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return Identity{}, errors.New("invalid Node podCIDR")
		}
		prefixes = append(prefixes, p.Masked())
	}
	if len(prefixes) == 0 {
		return Identity{}, errors.New("node has no podCIDR")
	}
	return Identity{NodeUID: nodeUID, BootID: boot, PodCIDRs: prefixes}, nil
}

// Epoch follows the runtime lifecycle source encoding of COMMON
// "Lifecycle source authentication and epoch": node UUID 32hex + SHA-256(boot ID) 64hex +
// process instance UUID 32hex. Kernel epoch encoding is not separately
// specified; this keeps one node/boot/instance format for both node sources.
func Epoch(id Identity, instance uuid.UUID) (string, error) {
	node, err := uuid.Parse(id.NodeUID)
	if err != nil || id.BootID == "" || instance == uuid.Nil {
		return "", errors.New("incomplete epoch identity")
	}
	boot := sha256.Sum256([]byte(id.BootID))
	return hex.EncodeToString(node[:]) + hex.EncodeToString(boot[:]) + hex.EncodeToString(instance[:]), nil
}
