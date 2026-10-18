// Package workload gives the probe runner its node-bound identity: the Pod,
// node and boot it runs on, and a Pod-bound clientAuth certificate obtained
// with the projected agentarium-identity token (TASK-03 3.3.2, COMMON
// Workload certificate bootstrap wire format). The private key stays in memory.
package workload

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// KSA is the probe runner service account and Pod label (TASK-01 profile).
const KSA = "probe-runner"

// Namespaces the probe runner runs in (TASK-10 3.2 answer probe).
const (
	ExecNamespace     = "agent-exec"
	AdaptersNamespace = "agent-adapters"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Self is the runner's own placement, read from the projected token claims.
// The claims are not verified here: they only address the runner's own
// reports, and control-health binds every report to the node and boot of the
// issued certificate (identity.issued_certificates) instead.
type Self struct {
	Namespace string
	PodUID    string
	NodeName  string
	NodeUID   string
}

// ReadSelf decodes the payload of the projected token. Kubernetes 1.32+
// (ServiceAccountTokenPodNodeInfo, GA; the lock requires GKE 1.33+) puts the
// bound Pod and its node in the "kubernetes.io" claim. The admission profile
// forbids downward API env values, so this claim is the only source of the
// node UID the COMMON probe-results wire requires.
func ReadSelf(tokenFile string) (Self, error) {
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return Self{}, fmt.Errorf("workload: read projected token: %w", err)
	}
	return ParseSelf(strings.TrimSpace(string(raw)))
}

// ParseSelf decodes one compact JWT's claims (no signature check, see Self).
func ParseSelf(token string) (Self, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(token) > 16384 {
		return Self{}, errors.New("workload: token is not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Self{}, errors.New("workload: token payload is not base64url")
	}
	var claims struct {
		K8s struct {
			Namespace string `json:"namespace"`
			Node      struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"node"`
			Pod struct {
				UID string `json:"uid"`
			} `json:"pod"`
			ServiceAccount struct {
				Name string `json:"name"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Self{}, errors.New("workload: token claims are not JSON")
	}
	k := claims.K8s
	if k.Namespace != ExecNamespace && k.Namespace != AdaptersNamespace {
		return Self{}, fmt.Errorf("workload: namespace %q runs no probe runner", k.Namespace)
	}
	if k.ServiceAccount.Name != KSA {
		return Self{}, fmt.Errorf("workload: service account %q is not %s", k.ServiceAccount.Name, KSA)
	}
	if !uuidPattern.MatchString(k.Pod.UID) {
		return Self{}, errors.New("workload: token is not bound to a Pod")
	}
	if !uuidPattern.MatchString(k.Node.UID) || k.Node.Name == "" {
		return Self{}, errors.New("workload: token carries no node UID (needs Kubernetes 1.32+ Pod node info)")
	}
	return Self{Namespace: k.Namespace, PodUID: k.Pod.UID, NodeName: k.Node.Name, NodeUID: k.Node.UID}, nil
}

// SAN is the Pod-bound SAN identity issues to this runner (TASK-03 3.3.1).
func (s Self) SAN() string {
	return "spiffe://agentarium.internal/ns/" + s.Namespace + "/sa/" + KSA + "/pod/" + s.PodUID
}

// ReadBootID reads the kernel boot ID, the value kubelet reports as Node
// status.nodeInfo.bootID and identity records on the issued certificate.
// /proc/sys/kernel/random/boot_id is not namespaced, so the container sees
// the node's value.
func ReadBootID(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("workload: read boot id: %w", err)
	}
	id := strings.TrimSpace(string(raw))
	if id == "" || len(id) > 256 || strings.ContainsAny(id, "/?# \t\n") {
		return "", errors.New("workload: invalid boot id")
	}
	return id, nil
}
