// Package pki holds the workload certificate rules of TASK-03 3.3.1 and the
// COMMON "service PKI and identifiers" table: which SAN and which EKU a registered
// workload gets, and how long the certificate lives.
package pki

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// SANPrefix is the URI SAN prefix the CA pool issuance policy allows.
const SANPrefix = "spiffe://agentarium.internal/"

// Lifetime is the certificate lifetime for every profile (renewed at 50%).
const Lifetime = 24 * time.Hour

// Role is identity.registered_workloads.role.
type Role string

const (
	RoleRuntime    Role = "runtime"
	RoleAdapter    Role = "adapter"
	RoleService    Role = "service"
	RoleNodeBridge Role = "node_bridge"
	RoleProbe      Role = "probe"
)

// Valid reports whether r is one of the roles the DDL allows.
func (r Role) Valid() bool {
	switch r {
	case RoleRuntime, RoleAdapter, RoleService, RoleNodeBridge, RoleProbe:
		return true
	}
	return false
}

// Profile is what the identity service asks the CA for.
type Profile struct {
	SAN        string
	ClientOnly bool // true: clientAuth only; false: serverAuth and clientAuth
	Lifetime   time.Duration
}

// ErrNodeBridgeDisabled is returned for the node_bridge role. TASK-03 3.3 and
// COMMON say node runtime bridge certificates are bound to node/boot, but no
// spec says which KSA may ask for one, so issuance stays closed until that is
// defined (SPEC-QUESTION in the PR description).
var ErrNodeBridgeDisabled = errors.New("node bridge issuance is not enabled")

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func checkLabel(kind, v string) error {
	if !dnsLabel.MatchString(v) {
		return fmt.Errorf("invalid %s %q", kind, v)
	}
	return nil
}

var uidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ServiceSAN is spiffe://agentarium.internal/ns/<namespace>/sa/<ksa>.
func ServiceSAN(namespace, ksa string) (string, error) {
	if err := checkLabel("namespace", namespace); err != nil {
		return "", err
	}
	if err := checkLabel("ksa", ksa); err != nil {
		return "", err
	}
	return SANPrefix + "ns/" + namespace + "/sa/" + ksa, nil
}

// PodSAN is the service SAN followed by /pod/<pod_uid>.
func PodSAN(namespace, ksa, podUID string) (string, error) {
	base, err := ServiceSAN(namespace, ksa)
	if err != nil {
		return "", err
	}
	if !uidPattern.MatchString(podUID) {
		return "", fmt.Errorf("invalid pod uid %q", podUID)
	}
	return base + "/pod/" + podUID, nil
}

// NodeBridgeSAN is spiffe://agentarium.internal/node-bridge/<node_uid>/<boot_id>.
func NodeBridgeSAN(nodeUID, bootID string) (string, error) {
	if !uidPattern.MatchString(nodeUID) {
		return "", fmt.Errorf("invalid node uid %q", nodeUID)
	}
	if bootID == "" || strings.ContainsAny(bootID, "/?#") || len(bootID) > 64 {
		return "", fmt.Errorf("invalid boot id %q", bootID)
	}
	return SANPrefix + "node-bridge/" + nodeUID + "/" + bootID, nil
}

// ProfileFor maps a registered role to its certificate profile
// (TASK-03 3.3.1 table): services and adapters get a service SAN with
// serverAuth+clientAuth; runtime and probe Pods get a Pod-bound SAN with
// clientAuth only.
func ProfileFor(role Role, namespace, ksa, podUID string) (Profile, error) {
	switch role {
	case RoleService, RoleAdapter:
		san, err := ServiceSAN(namespace, ksa)
		if err != nil {
			return Profile{}, err
		}
		return Profile{SAN: san, ClientOnly: false, Lifetime: Lifetime}, nil
	case RoleRuntime, RoleProbe:
		san, err := PodSAN(namespace, ksa, podUID)
		if err != nil {
			return Profile{}, err
		}
		return Profile{SAN: san, ClientOnly: true, Lifetime: Lifetime}, nil
	case RoleNodeBridge:
		return Profile{}, ErrNodeBridgeDisabled
	}
	return Profile{}, fmt.Errorf("unknown role %q", role)
}
