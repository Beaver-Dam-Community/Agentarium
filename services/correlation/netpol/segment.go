// Package netpol derives network evidence under TASK-10 section 3.7.
// Classification is descriptive; it never authorizes a connection or creates a hold.
package netpol

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"
)

const RuleVersion = "netfinding-rules-v1"

// Environment is a verified snapshot of the existing environment lock, TASK-06
// infrastructure address table and catalog target CIDRs. It is an internal
// adapter input, not a new environment.lock.json schema or a request body.
type Environment struct {
	LockDigest                           string
	PodsRange, ServicesRange, NodeCIDR   netip.Prefix
	ControlPlane, CloudSQL, Gateway, DNS netip.Addr
	Metadata, PGA, AllowedTargets        []netip.Prefix
}

type Classifier struct{ env Environment }

// Endpoint contains only fields actually present in a policy log. In
// particular, a kernel-only event must not invent a destination namespace.
type Endpoint struct{ Namespace, PodName string }

type Segment struct {
	NetworkSegment, BoundaryCrossing string
	RuleVersion, Reason              string
	Limitations                      []string
}

func NewClassifier(env Environment) (*Classifier, error) {
	decoded, err := hex.DecodeString(env.LockDigest)
	if err != nil || len(decoded) != 32 || strings.ToLower(env.LockDigest) != env.LockDigest {
		return nil, errors.New("verified environment lock digest required")
	}
	for _, p := range []netip.Prefix{env.PodsRange, env.ServicesRange, env.NodeCIDR} {
		if !validPrefix(p) {
			return nil, errors.New("invalid environment network range")
		}
	}
	for _, a := range []netip.Addr{env.ControlPlane, env.CloudSQL, env.Gateway, env.DNS} {
		if !validAddr(a) {
			return nil, errors.New("invalid environment infrastructure address")
		}
	}
	if !env.ServicesRange.Contains(env.Gateway) || !env.ServicesRange.Contains(env.DNS) || env.Gateway == env.DNS {
		return nil, errors.New("distinct gateway and DNS ClusterIPs required in service range")
	}
	if len(env.Metadata) == 0 || len(env.PGA) == 0 {
		return nil, errors.New("metadata and PGA address ranges required")
	}
	for _, list := range [][]netip.Prefix{env.Metadata, env.PGA, env.AllowedTargets} {
		for _, p := range list {
			if !validPrefix(p) {
				return nil, errors.New("invalid infrastructure or target CIDR")
			}
		}
	}
	// Do not retain mutable caller slices; a classifier represents one snapshot.
	env.Metadata = append([]netip.Prefix(nil), env.Metadata...)
	env.PGA = append([]netip.Prefix(nil), env.PGA...)
	env.AllowedTargets = append([]netip.Prefix(nil), env.AllowedTargets...)
	return &Classifier{env: env}, nil
}

// Classify uses the first matching destination row from TASK-10 3.7. Addresses
// are parsed without DNS lookup. Unknown input stays unknown, including nil or
// zero-value classifiers which have no verified environment snapshot.
func (c *Classifier) Classify(source Endpoint, destinationIP string, destination Endpoint) Segment {
	result := Segment{NetworkSegment: "unclassified", BoundaryCrossing: "unknown", RuleVersion: RuleVersion}
	if c == nil || c.env.LockDigest == "" {
		result.Reason = "verified environment snapshot unavailable"
		return result
	}
	ip, err := netip.ParseAddr(destinationIP)
	if err != nil || !validAddr(ip) {
		result.Reason = "destination address unavailable or invalid"
		return result
	}
	role := ""
	if source.PodName != "" {
		switch source.Namespace {
		case "agent-exec":
			role = "exec"
		case "agent-control", "agent-adapters", "agent-observe", "agent-release":
			role = "control"
		}
	}
	set := func(exec, control, boundary, reason string) Segment {
		result.BoundaryCrossing, result.Reason = boundary, reason
		if role == "exec" {
			result.NetworkSegment = exec
		} else if role == "control" {
			result.NetworkSegment = control
		}
		return result
	}
	env := c.env
	switch {
	case contains(env.Metadata, ip):
		return set("exec_to_metadata", "control_to_control", "internal", "TASK-06 metadata address")
	case ip == env.ControlPlane:
		return set("exec_to_cluster_api", "control_to_control", "internal", "environment control plane endpoint")
	case contains(env.PGA, ip):
		return set("exec_direct_external", "control_to_google_api", "external", "TASK-06 PGA address")
	}
	// Only namespaces present in the log participate in rows 4 through 7.
	switch destination.Namespace {
	case "agent-exec":
		return set("exec_to_exec", "unclassified", "internal", "recorded destination namespace")
	case "agent-control", "agent-adapters", "agent-observe", "agent-release", "agent-sensors":
		return set("exec_to_control", "control_to_control", "internal", "recorded destination namespace")
	case "agent-targets":
		return set("exec_to_internal_other", "control_to_target", "internal", "recorded destination namespace")
	case "kube-system":
		return set("exec_to_internal_other", "control_to_control", "internal", "recorded kube-system destination")
	}
	if ip == env.CloudSQL {
		return set("exec_to_internal_other", "control_to_control", "internal", "environment Cloud SQL private address")
	}
	// Row 7a is deliberately limited to the two lock-pinned Service IPs and
	// applies only when the log has no destination namespace at all.
	if destination.Namespace == "" {
		if ip == env.Gateway {
			return set("exec_to_control", "control_to_control", "internal", "gateway ClusterIP; environment lock sha256:"+env.LockDigest)
		}
		if ip == env.DNS {
			return set("exec_to_internal_other", "control_to_control", "internal", "kube-dns ClusterIP; environment lock sha256:"+env.LockDigest)
		}
	}
	if env.PodsRange.Contains(ip) || env.ServicesRange.Contains(ip) || env.NodeCIDR.Contains(ip) {
		if destination.Namespace == "" && env.ServicesRange.Contains(ip) {
			result.Limitations = []string{"dnat_unmeasured"}
		}
		return set("exec_to_internal_other", "unclassified", "internal", "environment cluster address range")
	}
	if contains(env.AllowedTargets, ip) {
		return set("exec_direct_external", "control_to_target", "external", "catalog target allowed CIDR")
	}
	return set("exec_direct_external", "control_to_external", "external", "outside configured cluster and infrastructure ranges")
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func validAddr(a netip.Addr) bool { return a.IsValid() && a.Zone() == "" && !a.Is4In6() }
func validPrefix(p netip.Prefix) bool {
	return p.IsValid() && validAddr(p.Addr()) && p == p.Masked()
}
