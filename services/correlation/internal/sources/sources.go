// Package sources builds the correlation service's installation inputs from
// the real files the spec names: the environment lock and network values
// (TASK-01/TASK-06 addresses), the TASK-06 3.1 allow matrix, and the
// historical Pod -> workload mapping from TASK-03 issued certificates.
package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/services/correlation/netpol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Verdict of the TASK-06 allow table for one destination.
type Verdict int

const (
	Allowed Verdict = iota
	Unregistered
	// Unknown: the destination is an in-cluster Pod/Service/node address whose
	// historical owner cannot be resolved from the kernel tuple. Callers treat
	// it as not unregistered (no hold, no unregistered finding).
	Unknown
)

type portRule struct {
	proto string
	port  int
}

// AllowTable is the TASK-06 3.1 matrix resolved to addresses that can be
// decided from a kernel tuple.
type AllowTable struct {
	podsRange, servicesRange, nodeCIDR netip.Prefix
	gateway, dns                       netip.Addr
	infra                              map[string][]netip.Prefix
	infraPorts                         map[string][]portRule
	edges                              map[string]map[string][]portRule // from -> to -> ports
	infraEdges                         map[string][]string
}

// Inputs are the parsed installation files.
type Inputs struct {
	Lock        []byte // deploy/gcp/environment.lock.json (exact bytes; digest input)
	Values      []byte // network values: control_plane_endpoint, cloudsql_private_ip, node_cidr
	AllowMatrix []byte // deploy/gcp/base/network/allow-matrix.yaml (JSON)
}

func ReadInputs(lockPath, valuesPath, matrixPath string) (Inputs, error) {
	var in Inputs
	var err error
	if in.Lock, err = os.ReadFile(lockPath); err != nil {
		return in, errors.New("cannot read environment lock")
	}
	if in.Values, err = os.ReadFile(valuesPath); err != nil {
		return in, errors.New("cannot read network values")
	}
	if in.AllowMatrix, err = os.ReadFile(matrixPath); err != nil {
		return in, errors.New("cannot read allow matrix")
	}
	return in, nil
}

type lockFile struct {
	Network struct {
		NodeCIDR         string `json:"node_cidr"`
		PodsRange        string `json:"pods_range"`
		ServicesRange    string `json:"services_range"`
		GatewayClusterIP string `json:"gateway_cluster_ip"`
	} `json:"network"`
}

type valuesFile struct {
	ControlPlane string `json:"control_plane_endpoint"`
	CloudSQL     string `json:"cloudsql_private_ip"`
	NodeCIDR     string `json:"node_cidr"`
}

type matrixFile struct {
	Infra map[string]struct {
		IPBlock  string   `json:"ipBlock"`
		IPBlocks []string `json:"ipBlocks"`
		Ports    []string `json:"ports"`
	} `json:"infra"`
	Edges []struct {
		From string `json:"from"`
		To   string `json:"to"`
		Port string `json:"port"`
	} `json:"edges"`
	InfraEdges []struct {
		From string   `json:"from"`
		To   []string `json:"to"`
	} `json:"infra_edges"`
}

func parsePort(s string) (portRule, error) {
	proto, port, ok := strings.Cut(s, "/")
	n, err := strconv.Atoi(port)
	if !ok || err != nil || n <= 0 || n > 65535 || (proto != "TCP" && proto != "UDP") {
		return portRule{}, fmt.Errorf("invalid port %q", s)
	}
	return portRule{strings.ToLower(proto), n}, nil
}

// hostN is Terraform cidrhost(prefix, n) for IPv4.
func hostN(p netip.Prefix, n int) (netip.Addr, error) {
	a := p.Masked().Addr()
	if !a.Is4() || p.Bits() > 28 {
		return netip.Addr{}, errors.New("IPv4 range too small")
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) + uint32(n)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), nil
}

// Build resolves the inputs. Any missing or malformed value fails closed:
// the service does not start with a partial allow table or classifier.
func Build(in Inputs) (*AllowTable, netpol.Environment, error) {
	var lock lockFile
	var values valuesFile
	var matrix matrixFile
	if json.Unmarshal(in.Lock, &lock) != nil || json.Unmarshal(in.Values, &values) != nil || json.Unmarshal(in.AllowMatrix, &matrix) != nil {
		return nil, netpol.Environment{}, errors.New("invalid installation input JSON")
	}
	prefix := func(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }
	addr := func(s string) (netip.Addr, error) { return netip.ParseAddr(s) }
	t := &AllowTable{infra: map[string][]netip.Prefix{}, infraPorts: map[string][]portRule{}, edges: map[string]map[string][]portRule{}, infraEdges: map[string][]string{}}
	var err error
	if t.podsRange, err = prefix(lock.Network.PodsRange); err != nil {
		return nil, netpol.Environment{}, errors.New("lock network.pods_range required")
	}
	if t.servicesRange, err = prefix(lock.Network.ServicesRange); err != nil {
		return nil, netpol.Environment{}, errors.New("lock network.services_range required")
	}
	if t.nodeCIDR, err = prefix(lock.Network.NodeCIDR); err != nil || values.NodeCIDR != lock.Network.NodeCIDR {
		return nil, netpol.Environment{}, errors.New("lock and network values node_cidr must agree")
	}
	if t.gateway, err = addr(lock.Network.GatewayClusterIP); err != nil {
		return nil, netpol.Environment{}, errors.New("lock network.gateway_cluster_ip required")
	}
	// kube-dns is the services range's .10 (TASK-01 lock rule, Q0
	// 20261014-task01-q0-min; TASK-02 uses the same address).
	if t.dns, err = hostN(t.servicesRange, 10); err != nil {
		return nil, netpol.Environment{}, errors.New("lock network.services_range too small for the kube-dns ClusterIP")
	}
	controlPlane, err1 := addr(values.ControlPlane)
	cloudSQL, err2 := addr(values.CloudSQL)
	if err1 != nil || err2 != nil {
		return nil, netpol.Environment{}, errors.New("network values control_plane_endpoint and cloudsql_private_ip required")
	}
	subst := strings.NewReplacer("${control_plane_endpoint}", controlPlane.String(), "${cloudsql_private_ip}", cloudSQL.String(), "${node_cidr}", t.nodeCIDR.String())
	for name, inf := range matrix.Infra {
		blocks := inf.IPBlocks
		if inf.IPBlock != "" {
			blocks = append(blocks, inf.IPBlock)
		}
		for _, b := range blocks {
			p, err := prefix(subst.Replace(b))
			if err != nil {
				return nil, netpol.Environment{}, fmt.Errorf("allow matrix infra %s: invalid block", name)
			}
			t.infra[name] = append(t.infra[name], p)
		}
		for _, ps := range inf.Ports {
			r, err := parsePort(ps)
			if err != nil {
				return nil, netpol.Environment{}, err
			}
			t.infraPorts[name] = append(t.infraPorts[name], r)
		}
	}
	for _, e := range matrix.Edges {
		r, err := parsePort(e.Port)
		if err != nil {
			return nil, netpol.Environment{}, err
		}
		if t.edges[e.From] == nil {
			t.edges[e.From] = map[string][]portRule{}
		}
		t.edges[e.From][e.To] = append(t.edges[e.From][e.To], r)
	}
	for _, e := range matrix.InfraEdges {
		t.infraEdges[e.From] = append(t.infraEdges[e.From], e.To...)
	}
	sum := sha256.Sum256(in.Lock)
	env := netpol.Environment{LockDigest: hex.EncodeToString(sum[:]), PodsRange: t.podsRange, ServicesRange: t.servicesRange, NodeCIDR: t.nodeCIDR,
		ControlPlane: controlPlane, CloudSQL: cloudSQL, Gateway: t.gateway, DNS: t.dns, Metadata: t.infra["metadata"], PGA: t.infra["pga"]}
	return t, env, nil
}

// Decide applies the matrix to a TCP destination of a workload
// (`<namespace>/<ksa>`).
func (t *AllowTable) Decide(workload string, dest netip.Addr, port int) Verdict {
	tcp := portRule{"tcp", port}
	for name, blocks := range t.infra {
		for _, b := range blocks {
			if b.Contains(dest) && name != "node_cidr" {
				if slices.Contains(t.infraEdges[workload], name) && (len(t.infraPorts[name]) == 0 || slices.Contains(t.infraPorts[name], tcp)) {
					return Allowed
				}
				return Unregistered
			}
		}
	}
	if dest == t.gateway {
		if slices.Contains(t.edges[workload]["agent-control/policy-gateway"], tcp) {
			return Allowed
		}
		return Unregistered
	}
	if dest == t.dns {
		if slices.Contains(t.infraEdges[workload], "kube_dns") && port == 53 {
			return Allowed
		}
		return Unregistered
	}
	if t.podsRange.Contains(dest) || t.servicesRange.Contains(dest) || t.nodeCIDR.Contains(dest) {
		// The historical owner of an in-cluster address is not in the
		// kernel tuple or the lifecycle records.
		return Unknown
	}
	// Outside every cluster and infrastructure range: the matrix has no
	// external destination for agent workloads except the infra blocks above.
	return Unregistered
}

// NetpolAllowed adapts Decide for NetworkFinding: unknown is not unregistered.
func (t *AllowTable) NetpolAllowed(workload *string, dest netip.Addr, port int) bool {
	return workload != nil && t.Decide(*workload, dest, port) != Unregistered
}

// RiskAllowed adapts Decide for risk events: only a decided unregistered
// destination can lead to a hold.
func (t *AllowTable) RiskAllowed(workload string, dest netip.Addr, port int) bool {
	return t.Decide(workload, dest, port) != Unregistered
}

// Workloads maps a historical Pod to `<namespace>/<ksa>` from the TASK-03
// certificate issuance record, which binds each certificate to its Pod UID at
// issuance. TASK-10 3.7 gives the correlation role no identity base-table
// privilege, so the lookup is the restricted TASK-03 function requested in
// #206 (`identity.pod_workloads(pod_uid)`). Until it is installed every Pod
// resolves to unknown: findings stay unlinked and no risk hold is requested.
// A Pod with no certificate or more than one identity is unknown.
type Workloads struct{ Pool *pgxpool.Pool }

// Available reports whether the restricted lookup is installed and executable.
func (w Workloads) Available(ctx context.Context) bool {
	var ok bool
	err := w.Pool.QueryRow(ctx, `SELECT to_regprocedure('identity.pod_workloads(uuid)') IS NOT NULL
		AND has_function_privilege(current_user, 'identity.pod_workloads(uuid)', 'EXECUTE')`).Scan(&ok)
	return err == nil && ok
}

func (w Workloads) Resolve(ctx context.Context, pod uuid.UUID) *string {
	rows, err := w.Pool.Query(ctx, `SELECT DISTINCT namespace, ksa FROM identity.pod_workloads($1) LIMIT 2`, pod)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var found []string
	for rows.Next() {
		var ns, ksa string
		if rows.Scan(&ns, &ksa) != nil {
			return nil
		}
		found = append(found, ns+"/"+ksa)
	}
	if rows.Err() != nil || len(found) != 1 {
		return nil
	}
	return &found[0]
}
