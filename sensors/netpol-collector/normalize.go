// Package netpolcollector captures the measured Dataplane V2 node JSONL format.
// It does not define the pending NetworkPolicyRecord ID or HTTP batch contract.
package netpolcollector

import (
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

var ErrSchema = errors.New("invalid policy-action record")

type Endpoint struct {
	Namespace    *string `json:"namespace"`
	PodName      *string `json:"pod_name"`
	WorkloadName *string `json:"workload_name"`
	WorkloadKind *string `json:"workload_kind"`
	Instance     *string `json:"instance"`
}
type Policy struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Observation contains only fields the dataplane actually supplied. It is not a
// complete NetworkPolicyRecord: record_id, collector identity and received_at
// are deliberately absent. Timestamp/IP spelling and packet counts are retained.
type Observation struct {
	NodeName     string    `json:"node_name"`
	SourceTime   string    `json:"source_time"`
	Disposition  string    `json:"disposition"`
	Direction    string    `json:"direction"`
	Protocol     string    `json:"protocol"`
	SrcIP        string    `json:"src_ip"`
	SrcPort      *int      `json:"src_port"`
	DestIP       string    `json:"dest_ip"`
	DestPort     *int      `json:"dest_port"`
	SrcEndpoint  *Endpoint `json:"src_endpoint"`
	DestEndpoint *Endpoint `json:"dest_endpoint"`
	Policies     []Policy  `json:"policies"`
	Count        int64     `json:"count"`
}

type vendorEndpoint struct {
	Namespace    *string `json:"namespace"`
	PodNamespace *string `json:"pod_namespace"`
	PodName      *string `json:"pod_name"`
	WorkloadName *string `json:"workload_name"`
	WorkloadKind *string `json:"workload_kind"`
	Instance     *string `json:"instance"`
}

func endpoint(v *vendorEndpoint) (*Endpoint, error) {
	if v == nil {
		return nil, nil
	}
	if v.Namespace != nil && v.PodNamespace != nil && *v.Namespace != *v.PodNamespace {
		return nil, ErrSchema
	}
	ns := v.Namespace
	if ns == nil {
		ns = v.PodNamespace
	}
	return &Endpoint{ns, v.PodName, v.WorkloadName, v.WorkloadKind, v.Instance}, nil
}

// Normalize accepts the measured flat node-file record, not Cloud Logging's
// jsonPayload wrapper. Unknown vendor fields (e.g. policy labels/revision) do not
// become invented observation fields. No namespace filter discards allow/deny.
func Normalize(raw []byte) (Observation, error) {
	var out Observation
	if len(raw) == 0 || len(raw) > wal.MaxRecordBytes || canonical.CheckJSONForJCS(raw) != nil {
		return out, ErrSchema
	}
	var v struct {
		Connection *struct {
			SrcIP     string `json:"src_ip"`
			DestIP    string `json:"dest_ip"`
			SrcPort   *int   `json:"src_port"`
			DestPort  *int   `json:"dest_port"`
			Protocol  string `json:"protocol"`
			Direction string `json:"direction"`
		} `json:"connection"`
		Disposition string          `json:"disposition"`
		NodeName    string          `json:"node_name"`
		Timestamp   string          `json:"timestamp"`
		Count       json.RawMessage `json:"count"`
		Src         *vendorEndpoint `json:"src"`
		Dest        *vendorEndpoint `json:"dest"`
		Policies    []Policy        `json:"policies"`
	}
	if json.Unmarshal(raw, &v) != nil || v.Connection == nil || v.NodeName == "" {
		return out, ErrSchema
	}
	c := v.Connection
	if v.Disposition != "allow" && v.Disposition != "deny" || c.Direction != "ingress" && c.Direction != "egress" || c.Protocol != "tcp" && c.Protocol != "udp" && c.Protocol != "icmp" {
		return out, ErrSchema
	}
	if _, err := time.Parse(time.RFC3339Nano, v.Timestamp); err != nil {
		return out, ErrSchema
	}
	for _, ip := range []string{c.SrcIP, c.DestIP} {
		a, e := netip.ParseAddr(ip)
		if e != nil || a.Zone() != "" {
			return out, ErrSchema
		}
	}
	for _, port := range []*int{c.SrcPort, c.DestPort} {
		if port != nil && (*port < 0 || *port > 65535 || c.Protocol == "icmp") {
			return out, ErrSchema
		}
	}
	count := int64(1)
	if len(v.Count) > 0 && (string(v.Count) == "null" || json.Unmarshal(v.Count, &count) != nil) {
		return out, ErrSchema
	}
	if count < 1 || count > 2147483647 {
		return out, ErrSchema
	} // TASK-10 SQL count integer
	if v.Disposition == "deny" && v.Policies != nil {
		return out, ErrSchema
	}
	for _, p := range v.Policies {
		if p.Name == "" || p.Namespace == "" {
			return out, ErrSchema
		}
	}
	src, e := endpoint(v.Src)
	if e != nil {
		return out, e
	}
	dst, e := endpoint(v.Dest)
	if e != nil {
		return out, e
	}
	return Observation{v.NodeName, v.Timestamp, v.Disposition, c.Direction, c.Protocol, c.SrcIP, c.SrcPort, c.DestIP, c.DestPort, src, dst, v.Policies, count}, nil
}
