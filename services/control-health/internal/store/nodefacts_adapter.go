package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NodePoolLabel is the GKE label naming a Node's pool (TASK-01 3.4.1).
const NodePoolLabel = "cloud.google.com/gke-nodepool"

// NodeRuntime is the Q0-measured Node status.nodeInfo (TASK-16 3.1).
type NodeRuntime struct {
	OSImage                 string `json:"os_image"`
	KernelVersion           string `json:"kernel_version"`
	ContainerRuntimeVersion string `json:"container_runtime_version"`
	KubeletVersion          string `json:"kubelet_version"`
}

// StartupCaptureRow is one environment lock startup_capture entry.
type StartupCaptureRow struct {
	NodePool             string       `json:"node_pool"`
	RuntimeProfileDigest *string      `json:"runtime_profile_digest"`
	Value                string       `json:"value"`
	Measurement          string       `json:"measurement"`
	Q0RunID              *string      `json:"q0_run_id"`
	NodeRuntime          *NodeRuntime `json:"node_runtime"`
}

var (
	profileDigest   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	startupRowKeys  = []string{"node_pool", "runtime_profile_digest", "value", "measurement", "q0_run_id", "node_runtime"}
	nodeRuntimeKeys = []string{"os_image", "kernel_version", "container_runtime_version", "kubelet_version"}
)

func strictKeys(raw json.RawMessage, keys []string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if len(m) != len(keys) {
		return errors.New("unexpected or missing keys")
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return fmt.Errorf("missing key %s", k)
		}
	}
	return nil
}

// ParseStartupCapture strictly decodes the mounted control-health-startup-capture
// input (the lock's startup_capture array) and returns one row per node pool.
// A duplicated pool rejects the whole input; no first row is ever chosen.
func ParseStartupCapture(raw []byte) (map[string]StartupCaptureRow, error) {
	var items []json.RawMessage
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := d.Decode(&items); err != nil || d.More() {
		return nil, errors.New("startup_capture is not a JSON array")
	}
	out := make(map[string]StartupCaptureRow, len(items))
	for i, item := range items {
		if err := strictKeys(item, startupRowKeys); err != nil {
			return nil, fmt.Errorf("startup_capture[%d]: %w", i, err)
		}
		var row StartupCaptureRow
		rd := json.NewDecoder(bytes.NewReader(item))
		rd.DisallowUnknownFields()
		if err := rd.Decode(&row); err != nil {
			return nil, fmt.Errorf("startup_capture[%d]: %w", i, err)
		}
		if row.NodeRuntime != nil {
			var nested struct {
				NodeRuntime json.RawMessage `json:"node_runtime"`
			}
			_ = json.Unmarshal(item, &nested)
			if err := strictKeys(nested.NodeRuntime, nodeRuntimeKeys); err != nil {
				return nil, fmt.Errorf("startup_capture[%d].node_runtime: %w", i, err)
			}
		}
		if err := row.validate(); err != nil {
			return nil, fmt.Errorf("startup_capture[%d]: %w", i, err)
		}
		if _, dup := out[row.NodePool]; dup {
			return nil, fmt.Errorf("startup_capture: node pool %q appears more than once", row.NodePool)
		}
		out[row.NodePool] = row
	}
	return out, nil
}

func (r StartupCaptureRow) validate() error {
	if r.NodePool == "" {
		return errors.New("node_pool required")
	}
	if r.Value != health.StartupGuarded && r.Value != health.StartupUnsupported {
		return errors.New("value must be guarded or unsupported")
	}
	if r.RuntimeProfileDigest != nil && !profileDigest.MatchString(*r.RuntimeProfileDigest) {
		return errors.New("runtime_profile_digest must be lowercase SHA-256 or null")
	}
	switch r.Measurement {
	case Measured:
		rt := r.NodeRuntime
		if r.Q0RunID == nil || *r.Q0RunID == "" || r.RuntimeProfileDigest == nil || rt == nil ||
			rt.OSImage == "" || rt.KernelVersion == "" || rt.ContainerRuntimeVersion == "" || rt.KubeletVersion == "" {
			return errors.New("measured row needs q0_run_id, runtime_profile_digest and node_runtime")
		}
	case NotMeasured:
		if r.Value != health.StartupUnsupported || r.NodeRuntime != nil || (r.Q0RunID != nil && *r.Q0RunID == "") {
			return errors.New("not_measured row must be unsupported with node_runtime null")
		}
	default:
		return errors.New("measurement must be measured or not_measured")
	}
	return nil
}

// Errors returned by KubeNodeFacts. Every one prevents boot registration.
var (
	ErrNodeNotFound    = errors.New("no current Node with the certified UID")
	ErrNodeAmbiguous   = errors.New("more than one Node with the certified UID")
	ErrNodeReplaced    = errors.New("Node name now has a different UID")
	ErrNodeNoBoot      = errors.New("Node reports no boot ID")
	ErrNodePoolUnknown = errors.New("Node pool has no single startup_capture row")
	ErrProfileStale    = errors.New("Node runtime differs from the Q0-measured profile")
)

// KubeNodeFacts is the production NodeFactsSource. It reads Nodes with the
// TASK-06 control-health get/list grant only and the trusted lock rows; it
// never hashes Node fields into a profile digest.
type KubeNodeFacts struct {
	Client kubernetes.Interface
	Rows   map[string]StartupCaptureRow
}

func (k KubeNodeFacts) Current(ctx context.Context, nodeUID string) (NodeFacts, error) {
	var empty NodeFacts
	if k.Client == nil || nodeUID == "" {
		return empty, errors.New("node facts source unavailable")
	}
	// Nodes cannot be selected by UID; list them all and match exactly.
	var matches []corev1.Node
	opts := metav1.ListOptions{Limit: 500}
	for pages := 0; ; pages++ {
		if pages > 100 {
			return empty, errors.New("Node LIST did not terminate")
		}
		list, err := k.Client.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return empty, err
		}
		for _, n := range list.Items {
			if string(n.UID) == nodeUID {
				matches = append(matches, n)
			}
		}
		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}
	switch len(matches) {
	case 0:
		return empty, ErrNodeNotFound
	case 1:
	default:
		return empty, ErrNodeAmbiguous
	}
	// Re-read by name: a replaced Node keeps its name but gets a new UID.
	node, err := k.Client.CoreV1().Nodes().Get(ctx, matches[0].Name, metav1.GetOptions{})
	if err != nil {
		return empty, err
	}
	if string(node.UID) != nodeUID {
		return empty, ErrNodeReplaced
	}
	info := node.Status.NodeInfo
	if info.BootID == "" {
		return empty, ErrNodeNoBoot
	}
	pool := node.Labels[NodePoolLabel]
	row, ok := k.Rows[pool]
	if pool == "" || !ok {
		return empty, ErrNodePoolUnknown
	}
	if row.Measurement == Measured {
		rt := row.NodeRuntime
		if info.OSImage != rt.OSImage || info.KernelVersion != rt.KernelVersion ||
			info.ContainerRuntimeVersion != rt.ContainerRuntimeVersion || info.KubeletVersion != rt.KubeletVersion {
			return empty, ErrProfileStale
		}
	}
	return NodeFacts{NodeUID: nodeUID, BootID: info.BootID, StartupCapture: row.Value, StartupMeasurement: row.Measurement}, nil
}
