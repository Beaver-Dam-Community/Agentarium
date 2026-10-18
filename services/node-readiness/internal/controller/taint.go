package controller

import (
	"encoding/json"
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

// Start taint (TASK-01 3.5). The node-readiness-scope VAP only accepts
// changes to taints with this key, and compares the remaining taints in order.
const (
	StartTaintKey   = "agentarium.io/observe-not-ready"
	StartTaintValue = "true"
)

var startTaint = corev1.Taint{Key: StartTaintKey, Value: StartTaintValue, Effect: corev1.TaintEffectNoSchedule}

func isStartTaint(t corev1.Taint) bool {
	return t.Key == StartTaintKey && t.Effect == corev1.TaintEffectNoSchedule
}

func hasStartTaint(n *corev1.Node) bool {
	for _, t := range n.Spec.Taints {
		if isStartTaint(t) {
			return true
		}
	}
	return false
}

type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// testOp always serializes value, including empty strings.
type testOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// startTaintPatch returns a JSON patch (RFC 6902) that only adds or removes
// the start taint, or nil when the node already matches want.
//
// The patch first tests resourceVersion and the current taint list, so it
// fails instead of overwriting a concurrent change. Removal deletes indices
// in place and appends on add, so the order of other taints is unchanged.
// Labels, annotations and spec.unschedulable are never part of the patch.
func startTaintPatch(n *corev1.Node, want bool) ([]byte, error) {
	if hasStartTaint(n) == want {
		return nil, nil
	}
	taints := n.Spec.Taints
	ops := []any{
		testOp{Op: "test", Path: "/metadata/resourceVersion", Value: n.ResourceVersion},
	}
	if len(taints) > 0 {
		ops = append(ops, testOp{Op: "test", Path: "/spec/taints", Value: taints})
	}

	if want {
		if len(taints) == 0 {
			ops = append(ops, patchOp{Op: "add", Path: "/spec/taints", Value: []corev1.Taint{startTaint}})
		} else {
			ops = append(ops, patchOp{Op: "add", Path: "/spec/taints/-", Value: startTaint})
		}
	} else {
		for i := len(taints) - 1; i >= 0; i-- {
			if isStartTaint(taints[i]) {
				ops = append(ops, patchOp{Op: "remove", Path: fmt.Sprintf("/spec/taints/%d", i)})
			}
		}
	}
	return json.Marshal(ops)
}
