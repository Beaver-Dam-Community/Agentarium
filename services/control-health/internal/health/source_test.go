package health

import "testing"

func TestNodeSourceID(t *testing.T) {
	node := "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed"
	for _, ok := range []string{"netpol-node/" + node, "lifecycle-node/" + node, "node-sensors-node/" + node, "runtime-guard-node/" + node} {
		if !NodeSourceID(ok, node) {
			t.Errorf("rejected %q", ok)
		}
	}
	for _, bad := range []string{node, "sensor-1", "-node/" + node, "Netpol-node/" + node, "netpol_x-node/" + node, "netpol-node/" + "1B9D6BCD-BBFD-4B2D-9B5D-AB8DFBBD4BED",
		"netpol-node/2b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed", "netpol-node/" + node + "/x", "spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector"} {
		if NodeSourceID(bad, node) {
			t.Errorf("accepted %q", bad)
		}
	}
}
