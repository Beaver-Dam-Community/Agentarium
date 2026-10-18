package netpolcollector

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestNormalizeDefaultsAndSchema(t *testing.T) {
	original := bytes.Split(q0(t), []byte("\n"))[0]
	for _, tc := range []struct {
		name  string
		edit  func(map[string]any)
		valid bool
	}{
		{"missing count and endpoints", func(v map[string]any) { delete(v, "count"); delete(v, "src"); delete(v, "dest"); delete(v, "policies") }, true},
		{"icmp null ports", func(v map[string]any) {
			c := v["connection"].(map[string]any)
			c["protocol"] = "icmp"
			delete(c, "src_port")
			delete(c, "dest_port")
		}, true},
		{"count zero", func(v map[string]any) { v["count"] = 0 }, false},
		{"count null", func(v map[string]any) { v["count"] = nil }, false},
		{"count SQL overflow", func(v map[string]any) { v["count"] = 2147483648 }, false},
		{"count fractional", func(v map[string]any) { v["count"] = 1.5 }, false},
		{"deny policies", func(v map[string]any) { v["disposition"] = "deny" }, false},
		{"unknown disposition", func(v map[string]any) { v["disposition"] = "blocked" }, false},
		{"unknown direction", func(v map[string]any) { v["connection"].(map[string]any)["direction"] = "both" }, false},
		{"unknown protocol", func(v map[string]any) { v["connection"].(map[string]any)["protocol"] = "sctp" }, false},
		{"bad address", func(v map[string]any) { v["connection"].(map[string]any)["dest_ip"] = "backend.local" }, false},
		{"zoned address", func(v map[string]any) { v["connection"].(map[string]any)["dest_ip"] = "fe80::1%eth0" }, false},
		{"port overflow", func(v map[string]any) { v["connection"].(map[string]any)["dest_port"] = 65536 }, false},
		{"icmp nonnull port", func(v map[string]any) { v["connection"].(map[string]any)["protocol"] = "icmp" }, false},
		{"bad timestamp", func(v map[string]any) { v["timestamp"] = "yesterday" }, false},
		{"namespace conflict", func(v map[string]any) { v["src"].(map[string]any)["pod_namespace"] = "another" }, false},
		{"Cloud Logging wrapper", func(v map[string]any) { delete(v, "connection") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v map[string]any
			_ = json.Unmarshal(original, &v)
			tc.edit(v)
			raw, _ := json.Marshal(v)
			got, e := Normalize(raw)
			if tc.valid && e != nil || !tc.valid && !errors.Is(e, ErrSchema) {
				t.Fatalf("Normalize error %v", e)
			}
			if tc.name == "missing count and endpoints" && (got.Count != 1 || got.SrcEndpoint != nil || got.DestEndpoint != nil || got.Policies != nil) {
				t.Fatal("invented missing metadata")
			}
		})
	}
	if _, e := Normalize([]byte(`{"count":1,"count":2}`)); !errors.Is(e, ErrSchema) {
		t.Fatal("duplicate field accepted")
	}
}
