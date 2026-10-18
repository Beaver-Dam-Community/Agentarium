package baseline

import (
	"fmt"
	"sort"
)

// NodePoolConfig projects a GKE clusters.get response (REST JSON, camelCase,
// as returned by google.golang.org/api/container/v1 or
// `gcloud container clusters describe --format=json`) to the node_pool_config
// baseline value:
//
//	{"nodePools": [{"name", "config": {"taints", "labels", "workloadMetadataConfig"},
//	                "management": {"autoUpgrade", "autoRepair"}, "maintenancePolicy"}...],
//	 "maintenanceExclusions": <cluster maintenancePolicy.window.maintenanceExclusions>}
//
// nodePools is sorted by name. The GKE REST API omits false/empty fields, so
// absent values are filled with explicit defaults (false, [], {}, null) to make
// the projection independent of how the response was serialized.
//
// SPEC-QUESTION: TASK-01 4 lists the fields and "sort by name" but not the
// shape that combines the per-pool list with the cluster exclusions, nor
// whether absent API fields are normalized; this shape and the defaults are
// an implementation choice. Taint order inside a pool is kept as returned.
func NodePoolConfig(cluster map[string]any) (map[string]any, error) {
	rawPools, ok := cluster["nodePools"].([]any)
	if !ok || len(rawPools) == 0 {
		return nil, fmt.Errorf("cluster has no nodePools")
	}
	pools := make([]map[string]any, 0, len(rawPools))
	seen := map[string]bool{}
	for i, rp := range rawPools {
		p, ok := rp.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("nodePools[%d] is not an object", i)
		}
		name, _ := p["name"].(string)
		if name == "" {
			return nil, fmt.Errorf("nodePools[%d] has no name", i)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate node pool %q", name)
		}
		seen[name] = true
		cfg, _ := p["config"].(map[string]any)
		mgmt, _ := p["management"].(map[string]any)
		pools = append(pools, map[string]any{
			"name": name,
			"config": map[string]any{
				"taints":                 orDefault(cfg["taints"], []any{}),
				"labels":                 orDefault(cfg["labels"], map[string]any{}),
				"workloadMetadataConfig": orDefault(cfg["workloadMetadataConfig"], nil),
			},
			"management": map[string]any{
				"autoUpgrade": orDefault(mgmt["autoUpgrade"], false),
				"autoRepair":  orDefault(mgmt["autoRepair"], false),
			},
			"maintenancePolicy": orDefault(p["maintenancePolicy"], nil),
		})
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i]["name"].(string) < pools[j]["name"].(string) })
	var excl any = map[string]any{}
	if mp, ok := cluster["maintenancePolicy"].(map[string]any); ok {
		if w, ok := mp["window"].(map[string]any); ok {
			excl = orDefault(w["maintenanceExclusions"], map[string]any{})
		}
	}
	arr := make([]any, len(pools))
	for i, p := range pools {
		arr[i] = p
	}
	return map[string]any{"nodePools": arr, "maintenanceExclusions": excl}, nil
}

func orDefault(v, def any) any {
	if v == nil {
		return def
	}
	return deepCopy(v)
}
