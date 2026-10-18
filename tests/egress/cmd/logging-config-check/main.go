// logging-config-check compares the installed NetworkLogging object and
// NetworkPolicy allow-logging annotations with the reviewed TASK-06 3.4
// manifests. It reads saved `kubectl get ... -o json` output only; it does not
// contact the cluster, and a passing report does not prove that any connection
// was actually logged.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"reflect"
	"sort"

	"sigs.k8s.io/yaml"
)

const annotation = "policy.network.gke.io/enable-logging"

type object struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	Spec json.RawMessage `json:"spec"`
}

type check struct {
	Name     string `json:"name"`
	Expected any    `json:"expected"`
	Observed any    `json:"observed"`
	Passed   bool   `json:"passed"`
}

type report struct {
	Checks []check `json:"checks"`
	Passed bool    `json:"passed"`
}

func decode(raw []byte, v any) error {
	j, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(j, v)
}

func spec(raw json.RawMessage) (any, error) {
	var v any
	if len(raw) == 0 {
		return nil, nil
	}
	err := json.Unmarshal(raw, &v)
	return v, err
}

// annotated returns the sorted namespace/name keys whose policy carries the
// allow-logging annotation with value "true", and every key seen.
func annotated(items []object) (on []string, all map[string]bool) {
	all = map[string]bool{}
	for _, p := range items {
		key := p.Metadata.Namespace + "/" + p.Metadata.Name
		all[key] = true
		if p.Metadata.Annotations[annotation] == "true" {
			on = append(on, key)
		}
	}
	sort.Strings(on)
	return on, all
}

func evaluate(manifest, rendered, liveLogging, livePolicies []byte) (report, error) {
	var want, got object
	var wantList, gotList struct {
		Items []object `json:"items"`
	}
	for _, d := range []struct {
		raw []byte
		v   any
		n   string
	}{{manifest, &want, "manifest"}, {rendered, &wantList, "rendered policies"},
		{liveLogging, &got, "live NetworkLogging"}, {livePolicies, &gotList, "live NetworkPolicies"}} {
		if err := decode(d.raw, d.v); err != nil {
			return report{}, fmt.Errorf("%s: %w", d.n, err)
		}
	}
	if len(wantList.Items) == 0 {
		return report{}, fmt.Errorf("rendered policies: no items")
	}
	var r report
	add := func(name string, expected, observed any) {
		r.Checks = append(r.Checks, check{name, expected, observed, reflect.DeepEqual(expected, observed)})
	}
	add("network_logging_identity",
		[]string{want.APIVersion, want.Kind, want.Metadata.Name},
		[]string{got.APIVersion, got.Kind, got.Metadata.Name})
	wantSpec, err := spec(want.Spec)
	if err != nil || wantSpec == nil {
		return report{}, fmt.Errorf("manifest: invalid spec")
	}
	gotSpec, err := spec(got.Spec)
	if err != nil {
		return report{}, fmt.Errorf("live NetworkLogging: invalid spec")
	}
	add("network_logging_spec", wantSpec, gotSpec)
	wantOn, _ := annotated(wantList.Items)
	gotOn, gotAll := annotated(gotList.Items)
	if wantOn == nil {
		return report{}, fmt.Errorf("rendered policies: no allow-logging annotation")
	}
	if gotOn == nil {
		gotOn = []string{}
	}
	add("allow_logging_annotated_policies", wantOn, gotOn)
	var missing []string
	for _, p := range wantList.Items {
		if key := p.Metadata.Namespace + "/" + p.Metadata.Name; !gotAll[key] {
			missing = append(missing, key)
		}
	}
	if missing == nil {
		missing = []string{}
	}
	add("rendered_policies_missing_live", []string{}, missing)
	r.Passed = true
	for _, c := range r.Checks {
		r.Passed = r.Passed && c.Passed
	}
	return r, nil
}

func main() {
	manifest := flag.String("manifest", "deploy/gcp/base/network/network-logging.yaml", "reviewed NetworkLogging manifest")
	rendered := flag.String("rendered", "deploy/gcp/base/network/rendered/policies.yaml", "reviewed rendered NetworkPolicy list")
	logging := flag.String("network-logging", "", "output of `kubectl get networklogging default -o json`")
	policies := flag.String("policies", "", "output of `kubectl get networkpolicies -A -o json`")
	flag.Parse()
	if *logging == "" || *policies == "" {
		fmt.Fprintln(os.Stderr, "--network-logging and --policies are required")
		os.Exit(2)
	}
	var inputs [4][]byte
	for i, path := range []string{*manifest, *rendered, *logging, *policies} {
		b, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		inputs[i] = b
	}
	r, err := evaluate(inputs[0], inputs[1], inputs[2], inputs[3])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	_ = out.Encode(r)
	if !r.Passed {
		os.Exit(1)
	}
}
