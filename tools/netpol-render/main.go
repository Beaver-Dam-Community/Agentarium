// Command netpol-render renders TASK-06 allow-matrix data. It never applies it.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Infra struct {
	IPBlock   string            `yaml:"ipBlock"`
	IPBlocks  []string          `yaml:"ipBlocks"`
	Namespace string            `yaml:"namespace"`
	PodLabels map[string]string `yaml:"podLabels"`
	Ports     []string          `yaml:"ports"`
}
type Edge struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
	Port string `yaml:"port"`
}
type InfraEdge struct {
	From string   `yaml:"from"`
	To   []string `yaml:"to"`
}
type Matrix struct {
	Version    int              `yaml:"version"`
	Namespaces []string         `yaml:"namespaces"`
	Workloads  []string         `yaml:"workloads"`
	Infra      map[string]Infra `yaml:"infra"`
	Edges      []Edge           `yaml:"edges"`
	InfraEdges []InfraEdge      `yaml:"infra_edges"`
}
type rule map[string]any
type policy struct {
	APIVersion string         `json:"apiVersion"`
	Kind       string         `json:"kind"`
	Metadata   map[string]any `json:"metadata"`
	Spec       map[string]any `json:"spec"`
}

func decode(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	return d.Decode(v)
}
func port(s string) (map[string]any, error) {
	p, n, ok := strings.Cut(s, "/")
	if !ok || (p != "TCP" && p != "UDP") {
		return nil, fmt.Errorf("invalid port %q", s)
	}
	v, err := strconv.Atoi(n)
	if err != nil || v < 1 || v > 65535 {
		return nil, fmt.Errorf("invalid port %q", s)
	}
	return map[string]any{"protocol": p, "port": v}, nil
}
func pod(s string) (map[string]any, error) {
	ns, ksa, ok := strings.Cut(s, "/")
	if !ok || ns == "" || ksa == "" || strings.Contains(ksa, "/") {
		return nil, fmt.Errorf("invalid workload %q", s)
	}
	return map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]string{"kubernetes.io/metadata.name": ns}}, "podSelector": map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": ksa}}}, nil
}
func peers(name string, m Matrix) ([]any, error) {
	if v, ok := m.Infra[name]; ok {
		if v.Namespace != "" {
			if len(v.PodLabels) == 0 {
				return nil, errors.New("infra namespace peer needs pod labels")
			}
			return []any{map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]string{"kubernetes.io/metadata.name": v.Namespace}}, "podSelector": map[string]any{"matchLabels": v.PodLabels}}}, nil
		}
		cidrs := v.IPBlocks
		if v.IPBlock != "" {
			cidrs = append(cidrs, v.IPBlock)
		}
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("empty infra peer %s", name)
		}
		out := []any{}
		for _, cidr := range cidrs {
			if strings.HasPrefix(cidr, "${") && cidr != "${control_plane_endpoint}/32" && cidr != "${cloudsql_private_ip}/32" && cidr != "${node_cidr}" {
				return nil, fmt.Errorf("unknown CIDR placeholder %s", cidr)
			}
			if !strings.HasPrefix(cidr, "${") {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
					return nil, fmt.Errorf("invalid/unsafe CIDR %s", cidr)
				}
			}
			out = append(out, map[string]any{"ipBlock": map[string]string{"cidr": cidr}})
		}
		return out, nil
	}
	p, err := pod(name)
	if err != nil {
		return nil, err
	}
	return []any{p}, nil
}
func render(m Matrix) ([]byte, error) {
	if m.Version != 1 {
		return nil, errors.New("unsupported matrix version")
	}
	namespaces := map[string]bool{}
	for _, ns := range m.Namespaces {
		if ns == "" || namespaces[ns] {
			return nil, errors.New("invalid namespace")
		}
		namespaces[ns] = true
	}
	workloads := map[string]bool{}
	in := map[string][]rule{}
	out := map[string][]rule{}
	for _, w := range m.Workloads {
		ns, _, ok := strings.Cut(w, "/")
		if !ok || !namespaces[ns] || workloads[w] {
			return nil, fmt.Errorf("unregistered workload %s", w)
		}
		if _, err := pod(w); err != nil {
			return nil, err
		}
		workloads[w] = true
		in[w] = []rule{}
		out[w] = []rule{}
	}
	for _, e := range m.Edges {
		if !workloads[e.To] {
			return nil, fmt.Errorf("unknown callee %s", e.To)
		}
		if !workloads[e.From] {
			if _, ok := m.Infra[e.From]; !ok {
				return nil, fmt.Errorf("unknown caller %s", e.From)
			}
		}
		p, err := port(e.Port)
		if err != nil {
			return nil, err
		}
		src, err := peers(e.From, m)
		if err != nil {
			return nil, err
		}
		dest, err := peers(e.To, m)
		if err != nil {
			return nil, err
		}
		in[e.To] = append(in[e.To], rule{"from": src, "ports": []any{p}})
		if workloads[e.From] {
			out[e.From] = append(out[e.From], rule{"to": dest, "ports": []any{p}})
		}
	}
	for _, e := range m.InfraEdges {
		if !workloads[e.From] {
			return nil, fmt.Errorf("unknown infra caller %s", e.From)
		}
		if strings.HasPrefix(e.From, "agent-exec/") {
			return nil, errors.New("execution workload cannot have infra egress")
		}
		for _, name := range e.To {
			infra, ok := m.Infra[name]
			if !ok || len(infra.Ports) == 0 {
				return nil, fmt.Errorf("unknown infra destination %s", name)
			}
			dest, err := peers(name, m)
			if err != nil {
				return nil, err
			}
			ports := []any{}
			for _, s := range infra.Ports {
				p, err := port(s)
				if err != nil {
					return nil, err
				}
				ports = append(ports, p)
			}
			out[e.From] = append(out[e.From], rule{"to": dest, "ports": ports})
		}
	}
	// Sort and de-duplicate semantically identical L3/L4 rules.
	stable := func(rules []rule) []rule {
		seen := map[string]bool{}
		pairs := []string{}
		for _, r := range rules {
			b, _ := json.Marshal(r)
			if !seen[string(b)] {
				seen[string(b)] = true
				pairs = append(pairs, string(b))
			}
		}
		sort.Strings(pairs)
		result := []rule{}
		for _, p := range pairs {
			var r rule
			_ = json.Unmarshal([]byte(p), &r)
			result = append(result, r)
		}
		return result
	}
	result := []policy{}
	ns := append([]string(nil), m.Namespaces...)
	sort.Strings(ns)
	for _, n := range ns {
		result = append(result, policy{"networking.k8s.io/v1", "NetworkPolicy", map[string]any{"name": "default-deny", "namespace": n}, map[string]any{"podSelector": map[string]any{}, "policyTypes": []string{"Ingress", "Egress"}}})
	}
	ws := append([]string(nil), m.Workloads...)
	sort.Strings(ws)
	for _, w := range ws {
		ns, ksa, _ := strings.Cut(w, "/")
		metadata := map[string]any{"name": ksa + "-allow", "namespace": ns}
		if ns == "agent-exec" || ns == "agent-adapters" {
			metadata["annotations"] = map[string]string{"policy.network.gke.io/enable-logging": "true"}
		}
		result = append(result, policy{"networking.k8s.io/v1", "NetworkPolicy", metadata, map[string]any{"podSelector": map[string]any{"matchLabels": map[string]string{"app.kubernetes.io/name": ksa}}, "policyTypes": []string{"Ingress", "Egress"}, "ingress": stable(in[w]), "egress": stable(out[w])}})
	}
	// JSON is valid YAML; a List keeps encoding deterministic and kube-compatible.
	return json.MarshalIndent(map[string]any{"apiVersion": "v1", "kind": "List", "items": result}, "", "  ")
}
func main() {
	matrix := flag.String("matrix", "deploy/gcp/base/network/allow-matrix.yaml", "allow matrix")
	output := flag.String("out", "deploy/gcp/base/network/rendered/policies.yaml", "output file")
	check := flag.Bool("check", false, "compare without writing")
	values := flag.String("values", "", "JSON network values from the environment lock")
	flag.Parse()
	var m Matrix
	if err := decode(*matrix, &m); err != nil {
		fail(err)
	}
	if *values != "" {
		raw, err := os.ReadFile(*values)
		if err != nil {
			fail(err)
		}
		var v map[string]string
		if err := json.Unmarshal(raw, &v); err != nil {
			fail(err)
		}
		if len(v) != 3 {
			fail(errors.New("network values must contain exactly control_plane_endpoint, cloudsql_private_ip, node_cidr"))
		}
		for _, key := range []string{"control_plane_endpoint", "cloudsql_private_ip", "node_cidr"} {
			value, ok := v[key]
			if !ok || strings.Contains(value, "${") {
				fail(errors.New("missing network value"))
			}
			if key != "node_cidr" {
				addr, err := netip.ParseAddr(value)
				if err != nil || !addr.Is4() {
					fail(errors.New("network endpoint must be IPv4"))
				}
			}
		}
		for key, infra := range m.Infra {
			for name, value := range v {
				infra.IPBlock = strings.ReplaceAll(infra.IPBlock, "${"+name+"}", value)
			}
			m.Infra[key] = infra
		}
	}
	data, err := render(m)
	if err != nil {
		fail(err)
	}
	data = append(data, '\n')
	if *check {
		old, err := os.ReadFile(*output)
		if err != nil {
			fail(err)
		}
		if !bytes.Equal(old, data) {
			fail(errors.New("rendered policies differ"))
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0755); err != nil {
		fail(err)
	}
	if err := os.WriteFile(*output, data, 0644); err != nil {
		fail(err)
	}
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
