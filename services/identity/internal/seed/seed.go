// Package seed loads the initial identity.registered_workloads rows
// (TASK-03 chapter 9 install input) and validates them before anything is written.
package seed

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/store"
)

type file struct {
	Workloads []entry `yaml:"workloads"`
}

type entry struct {
	Namespace        string `yaml:"namespace"`
	KSA              string `yaml:"ksa"`
	Role             string `yaml:"role"`
	AdapterID        string `yaml:"adapter_id"`
	ServicePrincipal string `yaml:"service_principal"`
}

// Parse decodes the seed file strictly (unknown fields and a second document
// are errors) and checks every row against the DDL rules.
func Parse(data []byte) ([]store.Registration, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f file
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("seed: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("seed: more than one YAML document")
	}
	if len(f.Workloads) == 0 {
		return nil, errors.New("seed: no workloads")
	}
	seen := map[string]bool{}
	out := make([]store.Registration, 0, len(f.Workloads))
	for i, e := range f.Workloads {
		role := pki.Role(e.Role)
		if !role.Valid() {
			return nil, fmt.Errorf("seed[%d]: unknown role %q", i, e.Role)
		}
		if role == pki.RoleNodeBridge {
			return nil, fmt.Errorf("seed[%d]: node_bridge issuance is not enabled", i)
		}
		if _, err := pki.ServiceSAN(e.Namespace, e.KSA); err != nil {
			return nil, fmt.Errorf("seed[%d]: %w", i, err)
		}
		key := e.Namespace + "/" + e.KSA
		if seen[key] {
			return nil, fmt.Errorf("seed[%d]: duplicate %s", i, key)
		}
		seen[key] = true
		if (role == pki.RoleAdapter) != (e.AdapterID != "") {
			return nil, fmt.Errorf("seed[%d]: %s: adapter_id is required for adapters and only for adapters", i, key)
		}
		if (role == pki.RoleService) != (e.ServicePrincipal != "") {
			return nil, fmt.Errorf("seed[%d]: %s: service_principal is required for services and only for services", i, key)
		}
		out = append(out, store.Registration{Namespace: e.Namespace, KSA: e.KSA, Role: role,
			AdapterID: e.AdapterID, ServicePrincipal: e.ServicePrincipal})
	}
	return out, nil
}
