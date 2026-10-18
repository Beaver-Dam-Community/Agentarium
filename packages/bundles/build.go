package bundles

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// SignaturesFile is the OPA bundle signature file. It is never accepted as
// input and never part of candidate_digest.
const SignaturesFile = ".signatures.json"

// policyDataKeys are the top-level keys of the policy data input (COMMON
// Appendix A). data.catalog comes from the catalog and data.data_class_rank
// is fixed, so neither may appear in the input.
var policyDataKeys = []string{"adapter_constraints", "receiver", "sensor_rules", "service_profiles", "standing_rules"}

// dataClassRank is the fixed data.data_class_rank (COMMON Appendix A).
var dataClassRank = map[string]any{"none": 0, "synthetic": 1, "internal": 2, "confidential": 3}

// Input is everything a bundle is built from.
type Input struct {
	// PolicyDir holds the Rego modules. Only regular *.rego files are read;
	// anything else (symlinks, other files, a .signatures.json) is an error.
	PolicyDir string
	// Catalog is data.catalog, loaded with canonical.LoadCatalogDir.
	Catalog canonical.Catalog
	// PolicyData is a JSON object with exactly the policyDataKeys.
	PolicyData []byte
	// Revision is the .manifest revision the gateway compares with
	// active_policy.expected_opa_revision. It must not be empty.
	Revision string
}

// Unsigned is a built bundle before signing.
type Unsigned struct {
	bundle          bundle.Bundle
	Tarball         []byte // unsigned tarball
	CandidateDigest string
}

// Build validates the input and returns the unsigned bundle with its
// candidate_digest.
func Build(in Input) (*Unsigned, error) {
	if strings.TrimSpace(in.Revision) == "" {
		return nil, errors.New("bundles: empty revision")
	}
	if in.Catalog.CatalogDigest == "" {
		return nil, errors.New("bundles: catalog has no catalog_digest")
	}
	modules, err := readModules(in.PolicyDir)
	if err != nil {
		return nil, err
	}
	data, err := assembleData(in.Catalog, in.PolicyData)
	if err != nil {
		return nil, err
	}
	b := bundle.Bundle{
		Manifest: bundle.Manifest{Revision: in.Revision},
		Data:     data,
		Modules:  modules,
	}
	b.Manifest.SetRegoVersion(ast.RegoV1)
	tarball, err := writeTarball(b)
	if err != nil {
		return nil, err
	}
	digest, err := CandidateDigest(tarball)
	if err != nil {
		return nil, err
	}
	return &Unsigned{bundle: b, Tarball: tarball, CandidateDigest: digest}, nil
}

// readModules reads and parses every *.rego file under dir as Rego v1,
// sorted by path. Paths in the bundle are slash-separated and relative.
func readModules(dir string) ([]bundle.ModuleFile, error) {
	if dir == "" {
		return nil, errors.New("bundles: empty policy dir")
	}
	var modules []bundle.ModuleFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("bundles: %s is not a regular file", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if path.Base(name) == SignaturesFile {
			return fmt.Errorf("bundles: %s must not be an input", SignaturesFile)
		}
		if path.Ext(name) != ".rego" {
			return fmt.Errorf("bundles: %s is not a .rego file", name)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		parsed, err := ast.ParseModuleWithOpts(name, string(raw), ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			return fmt.Errorf("bundles: %w", err)
		}
		modules = append(modules, bundle.ModuleFile{URL: "/" + name, Path: "/" + name, Raw: raw, Parsed: parsed})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(modules) == 0 {
		return nil, fmt.Errorf("bundles: no .rego files in %s", dir)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, nil
}

// assembleData builds the bundle data document (COMMON Appendix A).
func assembleData(cat canonical.Catalog, policyData []byte) (map[string]any, error) {
	if err := canonical.CheckJSONForJCS(policyData); err != nil {
		return nil, fmt.Errorf("bundles: policy data: %w", err)
	}
	var pd map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(policyData))
	dec.UseNumber()
	if err := dec.Decode(&pd); err != nil {
		return nil, fmt.Errorf("bundles: policy data: %w", err)
	}
	keys := make([]string, 0, len(pd))
	for k := range pd {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, policyDataKeys) {
		return nil, fmt.Errorf("bundles: policy data keys %v, want exactly %v", keys, policyDataKeys)
	}
	if err := checkPolicyData(pd); err != nil {
		return nil, err
	}

	// Round-trip everything through JSON so data holds only plain JSON
	// values, the same values the gateway gets back from data.json.
	catJSON, err := json.Marshal(cat)
	if err != nil {
		return nil, err
	}
	data := map[string]any{"data_class_rank": dataClassRank}
	if data["catalog"], err = decodeValue(catJSON); err != nil {
		return nil, err
	}
	for _, k := range policyDataKeys {
		if data[k], err = decodeValue(pd[k]); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func decodeValue(raw []byte) (any, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// checkPolicyData enforces the Appendix A shape rules that the bundle relies
// on: standing rule ids match their map keys and set-valued arrays are sorted
// and free of duplicates.
func checkPolicyData(pd map[string]json.RawMessage) error {
	var receiver struct {
		AllowedDisclosureFields []string `json:"allowed_disclosure_fields"`
	}
	if err := json.Unmarshal(pd["receiver"], &receiver); err != nil {
		return fmt.Errorf("bundles: receiver: %w", err)
	}
	if err := sortedSet("receiver.allowed_disclosure_fields", receiver.AllowedDisclosureFields); err != nil {
		return err
	}
	var rules map[string]struct {
		StandingRuleID string   `json:"standing_rule_id"`
		OperationIDs   []string `json:"operation_ids"`
	}
	if err := json.Unmarshal(pd["standing_rules"], &rules); err != nil {
		return fmt.Errorf("bundles: standing_rules: %w", err)
	}
	for id, r := range rules {
		if r.StandingRuleID != id {
			return fmt.Errorf("bundles: standing_rules[%q] has standing_rule_id %q", id, r.StandingRuleID)
		}
		if len(r.OperationIDs) == 0 {
			return fmt.Errorf("bundles: standing_rules[%q] has no operation_ids", id)
		}
	}
	return nil
}

func sortedSet(name string, v []string) error {
	for i := 1; i < len(v); i++ {
		if v[i-1] >= v[i] {
			return fmt.Errorf("bundles: %s must be sorted without duplicates", name)
		}
	}
	return nil
}

// writeTarball writes the bundle with OPA's writer. Module bytes are written
// as given (DisableFormat), so the signed hashes match the files.
func writeTarball(b bundle.Bundle) ([]byte, error) {
	var buf bytes.Buffer
	if err := bundle.NewWriter(&buf).DisableFormat(true).Write(b); err != nil {
		return nil, fmt.Errorf("bundles: write: %w", err)
	}
	return buf.Bytes(), nil
}

// DefinesRule reports whether a module in the bundle declares package pkg
// (for example "agentarium.gateway") and a rule named rule in it.
func (u *Unsigned) DefinesRule(pkg, rule string) bool {
	for _, m := range u.bundle.Modules {
		if m.Parsed == nil || strings.TrimPrefix(m.Parsed.Package.Path.String(), "data.") != pkg {
			continue
		}
		for _, r := range m.Parsed.Rules {
			if r.Head.Name.String() == rule || r.Head.Ref().String() == rule {
				return true
			}
		}
	}
	return false
}
