// model-config-render emits offline installation artifacts from COMMON Appendix B.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

var names = map[string][]string{
	"agent":           {"submit_action", "poll_action", "request_approval"},
	"policy_proposal": {"get_action_evidence", "get_policy_bundle", "get_regression_report"},
	"discovery":       {"discovery_source_read", "discovery_callgraph_read"},
	"intent_check":    {},
}
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
var apiVersion = regexp.MustCompile(`^v[0-9]+(?:beta[0-9]+)?$`)

type modelConfig struct {
	ModelID  string          `json:"model_id"`
	Region   string          `json:"model_region"`
	API      string          `json:"api_version"`
	Profiles json.RawMessage `json:"profiles"`
	Tools    json.RawMessage `json:"tools"`
}

func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	if err := canonical.CheckJSONForJCS(raw); err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errors.New("expected JSON object")
	}
	if keys != nil {
		if len(m) != len(keys) {
			return nil, errors.New("missing or unknown object keys")
		}
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				return nil, fmt.Errorf("missing key %s", k)
			}
		}
	}
	return m, nil
}

func parseLock(raw []byte) (modelConfig, string, error) {
	var m modelConfig
	root, err := object(raw)
	if err != nil {
		return m, "", err
	}
	project, err := object(root["project"])
	if err != nil {
		return m, "", fmt.Errorf("project: %w", err)
	}
	var projectID string
	if err := json.Unmarshal(project["id"], &projectID); err != nil || !identifier.MatchString(projectID) || strings.Contains(projectID, "REPLACE") {
		return m, "", errors.New("project.id must be an installed identifier")
	}
	if _, err := object(root["model"], "model_id", "model_region", "api_version", "profiles", "tools"); err != nil {
		return m, "", fmt.Errorf("model: %w", err)
	}
	if err := json.Unmarshal(root["model"], &m); err != nil {
		return m, "", err
	}
	for _, s := range []string{m.ModelID, m.Region} {
		if !identifier.MatchString(s) || strings.Contains(s, "REPLACE") {
			return m, "", errors.New("model ID and region must be installed identifiers")
		}
	}
	if !apiVersion.MatchString(m.API) {
		return m, "", errors.New("invalid model API version")
	}
	return m, projectID, nil
}

func validateTools(raw []byte) error {
	profiles, err := object(raw, "agent", "policy_proposal", "intent_check", "discovery")
	if err != nil {
		return err
	}
	for profile, want := range names {
		var declarations []json.RawMessage
		if err := json.Unmarshal(profiles[profile], &declarations); err != nil || declarations == nil || len(declarations) != len(want) {
			return fmt.Errorf("%s: wrong declaration array", profile)
		}
		for i, rawDeclaration := range declarations {
			fields, err := object(rawDeclaration, "name", "description", "parameters")
			if err != nil {
				return fmt.Errorf("%s declaration: %w", profile, err)
			}
			var name, description string
			if err := json.Unmarshal(fields["name"], &name); err != nil || name != want[i] {
				return fmt.Errorf("%s: wrong registered tool order/name", profile)
			}
			if err := json.Unmarshal(fields["description"], &description); err != nil || len(description) < 1 || len(description) > 1024 {
				return fmt.Errorf("%s: description must be 1..1024 bytes", profile)
			}
			if _, err := object(fields["parameters"]); err != nil {
				return fmt.Errorf("%s parameters: %w", profile, err)
			}
			// Apply the same JSON grammar/depth/integer rules as ClientAction input.
			if err := canonical.CheckStrictJSON(rawDeclaration); err != nil {
				return fmt.Errorf("%s: %w", profile, err)
			}
			p, err := canonical.JCS(fields["parameters"])
			if err != nil || len(p) > canonical.MaxToolParametersBytes {
				return fmt.Errorf("%s: parameters exceed canonical limit", profile)
			}
		}
	}
	return nil
}

func compareCatalog(m modelConfig, project string, cat canonical.Catalog) error {
	op, ok := cat.Operations[canonical.OpModelGenerate]
	if !ok {
		return errors.New("catalog has no model.generate operation")
	}
	route := "/" + m.API + "/projects/{project}/locations/{location}/publishers/google/models/{model_id}:generateContent"
	if op.RouteTemplate != route {
		return errors.New("model route API version differs from lock")
	}
	if op.ModelProfiles == nil || len(*op.ModelProfiles) != len(names) {
		return errors.New("catalog must register all four model profiles")
	}
	for name := range names {
		if !slices.Contains(*op.ModelProfiles, name) {
			return fmt.Errorf("catalog missing profile %s", name)
		}
	}
	count := 0
	for _, target := range cat.Targets {
		if !slices.Contains(target.OperationIDs, canonical.OpModelGenerate) {
			continue
		}
		count++
		t := target.Model
		if t == nil || t.Project == nil || t.Location == nil || t.ModelID == nil || *t.Project != project || *t.Location != m.Region || *t.ModelID != m.ModelID {
			return errors.New("catalog model target differs from lock project/location/model_id")
		}
	}
	if count == 0 {
		return errors.New("catalog has no model target")
	}
	return nil
}

// artifacts validates everything before producing any filesystem output.
func artifacts(raw []byte, cat canonical.Catalog, runtimeTools []byte) (map[string][]byte, error) {
	m, project, err := parseLock(raw)
	if err != nil {
		return nil, err
	}
	profiles, err := canonical.ParseModelProfiles(m.Profiles)
	if err != nil {
		return nil, fmt.Errorf("profiles: %w", err)
	}
	for name, profile := range profiles {
		limit := int64(65536)
		if name == "intent_check" {
			limit = 16384
			if profile.MaxOutputTokens > 1024 {
				return nil, errors.New("intent_check output exceeds 1024 tokens")
			}
		}
		if profile.MaxRequestBytes > limit {
			return nil, fmt.Errorf("%s request exceeds TASK-05 limit", name)
		}
	}
	if err := validateTools(m.Tools); err != nil {
		return nil, err
	}
	if err := compareCatalog(m, project, cat); err != nil {
		return nil, err
	}
	profileBytes, err := canonical.JCS(m.Profiles)
	if err != nil {
		return nil, err
	}
	toolBytes, err := canonical.JCS(m.Tools)
	if err != nil {
		return nil, err
	}
	if runtimeTools != nil {
		imageTools, err := canonical.JCS(runtimeTools)
		if err != nil || !bytes.Equal(imageTools, toolBytes) {
			return nil, errors.New("runtime image model-tools digest differs from lock")
		}
	}
	digests := map[string]string{"model-profiles.json": canonical.SHA256Hex(profileBytes), "model-tools.json": canonical.SHA256Hex(toolBytes)}
	combined, err := canonical.CanonicalDigest(digests)
	if err != nil {
		return nil, err
	}
	data := map[string]string{"model-profiles.json": string(profileBytes), "model-tools.json": string(toolBytes)}
	name := "model-config-" + combined[:32]
	files := map[string][]byte{"model-profiles.json": profileBytes, "model-tools.json": toolBytes}
	items := []any{}
	for _, namespace := range []string{"agent-control", "agent-adapters", "agent-observe"} {
		items = append(items, map[string]any{
			"apiVersion": "v1", "kind": "ConfigMap", "immutable": true,
			"metadata": map[string]any{"name": name, "namespace": namespace, "annotations": map[string]string{
				"agentarium.io/model-profiles-digest": digests["model-profiles.json"],
				"agentarium.io/model-tools-digest":    digests["model-tools.json"],
			}}, "data": data,
		})
	}
	files["configmaps.json"], err = json.MarshalIndent(map[string]any{"apiVersion": "v1", "kind": "List", "items": items}, "", "  ")
	if err != nil {
		return nil, err
	}
	files["digests.json"], err = json.MarshalIndent(map[string]any{"files": digests, "catalog_digest": cat.CatalogDigest, "configmap_name": name}, "", "  ")
	return files, err
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Installation input, not an HTTP payload. Keep memory and Kubernetes output bounded.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, errors.New("input must be a regular file no larger than 1 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("input exceeds 1 MiB")
	}
	return raw, nil
}

func run(lockPath, catalogDir, out, verifyTools string) error {
	raw, err := readBounded(lockPath)
	if err != nil {
		return err
	}
	cat, err := canonical.LoadCatalogDir(catalogDir)
	if err != nil {
		return err
	}
	var runtimeTools []byte
	if verifyTools != "" {
		runtimeTools, err = readBounded(verifyTools)
		if err != nil {
			return err
		}
	}
	files, err := artifacts(raw, cat, runtimeTools)
	if err != nil {
		return err
	}
	// Never overwrite an earlier artifact directory, including a symlink.
	if err := os.Mkdir(out, 0755); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(out)
		}
	}()
	for name, raw := range files {
		if err := os.WriteFile(filepath.Join(out, name), raw, 0444); err != nil {
			return err
		}
	}
	complete = true
	return nil
}

func main() {
	lock := flag.String("lock", "", "environment lock with Q0-selected model settings")
	catalog := flag.String("catalog", "", "catalog directory containing operations.yaml and targets.yaml")
	out := flag.String("out", "", "new output directory")
	runtimeTools := flag.String("verify-runtime-tools", "", "model-tools.json extracted from the approved runtime image")
	flag.Parse()
	if *lock == "" || *catalog == "" || *out == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "--lock, --catalog and --out are required")
		os.Exit(2)
	}
	if err := run(*lock, *catalog, *out, *runtimeTools); err != nil {
		fmt.Fprintln(os.Stderr, "model-config-render:", err)
		os.Exit(1)
	}
	fmt.Println(*out)
}
