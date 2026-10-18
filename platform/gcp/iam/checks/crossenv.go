package checks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// CrossEnvGrant is one production-resource grant that a regression workload
// principal may hold (TASK-06 3.3 "cross-environment grant exceptions", #97). A binding is
// exempt from CROSS_ENV_POOL only when the Cloud Asset Inventory record's name
// and asset type, the binding's role and the exact member equal one of these
// and the binding has no condition.
type CrossEnvGrant struct {
	Resource  string // full resource name, as in the asset record
	AssetType string
	Role      string
	Member    string
}

// CrossEnvInputs are the installation values from which the four allowed
// grants are built. Nothing else can be allowlisted.
type CrossEnvInputs struct {
	RegressionProjectID        string `json:"regression_project_id"`
	RegressionProjectNumber    string `json:"regression_project_number"`
	DecisionInputExportsBucket string `json:"decision_input_exports_bucket"`
	ManifestKey                string `json:"manifest_key"` // projects/<checked project ID>/locations/L/keyRings/R/cryptoKeys/K
	RegressionRequestsBucket   string `json:"regression_requests_bucket"`
	RegressionReportsBucket    string `json:"regression_reports_bucket"`
}

// RoleDefinition is `gcloud iam roles describe ROLE --project P --format=json`.
type RoleDefinition struct {
	Name                string   `json:"name"`
	Title               string   `json:"title"`
	Description         string   `json:"description"`
	IncludedPermissions []string `json:"includedPermissions"`
	Stage               string   `json:"stage"`
	Etag                string   `json:"etag"`
	Deleted             bool     `json:"deleted"`
}

const (
	// ManifestPublicKeyRoleID is the custom role fixed by TASK-06 3.3. The
	// predefined roles/cloudkms.publicKeyViewer also grants location and
	// project reads, so it is not accepted.
	ManifestPublicKeyRoleID = "agentariumManifestPublicKey"
	viewPublicKey           = "cloudkms.cryptoKeyVersions.viewPublicKey"
	bucketAssetType         = "storage.googleapis.com/Bucket"
	cryptoKeyAssetType      = "cloudkms.googleapis.com/CryptoKey"
)

var (
	projectIDRe     = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	projectNumberRe = regexp.MustCompile(`^[0-9]{6,20}$`)
	bucketRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]$`)
	keyTailRe       = regexp.MustCompile(`^locations/[a-z0-9-]+/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+$`)
)

// BucketResource is the Cloud Asset Inventory name of a Cloud Storage bucket,
// "//storage.googleapis.com/BUCKET" (asset-inventory/docs/resource-name-format).
// It differs from the JSON API path projects/_/buckets/BUCKET.
func BucketResource(bucket string) string { return "//storage.googleapis.com/" + bucket }

// CryptoKeyResource is the Cloud Asset Inventory name of a Cloud KMS key,
// "//cloudkms.googleapis.com/projects/P/locations/L/keyRings/R/cryptoKeys/K".
func CryptoKeyResource(key string) string { return "//cloudkms.googleapis.com/" + key }

// ManifestPublicKeyRole is the only role accepted on the manifest key.
func ManifestPublicKeyRole(prod Env) string {
	return "projects/" + prod.ProjectID + "/roles/" + ManifestPublicKeyRoleID
}

// CrossEnvAllowlist returns exactly the four grants of TASK-06 3.3 for the
// checked (production) environment. The manifest key must belong to that
// project, and role must be the definition of ManifestPublicKeyRole(prod)
// with exactly the viewPublicKey permission.
func CrossEnvAllowlist(in CrossEnvInputs, prod Env, role RoleDefinition) ([]CrossEnvGrant, error) {
	keyPrefix := "projects/" + prod.ProjectID + "/"
	switch {
	case !projectIDRe.MatchString(prod.ProjectID) || !projectNumberRe.MatchString(prod.ProjectNumber):
		return nil, errors.New("cross-env: the checked project ID and number are both required")
	case !projectIDRe.MatchString(in.RegressionProjectID) || !projectNumberRe.MatchString(in.RegressionProjectNumber):
		return nil, errors.New("cross-env: invalid regression project ID or number")
	case in.RegressionProjectID == prod.ProjectID || in.RegressionProjectNumber == prod.ProjectNumber:
		return nil, errors.New("cross-env: regression project must differ from the checked environment")
	case !bucketRe.MatchString(in.DecisionInputExportsBucket) || !bucketRe.MatchString(in.RegressionRequestsBucket) || !bucketRe.MatchString(in.RegressionReportsBucket):
		return nil, errors.New("cross-env: invalid bucket name")
	case in.RegressionRequestsBucket == in.RegressionReportsBucket || in.DecisionInputExportsBucket == in.RegressionRequestsBucket || in.DecisionInputExportsBucket == in.RegressionReportsBucket:
		return nil, errors.New("cross-env: the three buckets must be distinct")
	case !strings.HasPrefix(in.ManifestKey, keyPrefix) || !keyTailRe.MatchString(strings.TrimPrefix(in.ManifestKey, keyPrefix)):
		return nil, errors.New("cross-env: manifest_key must be projects/<checked project ID>/locations/L/keyRings/R/cryptoKeys/K")
	case role.Name != ManifestPublicKeyRole(prod):
		return nil, fmt.Errorf("cross-env: role definition must be %s", ManifestPublicKeyRole(prod))
	case role.Deleted || role.Stage == "DISABLED" || !slices.Equal(role.IncludedPermissions, []string{viewPublicKey}):
		return nil, fmt.Errorf("cross-env: %s must be active with exactly %s", role.Name, viewPublicKey)
	}
	member := func(ksa string) string {
		return fmt.Sprintf("principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s.svc.id.goog/subject/ns/agent-release/sa/%s",
			in.RegressionProjectNumber, in.RegressionProjectID, ksa)
	}
	return []CrossEnvGrant{
		{BucketResource(in.DecisionInputExportsBucket), bucketAssetType, "roles/storage.objectViewer", member("decision-replay")},
		{CryptoKeyResource(in.ManifestKey), cryptoKeyAssetType, role.Name, member("decision-replay")},
		{BucketResource(in.RegressionRequestsBucket), bucketAssetType, "roles/storage.objectViewer", member("regression-runner")},
		{BucketResource(in.RegressionReportsBucket), bucketAssetType, "roles/storage.objectCreator", member("regression-runner")},
	}, nil
}

func strictDecode(data []byte, v any, what string) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: trailing data", what)
	}
	return nil
}

// ParseCrossEnvInputs decodes the installation values strictly.
func ParseCrossEnvInputs(data []byte) (CrossEnvInputs, error) {
	var in CrossEnvInputs
	return in, strictDecode(data, &in, "cross-env inputs")
}

// ParseRoleDefinition decodes `gcloud iam roles describe --format=json`.
func ParseRoleDefinition(data []byte) (RoleDefinition, error) {
	var r RoleDefinition
	return r, strictDecode(data, &r, "role definition")
}

// AssetPolicy is one Cloud Asset Inventory IAM-policy record
// (`gcloud asset export --content-type=iam-policy`, one JSON object per line).
// The resource name comes from the export, never from an operator label.
type AssetPolicy struct {
	Name      string
	AssetType string
	Ancestors []string // e.g. projects/NUMBER, folders/..., organizations/...
	Policy    *Policy
}

// assetEnvelopeKeys maps each asset-record field the checks read to the two
// spellings Cloud Asset Inventory uses. `gcloud asset export
// --output-path=gs://…` writes snake_case keys (asset_type, iam_policy,
// update_time), while the asset REST API and BigQuery export use the proto3
// JSON camelCase (assetType, iamPolicy, updateTime). The record is accepted
// in either spelling; mixing the two spellings of one field in one record is
// rejected below. Only these fields are read: any other envelope field (a
// field Cloud Asset adds later, or resource/content fields the checks do not
// use) is ignored so a new field does not reject the whole export.
var assetEnvelopeKeys = map[string][2]string{
	"name":       {"name", "name"},
	"assetType":  {"assetType", "asset_type"},
	"iamPolicy":  {"iamPolicy", "iam_policy"},
	"ancestors":  {"ancestors", "ancestors"},
	"updateTime": {"updateTime", "update_time"},
}

// ParseAssetExport decodes every non-empty line. The IAM policy inside each
// record is still parsed strictly by ParsePolicy (exact camelCase field
// names, no duplicate or case-colliding keys), so a malformed policy cannot
// hide a member. The record envelope accepts the camelCase or snake_case
// spelling of each field it reads and ignores any field it does not.
// Duplicate resource names, inside the data or already in seen, are an error:
// two records for one resource could otherwise hide one of the policies.
func ParseAssetExport(data []byte, seen map[string]bool) ([]AssetPolicy, error) {
	var out []AssetPolicy
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		rec, err := decodeAssetEnvelope(line)
		if err != nil {
			return nil, fmt.Errorf("asset line %d: %w", n, err)
		}
		if !strings.HasPrefix(rec.name, "//") || rec.assetType == "" || len(rec.iamPolicy) == 0 {
			return nil, fmt.Errorf("asset line %d: name, assetType and iamPolicy are required", n)
		}
		if seen[rec.name] {
			return nil, fmt.Errorf("asset line %d: duplicate resource %s", n, rec.name)
		}
		seen[rec.name] = true
		p, err := ParsePolicy(rec.iamPolicy)
		if err != nil {
			return nil, fmt.Errorf("asset line %d: %w", n, err)
		}
		out = append(out, AssetPolicy{Name: rec.name, AssetType: rec.assetType, Ancestors: rec.ancestors, Policy: p})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type assetEnvelope struct {
	name       string
	assetType  string
	iamPolicy  json.RawMessage
	ancestors  []string
	updateTime string
}

// decodeAssetEnvelope reads one asset record. It rejects duplicate or
// case-colliding keys (the same guard ParsePolicy applies, so a member cannot
// be hidden by a stray key), then reads each known field in whichever
// spelling the export used. A field present under both its camelCase and
// snake_case spelling in one record is rejected as ambiguous. Unknown
// envelope fields are ignored.
func decodeAssetEnvelope(line []byte) (assetEnvelope, error) {
	// precheck on the top-level object only: reject duplicate/case-colliding
	// keys, but allow any field name (nil fields schema) so snake_case and
	// future fields pass. The iam_policy value itself is checked by ParsePolicy.
	if err := precheckWith(line, &schema{fields: nil}); err != nil {
		return assetEnvelope{}, err
	}
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return assetEnvelope{}, fmt.Errorf("decode asset record: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return assetEnvelope{}, errors.New("decode asset record: trailing data")
	}
	field := func(name string) (json.RawMessage, error) {
		spells := assetEnvelopeKeys[name]
		camel, hasCamel := raw[spells[0]]
		snake, hasSnake := raw[spells[1]]
		if spells[0] != spells[1] && hasCamel && hasSnake {
			return nil, fmt.Errorf("asset record has both %q and %q", spells[0], spells[1])
		}
		if hasCamel {
			return camel, nil
		}
		return snake, nil
	}
	var rec assetEnvelope
	get := func(name string, dst any) error {
		v, err := field(name)
		if err != nil {
			return err
		}
		if len(v) == 0 {
			return nil
		}
		if err := json.Unmarshal(v, dst); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
		return nil
	}
	if err := get("name", &rec.name); err != nil {
		return assetEnvelope{}, err
	}
	if err := get("assetType", &rec.assetType); err != nil {
		return assetEnvelope{}, err
	}
	if v, err := field("iamPolicy"); err != nil {
		return assetEnvelope{}, err
	} else {
		rec.iamPolicy = v
	}
	if err := get("ancestors", &rec.ancestors); err != nil {
		return assetEnvelope{}, err
	}
	if err := get("updateTime", &rec.updateTime); err != nil {
		return assetEnvelope{}, err
	}
	return rec, nil
}

// CheckAsset is Check for an exported resource policy. Only here can
// env.CrossEnv exempt a member, and only when the record's first ancestor is
// the checked project (projects/<env.ProjectNumber>).
func CheckAsset(a AssetPolicy, env Env) ([]Violation, error) {
	resource := a.Name
	if len(a.Ancestors) == 0 || env.ProjectNumber == "" || a.Ancestors[0] != "projects/"+env.ProjectNumber {
		resource = ""
	}
	return checkResource(a.Policy, env, resource, a.AssetType)
}

func crossEnvExempt(env Env, resource, assetType string, b Binding, raw string) bool {
	if resource == "" || b.Condition != nil {
		return false
	}
	for _, g := range env.CrossEnv {
		if g.Resource == resource && g.AssetType == assetType && g.Role == b.Role && g.Member == raw {
			return true
		}
	}
	return false
}
