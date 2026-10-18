package checks

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var crossInputs = CrossEnvInputs{
	RegressionProjectID:        "example-regression",
	RegressionProjectNumber:    "222222222222",
	DecisionInputExportsBucket: "example-decision-inputs",
	ManifestKey:                "projects/example-prod/locations/us-central1/keyRings/audit/cryptoKeys/manifest",
	RegressionRequestsBucket:   "example-regression-requests",
	RegressionReportsBucket:    "example-regression-reports",
}

var publicKeyRoleDef = RoleDefinition{
	Name:                "projects/example-prod/roles/agentariumManifestPublicKey",
	IncludedPermissions: []string{"cloudkms.cryptoKeyVersions.viewPublicKey"},
	Stage:               "GA",
}

const regPrincipal = "principal://iam.googleapis.com/projects/222222222222/locations/global/workloadIdentityPools/example-regression.svc.id.goog/subject/ns/agent-release/sa/"

func crossEnv(t *testing.T) Env {
	t.Helper()
	grants, err := CrossEnvAllowlist(crossInputs, prodEnv, publicKeyRoleDef)
	if err != nil {
		t.Fatal(err)
	}
	env := prodEnv
	env.CrossEnv = grants
	return env
}

var (
	decisionBucket = BucketResource("example-decision-inputs")
	manifestKey    = CryptoKeyResource("projects/example-prod/locations/us-central1/keyRings/audit/cryptoKeys/manifest")
	requestsBucket = BucketResource("example-regression-requests")
	reportsBucket  = BucketResource("example-regression-reports")
	publicKeyRole  = "projects/example-prod/roles/agentariumManifestPublicKey"
)

func asset(resource, assetType, role string, cond *Condition, members ...string) AssetPolicy {
	return AssetPolicy{Name: resource, AssetType: assetType, Ancestors: []string{"projects/" + prodEnv.ProjectNumber, "organizations/1"},
		Policy: &Policy{Bindings: []Binding{{Role: role, Members: members, Condition: cond}}}}
}

func bucket(resource, role string, members ...string) AssetPolicy {
	return asset(resource, bucketAssetType, role, nil, members...)
}

func TestCrossEnvAllowlistIsExactlyFour(t *testing.T) {
	grants := crossEnv(t).CrossEnv
	want := []CrossEnvGrant{
		{decisionBucket, bucketAssetType, "roles/storage.objectViewer", regPrincipal + "decision-replay"},
		{manifestKey, cryptoKeyAssetType, publicKeyRole, regPrincipal + "decision-replay"},
		{requestsBucket, bucketAssetType, "roles/storage.objectViewer", regPrincipal + "regression-runner"},
		{reportsBucket, bucketAssetType, "roles/storage.objectCreator", regPrincipal + "regression-runner"},
	}
	if len(grants) != len(want) {
		t.Fatalf("grants = %v", grants)
	}
	for i := range want {
		if grants[i] != want[i] {
			t.Errorf("grant %d = %+v, want %+v", i, grants[i], want[i])
		}
	}
}

func TestAllowedCrossEnvCombinationsPass(t *testing.T) {
	env := crossEnv(t)
	for _, g := range env.CrossEnv {
		t.Run(g.Resource+"/"+g.Role, func(t *testing.T) {
			a := asset(g.Resource, g.AssetType, g.Role, nil, g.Member)
			vs, err := CheckAsset(a, env)
			if err != nil || len(vs) != 0 {
				t.Fatalf("allowed combination rejected: %v %v", vs, err)
			}
			// The same policy read as a plain policy file is still rejected.
			vs, _ = Check(a.Policy, env)
			if got := rules(vs); len(got) != 1 || got[0] != RuleCrossEnvPool {
				t.Fatalf("plain policy: %v", got)
			}
		})
	}
}

func TestOtherCrossEnvGrantsStillFail(t *testing.T) {
	env := crossEnv(t)
	deny := map[string]AssetPolicy{
		"other regression KSA":         bucket(decisionBucket, "roles/storage.objectViewer", regPrincipal+"releaser"),
		"runner on decision inputs":    bucket(decisionBucket, "roles/storage.objectViewer", regPrincipal+"regression-runner"),
		"replay on requests bucket":    bucket(requestsBucket, "roles/storage.objectViewer", regPrincipal+"decision-replay"),
		"write to decision inputs":     bucket(decisionBucket, "roles/storage.objectCreator", regPrincipal+"decision-replay"),
		"admin on reports":             bucket(reportsBucket, "roles/storage.objectAdmin", regPrincipal+"regression-runner"),
		"read reports":                 bucket(reportsBucket, "roles/storage.objectViewer", regPrincipal+"regression-runner"),
		"write requests":               bucket(requestsBucket, "roles/storage.objectCreator", regPrincipal+"regression-runner"),
		"signer on manifest key":       asset(manifestKey, cryptoKeyAssetType, "roles/cloudkms.signerVerifier", nil, regPrincipal+"decision-replay"),
		"predefined public key viewer": asset(manifestKey, cryptoKeyAssetType, "roles/cloudkms.publicKeyViewer", nil, regPrincipal+"decision-replay"),
		"public key role on bucket":    bucket(decisionBucket, publicKeyRole, regPrincipal+"decision-replay"),
		"bucket name with key type":    asset(requestsBucket, cryptoKeyAssetType, "roles/storage.objectViewer", nil, regPrincipal+"regression-runner"),
		"other bucket":                 bucket(BucketResource("example-evidence"), "roles/storage.objectViewer", regPrincipal+"decision-replay"),
		"secret access": asset("//secretmanager.googleapis.com/projects/111111111111/secrets/receiver", "secretmanager.googleapis.com/Secret",
			"roles/secretmanager.secretAccessor", nil, regPrincipal+"regression-runner"),
		"database client": asset("//cloudresourcemanager.googleapis.com/projects/example-prod", "cloudresourcemanager.googleapis.com/Project",
			"roles/cloudsql.client", nil, regPrincipal+"decision-replay"),
		"conditioned binding": asset(decisionBucket, bucketAssetType, "roles/storage.objectViewer", &Condition{Title: "t", Expression: "true"}, regPrincipal+"decision-replay"),
		"principalSet namespace": bucket(decisionBucket, "roles/storage.objectViewer",
			"principalSet://iam.googleapis.com/projects/222222222222/locations/global/workloadIdentityPools/example-regression.svc.id.goog/namespace/agent-release"),
		"other namespace":        bucket(decisionBucket, "roles/storage.objectViewer", strings.Replace(regPrincipal, "agent-release", "agent-observe", 1)+"decision-replay"),
		"other project number":   bucket(decisionBucket, "roles/storage.objectViewer", strings.Replace(regPrincipal, "222222222222", "333333333333", 1)+"decision-replay"),
		"third environment pool": bucket(decisionBucket, "roles/storage.objectViewer", strings.Replace(regPrincipal, "example-regression", "example-staging", 1)+"decision-replay"),
		"case-changed member":    bucket(decisionBucket, "roles/storage.objectViewer", strings.ToUpper(regPrincipal[:9])+regPrincipal[9:]+"decision-replay"),
		"deleted member":         bucket(decisionBucket, "roles/storage.objectViewer", "deleted:"+regPrincipal+"decision-replay?uid=1"),
		"legacy member form":     bucket(decisionBucket, "roles/storage.objectViewer", "serviceAccount:example-regression.svc.id.goog[agent-release/decision-replay]"),
	}
	for name, a := range deny {
		t.Run(name, func(t *testing.T) {
			vs, err := CheckAsset(a, env)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, r := range rules(vs) {
				found = found || r == RuleCrossEnvPool
			}
			if !found {
				t.Fatalf("want CROSS_ENV_POOL, got %v", rules(vs))
			}
		})
	}
}

func TestAllowedMemberDoesNotHideOthers(t *testing.T) {
	env := crossEnv(t)
	a := bucket(decisionBucket, "roles/storage.objectViewer", regPrincipal+"decision-replay", regPrincipal+"releaser")
	vs, err := CheckAsset(a, env)
	if err != nil || len(vs) == 0 {
		t.Fatalf("releaser must still be reported: %v %v", vs, err)
	}
	for _, v := range vs {
		if !strings.HasSuffix(v.Member, "/releaser") || v.Rule != RuleCrossEnvPool {
			t.Fatalf("unexpected violation %v", v)
		}
	}
	a.Policy.Bindings = append(a.Policy.Bindings, Binding{Role: "roles/storage.objectViewer", Members: []string{"user:a@example.com"},
		Condition: &Condition{Expression: "request.auth.claims.pool == 'example-regression.svc.id.goog'"}})
	vs, _ = CheckAsset(a, env)
	cond := false
	for _, v := range vs {
		cond = cond || v.Member == "(condition)"
	}
	if !cond {
		t.Fatal("condition reference must still be reported")
	}
}

// Security review on #193: the key and the custom role must belong to the
// checked project, and the role definition must contain only viewPublicKey.
func TestCrossEnvInputsRejected(t *testing.T) {
	inputs := map[string]func(*CrossEnvInputs){
		"same project":  func(i *CrossEnvInputs) { i.RegressionProjectID = prodEnv.ProjectID },
		"same number":   func(i *CrossEnvInputs) { i.RegressionProjectNumber = prodEnv.ProjectNumber },
		"bad number":    func(i *CrossEnvInputs) { i.RegressionProjectNumber = "12a" },
		"bucket path":   func(i *CrossEnvInputs) { i.RegressionReportsBucket = "a/b" },
		"shared bucket": func(i *CrossEnvInputs) { i.RegressionReportsBucket = i.RegressionRequestsBucket },
		"key version":   func(i *CrossEnvInputs) { i.ManifestKey += "/cryptoKeyVersions/1" },
		"key in regression": func(i *CrossEnvInputs) {
			i.ManifestKey = strings.Replace(i.ManifestKey, "example-prod", "example-regression", 1)
		},
		"key in other proj": func(i *CrossEnvInputs) {
			i.ManifestKey = strings.Replace(i.ManifestKey, "example-prod", "attacker-project", 1)
		},
		"missing bucket":     func(i *CrossEnvInputs) { i.DecisionInputExportsBucket = "" },
		"wildcard namespace": func(i *CrossEnvInputs) { i.RegressionProjectID = "*" },
	}
	for name, m := range inputs {
		t.Run(name, func(t *testing.T) {
			in := crossInputs
			m(&in)
			if _, err := CrossEnvAllowlist(in, prodEnv, publicKeyRoleDef); err == nil {
				t.Fatal("expected an input error")
			}
		})
	}
	roles := map[string]func(*RoleDefinition){
		"predefined role":       func(r *RoleDefinition) { r.Name = "roles/cloudkms.publicKeyViewer" },
		"role in other project": func(r *RoleDefinition) { r.Name = "projects/attacker-project/roles/agentariumManifestPublicKey" },
		"other role ID":         func(r *RoleDefinition) { r.Name = "projects/example-prod/roles/somethingElse" },
		"extra permission": func(r *RoleDefinition) {
			r.IncludedPermissions = []string{"cloudkms.cryptoKeyVersions.viewPublicKey", "cloudkms.cryptoKeyVersions.useToDecrypt"}
		},
		"other permission": func(r *RoleDefinition) { r.IncludedPermissions = []string{"cloudkms.cryptoKeys.get"} },
		"no permission":    func(r *RoleDefinition) { r.IncludedPermissions = nil },
		"disabled":         func(r *RoleDefinition) { r.Stage = "DISABLED" },
		"deleted":          func(r *RoleDefinition) { r.Deleted = true },
	}
	for name, m := range roles {
		t.Run(name, func(t *testing.T) {
			r := publicKeyRoleDef
			r.IncludedPermissions = append([]string(nil), r.IncludedPermissions...)
			m(&r)
			if _, err := CrossEnvAllowlist(crossInputs, prodEnv, r); err == nil {
				t.Fatal("expected a role definition error")
			}
		})
	}
	if _, err := ParseCrossEnvInputs([]byte(`{"regression_project_id":"x","extra":1}`)); err == nil {
		t.Fatal("unknown fields must be rejected")
	}
	if _, err := ParseRoleDefinition([]byte(`{"name":"x","includedPermissions":[],"extra":1}`)); err == nil {
		t.Fatal("unknown role fields must be rejected")
	}
}

func TestParseAssetExport(t *testing.T) {
	data, err := os.ReadFile("testdata/assets_allowed.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	records, err := ParseAssetExport(data, map[string]bool{})
	if err != nil || len(records) != 4 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if records[1].Name != manifestKey || records[1].AssetType != cryptoKeyAssetType {
		t.Fatalf("resource must come from the record: %+v", records[1])
	}
	seen := map[string]bool{}
	if _, err := ParseAssetExport(data, seen); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAssetExport(data, seen); err == nil {
		t.Fatal("a resource seen in another file must be rejected")
	}
	bad := map[string]string{
		"duplicate line":        string(data[:strings.Index(string(data), "\n")+1]) + string(data[:strings.Index(string(data), "\n")+1]),
		"case collision":        `{"name":"//x","Name":"//y","assetType":"t","iamPolicy":{}}`,
		"missing name":          `{"assetType":"t","iamPolicy":{"bindings":[]}}`,
		"relative name":         `{"name":"buckets/x","assetType":"t","iamPolicy":{"bindings":[]}}`,
		"policy key":            `{"name":"//x","assetType":"t","iamPolicy":{"bindings":[],"Bindings":[]}}`,
		"both asset_type camel": `{"name":"//x","assetType":"t","asset_type":"t","iamPolicy":{"bindings":[]}}`,
		"both iam_policy camel": `{"name":"//x","assetType":"t","iamPolicy":{"bindings":[]},"iam_policy":{"bindings":[]}}`,
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAssetExport([]byte(in), map[string]bool{}); err == nil {
				t.Fatal("expected a parse error")
			}
		})
	}
	// A field Cloud Asset adds later must not reject the whole record: only
	// the fields the checks read are required, and the IAM policy inside is
	// still parsed strictly.
	if _, err := ParseAssetExport([]byte(`{"name":"//x","assetType":"t","iamPolicy":{"bindings":[]},"resource":{"data":{}},"future":1}`), map[string]bool{}); err != nil {
		t.Fatalf("an unknown envelope field must be ignored: %v", err)
	}
}

// TestRealisticAssetExport uses records shaped like `gcloud asset export
// --content-type=iam-policy` output: documented asset names
// (//storage.googleapis.com/BUCKET, //cloudkms.googleapis.com/projects/P/
// locations/L/keyRings/R/cryptoKeys/K), legacy bucket bindings, ancestors and
// updateTime. The four allowed grants pass; changing the bucket name form
// to the JSON API path makes them fail.
func TestRealisticAssetExport(t *testing.T) {
	data, err := os.ReadFile("testdata/asset_export_realistic.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	env := crossEnv(t)
	records, err := ParseAssetExport(data, map[string]bool{})
	if err != nil || len(records) != 4 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	for _, a := range records {
		vs, err := CheckAsset(a, env)
		if err != nil || len(vs) != 0 {
			t.Errorf("%s: %v %v", a.Name, vs, err)
		}
	}
	wrong := strings.ReplaceAll(string(data), "//storage.googleapis.com/example-", "//storage.googleapis.com/projects/_/buckets/example-")
	records, err = ParseAssetExport([]byte(wrong), map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, a := range records {
		if vs, _ := CheckAsset(a, env); len(vs) != 0 {
			failed++
		}
	}
	if failed != 3 {
		t.Fatalf("bucket records under a non-asset name must not be exempt; %d of 3 failed", failed)
	}

	// Review on #193: `gcloud asset export --output-path=gs://…` writes the
	// envelope fields in snake_case (asset_type, iam_policy, update_time).
	// Only the envelope keys change; the IAM policy inside stays camelCase, as
	// the IAM Policy resource always uses. The four grants must still pass.
	snake := string(data)
	for camel, snk := range map[string]string{`"assetType":`: `"asset_type":`, `"iamPolicy":`: `"iam_policy":`, `"updateTime":`: `"update_time":`} {
		snake = strings.ReplaceAll(snake, camel, snk)
	}
	records, err = ParseAssetExport([]byte(snake), map[string]bool{})
	if err != nil || len(records) != 4 {
		t.Fatalf("snake_case export: records=%d err=%v", len(records), err)
	}
	for _, a := range records {
		if a.AssetType == "" || a.Policy == nil {
			t.Fatalf("snake_case export dropped a field: %+v", a)
		}
		if vs, err := CheckAsset(a, env); err != nil || len(vs) != 0 {
			t.Errorf("snake_case %s: %v %v", a.Name, vs, err)
		}
	}
}

// Review on #193: the exemption needs the record's ancestors to place the
// resource in the checked project, and the allowlist needs the project number.
func TestCrossEnvRequiresProductionAncestor(t *testing.T) {
	env := crossEnv(t)
	g := env.CrossEnv[0]
	for name, ancestors := range map[string][]string{
		"regression project": {"projects/222222222222"},
		"other project":      {"projects/999999999999", "organizations/1"},
		"folder first":       {"folders/1", "projects/111111111111"},
		"no ancestors":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			a := asset(g.Resource, g.AssetType, g.Role, nil, g.Member)
			a.Ancestors = ancestors
			vs, _ := CheckAsset(a, env)
			if got := rules(vs); len(got) != 1 || got[0] != RuleCrossEnvPool {
				t.Fatalf("want CROSS_ENV_POOL, got %v", got)
			}
		})
	}
	noNumber := Env{ProjectID: prodEnv.ProjectID}
	if _, err := CrossEnvAllowlist(crossInputs, noNumber, publicKeyRoleDef); err == nil {
		t.Fatal("the allowlist must require the checked project number")
	}
}

// TestTerraformCrossEnvGrantsMatchAllowlist ties the checker to
// platform/gcp/iam/workload-services: its tftest asserts that the module's
// cross_env_grants output equals the same fixture, so the Terraform bindings
// are exactly what CrossEnvAllowlist exempts.
func TestTerraformCrossEnvGrantsMatchAllowlist(t *testing.T) {
	data, err := os.ReadFile("testdata/cross_env_expected.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture []struct {
		Resource  string `json:"resource"`
		AssetType string `json:"asset_type"`
		Role      string `json:"role"`
		Member    string `json:"member"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	inputs, err := os.ReadFile("testdata/cross_env_inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	in, err := ParseCrossEnvInputs(inputs)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := CrossEnvAllowlist(in, prodEnv, publicKeyRoleDef)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != len(fixture) {
		t.Fatalf("grants %v fixture %v", grants, fixture)
	}
	for i, f := range fixture {
		if g := grants[i]; g != (CrossEnvGrant{f.Resource, f.AssetType, f.Role, f.Member}) {
			t.Errorf("grant %d = %+v, fixture %+v", i, g, f)
		}
	}
}
