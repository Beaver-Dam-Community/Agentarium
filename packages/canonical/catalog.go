package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Catalog YAML types (TASK-02 Appendix A). Struct tag `cat` marks JSON Schema
// "required" (req) and whether null is a valid value (null).
//
// JSON form used for catalog_digest: nullable fields are always present (null
// when absent in YAML); non-nullable optional fields are omitted when absent.
// SPEC-QUESTION: Appendix A does not say how absent optional fields map to
// the JSON value; this rule keeps the value valid against the JSON Schema.

type LimitSpec struct {
	Min   *int64 `yaml:"min" json:"min,omitempty"`
	Max   int64  `yaml:"max" json:"max" cat:"req"`
	Fixed *int64 `yaml:"fixed" json:"fixed,omitempty"`
}

type Disclosure struct {
	Kind string `yaml:"kind" json:"kind" cat:"req"`
}

type ContentChecks struct {
	Fields               *[]string `yaml:"fields" json:"fields,omitempty"`
	EmailPattern         *bool     `yaml:"email_pattern" json:"email_pattern,omitempty"`
	SyntheticIdentifiers *[]string `yaml:"synthetic_identifiers" json:"synthetic_identifiers,omitempty"`
}

type CatalogOperation struct {
	OperationID               string               `yaml:"operation_id" json:"operation_id" cat:"req"`
	EndpointID                string               `yaml:"endpoint_id" json:"endpoint_id" cat:"req"`
	ServiceID                 string               `yaml:"service_id" json:"service_id" cat:"req"`
	AdapterID                 string               `yaml:"adapter_id" json:"adapter_id" cat:"req"`
	Transport                 string               `yaml:"transport" json:"transport" cat:"req"`
	Method                    string               `yaml:"method" json:"method" cat:"req"`
	RouteID                   string               `yaml:"route_id" json:"route_id" cat:"req"`
	RouteTemplate             string               `yaml:"route_template" json:"route_template" cat:"req"`
	EffectType                string               `yaml:"effect_type" json:"effect_type" cat:"req"`
	Disclosure                Disclosure           `yaml:"disclosure" json:"disclosure" cat:"req"`
	CredentialBinding         *string              `yaml:"credential_binding" json:"credential_binding" cat:"req,null"`
	Limits                    map[string]LimitSpec `yaml:"limits" json:"limits" cat:"req"`
	RetryPolicy               string               `yaml:"retry_policy" json:"retry_policy" cat:"req"`
	IdempotencySupport        string               `yaml:"idempotency_support" json:"idempotency_support" cat:"req"`
	EvidenceStrategy          string               `yaml:"evidence_strategy" json:"evidence_strategy" cat:"req"`
	EvidenceLevelMax          string               `yaml:"evidence_level_max" json:"evidence_level_max" cat:"req"`
	EvidenceDeadlineSeconds   int64                `yaml:"evidence_deadline_seconds" json:"evidence_deadline_seconds" cat:"req"`
	IntentCheckOnStandingRule bool                 `yaml:"intent_check_on_standing_rule" json:"intent_check_on_standing_rule" cat:"req"`
	ModelProfiles             *[]string            `yaml:"model_profiles" json:"model_profiles,omitempty"`
	ResponseDataClass         string               `yaml:"response_data_class" json:"response_data_class" cat:"req"`
	RedactFields              []string             `yaml:"redact_fields" json:"redact_fields" cat:"req"`
	ResponseLimitBytes        int64                `yaml:"response_limit_bytes" json:"response_limit_bytes" cat:"req"`
	ContentChecks             *ContentChecks       `yaml:"content_checks" json:"content_checks,omitempty"`
	Description               string               `yaml:"description" json:"description" cat:"req"`
	SchemaVersion             string               `yaml:"schema_version" json:"schema_version" cat:"req"`
	Owner                     string               `yaml:"owner" json:"owner" cat:"req"`
}

type TargetModel struct {
	Project  *string `yaml:"project" json:"project,omitempty"`
	Location *string `yaml:"location" json:"location,omitempty"`
	ModelID  *string `yaml:"model_id" json:"model_id,omitempty"`
}

type CatalogTarget struct {
	TargetID        string       `yaml:"target_id" json:"target_id" cat:"req"`
	EndpointID      string       `yaml:"endpoint_id" json:"endpoint_id" cat:"req"`
	Environment     string       `yaml:"environment" json:"environment" cat:"req"`
	Tenant          string       `yaml:"tenant" json:"tenant" cat:"req"`
	Origin          string       `yaml:"origin" json:"origin" cat:"req"`
	ExpectedTLSName string       `yaml:"expected_tls_name" json:"expected_tls_name" cat:"req"`
	CARef           string       `yaml:"ca_ref" json:"ca_ref" cat:"req"`
	ExpectedURISAN  *string      `yaml:"expected_uri_san" json:"expected_uri_san,omitempty"` // agentarium-trust only
	AuthAudience    *string      `yaml:"auth_audience" json:"auth_audience" cat:"null"`
	AllowedCIDRs    []string     `yaml:"allowed_cidrs" json:"allowed_cidrs" cat:"req"`
	MaxDataClass    string       `yaml:"max_data_class" json:"max_data_class" cat:"req"`
	OperationIDs    []string     `yaml:"operation_ids" json:"operation_ids" cat:"req"`
	Namespace       *string      `yaml:"namespace" json:"namespace" cat:"null"`
	Model           *TargetModel `yaml:"model" json:"model" cat:"null"`
}

type operationsFile struct {
	CatalogVersion string             `yaml:"catalog_version" cat:"req"`
	Operations     []CatalogOperation `yaml:"operations" cat:"req"`
}

type targetsFile struct {
	Targets []CatalogTarget `yaml:"targets" cat:"req"`
}

// ModelProfileConfig holds the server-fixed model.generate constants of one
// profile (TASK-02 3.3, values from the environment lock via TASK-05).
// ResponseSchema nil means no response schema (response_schema_digest = null).
type ModelProfileConfig struct {
	MaxOutputTokens  int64           `json:"max_output_tokens"`
	MaxRequestBytes  int64           `json:"max_request_bytes"`
	GenerationConfig json.RawMessage `json:"generation_config"`
	ResponseSchema   json.RawMessage `json:"response_schema"`
}

// Catalog is the Go form of bundle data.catalog (COMMON Appendix A).
// SPEC-QUESTION: data.catalog has no catalog_version and no model profile
// constants, but ActionEnvelope needs catalog_version and model.generate needs
// profile constants. Both are extra Go fields excluded from JSON and from catalog_digest.
// ModelProfiles therefore never survives a JSON round trip (policyloader
// Snapshot.Catalog); services attach it from LoadModelProfiles.
type Catalog struct {
	CatalogDigest  string                        `json:"catalog_digest"`
	CatalogVersion string                        `json:"-"`
	Operations     map[string]CatalogOperation   `json:"operations"`
	Targets        map[string]CatalogTarget      `json:"targets"`
	ModelProfiles  map[string]ModelProfileConfig `json:"-"`
}

// LoadCatalogDir reads <dir>/operations.yaml and <dir>/targets.yaml.
func LoadCatalogDir(dir string) (Catalog, error) {
	ops, err := os.ReadFile(filepath.Join(dir, "operations.yaml"))
	if err != nil {
		return Catalog{}, err
	}
	tgs, err := os.ReadFile(filepath.Join(dir, "targets.yaml"))
	if err != nil {
		return Catalog{}, err
	}
	return ParseCatalogYAML(ops, tgs)
}

// ParseCatalogYAML strictly decodes both files (unknown fields, duplicate keys,
// aliases, missing required fields, wrong scalar types and out-of-enum values
// are errors), validates them, and computes catalog_digest.
func ParseCatalogYAML(operationsYAML, targetsYAML []byte) (Catalog, error) {
	var of operationsFile
	if err := strictYAML(operationsYAML, &of); err != nil {
		return Catalog{}, fmt.Errorf("operations.yaml: %w", err)
	}
	var tf targetsFile
	if err := strictYAML(targetsYAML, &tf); err != nil {
		return Catalog{}, fmt.Errorf("targets.yaml: %w", err)
	}
	c := Catalog{CatalogVersion: of.CatalogVersion, Operations: map[string]CatalogOperation{}, Targets: map[string]CatalogTarget{}}
	for _, op := range of.Operations {
		if _, dup := c.Operations[op.OperationID]; dup {
			return Catalog{}, fmt.Errorf("duplicate operation_id %q", op.OperationID)
		}
		c.Operations[op.OperationID] = op
	}
	for _, t := range tf.Targets {
		if _, dup := c.Targets[t.TargetID]; dup {
			return Catalog{}, fmt.Errorf("duplicate target_id %q", t.TargetID)
		}
		c.Targets[t.TargetID] = t
	}
	if err := c.validate(); err != nil {
		return Catalog{}, err
	}
	d, err := c.ComputeDigest()
	if err != nil {
		return Catalog{}, err
	}
	c.CatalogDigest = d
	return c, nil
}

// ParseBundleCatalog decodes bundle data.catalog JSON and checks that its
// catalog_digest equals the digest recomputed from operations and targets.
//
// encoding/json matches keys case-insensitively and accepts missing fields, so
// before decoding the raw bytes are checked like a request body: duplicate and
// case-only duplicate keys are rejected, and every object key must equal a
// json tag exactly (unknown keys rejected, keys without omitempty required,
// null only where the cat tag says null). Otherwise {"effect_type":"read",
// "EFFECT_TYPE":"external_send"} would read differently in Go and in Rego's
// data.catalog, and a dropped redact_fields would just change the digest.
func ParseBundleCatalog(raw []byte) (Catalog, error) {
	root, err := scanJSON(raw, scanOptions{integralRange: true, caseFoldDuplicates: true})
	if err != nil {
		return Catalog{}, err
	}
	if err := checkCatalogJSON(root, reflect.TypeOf(Catalog{}), "$"); err != nil {
		return Catalog{}, err
	}
	var c Catalog
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Catalog{}, err
	}
	for id, op := range c.Operations {
		if id != op.OperationID {
			return Catalog{}, fmt.Errorf("operations key %q != operation_id %q", id, op.OperationID)
		}
	}
	for id, t := range c.Targets {
		if id != t.TargetID {
			return Catalog{}, fmt.Errorf("targets key %q != target_id %q", id, t.TargetID)
		}
	}
	if err := c.validate(); err != nil {
		return Catalog{}, err
	}
	d, err := c.ComputeDigest()
	if err != nil {
		return Catalog{}, err
	}
	if d != c.CatalogDigest {
		return Catalog{}, fmt.Errorf("catalog_digest mismatch: data has %s, computed %s", c.CatalogDigest, d)
	}
	return c, nil
}

// checkCatalogJSON checks the pre-scan tree of data.catalog against the Go
// catalog types: exact json tag keys, required keys (no omitempty) present,
// null only for pointer fields whose cat tag contains "null", integers without
// fraction or exponent, and map values checked recursively.
func checkCatalogJSON(n *jnode, t reflect.Type, path string) error {
	if t.Kind() == reflect.Pointer {
		return checkCatalogJSON(n, t.Elem(), path)
	}
	if n.kind == kindNull {
		return fmt.Errorf("%s: null not allowed", path)
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.kind != kindObject {
			return fmt.Errorf("%s: expected object", path)
		}
		type field struct {
			typ      reflect.Type
			required bool
			nullable bool
		}
		fields := map[string]field{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" || name == "-" {
				continue
			}
			fields[name] = field{
				typ:      f.Type,
				required: !strings.Contains(","+opts+",", ",omitempty,"),
				nullable: f.Type.Kind() == reflect.Pointer && strings.Contains(","+f.Tag.Get("cat")+",", ",null,"),
			}
		}
		for i, k := range n.keys {
			f, ok := fields[k]
			if !ok {
				return fmt.Errorf("%s: unknown key %q", path, k)
			}
			if n.vals[i].kind == kindNull {
				if !f.nullable {
					return fmt.Errorf("%s.%s: null not allowed", path, k)
				}
				continue
			}
			if err := checkCatalogJSON(n.vals[i], f.typ, path+"."+k); err != nil {
				return err
			}
		}
		for name, f := range fields {
			if f.required && !contains(n.keys, name) {
				return fmt.Errorf("%s: missing key %q", path, name)
			}
		}
	case reflect.Map:
		if n.kind != kindObject {
			return fmt.Errorf("%s: expected object", path)
		}
		for i, k := range n.keys {
			if err := checkCatalogJSON(n.vals[i], t.Elem(), fmt.Sprintf("%s[%q]", path, k)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.kind != kindArray {
			return fmt.Errorf("%s: expected array", path)
		}
		for i, e := range n.elems {
			if err := checkCatalogJSON(e, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.String:
		if n.kind != kindString {
			return fmt.Errorf("%s: expected string", path)
		}
	case reflect.Int64:
		if n.kind != kindNumber || strings.ContainsAny(n.num, ".eE") {
			return fmt.Errorf("%s: expected integer", path)
		}
	case reflect.Bool:
		if n.kind != kindBool {
			return fmt.Errorf("%s: expected boolean", path)
		}
	default:
		return fmt.Errorf("%s: unsupported type %s", path, t)
	}
	return nil
}

// DigestInput returns {"operations": [by operation_id], "targets": [by target_id]}.
func (c Catalog) DigestInput() any {
	ops := make([]CatalogOperation, 0, len(c.Operations))
	for _, op := range c.Operations {
		ops = append(ops, op)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].OperationID < ops[j].OperationID })
	tgs := make([]CatalogTarget, 0, len(c.Targets))
	for _, t := range c.Targets {
		tgs = append(tgs, t)
	}
	sort.Slice(tgs, func(i, j int) bool { return tgs[i].TargetID < tgs[j].TargetID })
	return struct {
		Operations []CatalogOperation `json:"operations"`
		Targets    []CatalogTarget    `json:"targets"`
	}{ops, tgs}
}

// ComputeDigest returns catalog_digest = SHA-256(JCS(DigestInput())).
func (c Catalog) ComputeDigest() (string, error) {
	return CanonicalDigest(c.DigestInput())
}

var (
	reOperationID = regexp.MustCompile(`^[a-z0-9]+(\.[a-z0-9_]+)+$`)
	// SPEC-QUESTION: the Appendix A example origin "https://<location>-aiplatform..."
	// does not match this schema pattern; the pattern is enforced.
	reOrigin      = regexp.MustCompile(`^https://[a-z0-9.-]+(:[0-9]{1,5})?$`)
	reJSONPointer = regexp.MustCompile(`^(/([^/~]|~[01])*)*$`)
	// reServiceURISAN is the targets schema pattern of expected_uri_san:
	// exactly spiffe://agentarium.internal/ns/<ns>/sa/<sa>, DNS label
	// characters only, no wildcard, query or fragment.
	reServiceURISAN = regexp.MustCompile(`^spiffe://agentarium\.internal/ns/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?/sa/[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// CARefAgentariumTrust is the ca_ref of internal service targets. Their
// certificates are verified by the exact service URI SAN, not by the DNS name
// (TASK-05 3.2).
const CARefAgentariumTrust = "agentarium-trust"

// ValidServiceURISAN reports whether s matches the expected_uri_san pattern.
func ValidServiceURISAN(s string) bool { return reServiceURISAN.MatchString(s) }

func inEnum(v string, allowed ...string) bool {
	for _, a := range allowed {
		if v == a {
			return true
		}
	}
	return false
}

func safeInt(v int64) bool { return v <= MaxSafeInteger && v >= -MaxSafeInteger }

func (c Catalog) validate() error {
	for id, op := range c.Operations {
		if err := validateOperation(op); err != nil {
			return fmt.Errorf("operation %q: %w", id, err)
		}
	}
	for id, t := range c.Targets {
		if err := validateTarget(t); err != nil {
			return fmt.Errorf("target %q: %w", id, err)
		}
		// Not in the JSON Schema: a target may only reference defined operations.
		for _, opID := range t.OperationIDs {
			if _, ok := c.Operations[opID]; !ok {
				return fmt.Errorf("target %q: operation_ids references unknown operation %q", id, opID)
			}
		}
	}
	return nil
}

func validateOperation(op CatalogOperation) error {
	switch {
	case !reOperationID.MatchString(op.OperationID):
		return errors.New("operation_id has invalid format")
	case !inEnum(op.AdapterID, "kubernetes-reader", "receiver-sender", "model", "evidence-reader"):
		return fmt.Errorf("adapter_id %q not in enum", op.AdapterID)
	case !inEnum(op.Transport, "https_rest"):
		return fmt.Errorf("transport %q not in enum", op.Transport)
	case !inEnum(op.Method, "GET", "POST"):
		return fmt.Errorf("method %q not in enum", op.Method)
	case !strings.HasPrefix(op.RouteTemplate, "/"):
		return errors.New("route_template must start with /")
	case !inEnum(op.EffectType, "read", "external_send", "model_disclosure"):
		return fmt.Errorf("effect_type %q not in enum", op.EffectType)
	case !inEnum(op.Disclosure.Kind, "none", "payload_fields", "message_sources"):
		return fmt.Errorf("disclosure.kind %q not in enum", op.Disclosure.Kind)
	case !inEnum(op.RetryPolicy, "none"):
		return fmt.Errorf("retry_policy %q not in enum", op.RetryPolicy)
	case !inEnum(op.IdempotencySupport, "none", "idempotency_key"):
		return fmt.Errorf("idempotency_support %q not in enum", op.IdempotencySupport)
	case !inEnum(op.EvidenceStrategy, "response_only", "receiver_receipt", "provider_response"):
		return fmt.Errorf("evidence_strategy %q not in enum", op.EvidenceStrategy)
	case !inEnum(op.EvidenceLevelMax, "accepted", "effect_verified"):
		return fmt.Errorf("evidence_level_max %q not in enum", op.EvidenceLevelMax)
	case op.EvidenceDeadlineSeconds < 0 || op.EvidenceDeadlineSeconds > 300:
		return errors.New("evidence_deadline_seconds out of range 0..300")
	case !inEnum(op.ResponseDataClass, "none", "synthetic", "internal", "confidential", "inherit"):
		return fmt.Errorf("response_data_class %q not in enum", op.ResponseDataClass)
	case op.ResponseLimitBytes < 1 || op.ResponseLimitBytes > 1048576:
		return errors.New("response_limit_bytes out of range 1..1048576")
	case utf8.RuneCountInString(op.Description) > 512:
		return errors.New("description longer than 512 characters")
	}
	if op.ModelProfiles != nil {
		for _, p := range *op.ModelProfiles {
			if !modelProfiles[p] {
				return fmt.Errorf("model_profiles value %q not in enum", p)
			}
		}
	}
	for _, f := range op.RedactFields {
		if !reJSONPointer.MatchString(f) {
			return fmt.Errorf("redact_fields value %q is not a JSON Pointer", f)
		}
	}
	for k, l := range op.Limits {
		if !safeInt(l.Max) || (l.Min != nil && !safeInt(*l.Min)) || (l.Fixed != nil && !safeInt(*l.Fixed)) {
			return fmt.Errorf("limits.%s outside ±(2^53-1)", k)
		}
	}
	return nil
}

func validateTarget(t CatalogTarget) error {
	switch {
	case !reTargetID.MatchString(t.TargetID):
		return errors.New("target_id has invalid format")
	case !reOrigin.MatchString(t.Origin):
		return fmt.Errorf("origin %q does not match %s", t.Origin, reOrigin)
	case !inEnum(t.CARef, "system", "cluster", "agentarium-trust"):
		return fmt.Errorf("ca_ref %q not in enum", t.CARef)
	case len(t.AllowedCIDRs) < 1:
		return errors.New("allowed_cidrs needs at least one item")
	case dataClassRank[t.MaxDataClass] == 0 && t.MaxDataClass != "none":
		return fmt.Errorf("max_data_class %q not in enum", t.MaxDataClass)
	case len(t.OperationIDs) < 1:
		return errors.New("operation_ids needs at least one item")
	case t.CARef == CARefAgentariumTrust && t.ExpectedURISAN == nil:
		return errors.New("expected_uri_san is required when ca_ref is agentarium-trust")
	case t.CARef != CARefAgentariumTrust && t.ExpectedURISAN != nil:
		return fmt.Errorf("expected_uri_san is allowed only with ca_ref agentarium-trust, not %q", t.CARef)
	case t.ExpectedURISAN != nil && !reServiceURISAN.MatchString(*t.ExpectedURISAN):
		return fmt.Errorf("expected_uri_san %q does not match %s", *t.ExpectedURISAN, reServiceURISAN)
	}
	return nil
}

// strictYAML decodes exactly one YAML document into v after checking the node
// tree against v's type: duplicate keys, aliases/anchors, unknown keys, missing
// required keys, null outside nullable fields and scalar tag mismatches fail.
func strictYAML(data []byte, v any) error {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("more than one YAML document")
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		return errors.New("expected one YAML document")
	}
	if err := checkYAMLNode(doc.Content[0], reflect.TypeOf(v).Elem(), false, "$"); err != nil {
		return err
	}
	kd := yaml.NewDecoder(bytes.NewReader(data))
	kd.KnownFields(true)
	return kd.Decode(v)
}

func checkYAMLNode(n *yaml.Node, t reflect.Type, nullable bool, path string) error {
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return fmt.Errorf("%s: anchors and aliases are not allowed", path)
	}
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		if nullable {
			return nil
		}
		return fmt.Errorf("%s: null not allowed", path)
	}
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return fmt.Errorf("%s: expected mapping", path)
		}
		type fieldInfo struct {
			t        reflect.Type
			req, nul bool
		}
		fields := map[string]fieldInfo{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			cat := f.Tag.Get("cat")
			fields[name] = fieldInfo{f.Type, strings.Contains(cat, "req"), strings.Contains(cat, "null")}
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return fmt.Errorf("%s: mapping key must be a string", path)
			}
			if seen[k.Value] {
				return fmt.Errorf("%s: duplicate key %q", path, k.Value)
			}
			seen[k.Value] = true
			fi, ok := fields[k.Value]
			if !ok {
				return fmt.Errorf("%s: unknown field %q", path, k.Value)
			}
			if err := checkYAMLNode(n.Content[i+1], fi.t, fi.nul, path+"."+k.Value); err != nil {
				return err
			}
		}
		for name, fi := range fields {
			if fi.req && !seen[name] {
				return fmt.Errorf("%s: missing required field %q", path, name)
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return fmt.Errorf("%s: expected mapping", path)
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.ShortTag() != "!!str" {
				return fmt.Errorf("%s: mapping key must be a string", path)
			}
			if seen[k.Value] {
				return fmt.Errorf("%s: duplicate key %q", path, k.Value)
			}
			seen[k.Value] = true
			if err := checkYAMLNode(n.Content[i+1], t.Elem(), false, path+"."+k.Value); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return fmt.Errorf("%s: expected sequence", path)
		}
		for i, e := range n.Content {
			if err := checkYAMLNode(e, t.Elem(), false, path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
	case reflect.String:
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!str" {
			return fmt.Errorf("%s: expected string", path)
		}
	case reflect.Int64:
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!int" {
			return fmt.Errorf("%s: expected integer", path)
		}
	case reflect.Bool:
		if n.Kind != yaml.ScalarNode || n.ShortTag() != "!!bool" {
			return fmt.Errorf("%s: expected boolean", path)
		}
	default:
		return fmt.Errorf("%s: unsupported type %s", path, t)
	}
	return nil
}
