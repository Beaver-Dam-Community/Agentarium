package canonical

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func readFile(t *testing.T, p string) ([]byte, error) {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b, nil
}

func fixtureYAML(t *testing.T) (string, string) {
	ops, _ := readFile(t, "testdata/catalog/operations.yaml")
	tgs, _ := readFile(t, "testdata/catalog/targets.yaml")
	return string(ops), string(tgs)
}

func TestCatalogStrictRejects(t *testing.T) {
	ops, tgs := fixtureYAML(t)
	opsCases := map[string]string{
		"unknown field":            strings.Replace(ops, "    owner: platform-team\n", "    owner: platform-team\n    owners: x\n", 1),
		"duplicate key":            strings.Replace(ops, "    method: GET\n", "    method: GET\n    method: POST\n", 1),
		"duplicate top-level key":  ops + "catalog_version: again\n",
		"enum outside":             strings.Replace(ops, "adapter_id: kubernetes-reader", "adapter_id: shell", 1),
		"method enum":              strings.Replace(ops, "method: GET", "method: DELETE", 1),
		"retry enum":               strings.Replace(ops, "retry_policy: none", "retry_policy: exponential", 1),
		"missing required":         strings.Replace(ops, "    response_limit_bytes: 1048576\n", "", 1),
		"wrong type":               strings.Replace(ops, "evidence_deadline_seconds: 30", "evidence_deadline_seconds: \"30\"", 1),
		"float for integer":        strings.Replace(ops, "evidence_deadline_seconds: 30", "evidence_deadline_seconds: 30.5", 1),
		"range":                    strings.Replace(ops, "evidence_deadline_seconds: 30", "evidence_deadline_seconds: 301", 1),
		"null for non-nullable":    strings.Replace(ops, "model_profiles: [agent, policy_proposal, intent_check, discovery]", "model_profiles: null", 1),
		"profile enum":             strings.Replace(ops, "model_profiles: [agent,", "model_profiles: [root,", 1),
		"limits missing max":       strings.Replace(ops, "tail_lines: {min: 1, max: 200}", "tail_lines: {min: 1}", 1),
		"limits unknown key":       strings.Replace(ops, "tail_lines: {min: 1, max: 200}", "tail_lines: {min: 1, max: 200, step: 1}", 1),
		"bad redact pointer":       strings.Replace(ops, `"/a~1b"`, `"/a~2b"`, 1),
		"duplicate operation_id":   strings.Replace(ops, "operation_id: k8s.events.list", "operation_id: k8s.pods.list", 1),
		"bad operation_id":         strings.Replace(ops, "operation_id: k8s.events.list", "operation_id: K8s.Events", 1),
		"anchor":                   strings.Replace(ops, "disclosure: {kind: none}", "disclosure: &d {kind: none}", 1),
		"alias":                    strings.Replace(strings.Replace(ops, "redact_fields: []", "redact_fields: &r []", 1), "redact_fields: []", "redact_fields: *r", 1),
		"second document":          ops + "---\ncatalog_version: x\noperations: []\n",
		"description too long":     strings.Replace(ops, `description: "자체 시험 receiver에 승인된 요약을 보낸다"`, `description: "`+strings.Repeat("가", 513)+`"`, 1),
		"content_checks unknown":   strings.Replace(ops, "email_pattern: true,", "email_pattern: true, phone_pattern: true,", 1),
		"integer beyond 2^53":      strings.Replace(ops, "limit_bytes: {min: 1, max: 1048576}", "limit_bytes: {min: 1, max: 9007199254740992}", 1),
		"boolean as string":        strings.Replace(ops, "intent_check_on_standing_rule: false", "intent_check_on_standing_rule: \"false\"", 1),
		"yaml 1.1 boolean literal": strings.Replace(ops, "intent_check_on_standing_rule: false", "intent_check_on_standing_rule: no", 1),
	}
	for name, o := range opsCases {
		if o == ops {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseCatalogYAML([]byte(o), []byte(tgs)); err == nil {
			t.Errorf("operations %s: accepted", name)
		}
	}
	tgsCases := map[string]string{
		"unknown field":          strings.Replace(tgs, "    namespace: agent-targets\n", "    namespace: agent-targets\n    labels: {}\n", 1),
		"duplicate key":          strings.Replace(tgs, "    tenant: hackathon\n", "    tenant: hackathon\n    tenant: other\n", 1),
		"ca_ref enum":            strings.Replace(tgs, "ca_ref: cluster", "ca_ref: none", 1),
		"max_data_class enum":    strings.Replace(tgs, "max_data_class: internal", "max_data_class: secret", 1),
		"origin http":            strings.Replace(tgs, "origin: https://kubernetes.default.svc:443", "origin: http://kubernetes.default.svc:443", 1),
		"origin placeholder":     strings.Replace(tgs, "origin: https://us-central1-aiplatform", "origin: https://<location>-aiplatform", 1),
		"empty cidrs":            strings.Replace(tgs, `allowed_cidrs: ["10.96.0.1/32"]`, "allowed_cidrs: []", 1),
		"empty operation_ids":    strings.Replace(tgs, "operation_ids: [receiver.submit]", "operation_ids: []", 1),
		"unknown operation ref":  strings.Replace(tgs, "operation_ids: [receiver.submit]", "operation_ids: [receiver.delete]", 1),
		"duplicate target_id":    strings.Replace(tgs, "target_id: receiver-probe", "target_id: receiver-primary", 1),
		"bad target_id":          strings.Replace(tgs, "target_id: receiver-probe", "target_id: Receiver_Probe", 1),
		"model unknown field":    strings.Replace(tgs, `model_id: "gemini-test-model"}`, `model_id: "gemini-test-model", region: "x"}`, 1),
		"missing required field": strings.Replace(tgs, "    expected_tls_name: receiver.agent-targets.svc\n", "", 1),
	}
	const san = "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets/sa/receiver\n"
	for name, v := range map[string]string{
		"uri_san missing on trust target": "",
		"uri_san null":                    "    expected_uri_san: null\n",
		"uri_san empty":                   "    expected_uri_san: \"\"\n",
		"uri_san wildcard":                "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets/sa/*\n",
		"uri_san query":                   "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets/sa/receiver?x=1\n",
		"uri_san fragment":                "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets/sa/receiver#x\n",
		"uri_san other trust domain":      "    expected_uri_san: spiffe://example.org/ns/agent-targets/sa/receiver\n",
		"uri_san uppercase":               "    expected_uri_san: spiffe://agentarium.internal/ns/Agent-Targets/sa/receiver\n",
		"uri_san trailing slash":          "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets/sa/receiver/\n",
		"uri_san label dash end":          "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets-/sa/receiver\n",
		"uri_san extra segment":           "    expected_uri_san: spiffe://agentarium.internal/ns/agent-targets/sa/receiver/x\n",
		"uri_san number":                  "    expected_uri_san: 1\n",
	} {
		tgsCases[name] = strings.Replace(tgs, san, v, 1)
	}
	tgsCases["uri_san on cluster target"] = strings.Replace(tgs, "    ca_ref: cluster\n", "    ca_ref: cluster\n"+san, 1)
	tgsCases["uri_san on system target"] = strings.Replace(tgs, "    ca_ref: system\n", "    ca_ref: system\n"+san, 1)
	tgsCases["trust target switched to cluster"] = strings.Replace(tgs, "    ca_ref: agentarium-trust\n"+san, "    ca_ref: cluster\n"+san, 1)
	for name, g := range tgsCases {
		if g == tgs {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if _, err := ParseCatalogYAML([]byte(ops), []byte(g)); err == nil {
			t.Errorf("targets %s: accepted", name)
		}
	}
}

func TestCatalogDigestProperties(t *testing.T) {
	ops, tgs := fixtureYAML(t)
	base, err := ParseCatalogYAML([]byte(ops), []byte(tgs))
	if err != nil {
		t.Fatal(err)
	}
	digest := func(o, g string) string {
		t.Helper()
		c, err := ParseCatalogYAML([]byte(o), []byte(g))
		if err != nil {
			t.Fatal(err)
		}
		return c.CatalogDigest
	}
	// catalog_version is a display label, not a digest input.
	if digest(strings.Replace(ops, "catalog_version: test-2026-10-11", "catalog_version: relabeled", 1), tgs) != base.CatalogDigest {
		t.Error("catalog_version changed catalog_digest")
	}
	// Comments, flow vs block style and YAML order do not matter.
	reordered := strings.Replace(tgs, "    ca_ref: cluster\n    auth_audience: null\n", "    auth_audience: null\n    ca_ref: cluster\n", 1)
	if reordered == tgs || digest(ops, "# comment\n"+reordered) != base.CatalogDigest {
		t.Error("formatting changed catalog_digest")
	}
	// Absent nullable field equals explicit null.
	if digest(ops, strings.Replace(tgs, "    auth_audience: null\n", "", 1)) != base.CatalogDigest {
		t.Error("absent nullable field differs from null")
	}
	// Content changes do change it.
	for name, g := range map[string]string{
		"cidr":    strings.Replace(tgs, "10.96.0.1/32", "10.96.0.2/32", 1),
		"tls":     strings.Replace(tgs, "expected_tls_name: kubernetes.default.svc", "expected_tls_name: kubernetes.default.svc.cluster.local", 1),
		"ca":      strings.Replace(tgs, "ca_ref: cluster", "ca_ref: system", 1),
		"origin":  strings.Replace(tgs, "https://receiver.agent-targets.svc:8443", "https://receiver.agent-targets.svc:9443", 1),
		"uri_san": strings.Replace(tgs, "ns/agent-targets/sa/receiver\n", "ns/agent-targets/sa/receiver-two\n", 1),
	} {
		if digest(ops, g) == base.CatalogDigest {
			t.Errorf("%s change did not change catalog_digest", name)
		}
	}
	if digest(strings.Replace(ops, "response_limit_bytes: 65536\n    content_checks", "response_limit_bytes: 32768\n    content_checks", 1), tgs) == base.CatalogDigest {
		t.Error("operation change did not change catalog_digest")
	}
}

func TestParseBundleCatalog(t *testing.T) {
	cat, err := LoadCatalogDir("testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseBundleCatalog(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.CatalogDigest != cat.CatalogDigest || len(got.Operations) != len(cat.Operations) || len(got.Targets) != len(cat.Targets) {
		t.Fatal("round trip mismatch")
	}
	tampered := strings.Replace(string(b), "10.96.0.1/32", "0.0.0.0/0", 1)
	if _, err := ParseBundleCatalog([]byte(tampered)); err == nil {
		t.Fatal("tampered data.catalog accepted")
	}
	wrongKey := strings.Replace(string(b), `"receiver-probe":{`, `"receiver-x":{`, 1)
	if _, err := ParseBundleCatalog([]byte(wrongKey)); err == nil {
		t.Fatal("map key / id mismatch accepted")
	}
	if _, err := ParseBundleCatalog([]byte(strings.Replace(string(b), `"catalog_digest":`, `"extra":1,"catalog_digest":`, 1))); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// TestParseBundleCatalogStrict covers keys that encoding/json alone would
// accept: case variants (read differently by Go and by Rego), and missing
// required or nullable-but-required keys (digest recomputed silently).
func TestParseBundleCatalogStrict(t *testing.T) {
	cat, err := LoadCatalogDir("testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	raw := string(b)
	for _, must := range []string{`"effect_type":"read"`, `"operation_id":`, `"redact_fields":`, `"credential_binding":`, `"auth_audience":`} {
		if !strings.Contains(raw, must) {
			t.Fatalf("fixture lacks %s", must)
		}
	}
	dropKey := func(s, key string) string {
		// Remove the first `"key":<value>,` member; values here are null, a
		// string or a flat array.
		i := strings.Index(s, `"`+key+`":`)
		j := i + len(key) + 3
		depth := 0
		for ; j < len(s); j++ {
			switch s[j] {
			case '[', '{':
				depth++
			case ']', '}':
				depth--
			case '"':
				for j++; s[j] != '"'; j++ {
					if s[j] == '\\' {
						j++
					}
				}
			case ',':
				if depth == 0 {
					return s[:i] + s[j+1:]
				}
			}
		}
		t.Fatalf("could not drop %s", key)
		return s
	}
	cases := map[string]string{
		"case-only duplicate key":        strings.Replace(raw, `"effect_type":"read"`, `"effect_type":"read","EFFECT_TYPE":"external_send"`, 1),
		"key differing only by case":     strings.Replace(raw, `"operation_id":`, `"OPERATION_ID":`, 1),
		"missing redact_fields":          dropKey(raw, "redact_fields"),
		"missing credential_binding":     dropKey(raw, "credential_binding"),
		"missing nullable auth_audience": dropKey(raw, "auth_audience"),
		"null for a non-nullable key":    strings.Replace(raw, `"effect_type":"read"`, `"effect_type":null`, 1),
		"integer written as decimal":     strings.Replace(raw, `"response_limit_bytes":65536`, `"response_limit_bytes":65536.0`, 1),
		"null expected_uri_san":          strings.Replace(raw, `"expected_uri_san":"spiffe://agentarium.internal/ns/agent-targets/sa/receiver"`, `"expected_uri_san":null`, 1),
		"expected_uri_san on k8s target": strings.Replace(raw, `"ca_ref":"cluster"`, `"ca_ref":"cluster","expected_uri_san":"spiffe://agentarium.internal/ns/a/sa/b"`, 1),
	}
	for name, in := range cases {
		if in == raw {
			t.Fatalf("%s: mutation did not apply", name)
		}
		_, err := ParseBundleCatalog([]byte(in))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if strings.Contains(err.Error(), "catalog_digest mismatch") {
			t.Errorf("%s: rejected only by the digest check: %v", name, err)
		} else {
			t.Logf("%s: %v", name, err)
		}
	}
}
