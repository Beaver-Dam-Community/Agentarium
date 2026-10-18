package canonical

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const testSession = "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"

func body(op, target, args string) []byte {
	return []byte(fmt.Sprintf(`{"session_id":%q,"operation_id":%q,"requested_target":%s,"arguments":%s,"client_request_key":"req-00000001"}`, testSession, op, target, args))
}

func testTrusted() TrustedContext {
	w := "agent-runtime-0"
	return TrustedContext{
		ActionID: "8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f", RequestID: "0f9e8d7c-6b5a-4f3e-8d2c-1b0a9f8e7d6c",
		AuthenticatedActor: "user:alice@example.com", SessionKind: "user", SessionID: testSession, WorkloadID: &w,
		Tenant: "hackathon", Environment: "test",
	}
}

func testCatalog(t *testing.T) Catalog {
	t.Helper()
	c, err := LoadCatalogDir("testdata/catalog")
	if err != nil {
		t.Fatal(err)
	}
	gen := json.RawMessage(`{"temperature":0}`)
	c.ModelProfiles = map[string]ModelProfileConfig{
		"agent":           {MaxOutputTokens: 8192, MaxRequestBytes: 65536, GenerationConfig: gen},
		"policy_proposal": {MaxOutputTokens: 8192, MaxRequestBytes: 65536, GenerationConfig: gen, ResponseSchema: json.RawMessage(`{"type":"object"}`)},
		"intent_check":    {MaxOutputTokens: 1024, MaxRequestBytes: 16384, GenerationConfig: gen, ResponseSchema: json.RawMessage(`{"type":"object"}`)},
		"discovery":       {MaxOutputTokens: 8192, MaxRequestBytes: 65536, GenerationConfig: gen, ResponseSchema: json.RawMessage(`{"type":"object"}`)},
	}
	return c
}

const (
	hex64  = "3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f"
	snap64 = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	uuidA  = "2b7e4f10-3c2d-4e5f-9a6b-7c8d9e0f1a2b"
	conv   = "6f1c2d3e-4a5b-4c6d-8e7f-901a2b3c4d5e"
)

const msgUser = `{"kind":"text","role":"user","source":"user","text":"요약해 줘","ref":null,"function_name":null}`

// Every valid and reject example of the TASK-02 3.2 table.
func TestTypedSchemaTable32(t *testing.T) {
	cat := testCatalog(t)
	type tc struct {
		name, op, target, args string
		status                 int    // 0 = valid
		code                   string // expected reason code
	}
	cases := []tc{
		{"pods.list valid", OpK8sPodsList, `{"target_id":"k8s-agent-targets"}`, `{}`, 0, ""},
		{"pods.list limit", OpK8sPodsList, `{"target_id":"k8s-agent-targets"}`, `{"limit":500}`, 422, ReasonSchemaInvalid},
		{"events.list valid", OpK8sEventsList, `{"target_id":"k8s-agent-targets"}`, `{}`, 0, ""},
		{"events.list kube-system", OpK8sEventsList, `{"target_id":"k8s-kube-system"}`, `{}`, 403, ReasonEndpointNotRegistered},
		{"pods.logs valid", OpK8sPodsLogs, `{"target_id":"k8s-agent-targets","pod_name":"demo-api-7d9f","container":"app"}`, `{"tail_lines":100,"limit_bytes":65536}`, 0, ""},
		{"pods.logs tail 500", OpK8sPodsLogs, `{"target_id":"k8s-agent-targets","pod_name":"demo-api-7d9f","container":"app"}`, `{"tail_lines":500,"limit_bytes":65536}`, 422, ReasonSchemaInvalid},
		{"receiver valid", OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"3 pods restarted","email":null}}`, 0, ""},
		{"receiver case dup", OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"x","Summary":"y"}}`, 422, ReasonSchemaInvalid},
		{"model valid", OpModelGenerate, `{"target_id":"agent-platform-gemini","profile":"agent"}`, `{"conversation_id":"` + conv + `","messages":[` + msgUser + `],"tool_declarations":[]}`, 0, ""},
		// Schema-valid; Rego decides SERVICE_SCOPE_DENIED or approval (TASK-04).
		{"model policy_proposal from user", OpModelGenerate, `{"target_id":"agent-platform-gemini","profile":"policy_proposal"}`, `{"conversation_id":"` + conv + `","messages":[` + msgUser + `],"tool_declarations":[],"phase":"final"}`, 0, ""},
		{"evidence.action valid", OpEvidenceActionRead, `{"target_id":"evidence-api","resource_id":"` + uuidA + `"}`, `{}`, 0, ""},
		{"evidence.action ../x", OpEvidenceActionRead, `{"target_id":"evidence-api","resource_id":"../x"}`, `{}`, 422, ReasonSchemaInvalid},
		{"evidence.bundle valid", OpEvidenceBundleRead, `{"target_id":"evidence-api","resource_id":"` + hex64 + `"}`, `{}`, 0, ""},
		{"evidence.bundle ABC", OpEvidenceBundleRead, `{"target_id":"evidence-api","resource_id":"ABC"}`, `{}`, 422, ReasonSchemaInvalid},
		{"evidence.regression valid", OpEvidenceRegressionRead, `{"target_id":"evidence-api","resource_id":"` + uuidA + `"}`, `{}`, 0, ""},
		{"evidence.regression args", OpEvidenceRegressionRead, `{"target_id":"evidence-api","resource_id":"` + uuidA + `"}`, `{"run_id":"` + uuidA + `"}`, 422, ReasonSchemaInvalid},
		{"discovery.source valid", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","path":"httpx/_client.py"}`, `{"start_line":1,"end_line":200}`, 0, ""},
		{"discovery.source 900", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","path":"httpx/_client.py"}`, `{"start_line":1,"end_line":900}`, 422, ReasonSchemaInvalid},
		{"discovery.callgraph valid", OpDiscoveryCallgraphRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","symbol":"httpx.Client.send"}`, `{"depth":2}`, 0, ""},
		{"discovery.callgraph 1.5", OpDiscoveryCallgraphRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","symbol":"httpx.Client.send"}`, `{"depth":1.5}`, 422, ReasonSchemaInvalid},
	}
	for _, c := range cases {
		env, _, err := NormalizeRaw(body(c.op, c.target, c.args), testTrusted(), cat)
		if c.status == 0 {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			} else if len(env.ActionDigest) != 64 {
				t.Errorf("%s: no action_digest", c.name)
			}
			continue
		}
		if err == nil || err.HTTPStatus != c.status || err.ReasonCodes[0] != c.code {
			t.Errorf("%s: got %v, want %d %s", c.name, err, c.status, c.code)
		}
	}
}

func TestMoreSchemaRejects(t *testing.T) {
	cat := testCatalog(t)
	logsT := `{"target_id":"k8s-agent-targets","pod_name":"demo-api-7d9f","container":"app"}`
	agentT := `{"target_id":"agent-platform-gemini","profile":"agent"}`
	tool := func(params string) string {
		return `{"conversation_id":"` + conv + `","messages":[` + msgUser + `],"tool_declarations":[{"name":"t","description":"d","parameters":` + params + `}]}`
	}
	bigParams := `{"description":"` + strings.Repeat("x", 4100) + `"}`
	cases := []struct{ name, op, target, args string }{
		{"limit_bytes 0", OpK8sPodsLogs, logsT, `{"tail_lines":1,"limit_bytes":0}`},
		{"limit_bytes too big", OpK8sPodsLogs, logsT, `{"tail_lines":1,"limit_bytes":1048577}`},
		{"container uppercase", OpK8sPodsLogs, `{"target_id":"k8s-agent-targets","pod_name":"demo","container":"App"}`, `{"tail_lines":1,"limit_bytes":1}`},
		{"tail_lines string", OpK8sPodsLogs, logsT, `{"tail_lines":"1","limit_bytes":1}`},
		{"email too short", OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"s","email":"ab"}}`},
		{"summary too long", OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"` + strings.Repeat("a", 4097) + `","email":null}}`},
		{"tool params too large", OpModelGenerate, agentT, tool(bigParams)},
		{"tool params not object", OpModelGenerate, agentT, tool(`[1]`)},
		{"tool name invalid", OpModelGenerate, agentT, `{"conversation_id":"` + conv + `","messages":[` + msgUser + `],"tool_declarations":[{"name":"1bad","description":"d","parameters":{}}]}`},
		{"nine tools", OpModelGenerate, agentT, `{"conversation_id":"` + conv + `","messages":[` + msgUser + `],"tool_declarations":[` + strings.TrimSuffix(strings.Repeat(`{"name":"t","description":"d","parameters":{}},`, 9), ",") + `]}`},
		{"conversation uppercase", OpModelGenerate, agentT, `{"conversation_id":"` + strings.ToUpper(conv) + `","messages":[` + msgUser + `],"tool_declarations":[]}`},
		{"model_turn with source", OpModelGenerate, agentT, `{"conversation_id":"` + conv + `","messages":[{"kind":"model_turn","role":"model","source":"user","text":null,"ref":{"ref":"model_turn","action_id":null,"turn_index":1},"function_name":null}],"tool_declarations":[]}`},
		{"tool_result without function", OpModelGenerate, agentT, `{"conversation_id":"` + conv + `","messages":[{"kind":"tool_result","role":"user","source":"tool_result","text":null,"ref":{"ref":"action_result","action_id":"` + uuidA + `","turn_index":null},"function_name":null}],"tool_declarations":[]}`},
		{"text role model", OpModelGenerate, agentT, `{"conversation_id":"` + conv + `","messages":[{"kind":"text","role":"model","source":"user","text":"x","ref":null,"function_name":null}],"tool_declarations":[]}`},
		{"snapshot uppercase", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + strings.ToUpper(snap64) + `","path":"a.py"}`, `{"start_line":1,"end_line":2}`},
		{"absolute path", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","path":"/etc/passwd"}`, `{"start_line":1,"end_line":2}`},
		{"query in path", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","path":"a.py?x=1"}`, `{"start_line":1,"end_line":2}`},
		{"start_line 0", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","path":"a.py"}`, `{"start_line":0,"end_line":2}`},
		{"end before start", OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","path":"a.py"}`, `{"start_line":5,"end_line":4}`},
		{"symbol with space", OpDiscoveryCallgraphRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","symbol":"a b"}`, `{"depth":1}`},
		{"depth 0", OpDiscoveryCallgraphRead, `{"target_id":"discovery-snapshots","snapshot_id":"` + snap64 + `","symbol":"a"}`, `{"depth":0}`},
	}
	for _, c := range cases {
		_, _, err := NormalizeRaw(body(c.op, c.target, c.args), testTrusted(), cat)
		if err == nil || err.HTTPStatus != 422 || err.ReasonCodes[0] != ReasonSchemaInvalid {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
	// discovery.source accepts exactly 400 extra lines.
	if _, _, err := NormalizeRaw(body(OpDiscoverySourceRead, `{"target_id":"discovery-snapshots","snapshot_id":"`+snap64+`","path":"a.py"}`, `{"start_line":10,"end_line":410}`), testTrusted(), cat); err != nil {
		t.Errorf("start+400 rejected: %v", err)
	}
}

func TestNormalizeTrustedContext(t *testing.T) {
	cat := testCatalog(t)
	raw := body(OpK8sPodsList, `{"target_id":"k8s-agent-targets"}`, `{}`)
	bad := testTrusted()
	bad.SessionKind = "admin"
	if _, _, err := NormalizeRaw(raw, bad, cat); err == nil || err.ReasonCodes[0] != ReasonContextIncomplete {
		t.Errorf("bad session_kind: %v", err)
	}
	bad = testTrusted()
	bad.WorkloadDataState.DataClassHighWater = "secret"
	if _, _, err := NormalizeRaw(raw, bad, cat); err == nil {
		t.Error("bad data class accepted")
	}
	// No workload_data_state row: data_class none, data_sources [].
	env, _, err := NormalizeRaw(raw, testTrusted(), cat)
	if err != nil {
		t.Fatal(err)
	}
	if env.DataClass != "none" || env.DataSources == nil || len(env.DataSources) != 0 {
		t.Errorf("default data state: %q %v", env.DataClass, env.DataSources)
	}
	// Service session: workload_id null.
	svc := testTrusted()
	svc.SessionKind, svc.WorkloadID = "service", nil
	env, _, err = NormalizeRaw(raw, svc, cat)
	if err != nil || env.WorkloadID != nil {
		t.Errorf("service session: %v %v", err, env.WorkloadID)
	}
	b, _ := json.Marshal(env)
	if !strings.Contains(string(b), `"workload_id":null`) || !strings.Contains(string(b), `"content_digest":null`) {
		t.Errorf("optional envelope fields must serialize as null: %s", b)
	}
}

func TestNormalizeModelProfileRegistration(t *testing.T) {
	raw := body(OpModelGenerate, `{"target_id":"agent-platform-gemini","profile":"agent"}`, `{"conversation_id":"`+conv+`","messages":[`+msgUser+`],"tool_declarations":[]}`)
	cat := testCatalog(t)
	delete(cat.ModelProfiles, "agent")
	if _, _, err := NormalizeRaw(raw, testTrusted(), cat); err == nil || err.ReasonCodes[0] != ReasonEndpointNotRegistered {
		t.Errorf("missing profile constants: %v", err)
	}
	cat = testCatalog(t)
	op := cat.Operations[OpModelGenerate]
	only := []string{"discovery"}
	op.ModelProfiles = &only
	cat.Operations[OpModelGenerate] = op
	if _, _, err := NormalizeRaw(raw, testTrusted(), cat); err == nil || err.ReasonCodes[0] != ReasonEndpointNotRegistered {
		t.Errorf("profile not in model_profiles: %v", err)
	}
	// Profile constants are part of action_digest.
	a := testCatalog(t)
	b := testCatalog(t)
	pc := b.ModelProfiles["agent"]
	pc.GenerationConfig = json.RawMessage(`{"temperature":1}`)
	b.ModelProfiles["agent"] = pc
	ea, _, err1 := NormalizeRaw(raw, testTrusted(), a)
	eb, _, err2 := NormalizeRaw(raw, testTrusted(), b)
	if err1 != nil || err2 != nil || ea.ActionDigest == eb.ActionDigest {
		t.Errorf("generation config change must change action_digest: %v %v", err1, err2)
	}
}

func TestCatalogDigestIsInActionDigest(t *testing.T) {
	ops, _ := readFile(t, "testdata/catalog/operations.yaml")
	tgs, _ := readFile(t, "testdata/catalog/targets.yaml")
	a, err := ParseCatalogYAML(ops, tgs)
	if err != nil {
		t.Fatal(err)
	}
	// Same catalog_version label, only a target address changes.
	b, err := ParseCatalogYAML(ops, []byte(strings.Replace(string(tgs), "10.96.10.20/32", "10.96.10.99/32", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if a.CatalogVersion != b.CatalogVersion || a.CatalogDigest == b.CatalogDigest {
		t.Fatalf("address change must change catalog_digest under the same label")
	}
	raw := body(OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"3 pods restarted","email":null}}`)
	ea, _, err1 := NormalizeRaw(raw, testTrusted(), a)
	eb, _, err2 := NormalizeRaw(raw, testTrusted(), b)
	if err1 != nil || err2 != nil || ea.ActionDigest == eb.ActionDigest {
		t.Fatalf("catalog_digest change must change action_digest: %v %v", err1, err2)
	}
}

func TestReceiverWireBodyTamper(t *testing.T) {
	cat := testCatalog(t)
	env, content, err := NormalizeRaw(body(OpReceiverSubmit, `{"target_id":"receiver-primary"}`, `{"payload":{"summary":"3 pods restarted","email":null}}`), testTrusted(), cat)
	if err != nil {
		t.Fatal(err)
	}
	wire, werr := ReceiverWireBody(env, content)
	if werr != nil || string(wire) != `{"email":null,"summary":"3 pods restarted"}` {
		t.Fatalf("%s %v", wire, werr)
	}
	if WireBodyDigest(wire) != *env.ContentDigest {
		t.Fatal("receiver wire body digest must equal content_digest")
	}
	content.ContentBytes = []byte(`{"email":null,"summary":"4 pods restarted"}`)
	if _, err := ReceiverWireBody(env, content); err == nil {
		t.Fatal("tampered content accepted")
	}
	envNoContent, c2, _ := NormalizeRaw(body(OpK8sPodsList, `{"target_id":"k8s-agent-targets"}`, `{}`), testTrusted(), cat)
	if err := VerifyContent(envNoContent, c2); err != nil {
		t.Fatal(err)
	}
	if _, err := ReceiverWireBody(envNoContent, c2); err == nil {
		t.Fatal("non-receiver envelope accepted")
	}
}

func TestNormalizeUnknownTypedOperation(t *testing.T) {
	cat := testCatalog(t)
	op := cat.Operations[OpK8sPodsList]
	op.OperationID = "k8s.nodes.list"
	cat.Operations[op.OperationID] = op
	_, _, err := NormalizeRaw(body("k8s.nodes.list", `{"target_id":"k8s-agent-targets"}`, `{}`), testTrusted(), cat)
	if err == nil || err.HTTPStatus != 403 || err.RuleID != RuleEndpointRegistered {
		t.Fatalf("got %v", err)
	}
}
