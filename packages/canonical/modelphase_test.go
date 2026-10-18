package canonical

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestModelPhaseBoundToContent(t *testing.T) {
	cat := testCatalog(t)
	var digests []string
	for _, phase := range []string{"exploration", "final"} {
		raw := body(OpModelGenerate, `{"target_id":"agent-platform-gemini","profile":"policy_proposal"}`,
			fmt.Sprintf(`{"conversation_id":%q,"phase":%q,"messages":[%s],"tool_declarations":[]}`, conv, phase, msgUser))
		env, content, err := NormalizeRaw(raw, testTrusted(), cat)
		if err != nil {
			t.Fatal(err)
		}
		var stored modelContent
		if err := json.Unmarshal(content.ContentBytes, &stored); err != nil {
			t.Fatal(err)
		}
		if stored.Phase == nil || *stored.Phase != phase {
			t.Fatalf("phase missing: %s", content.ContentBytes)
		}
		if (stored.ResponseSchemaDigest == nil) != (phase == "exploration") {
			t.Fatalf("schema digest does not match phase: %s", content.ContentBytes)
		}
		if err := VerifyContent(env, content); err != nil {
			t.Fatal(err)
		}
		digests = append(digests, *env.ContentDigest)
	}
	if digests[0] == digests[1] {
		t.Fatal("phase did not change content digest")
	}
}

func TestInvalidModelPhaseRejected(t *testing.T) {
	for _, profile := range []string{"agent", "policy_proposal", "intent_check", "discovery"} {
		for _, field := range []string{"", `,"phase":null`, `,"phase":""`, `,"phase":"other"`, `,"phase":"final"`} {
			if (profile == "policy_proposal" && field == `,"phase":"final"`) || (profile != "policy_proposal" && field == "") {
				continue
			}
			t.Run(profile+field, func(t *testing.T) {
				raw := body(OpModelGenerate, fmt.Sprintf(`{"target_id":"agent-platform-gemini","profile":%q}`, profile),
					fmt.Sprintf(`{"conversation_id":%q,"messages":[%s],"tool_declarations":[]%s}`, conv, msgUser, field))
				_, _, err := NormalizeRaw(raw, testTrusted(), testCatalog(t))
				if err == nil || err.HTTPStatus != 422 {
					t.Fatalf("want schema rejection, got %v", err)
				}
			})
		}
	}
}
