package collector

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
	"github.com/google/uuid"
)

const digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func fakeReceipt(action string, effects, attempts int, outcome string) *receipt.Receipt {
	r := &receipt.Receipt{ActionKey: action, TargetIdentity: "receiver-primary", Route: "submissions-v1", ReceiverMode: "non_idempotent", TargetVersion: "v", Effects: []receipt.Effect{}, ReceiverAttempts: []receipt.Attempt{}}
	for i := 0; i < effects; i++ {
		r.Effects = append(r.Effects, receipt.Effect{EffectID: uuid.NewString(), WireBodyDigest: digestA, BodyBytes: 10 + i, CommittedAt: "2026-10-18T00:00:00Z"})
	}
	r.EffectCount = effects
	for i := 0; i < attempts; i++ {
		r.ReceiverAttempts = append(r.ReceiverAttempts, receipt.Attempt{ReceiptAttemptID: uuid.NewString(), ReceivedAt: "2026-10-18T00:00:00Z", WireBodyDigest: digestA, Outcome: outcome})
	}
	return r
}

func asMap(t *testing.T, p Payload) map[string]any {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if len(m) != 10 {
		t.Fatalf("payload has %d keys, want all 10: %s", len(m), raw)
	}
	return m
}

func TestReceiptPayloadSituations(t *testing.T) {
	a := uuid.NewString()
	cases := []struct {
		name, rule, level string
		effects, attempts int
		outcome           string
		reason            any
		listLen           int // -1: null
		scalars           bool
	}{
		{"one effect verified", "R1", "effect_verified", 1, 1, "effect_created", nil, 1, true},
		{"one effect mismatch", "R2", "effect_mismatch", 1, 2, "effect_created", nil, 1, true},
		{"two effects", "R2", "effect_mismatch", 2, 2, "effect_created", MissingMultipleEffects, 2, false},
		{"64 effects", "R2", "effect_mismatch", 64, 64, "effect_created", MissingMultipleEffects, 64, false},
		{"65 effects", "R2", "effect_mismatch", 65, 65, "effect_created", MissingEffectListLimit, -1, false},
		{"conflict no effect R3", "R3", "effect_mismatch", 0, 1, "key_body_conflict", MissingNoReceiverEffect, 0, false},
		{"target mismatch no effect R2", "R2", "effect_mismatch", 0, 1, "key_missing_rejected", MissingNoReceiverEffect, 0, false},
		{"empty R5", "R5", "unknown", 0, 0, "", MissingNoReceiverAttempt, 0, false},
		{"empty R6", "R6", "none", 0, 0, "", MissingNoReceiverAttempt, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := fakeReceipt(a, c.effects, c.attempts, c.outcome)
			p, err := receiptPayload(a, receipt.Result{RuleID: c.rule, EvidenceLevel: c.level, ReceiptDigest: digestA, Receipt: r})
			if err != nil {
				t.Fatal(err)
			}
			m := asMap(t, p)
			if m["action_key"] != a || m["receipt_digest"] != digestA || m["effect_count"] != float64(c.effects) || m["missing_reason"] != c.reason {
				t.Fatalf("payload %v", m)
			}
			if c.listLen < 0 {
				if m["effects"] != nil {
					t.Fatal("over-limit effects list not null")
				}
			} else if l, ok := m["effects"].([]any); !ok || len(l) != c.listLen {
				t.Fatalf("effects %v", m["effects"])
			}
			if c.scalars != (m["wire_body_digest"] != nil) || c.scalars != (m["bytes"] != nil) {
				t.Fatalf("scalars %v %v", m["wire_body_digest"], m["bytes"])
			}
			if c.scalars && (m["wire_body_digest"] != digestA || m["bytes"] != float64(10)) {
				t.Fatal("scalars are not the single effect's values")
			}
		})
	}
}

func TestReceiptPayloadRejectsImpossiblePairs(t *testing.T) {
	a := uuid.NewString()
	for _, c := range []struct {
		rule, level string
		effects     int
		attempts    int
	}{
		{"R1", "effect_verified", 2, 2}, // R1 with several effects
		{"R3", "effect_mismatch", 1, 1}, // R3 with an effect
		{"R5", "unknown", 0, 1},         // R5 with receiver attempts
		{"R1", "effect_mismatch", 1, 1}, // wrong level
		{"R4", "accepted", 0, 0},        // R4 from a receipt
		{"R6", "none", 1, 1},            // R6 with an effect
		{"R2", "effect_mismatch", 0, 0}, // R2 from an empty receipt
	} {
		r := fakeReceipt(a, c.effects, c.attempts, "effect_created")
		if _, err := receiptPayload(a, receipt.Result{RuleID: c.rule, EvidenceLevel: c.level, ReceiptDigest: digestA, Receipt: r}); err == nil {
			t.Fatalf("%s/%s effects=%d accepted", c.rule, c.level, c.effects)
		}
	}
	r := fakeReceipt(uuid.NewString(), 1, 1, "effect_created")
	if _, err := receiptPayload(a, receipt.Result{RuleID: "R1", EvidenceLevel: "effect_verified", ReceiptDigest: digestA, Receipt: r}); err == nil {
		t.Fatal("receipt of another action accepted")
	}
	if _, err := receiptPayload(a, receipt.Result{RuleID: "R1", EvidenceLevel: "effect_verified"}); err == nil {
		t.Fatal("result without receipt accepted")
	}
}

func TestFixedPayloads(t *testing.T) {
	a := uuid.NewString()
	m := asMap(t, notReceiverPayload(a))
	if m["rule_id"] != "R4" || m["evidence_level"] != "accepted" || m["action_key"] != nil || m["missing_reason"] != MissingNotReceiverTarget || m["effects"] != nil || m["receipt_digest"] != nil || m["effect_count"] != nil {
		t.Fatalf("R4 %v", m)
	}
	m = asMap(t, unavailablePayload(a))
	if m["rule_id"] != "R5" || m["evidence_level"] != "unknown" || m["action_key"] != a || m["missing_reason"] != MissingReceiptUnavailable || m["effects"] != nil || m["receipt_digest"] != nil || m["effect_count"] != nil {
		t.Fatalf("R5 unavailable %v", m)
	}
	raw, _ := json.Marshal(unavailablePayload(a))
	if strings.Contains(string(raw), ":0") {
		t.Fatal("absent receiver fact filled with zero")
	}
}

func TestBackoffSchedule(t *testing.T) {
	var got []string
	for _, d := range Backoff {
		got = append(got, d.String())
	}
	if strings.Join(got, ",") != "1s,2s,4s,8s" || ObservationDeadline.Seconds() != 30 {
		t.Fatalf("schedule %v deadline %v", got, ObservationDeadline)
	}
}
