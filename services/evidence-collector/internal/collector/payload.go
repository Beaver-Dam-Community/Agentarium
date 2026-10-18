package collector

import (
	"errors"

	"github.com/Beaver-Dam-Community/Agentarium/services/evidence-collector/internal/receipt"
)

// MaxPayloadEffects is the TASK-08 3.2 effects[] limit.
const MaxPayloadEffects = 64

// COMMON destination_observed.missing_reason.
const (
	MissingMultipleEffects    = "MULTIPLE_EFFECTS"
	MissingEffectListLimit    = "EFFECT_LIST_LIMIT_EXCEEDED"
	MissingNoReceiverEffect   = "NO_RECEIVER_EFFECT"
	MissingNoReceiverAttempt  = "NO_RECEIVER_ATTEMPT"
	MissingReceiptUnavailable = "RECEIPT_UNAVAILABLE"
	MissingNotReceiverTarget  = "NOT_RECEIVER_TARGET"
)

// EffectRef is one destination_observed effects[] item.
type EffectRef struct {
	WireBodyDigest string `json:"wire_body_digest"`
	BodyBytes      int    `json:"body_bytes"`
}

// Payload is the destination_observed safe_payload (TASK-08 3.2). Every key
// is always present; an absent receiver fact is null, never zero, an adapter
// value or the first of several effects.
type Payload struct {
	ActionID       string       `json:"action_id"`
	ActionKey      *string      `json:"action_key"`
	RuleID         string       `json:"rule_id"`
	EvidenceLevel  string       `json:"evidence_level"`
	ReceiptDigest  *string      `json:"receipt_digest"`
	EffectCount    *int         `json:"effect_count"`
	WireBodyDigest *string      `json:"wire_body_digest"`
	Bytes          *int         `json:"bytes"`
	Effects        *[]EffectRef `json:"effects"`
	MissingReason  *string      `json:"missing_reason"`
}

func ptr[T any](v T) *T { return &v }

// notReceiverPayload is R4: a k8s or model call whose response was received.
func notReceiverPayload(actionID string) Payload {
	return Payload{ActionID: actionID, RuleID: "R4", EvidenceLevel: "accepted", MissingReason: ptr(MissingNotReceiverTarget)}
}

// unavailablePayload is R5 when no valid receipt was obtained by the deadline.
func unavailablePayload(actionID string) Payload {
	return Payload{ActionID: actionID, ActionKey: ptr(actionID), RuleID: "R5", EvidenceLevel: "unknown", MissingReason: ptr(MissingReceiptUnavailable)}
}

// receiptPayload maps a classified receipt to the situation table of TASK-08
// 3.2. It rejects a classification that has no row in that table.
func receiptPayload(actionID string, res receipt.Result) (Payload, error) {
	r := res.Receipt
	if r == nil || res.ReceiptDigest == "" || r.ActionKey != actionID || r.EffectCount != len(r.Effects) {
		return Payload{}, errors.New("collector: incomplete receipt result")
	}
	p := Payload{ActionID: actionID, ActionKey: ptr(actionID), RuleID: res.RuleID, EvidenceLevel: res.EvidenceLevel,
		ReceiptDigest: ptr(res.ReceiptDigest), EffectCount: ptr(r.EffectCount)}
	n := r.EffectCount
	if n <= MaxPayloadEffects {
		list := make([]EffectRef, 0, n)
		for _, e := range r.Effects {
			list = append(list, EffectRef{WireBodyDigest: e.WireBodyDigest, BodyBytes: e.BodyBytes})
		}
		p.Effects = &list
	}
	var allowed []string
	switch {
	case n == 1:
		p.WireBodyDigest, p.Bytes = ptr(r.Effects[0].WireBodyDigest), ptr(r.Effects[0].BodyBytes)
		allowed = []string{"R1", "R2"}
	case n > MaxPayloadEffects:
		p.MissingReason, allowed = ptr(MissingEffectListLimit), []string{"R2"}
	case n > 1:
		p.MissingReason, allowed = ptr(MissingMultipleEffects), []string{"R2"}
	case len(r.ReceiverAttempts) > 0:
		p.MissingReason, allowed = ptr(MissingNoReceiverEffect), []string{"R2", "R3"}
	default:
		p.MissingReason, allowed = ptr(MissingNoReceiverAttempt), []string{"R5", "R6"}
	}
	ok := false
	for _, rule := range allowed {
		ok = ok || rule == p.RuleID
	}
	if !ok || levelOf(p.RuleID) != p.EvidenceLevel {
		return Payload{}, errors.New("collector: classification has no destination_observed situation row")
	}
	return p, nil
}

// levelOf is the R1..R6 evidence_level pair of the TASK-08 judgment table.
func levelOf(rule string) string {
	switch rule {
	case "R1":
		return "effect_verified"
	case "R2", "R3":
		return "effect_mismatch"
	case "R4":
		return "accepted"
	case "R5":
		return "unknown"
	case "R6":
		return "none"
	}
	return ""
}
