// Package receipt implements the TASK-08 receiver receipt boundary. It does not
// schedule polls, persist observations, or construct destination_observed events.
package receipt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

type Receipt struct {
	ActionKey        string    `json:"action_key"`
	TargetIdentity   string    `json:"target_identity"`
	Route            string    `json:"route"`
	ReceiverMode     string    `json:"receiver_mode"`
	Effects          []Effect  `json:"effects"`
	EffectCount      int       `json:"effect_count"`
	ReceiverAttempts []Attempt `json:"receiver_attempts"`
	TargetVersion    string    `json:"target_version"`
}
type Effect struct {
	EffectID            string  `json:"effect_id"`
	WireBodyDigest      string  `json:"wire_body_digest"`
	ContentDigestServer *string `json:"content_digest_server"`
	BodyBytes           int     `json:"body_bytes"`
	CommittedAt         string  `json:"committed_at"`
}
type Attempt struct {
	ReceiptAttemptID string  `json:"receipt_attempt_id"`
	ClientAttemptID  *string `json:"client_attempt_id"`
	ReceivedAt       string  `json:"received_at"`
	WireBodyDigest   string  `json:"wire_body_digest"`
	Outcome          string  `json:"outcome"`
}

func decode(raw []byte) (*Receipt, string, error) {
	if len(raw) > canonical.MaxBodyBytes {
		return nil, "", errors.New("receipt exceeds JSON size limit")
	}
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return nil, "", err
	}
	// Required fields must be present, including zero counts and empty arrays.
	// Optional nullable fields are accepted both omitted and null per TASK-08 §4.
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(raw, &shape); err != nil {
		return nil, "", err
	}
	if err := exactKeys(shape, []string{"action_key", "target_identity", "route", "receiver_mode", "effects", "effect_count", "receiver_attempts", "target_version"}); err != nil {
		return nil, "", err
	}
	if err := required(shape, "action_key", "target_identity", "route", "receiver_mode", "effects", "effect_count", "receiver_attempts", "target_version"); err != nil {
		return nil, "", err
	}
	for key, fields := range map[string][]string{"effects": {"effect_id", "wire_body_digest", "body_bytes", "committed_at"}, "receiver_attempts": {"receipt_attempt_id", "received_at", "wire_body_digest", "outcome"}} {
		var rows []map[string]json.RawMessage
		if err := json.Unmarshal(shape[key], &rows); err != nil {
			return nil, "", err
		}
		for _, row := range rows {
			optional := "content_digest_server"
			if key == "receiver_attempts" {
				optional = "client_attempt_id"
			}
			if err := exactKeys(row, append(append([]string{}, fields...), optional)); err != nil {
				return nil, "", err
			}
			if err := required(row, fields...); err != nil {
				return nil, "", err
			}
		}
	}
	var out Receipt
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, "", err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, "", errors.New("trailing receipt JSON")
	}
	if err := out.validate(); err != nil {
		return nil, "", err
	}
	// Digest the actual JSON, preserving optional-field presence. Re-marshalling
	// the typed struct would invent nulls for omitted optional fields.
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, "", err
	}
	jcs, err := canonical.CanonicalJSON(value)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(jcs)
	return &out, hex.EncodeToString(digest[:]), nil
}
func exactKeys(row map[string]json.RawMessage, allowed []string) error {
	for key := range row {
		ok := false
		for _, name := range allowed {
			if key == name {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("unknown receipt field %s", key)
		}
	}
	return nil
}
func required(row map[string]json.RawMessage, fields ...string) error {
	for _, key := range fields {
		v, ok := row[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("missing receipt field %s", key)
		}
	}
	return nil
}
func validUUID(v string) bool { id, err := uuid.Parse(v); return err == nil && id.String() == v }
func validDigest(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (r *Receipt) validate() error {
	if r == nil || !validUUID(r.ActionKey) || r.TargetIdentity == "" || r.Route == "" || r.TargetVersion == "" || r.Effects == nil || r.ReceiverAttempts == nil || r.EffectCount != len(r.Effects) {
		return errors.New("invalid receipt context or count")
	}
	if r.ReceiverMode != "idempotent" && r.ReceiverMode != "non_idempotent" {
		return errors.New("unknown receiver mode")
	}
	effects, attempts := map[string]bool{}, map[string]bool{}
	created := 0
	for _, e := range r.Effects {
		if !validUUID(e.EffectID) || effects[e.EffectID] || !validDigest(e.WireBodyDigest) || e.BodyBytes < 0 || (e.ContentDigestServer != nil && !validDigest(*e.ContentDigestServer)) {
			return errors.New("invalid receipt effect")
		}
		if _, err := time.Parse(time.RFC3339Nano, e.CommittedAt); err != nil {
			return err
		}
		effects[e.EffectID] = true
	}
	for _, a := range r.ReceiverAttempts {
		if !validUUID(a.ReceiptAttemptID) || attempts[a.ReceiptAttemptID] || !validDigest(a.WireBodyDigest) || (a.ClientAttemptID != nil && !validUUID(*a.ClientAttemptID)) {
			return errors.New("invalid receipt attempt")
		}
		if _, err := time.Parse(time.RFC3339Nano, a.ReceivedAt); err != nil {
			return err
		}
		switch a.Outcome {
		case "effect_created":
			created++
		case "duplicate_returned":
			// A duplicate returns an existing effect; without one it is malformed.
			if r.EffectCount == 0 {
				return errors.New("duplicate_returned attempt without an effect")
			}
		case "key_body_conflict", "key_missing_rejected":
		default:
			return errors.New("unknown receipt outcome")
		}
		attempts[a.ReceiptAttemptID] = true
	}
	// The receiver writes each effect and its effect_created attempt in one
	// transaction, so both directions of a count mismatch are malformed.
	if created != r.EffectCount {
		return errors.New("effect_created attempts do not match effects")
	}
	return nil
}

// Expected is trusted action/preflight context, not adapter-supplied receipt
// evidence. A future feed adapter must tenant-filter both defined DB views,
// resolve canonical_target to the catalog TargetID and set AttemptFailed only
// from a verified attempt_failed event.
type Expected struct {
	ActionID, TargetID, RouteID, WireBodyDigest string
	AttemptFailed                               bool
}

// Result retains every independent receipt fact. It does not collapse multiple
// effect digests into a fabricated single destination_observed payload.
type Result struct {
	EvidenceLevel, RuleID, ReceiptDigest string
	Receipt                              *Receipt
}

func classify(want Expected, r *Receipt, digest string) (Result, error) {
	if !validUUID(want.ActionID) || want.TargetID == "" || want.RouteID == "" || !validDigest(want.WireBodyDigest) {
		return Result{}, errors.New("incomplete trusted action/preflight context")
	}
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	if r.ActionKey != want.ActionID {
		return Result{}, errors.New("receipt action key differs from requested action")
	}
	result := Result{EvidenceLevel: "unknown", RuleID: "R5", Receipt: r, ReceiptDigest: digest}
	// An empty receipt contains no observed target/route or body evidence.
	if r.EffectCount == 0 && len(r.ReceiverAttempts) == 0 {
		if want.AttemptFailed {
			result.EvidenceLevel, result.RuleID = "none", "R6"
		}
		return result, nil
	}
	if r.TargetIdentity != want.TargetID || r.Route != want.RouteID || r.EffectCount > 1 {
		result.EvidenceLevel, result.RuleID = "effect_mismatch", "R2"
		return result, nil
	}
	for _, e := range r.Effects {
		if e.WireBodyDigest != want.WireBodyDigest {
			result.EvidenceLevel, result.RuleID = "effect_mismatch", "R2"
			return result, nil
		}
	}
	for _, a := range r.ReceiverAttempts {
		if a.WireBodyDigest != want.WireBodyDigest {
			result.EvidenceLevel, result.RuleID = "effect_mismatch", "R2"
			return result, nil
		}
	}
	if r.EffectCount == 1 {
		result.EvidenceLevel, result.RuleID = "effect_verified", "R1"
		return result, nil
	}
	for _, a := range r.ReceiverAttempts {
		if a.Outcome == "key_body_conflict" || a.Outcome == "key_missing_rejected" {
			result.EvidenceLevel, result.RuleID = "effect_mismatch", "R3"
			return result, nil
		}
	}
	return result, nil
}
