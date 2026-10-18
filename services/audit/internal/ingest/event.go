// Package ingest implements the TASK-07 business-event ingress boundary.
package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

// Event contains only producer-controlled AuditEvent fields. ReceivedAt is
// deliberately absent: the database supplies it after successful validation.
type Event struct {
	EventID            string                     `json:"event_id"`
	EventType          string                     `json:"event_type"`
	Tenant             string                     `json:"tenant"`
	SourceID           string                     `json:"source_id"`
	SourceVersion      string                     `json:"source_version"`
	SourceEpoch        string                     `json:"source_epoch"`
	SourceSequence     *int64                     `json:"source_sequence"`
	SourceTime         string                     `json:"source_time"`
	SchemaVersion      int                        `json:"schema_version"`
	AuthenticatedActor *string                    `json:"authenticated_actor"`
	WorkloadID         *string                    `json:"workload_id"`
	SessionID          *string                    `json:"session_id"`
	ActionID           *string                    `json:"action_id"`
	RequestID          *string                    `json:"request_id"`
	AttemptID          *string                    `json:"attempt_id"`
	PolicyBundleID     *string                    `json:"policy_bundle_id"`
	PolicyEpoch        *int64                     `json:"policy_epoch"`
	CatalogDigest      *string                    `json:"catalog_digest"`
	CatalogVersion     *string                    `json:"catalog_version"`
	PayloadDigest      string                     `json:"payload_digest"`
	EvidenceRefs       []json.RawMessage          `json:"evidence_refs"`
	SafePayload        map[string]json.RawMessage `json:"safe_payload"`
}

func Decode(raw []byte) (Event, error) {
	var e Event
	if len(raw) > canonical.MaxBodyBytes {
		return e, errors.New("body too large")
	}
	if err := canonical.CheckStrictJSON(raw); err != nil {
		return e, err
	}
	// Additional TASK-07 collection/string limits, after the token pre-scan.
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return e, err
	}
	if err := limits(value); err != nil {
		return e, err
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return e, err
	}
	// encoding/json accepts case-insensitive aliases; the wire contract does not.
	encoded, _ := json.Marshal(Event{})
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &keys)
	for key := range fields {
		if _, ok := keys[key]; !ok {
			return e, fmt.Errorf("unknown field %q", key)
		}
	}
	for _, key := range []string{"event_id", "event_type", "tenant", "source_id", "source_version", "source_epoch", "source_time", "schema_version", "payload_digest", "evidence_refs", "safe_payload"} {
		if v, ok := fields[key]; !ok || bytes.Equal(v, []byte("null")) {
			return e, fmt.Errorf("missing %s", key)
		}
	}
	if e.EventID == "" || e.EventType == "" || e.Tenant == "" || e.SourceID == "" || e.SourceVersion == "" || e.SourceEpoch == "" || e.SchemaVersion != 1 || e.EvidenceRefs == nil || e.SafePayload == nil {
		return e, errors.New("invalid required field")
	}
	if !validUUID(e.EventID) {
		return e, errors.New("invalid event id")
	}
	for _, id := range []*string{e.SessionID, e.ActionID, e.RequestID, e.AttemptID} {
		if id != nil && !validUUID(*id) {
			return e, errors.New("invalid optional id")
		}
	}
	if _, err := time.Parse(time.RFC3339Nano, e.SourceTime); err != nil {
		return e, errors.New("invalid source time")
	}
	if e.SourceSequence != nil && *e.SourceSequence < 1 {
		return e, errors.New("invalid sequence")
	}
	if e.CatalogDigest != nil && !validDigest(*e.CatalogDigest) {
		return e, errors.New("invalid catalog digest")
	}
	digest, err := canonical.PayloadDigest(raw)
	if err != nil {
		return e, err
	}
	if !validDigest(e.PayloadDigest) || digest != e.PayloadDigest {
		return e, errors.New("digest mismatch")
	}
	return e, nil
}

func validUUID(s string) bool { u, err := uuid.Parse(s); return err == nil && u.String() == s }
func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func limits(v any) error {
	switch x := v.(type) {
	case map[string]any:
		if len(x) > 256 {
			return errors.New("too many object keys")
		}
		for _, v := range x {
			if err := limits(v); err != nil {
				return err
			}
		}
	case []any:
		if len(x) > 1000 {
			return errors.New("too many array entries")
		}
		for _, v := range x {
			if err := limits(v); err != nil {
				return err
			}
		}
	case string:
		if len(x) > 16384 {
			return errors.New("string too long")
		}
	}
	return nil
}
