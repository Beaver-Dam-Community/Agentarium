package health

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// CodeHoldRequestDenied is the TASK-10 denial code defined by shared spec #129.
const CodeHoldRequestDenied = "HOLD_REQUEST_DENIED"

// HoldRequest is the registered component request. Operator console requests
// require the separate authenticated operator flow, never this authorization.
type HoldRequest struct {
	Scope        string   `json:"scope"`
	ScopeID      string   `json:"scope_id"`
	Reason       string   `json:"reason"`
	ReasonDetail *string  `json:"reason_detail,omitempty"`
	EvidenceRefs []string `json:"evidence_refs"`
}

// RiskEventDetails is the COMMON hold.reason_detail enum (TASK-10 3.2).
var RiskEventDetails = []string{"unregistered_connect_established", "protected_path_write", "unexpected_child_exec"}

type HoldAck struct {
	HoldID      *string  `json:"hold_id"`
	Decision    string   `json:"decision"`
	ReasonCodes []string `json:"reason_codes"`
}

func DecodeHoldRequest(raw []byte) (HoldRequest, error) {
	var h HoldRequest
	if len(raw) > canonical.MaxBodyBytes || canonical.CheckStrictJSON(raw) != nil {
		return h, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) < 4 || len(fields) > 5 {
		return h, ErrInvalid
	}
	if v, ok := fields["reason_detail"]; len(fields) == 5 && (!ok || bytes.Equal(v, []byte("null"))) {
		return h, ErrInvalid
	}
	for _, key := range []string{"scope", "scope_id", "reason", "evidence_refs"} {
		v, ok := fields[key]
		if !ok || bytes.Equal(v, []byte("null")) {
			return h, ErrInvalid
		}
	}
	if json.Unmarshal(raw, &h) != nil || !h.Valid() {
		return h, ErrInvalid
	}
	return h, nil
}

func (h HoldRequest) Valid() bool {
	// operator_stop needs the BFF actor/roles and durable session revocation
	// workflow; it cannot be requested through a component grant alone.
	if !ValidScopeID(h.Scope, h.ScopeID) || !ValidHoldReason(h.Reason) || h.Reason == "operator_stop" || h.EvidenceRefs == nil {
		return false
	}
	// reason_detail is required exactly for risk_event (#172), a workload hold
	// decided by the correlation evaluator with its kernel evidence.
	if (h.Reason == "risk_event") != (h.ReasonDetail != nil) {
		return false
	}
	if h.Reason == "risk_event" && (!slices.Contains(RiskEventDetails, *h.ReasonDetail) || h.Scope != "workload" || len(h.EvidenceRefs) == 0) {
		return false
	}
	if (h.Reason == "sensor_degraded" && h.Scope != "node") || (h.Reason == "db_unavailable" && h.Scope != "global") {
		return false
	}
	for _, ref := range h.EvidenceRefs {
		if ref == "" || len(ref) > 16384 {
			return false
		}
	}
	return true
}

// HoldOwner follows TASK-10 3.2; requester is not automatically release owner.
func HoldOwner(reason, component string) string {
	switch reason {
	case "export_lag":
		return "audit-export"
	case "db_unavailable":
		return "audit-db"
	case "probe_failed":
		return component
	case "start_unknown":
		return "start-coordinator"
	case "sensor_degraded":
		return "node-sensors"
	case "policy_activation":
		return "releaser"
	default:
		return "control-health"
	}
}

// OwnedHolds is the GET /internal/holds?owner_component= response (#177).
type OwnedHolds struct {
	Holds []Hold `json:"holds"`
}
