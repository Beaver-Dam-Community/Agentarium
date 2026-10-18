// Package receiver is the receiver-sender adapter (TASK-05 3.1): the
// receiver.submit WirePlan mapper with the bundle policy checks, and the
// receiver row of the response mapping table (TASK-05 3.3).
package receiver

import (
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/prepare"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// AdapterID is this adapter's catalog adapter_id.
const AdapterID = prepare.ReceiverAdapterID

// Adapter implements execute.Adapter for receiver.submit.
type Adapter struct{}

var _ execute.Adapter = Adapter{}

func (Adapter) ID() string { return AdapterID }

func reject(m *prepare.Mismatch) *execute.Rejection {
	return &execute.Rejection{ReasonCodes: []string{m.ReasonCode}, ComparedFields: []string{m.Field}, Detail: m.Detail}
}

// Prepare rebuilds the request from the stored envelope and content and the
// loaded bundle: catalog route and target, JCS payload body, disclosure
// fields, size limits, data.receiver.allowed_disclosure_fields and
// data.adapter_constraints["receiver-sender"].
func (Adapter) Prepare(in execute.Inputs, b *execute.Bundle) (execute.Prepared, *execute.Rejection) {
	plan, op, tg, m := prepare.ReceiverPlan(in.Envelope, in.Content, b.Catalog)
	if m != nil {
		return execute.Prepared{}, reject(m)
	}
	c, ok := b.AdapterConstraints[AdapterID]
	if !ok {
		return execute.Prepared{}, &execute.Rejection{ReasonCodes: []string{execute.ReasonPreflightMismatch}, ComparedFields: []string{"adapter_constraints"}, Detail: "bundle has no adapter_constraints for receiver-sender"}
	}
	plan, m = prepare.CheckReceiverPolicy(plan, in.Envelope, op, prepare.ReceiverPolicy{
		AllowedDisclosureFields: b.ReceiverAllowedFields,
		MaxRequestBytes:         c.MaxRequestBytes,
		MaxResponseBytes:        c.MaxResponseBytes,
		AllowedRouteIDs:         c.AllowedRouteIDs,
	})
	if m != nil {
		return execute.Prepared{}, reject(m)
	}
	// The receiver needs the broker's synthetic API key (TASK-05 3.1:
	// credential_binding = receiver-api-key); a catalog without one is not
	// the registered receiver operation.
	if op.CredentialBinding == nil || *op.CredentialBinding == "" {
		return execute.Prepared{}, &execute.Rejection{ReasonCodes: []string{execute.ReasonPreflightMismatch}, ComparedFields: []string{"credential_binding"}, Detail: "receiver.submit has no credential_binding"}
	}
	return execute.Prepared{
		Plan:              plan,
		CredentialBinding: *op.CredentialBinding,
		CARef:             tg.CARef,
		ResponseDataClass: op.ResponseDataClass,
		RedactFields:      append([]string(nil), op.RedactFields...),
		EvidenceLevelMax:  op.EvidenceLevelMax,
	}, nil
}

// Response mapping reason codes (COMMON reason code dictionary).
const (
	ReasonResponseTooLarge      = "RESPONSE_TOO_LARGE"
	ReasonTargetRejected        = "TARGET_REJECTED"
	ReasonTargetUnavailable     = "TARGET_UNAVAILABLE"
	ReasonTargetKeyBodyConflict = "TARGET_KEY_BODY_CONFLICT"
)

// MapResponse is the receiver-sender rows of TASK-05 3.3 plus the common
// rows (oversize, 3xx). Every received response is attempt
// response_received; this decides execution_state, reason_codes and
// evidence_level.
func (Adapter) MapResponse(r transport.Result) execute.Mapping {
	s := r.StatusCode
	switch {
	case r.Oversize:
		return execute.Mapping{ExecutionState: "failed", ReasonCodes: []string{ReasonResponseTooLarge}, EvidenceLevel: "none"}
	case s == 200 || s == 201:
		// Acceptance only; the effect is verified by TASK-08 receipts.
		return execute.Mapping{ExecutionState: "accepted", ReasonCodes: []string{}, EvidenceLevel: "accepted"}
	case s >= 300 && s < 400:
		return execute.Mapping{ExecutionState: "failed", ReasonCodes: []string{ReasonTargetRejected}, EvidenceLevel: "none"}
	case s == 409:
		return execute.Mapping{ExecutionState: "failed", ReasonCodes: []string{ReasonTargetKeyBodyConflict}, EvidenceLevel: "none"}
	case s == 429:
		// The receiver answers 429 before processing.
		return execute.Mapping{ExecutionState: "failed", ReasonCodes: []string{ReasonTargetUnavailable}, EvidenceLevel: "none"}
	case s >= 400 && s < 500:
		return execute.Mapping{ExecutionState: "failed", ReasonCodes: []string{ReasonTargetRejected}, EvidenceLevel: "none"}
	default:
		// 5xx: processing unknown, resolved by TASK-08 receipts.
		// SPEC-QUESTION: the table has no row for other 2xx (202, 204) or
		// 1xx; they are treated like 5xx (effect unknown) rather than as
		// acceptance or rejection.
		return execute.Mapping{ExecutionState: "unknown", ReasonCodes: []string{ReasonTargetUnavailable}, EvidenceLevel: "unknown"}
	}
}
