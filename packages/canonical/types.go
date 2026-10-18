package canonical

import (
	"encoding/json"
	"fmt"
)

// Versions written into every ActionEnvelope and action_digest.
const (
	CanonicalizationVersion = "v1"
)

// Operation IDs with a typed ClientAction schema (TASK-02 3.2).
const (
	OpK8sPodsList            = "k8s.pods.list"
	OpK8sEventsList          = "k8s.events.list"
	OpK8sPodsLogs            = "k8s.pods.logs"
	OpReceiverSubmit         = "receiver.submit"
	OpModelGenerate          = "model.generate"
	OpEvidenceActionRead     = "evidence.action.read"
	OpEvidenceBundleRead     = "evidence.bundle.read"
	OpEvidenceRegressionRead = "evidence.regression.read"
	OpDiscoverySourceRead    = "discovery.source.read"
	OpDiscoveryCallgraphRead = "discovery.callgraph.read"
)

// Reason codes used by this package (COMMON "reason code dictionary").
const (
	ReasonSchemaInvalid         = "SCHEMA_INVALID"
	ReasonEndpointNotRegistered = "ENDPOINT_NOT_REGISTERED"
	ReasonContentPatternDenied  = "CONTENT_PATTERN_DENIED"
	ReasonBodyTooLarge          = "BODY_TOO_LARGE"
	ReasonContextIncomplete     = "CONTEXT_INCOMPLETE"
)

// Normalize rule IDs (TASK-02 3.1 error contract).
const (
	RuleSchema             = "normalize.schema.v1"
	RuleEndpointRegistered = "normalize.endpoint_registered.v1"
	RuleContentPattern     = "normalize.content_pattern.v1"
)

// Data classes in rank order (COMMON enum data_class).
var dataClassRank = map[string]int{"none": 0, "synthetic": 1, "internal": 2, "confidential": 3}

// Model profiles (COMMON enum model_profile).
var modelProfiles = map[string]bool{"agent": true, "policy_proposal": true, "intent_check": true, "discovery": true}

// NormalizeError is the error contract of Normalize (TASK-02 3.1).
// RuleID is empty when the outer ClientAction could not be read; the gateway
// records nothing in that case (TASK-04 3.1).
type NormalizeError struct {
	ReasonCodes []string `json:"reason_codes"`
	HTTPStatus  int      `json:"http_status"`
	RuleID      string   `json:"rule_id"`
	Detail      string   `json:"-"`
}

func (e *NormalizeError) Error() string {
	return fmt.Sprintf("%v (%d, %s): %s", e.ReasonCodes, e.HTTPStatus, e.RuleID, e.Detail)
}

func schemaErr(rule, format string, a ...any) *NormalizeError {
	return &NormalizeError{ReasonCodes: []string{ReasonSchemaInvalid}, HTTPStatus: 422, RuleID: rule, Detail: fmt.Sprintf(format, a...)}
}

func notRegisteredErr(format string, a ...any) *NormalizeError {
	return &NormalizeError{ReasonCodes: []string{ReasonEndpointNotRegistered}, HTTPStatus: 403, RuleID: RuleEndpointRegistered, Detail: fmt.Sprintf(format, a...)}
}

// ClientAction is the outer request body (COMMON "common data structures").
// requested_target and arguments are re-validated per operation.
type ClientAction struct {
	SessionID        string          `json:"session_id"`
	OperationID      string          `json:"operation_id"`
	RequestedTarget  json.RawMessage `json:"requested_target"`
	Arguments        json.RawMessage `json:"arguments"`
	ClientRequestKey string          `json:"client_request_key"`
}

// Operation typed schemas (TASK-02 3.2). Field comments there are normative.

type TargetRef struct {
	TargetID string `json:"target_id"`
}

type Empty struct{}

type K8sListTarget = TargetRef
type K8sListArgs = Empty

type K8sLogsTarget struct {
	TargetID  string `json:"target_id"`
	PodName   string `json:"pod_name"`
	Container string `json:"container"`
}

type K8sLogsArgs struct {
	TailLines  int64 `json:"tail_lines"`
	LimitBytes int64 `json:"limit_bytes"`
}

type ReceiverTarget = TargetRef

type ReceiverArgs struct {
	Payload ReceiverPayload `json:"payload"`
}

type ReceiverPayload struct {
	Summary string  `json:"summary"`
	Email   *string `json:"email"`
}

type ModelTarget struct {
	TargetID string `json:"target_id"`
	Profile  string `json:"profile"`
}

// ModelArgs follows COMMON model integration and TASK-02 typed messages.
type ModelArgs struct {
	Phase            *string           `json:"phase,omitempty" canonical:"optional"` // required only for policy_proposal
	ConversationID   string            `json:"conversation_id"`
	Messages         []ModelMessage    `json:"messages"`
	ToolDeclarations []ToolDeclaration `json:"tool_declarations"`
}

type ModelMessage struct {
	Kind         string     `json:"kind"`
	Role         string     `json:"role"`
	Source       *string    `json:"source"`
	Text         *string    `json:"text"`
	Ref          *ResultRef `json:"ref"`
	FunctionName *string    `json:"function_name"`
}

type ResultRef struct {
	Ref       string  `json:"ref"`
	ActionID  *string `json:"action_id"`
	TurnIndex *int64  `json:"turn_index"`
}

type ToolDeclaration struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type EvidenceTarget struct {
	TargetID   string `json:"target_id"`
	ResourceID string `json:"resource_id"`
}

type EvidenceArgs = Empty

type DiscoverySourceTarget struct {
	TargetID   string `json:"target_id"`
	SnapshotID string `json:"snapshot_id"`
	Path       string `json:"path"`
}

type DiscoverySourceArgs struct {
	StartLine int64 `json:"start_line"`
	EndLine   int64 `json:"end_line"`
}

type DiscoveryCallgraphTarget struct {
	TargetID   string `json:"target_id"`
	SnapshotID string `json:"snapshot_id"`
	Symbol     string `json:"symbol"`
}

type DiscoveryCallgraphArgs struct {
	Depth int64 `json:"depth"`
}

// WorkloadDataState is the trusted high-water mark passed in by the gateway
// (OPA input shape in TASK-04 3.2). An empty class means no row, i.e. "none".
type WorkloadDataState struct {
	DataClassHighWater string   `json:"data_class_high_water"`
	DataSources        []string `json:"data_sources"`
}

// TrustedContext is server-side context for Normalize (TASK-02 4).
type TrustedContext struct {
	ActionID           string            `json:"action_id"`
	RequestID          string            `json:"request_id"`
	AuthenticatedActor string            `json:"authenticated_actor"`
	SessionKind        string            `json:"session_kind"`
	SessionID          string            `json:"session_id"`
	WorkloadID         *string           `json:"workload_id"`
	Tenant             string            `json:"tenant"`
	Environment        string            `json:"environment"`
	WorkloadDataState  WorkloadDataState `json:"workload_data_state"`
}

// CanonicalTarget always has target_id and route_id; the rest depend on the
// operation (TASK-02 3.3 table). Empty optional fields are omitted.
type CanonicalTarget struct {
	TargetID   string `json:"target_id"`
	RouteID    string `json:"route_id"`
	Namespace  string `json:"namespace,omitempty"`
	PodName    string `json:"pod_name,omitempty"`
	Container  string `json:"container,omitempty"`
	Profile    string `json:"profile,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
	SnapshotID string `json:"snapshot_id,omitempty"`
	Path       string `json:"path,omitempty"`
	Symbol     string `json:"symbol,omitempty"`
}

// HashObject is the fixed 10-key input of action_digest (TASK-02 3.3).
type HashObject struct {
	OperationID             string           `json:"operation_id"`
	CanonicalTarget         CanonicalTarget  `json:"canonical_target"`
	DisclosureFields        []string         `json:"disclosure_fields"`
	ContentDigest           *string          `json:"content_digest"`
	Limits                  map[string]int64 `json:"limits"`
	CatalogDigest           string           `json:"catalog_digest"`
	CanonicalizationVersion string           `json:"canonicalization_version"`
	SchemaVersion           string           `json:"schema_version"`
	Environment             string           `json:"environment"`
	Tenant                  string           `json:"tenant"`
}

// ActionEnvelope (COMMON "common data structures").
type ActionEnvelope struct {
	SchemaVersion           string           `json:"schema_version"`
	ActionID                string           `json:"action_id"`
	RequestID               string           `json:"request_id"`
	AuthenticatedActor      string           `json:"authenticated_actor"`
	SessionKind             string           `json:"session_kind"`
	SessionID               string           `json:"session_id"`
	WorkloadID              *string          `json:"workload_id"`
	EndpointID              string           `json:"endpoint_id"`
	OperationID             string           `json:"operation_id"`
	CanonicalTarget         CanonicalTarget  `json:"canonical_target"`
	Environment             string           `json:"environment"`
	Tenant                  string           `json:"tenant"`
	DisclosureFields        []string         `json:"disclosure_fields"`
	DataClass               string           `json:"data_class"`
	DataSources             []string         `json:"data_sources"`
	ContentDigest           *string          `json:"content_digest"`
	ContentRef              *string          `json:"content_ref"`
	Bytes                   int64            `json:"bytes"`
	Limits                  map[string]int64 `json:"limits"`
	CatalogDigest           string           `json:"catalog_digest"`
	CatalogVersion          string           `json:"catalog_version"`
	CanonicalizationVersion string           `json:"canonicalization_version"`
	RawBodyDigest           string           `json:"raw_body_digest"`
	ActionDigest            string           `json:"action_digest"`
}

// HashObject returns the action_digest input derived from the envelope.
func (e ActionEnvelope) HashObject() HashObject {
	return HashObject{
		OperationID:             e.OperationID,
		CanonicalTarget:         e.CanonicalTarget,
		DisclosureFields:        e.DisclosureFields,
		ContentDigest:           e.ContentDigest,
		Limits:                  e.Limits,
		CatalogDigest:           e.CatalogDigest,
		CanonicalizationVersion: e.CanonicalizationVersion,
		SchemaVersion:           e.SchemaVersion,
		Environment:             e.Environment,
		Tenant:                  e.Tenant,
	}
}

// Content is the ActionContent row produced by Normalize (COMMON ActionContent
// without created_at/expires_at, which the gateway sets when storing).
// It is the zero value for operations without content.
// Invariant: SHA-256(ContentBytes) == ContentDigest.
type Content struct {
	ContentDigest string `json:"content_digest"`
	Tenant        string `json:"tenant"`
	ActionID      string `json:"action_id"`
	AdapterID     string `json:"adapter_id"`
	ContentBytes  []byte `json:"content_bytes"`
}
