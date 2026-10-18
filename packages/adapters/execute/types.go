// Package execute is the TASK-05 3.3 execute engine shared by the adapters:
// the idempotent POST /internal/adapter/{adapter_id}/execute, preflight
// against the stored decision and the loaded bundle, the dispatch
// coordinator reservation, credential, permit claim, one transport attempt,
// the COMMON failure classification and the adapter commit order
// (① workload_data_state → ② outcome → ③ action_results → ④ completed).
//
// What other Tasks own is reached through the interfaces below. A nil
// dependency gets the Unwired default, which fails, so nothing is reserved or
// sent: fail-closed. A binary checks Config.Wired before New so that it never
// runs with an Unwired default.
package execute

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// adapter_executions.state (COMMON AdapterExecution).
const (
	StateReceived          = "received"
	StatePreflightRejected = "preflight_rejected"
	StateReserved          = "reserved"
	StateCompleted         = "completed"
	StateFailed            = "failed"
)

// Outcome transitions (COMMON API implementation contract, attempt.state).
const (
	TransitionReleased         = "released"
	TransitionDispatched       = "dispatched"
	TransitionResponseReceived = "response_received"
	TransitionFailed           = "failed"
	TransitionUnknown          = "unknown"
)

// Reason codes used by the engine (COMMON reason code dictionary).
const (
	ReasonPreflightMismatch     = "PREFLIGHT_MISMATCH"
	ReasonContentDigestMismatch = "CONTENT_DIGEST_MISMATCH"
	ReasonCatalogDigestMismatch = "CATALOG_DIGEST_MISMATCH"
	ReasonCredentialUnavailable = "CREDENTIAL_UNAVAILABLE"
	ReasonPermitInvalid         = "PERMIT_INVALID"
	ReasonStateStoreUnavailable = "STATE_STORE_UNAVAILABLE"
	ReasonTargetUnavailable     = "TARGET_UNAVAILABLE"
)

// Decision is the part of the TASK-04 GatewayDecision the adapter compares.
type Decision struct {
	DecisionID     string
	RequestID      string
	ActionID       string
	ActionDigest   string
	AdapterID      string
	Verdict        string
	PolicyBundleID string
	PolicyEpoch    int64
	CatalogDigest  string
	ExpiresAt      time.Time
	// ServiceSessionID is decisions.service_session_id, empty when null. The
	// preflight requires it to equal the envelope session_id of a service
	// session action (session_id is not an action_digest input), and the
	// evidence-reader builds X-Agentarium-Service-Session from it (COMMON
	// identifier registration).
	ServiceSessionID string
}

// Inputs are the stored values of one execute request: the immutable
// decision, the action envelope and the action_contents row (zero Content
// when the operation has none).
type Inputs struct {
	Decision Decision
	Envelope canonical.ActionEnvelope
	Content  canonical.Content
	// Resolved is the value the adapter's Resolver returned for these
	// inputs (TASK-05 3.1 Prepare(envelope, content, resolved)); nil for an
	// adapter without one. The engine sets it after loading the inputs and
	// before Prepare; an InputStore leaves it nil.
	Resolved any
}

// RefSession is the session a referenced row belongs to: the session_kind
// and the user session_id or the service_session_id.
type RefSession struct {
	Kind string
	ID   string
}

// RefResult is an action_results row together with the session of the
// action it answers.
type RefResult struct {
	Result  ActionResult
	Session RefSession
}

// RefModelTurn is a model_turns row (TASK-05 3.1 reference resolution).
type RefModelTurn struct {
	ConversationID string
	TurnIndex      int64
	ActionID       string
	RawParts       json.RawMessage
	Session        RefSession
}

// RefStore reads, without changing anything, the rows a stored message may
// reference (TASK-05 3.3 "resolve refs"). ErrNotFound when the row does not
// exist.
//
// SPEC-QUESTION: action_results has no session column, so the session of a
// referenced result comes from its action; TASK-05 3.2 lets adapters read
// "action_results of the same session" but the adapter views of TASK-04 show
// only rows of the reading adapter_id, while a model tool_result usually
// references another adapter's action (evidence-reader). The production
// RefStore needs a view for that; until it exists the default is Unwired.
type RefStore interface {
	ActionResult(ctx context.Context, actionID string) (RefResult, error)
	ModelTurn(ctx context.Context, conversationID string, turnIndex int64) (RefModelTurn, error)
}

// ErrRefNotOwned is returned by the RefStore an engine passes to a Resolver
// when the referenced row belongs to another session.
var ErrRefNotOwned = errors.New("execute: referenced row belongs to another session")

// Resolver is optionally implemented by an Adapter whose stored content
// references other rows (model: model_turn and action_result references).
// The engine calls it after loading the inputs and checking their digests,
// and before Prepare. refs returns only rows of the envelope's own session:
// a row of another session yields ErrRefNotOwned, and the execution is then
// preflight_rejected PREFLIGHT_MISMATCH whatever the Resolver returns.
//
// A *Rejection, ErrNotFound or ErrRefNotOwned rejects the preflight. Any
// other error (store unavailable, Unwired) leaves the execution received,
// with nothing reserved.
type Resolver interface {
	ResolveRefs(ctx context.Context, in Inputs, b *Bundle, refs RefStore) (any, *Rejection, error)
}

// InputStore reads the TASK-04 decision, action envelope and action content.
// ErrNotFound when the decision or action does not exist or they do not
// belong together.
//
// SPEC-QUESTION: COMMON gives adapter_reader SELECT on decisions and
// action_contents only, while TASK-05 3.2 also reads the envelope.
// packages/adapters/inputs reads decisions.decisions and the adapter_reader
// views adapter_action_envelopes and adapter_action_contents of the TASK-04
// migration 20261016181826_gateway_decisions; the receiver-sender binary
// always uses it.
type InputStore interface {
	Load(ctx context.Context, decisionID, actionID string) (Inputs, error)
}

// AdapterConstraint is data.adapter_constraints[<adapter_id>] (COMMON appendix A).
type AdapterConstraint struct {
	MaxRequestBytes  int64    `json:"max_request_bytes"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
	AllowedRouteIDs  []string `json:"allowed_route_ids"`
}

// Bundle is one loaded, verified policy bundle snapshot (TASK-05 3.4 bundle
// loading): its desired_bundle identity and the data the adapter reads.
type Bundle struct {
	BundleID              string
	ArtifactDigest        string
	Catalog               canonical.Catalog
	ReceiverAllowedFields []string
	AdapterConstraints    map[string]AdapterConstraint
}

// BundleSource returns the current snapshot. packages/adapters/bundle reads
// it from packages/policyloader (TASK-04); the Unwired default fails.
type BundleSource interface {
	Current(ctx context.Context) (*Bundle, error)
}

// Event is one audit event the adapter produces (COMMON event_type
// registry: preflight_passed, preflight_rejected, dispatch_started,
// response_received, attempt_uncertain, attempt_failed).
//
// EventID is generated once. For an event kept in a recovery record it is
// stored with the record and reused on replay, so TASK-07 deduplicates a
// re-sent event (same event_id, same body).
type Event struct {
	EventID   string
	Type      string
	ActionID  string
	RequestID string
	AttemptID string
	Payload   map[string]any
}

// Auditor appends an event through TASK-07 (POST /internal/audit/events or
// audit_append()). Failure before the reservation stops the execution.
type Auditor interface {
	Emit(ctx context.Context, ev Event) error
}

// Credential is the header an attempt sends: the TASK-06 broker answer, or
// an Authorization bearer token from a token file or token source.
// HeaderValue lives in memory only and is never logged, audited, hashed or
// serialized; only SecretVersion (broker) is recorded.
type Credential struct {
	SecretVersion string
	HeaderName    string
	HeaderValue   string
	ExpiresAt     time.Time
}

const redacted = "[REDACTED]"

// String, GoString, LogValue and MarshalJSON keep HeaderValue out of
// formatted output, logs and JSON.
func (c Credential) String() string { return c.GoString() }
func (c Credential) GoString() string {
	return fmt.Sprintf("execute.Credential{SecretVersion:%q, HeaderName:%q, HeaderValue:%s, ExpiresAt:%s}", c.SecretVersion, c.HeaderName, redacted, c.ExpiresAt.Format(time.RFC3339))
}
func (c Credential) LogValue() slog.Value {
	return slog.GroupValue(slog.String("secret_version", c.SecretVersion), slog.String("header_name", c.HeaderName), slog.Time("expires_at", c.ExpiresAt))
}
func (Credential) MarshalJSON() ([]byte, error) {
	return nil, errors.New("execute: a credential is never serialized")
}

// Credentials resolves a credential_binding for a planned attempt
// (POST /internal/credentials:resolve).
type Credentials interface {
	Resolve(ctx context.Context, attemptID, adapterID, binding string) (Credential, error)
}

// CredentialKind selects how an adapter obtains its credential (TASK-05 3.1
// credential column). catalog credential_binding alone cannot tell a
// projected token file from a WIF token or mTLS only (all are null), so the
// adapter chooses explicitly.
type CredentialKind string

const (
	// CredentialNone: mTLS client certificate only (evidence-reader).
	CredentialNone CredentialKind = "none"
	// CredentialBroker: the TASK-06 broker resolves the operation's
	// credential_binding (receiver-sender).
	CredentialBroker CredentialKind = "broker"
	// CredentialTokenFile: a projected KSA token file, sent as
	// Authorization: Bearer (kubernetes-reader).
	CredentialTokenFile CredentialKind = "token_file"
	// CredentialTokenSource: an access token source, sent as
	// Authorization: Bearer (model; GKE metadata server WIF in production).
	CredentialTokenSource CredentialKind = "token_source"
)

// AccessToken is one token from a TokenSource. Expiry is required.
type AccessToken struct {
	Value  string
	Type   string // "" or "Bearer"
	Expiry time.Time
}

// TokenSource is the small subset of oauth2.TokenSource the engine needs;
// the model adapter wraps golang.org/x/oauth2/google's metadata token source
// in it. The source may retry its own metadata server calls (TASK-05 3.1
// allows that on the credential path).
type TokenSource interface {
	Token(ctx context.Context) (AccessToken, error)
}

// CredentialStrategy is the adapter's explicit credential choice. Kind is
// required. TokenFile is the token file path for token_file; TokenSource is
// the source for token_source (Unwired when nil, fail-closed). broker uses
// Config.Credentials.
type CredentialStrategy struct {
	Kind        CredentialKind
	TokenFile   string
	TokenSource TokenSource
}

// TLSMaterial is the adapter's mTLS client certificate (TASK-03 issuance) and
// the CA pools the catalog ca_ref values name.
type TLSMaterial interface {
	ClientCertificate() (*tls.Certificate, error)
	// RootCAs returns the pool for a catalog ca_ref (system, cluster,
	// agentarium-trust). A nil pool with nil error means the system pool and
	// is accepted only for ca_ref system.
	RootCAs(caRef string) (*x509.CertPool, error)
}

// ErrNotFound and ErrUnwired are the shared sentinel errors.
var (
	ErrNotFound = errors.New("execute: not found")
	ErrUnwired  = errors.New("execute: dependency not wired")
)

// Unwired is the fail-closed default for every external dependency.
type Unwired struct{}

func (Unwired) Load(context.Context, string, string) (Inputs, error) { return Inputs{}, ErrUnwired }
func (Unwired) Current(context.Context) (*Bundle, error)             { return nil, ErrUnwired }
func (Unwired) Emit(context.Context, Event) error                    { return ErrUnwired }
func (Unwired) Resolve(context.Context, string, string, string) (Credential, error) {
	return Credential{}, ErrUnwired
}
func (Unwired) ClientCertificate() (*tls.Certificate, error) { return nil, ErrUnwired }
func (Unwired) RootCAs(string) (*x509.CertPool, error)       { return nil, ErrUnwired }
func (Unwired) Token(context.Context) (AccessToken, error)   { return AccessToken{}, ErrUnwired }
func (Unwired) ActionResult(context.Context, string) (RefResult, error) {
	return RefResult{}, ErrUnwired
}
func (Unwired) ModelTurn(context.Context, string, int64) (RefModelTurn, error) {
	return RefModelTurn{}, ErrUnwired
}

// Prepared is what an adapter's Prepare returns for a passed preflight.
type Prepared struct {
	Plan              canonical.WirePlan
	CredentialBinding string // empty when the operation uses none
	CARef             string
	// ResponseDataClass is the catalog response_data_class with inherit
	// already replaced by the envelope data_class.
	ResponseDataClass string
	RedactFields      []string
	EvidenceLevelMax  string
	// AdapterState is the adapter's own value from Prepare (model: profile,
	// tool declarations, output schema). The engine never reads, logs or
	// stores it; it hands it back unchanged to ContextMapper, ModelTurnWriter
	// and ResultBuilder for the response of the same attempt. It does not
	// survive a restart, which only redoes ②–④ from the recovery record.
	AdapterState any
}

// Rejection is a failed preflight: reason codes and the compared fields
// (preflight_rejected payload).
type Rejection struct {
	ReasonCodes    []string
	ComparedFields []string
	Detail         string
}

// Mapping is an adapter's classification of a received response (TASK-05
// 3.3 per-adapter response mapping).
type Mapping struct {
	ExecutionState string
	ReasonCodes    []string
	EvidenceLevel  string
	// ProviderRequestID is the target's own request ID read from the
	// response (model: responseId, TASK-05 3.3); empty when there is none.
	// The engine copies it into AdapterObservation.provider_request_id before
	// the recovery record and the response_received event are written. A
	// value longer than MaxProviderRequestID bytes or with characters outside
	// printable ASCII is not recorded.
	ProviderRequestID string
	// Truncated and TruncationReason are action_results.truncated and
	// truncation_reason for an adapter without a ResultBuilder (kubernetes-
	// reader: a list response with metadata.continue is truncated=true,
	// truncation_reason "continue", TASK-05 3.1 response size). TruncationReason
	// must be non-empty exactly when Truncated; otherwise the mapping is
	// invalid and the engine stores conservativeResult. A ResultBuilder
	// returns its own values and these are not used.
	Truncated        bool
	TruncationReason string
}

// MaxProviderRequestID bounds Mapping.ProviderRequestID (the coordinator
// keeps 256 bytes of provider_request_id).
const MaxProviderRequestID = 256

// Adapter is the service-specific part: the pure WirePlan mapper and the
// response mapping table. An adapter whose content references stored rows
// also implements Resolver; Prepare then finds the result in in.Resolved.
type Adapter interface {
	ID() string
	Prepare(in Inputs, b *Bundle) (Prepared, *Rejection)
	MapResponse(r transport.Result) Mapping
}

// CredentialChecker is implemented by an adapter whose target accepts a
// credential of one fixed form only (for example the receiver key header).
// The engine calls it after the broker answers and before the permit claim;
// an error is CREDENTIAL_UNAVAILABLE (outcome released, nothing sent). The
// error must not contain the header value.
type CredentialChecker interface {
	CheckCredential(binding string, c Credential) error
}

// ContextMapper is optionally implemented by an Adapter whose response
// mapping depends on the request (model: profile, registered tools and the
// output schema). The engine then calls it instead of MapResponse, with the
// stored inputs and the Prepared value (including AdapterState) of the same
// attempt.
type ContextMapper interface {
	MapResponseWithContext(in Inputs, prep Prepared, r transport.Result) Mapping
}

// ResultBuilder is optionally implemented by an Adapter whose result_body is
// not the redacted response body (model: the cleaned text and functionCall
// names and arguments, never thoughtSignature, plus the {conversation_id,
// turn_index} of the stored model turn). The engine then stores the returned
// body instead of the redacted raw body; the adapter applies prep.RedactFields
// itself where they apply. aux is the result of the adapter's durable write
// (ModelTurnWriter) in the SavePending transaction, nil when there was none.
//
// body must be JSON null or a strict JSON object or array; truncated=false
// requires reason=nil. The engine computes result_digest. An error or an
// invalid return value is a result the adapter could not build: see
// conservativeResult.
type ResultBuilder interface {
	BuildResult(in Inputs, prep Prepared, r transport.Result, m Mapping, aux *AuxWriteResult) (body json.RawMessage, truncated bool, reason *string, err error)
}

// ModelTurnWriter is optionally implemented by the model adapter: the
// model_turns row of a received response (TASK-05 3.1: the raw candidate
// parts, thought signatures included). nil, nil writes no turn for this
// response. An Adapter that implements it must also implement ResultBuilder,
// so the raw body never becomes result_body.
type ModelTurnWriter interface {
	ModelTurn(in Inputs, prep Prepared, r transport.Result, m Mapping) (*ModelTurnWrite, error)
}

// ModelTurnWrite is one model_turns row before its turn_index is allocated.
// RawParts must be a strict JSON array. The engine sets ActionID and
// SessionKey (user session_id or service_session_id, both the envelope
// session_id) from the stored envelope; values the adapter set must agree.
//
// RawParts is kept only in model_turns, never in pending_outcomes, an event
// or a log.
type ModelTurnWrite struct {
	ConversationID string
	SessionKey     string
	ActionID       string
	RawParts       json.RawMessage
	ExpiresAt      time.Time
}

// String, GoString and LogValue keep RawParts (thought signatures) out of
// formatted output and logs.
func (w ModelTurnWrite) String() string { return w.GoString() }
func (w ModelTurnWrite) GoString() string {
	return fmt.Sprintf("execute.ModelTurnWrite{ConversationID:%q, SessionKey:%q, ActionID:%q, RawParts:%s, ExpiresAt:%s}",
		w.ConversationID, w.SessionKey, w.ActionID, redacted, w.ExpiresAt.Format(time.RFC3339))
}
func (w ModelTurnWrite) LogValue() slog.Value {
	return slog.GroupValue(slog.String("conversation_id", w.ConversationID), slog.String("action_id", w.ActionID), slog.Int("raw_parts_bytes", len(w.RawParts)))
}

// ModelTurnKey is the allocated key of a stored model turn.
type ModelTurnKey struct {
	ConversationID string
	TurnIndex      int64
}

// AuxWriteResult is what the adapter-specific write in the SavePending
// transaction produced; it is handed to ResultBuilder.
type AuxWriteResult struct {
	ModelTurn *ModelTurnKey
}

// AuxWriteError is returned by SavePending when the adapter-specific write
// could not be done (conversation owned by another session, invalid row) or
// the result could not be built from it. The whole transaction is rolled
// back. The engine then saves the record again without the write and with
// conservativeResult.
type AuxWriteError struct{ Err error }

func (e *AuxWriteError) Error() string {
	return "execute: adapter write in the recovery transaction: " + e.Err.Error()
}
func (e *AuxWriteError) Unwrap() error { return e.Err }

// ---- TASK-05 storage --------------------------------------------------------

// Execution is an adapter_executions row.
type Execution struct {
	DecisionID string
	ActionID   string
	AdapterID  string
	State      string
	AttemptID  string // empty when null
	UpdatedAt  time.Time
}

// DataStateKey is the workload_data_state key: the workload_id of a user
// session or the service_session_id of a service session (COMMON
// WorkloadDataState).
type DataStateKey struct {
	WorkloadID       string
	ServiceSessionID string
}

// DataStateRaise is step ① of the commit order.
type DataStateRaise struct {
	Key       DataStateKey
	DataClass string
	Source    string // added to data_sources when DataClass ranks above none
	AttemptID string
}

// ActionResult is the COMMON ActionResult row.
type ActionResult struct {
	ActionID         string          `json:"action_id"`
	AttemptID        string          `json:"attempt_id"`
	ExecutionState   string          `json:"execution_state"`
	DataClass        string          `json:"data_class"`
	ResultBody       json.RawMessage `json:"result_body"`
	Truncated        bool            `json:"truncated"`
	TruncationReason *string         `json:"truncation_reason"`
	EvidenceLevel    string          `json:"evidence_level"`
	ResultDigest     string          `json:"result_digest"`
	CreatedAt        time.Time       `json:"created_at"`
}

// PendingOutcome is the durable recovery record of a claimed attempt that
// ended (response, failure before WroteHeaders or unknown). It is written
// before step ② — for a response in the same transaction as step ① — so a
// restart can redo ②, ③ and ④ in order without sending again.
//
// SPEC-QUESTION: COMMON says a restart redoes the commit order for every
// adapter_executions row that is not completed, but no COMMON structure
// keeps the response until ③. adapter.pending_outcomes is TASK-05 internal
// storage for that; it holds the redacted result only, never credentials.
type PendingOutcome struct {
	DecisionID  string
	AttemptID   string
	Transition  string
	ReasonCodes []string
	Observation transport.Observation
	Event       *Event        // the attempt event to emit with the outcome
	Result      *ActionResult // set for response_received
	// ModelTurn, when set, is inserted by SavePending into model_turns in the
	// same transaction as step ① and the recovery record, with the next
	// turn_index of its conversation. Result is then nil and BuildResult
	// makes it inside the transaction from the allocated key; SavePending
	// stores what it returns. A failure of either is an *AuxWriteError and
	// nothing is written. When the decision already has a record nothing is
	// inserted and BuildResult is not called. Neither field is stored in
	// pending_outcomes or read back by Pending, and JSON encoding skips them.
	ModelTurn   *ModelTurnWrite                            `json:"-"`
	BuildResult func(AuxWriteResult) (ActionResult, error) `json:"-"`
}

// Store is the TASK-05 tables (adapter schema).
type Store interface {
	// Begin inserts a received row. When the decision already has a row it
	// returns that row and created=false (no new work).
	Begin(ctx context.Context, decisionID, actionID, adapterID string) (row Execution, created bool, err error)
	// SetState moves a row from one of from to "to". attemptID is stored when
	// non-empty. It returns false if the row was not in a from state.
	SetState(ctx context.Context, decisionID string, from []string, to, attemptID string) (bool, error)
	// Unfinished lists this adapter's received and reserved rows.
	Unfinished(ctx context.Context, adapterID string) ([]Execution, error)
	// SavePending stores the recovery record and, when raise is not nil, runs
	// step ① in the same transaction, together with p.ModelTurn when set. A
	// second call for the same decision keeps the first record and writes no
	// second model turn.
	SavePending(ctx context.Context, p PendingOutcome, raise *DataStateRaise) error
	// Pending returns the recovery record of a decision, ErrNotFound if none.
	Pending(ctx context.Context, decisionID string) (PendingOutcome, error)
	// InsertResult is step ③; a second insert for the same attempt is a no-op.
	InsertResult(ctx context.Context, r ActionResult) error
	// EventID returns the event_id stored on the execution row for a
	// pre-reservation event (preflight_passed, preflight_rejected), storing
	// candidate first if none is stored yet.
	EventID(ctx context.Context, decisionID, eventType, candidate string) (string, error)
}
