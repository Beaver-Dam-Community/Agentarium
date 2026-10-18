package receiver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Caller identities (COMMON service PKI: spiffe://agentarium.internal/ns/<namespace>/sa/<ksa>).
const (
	// SubmitterSAN is the receiver-sender adapter, the only caller of POST /test/v1/submissions.
	SubmitterSAN = "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
	// ReceiptReaderSAN is the TASK-08 evidence collector, the only caller of GET /test/v1/receipts/{action_id}.
	ReceiptReaderSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector"
)

// Header names (TASK-05 WirePlan safe_headers).
const (
	HeaderIdempotencyKey = "Idempotency-Key"
	HeaderAttemptID      = "X-Agentarium-Attempt-Id"
)

// Config is the deployment's fixed receiver configuration.
type Config struct {
	Mode Mode
	// TargetID is the catalog target_id this deployment serves (receipt target_identity).
	TargetID string
	// RouteID is the catalog route_id of receiver.submit (receipt route).
	RouteID string
	// TargetVersion is reported as the receipt target_version.
	TargetVersion string
}

// Handler serves the two TASK-08 receiver APIs.
type Handler struct {
	Store Store
	Cfg   Config
	Log   *slog.Logger
	// Keys is the active receiver API key set (--api-key-dir). Nil rejects
	// every submission with 401 RECEIVER_KEY_INVALID.
	Keys *KeySet
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /test/v1/submissions", h.submit)
	mux.HandleFunc("GET /test/v1/receipts/{action_id}", h.receipt)
}

// submissionResponse is the 201/200 body (TASK-08 3.1 submission response).
// duplicate is only present, and true, on 200.
type submissionResponse struct {
	ReceiptAttemptID string  `json:"receipt_attempt_id"`
	EffectID         string  `json:"effect_id"`
	ActionKey        *string `json:"action_key"`
	WireBodyDigest   string  `json:"wire_body_digest"`
	BodyBytes        int     `json:"body_bytes"`
	Duplicate        bool    `json:"duplicate,omitempty"`
}

// errorResponse is the COMMON error body. receipt_attempt_id is added for the
// 409 and 422 rows of TASK-08 3.1 that record an attempt.
//
// SPEC-QUESTION: COMMON "error, status and health defaults" lets an error body carry only
// request_id, reason_codes, action_id and decision_id, while TASK-08 3.1 adds
// receipt_attempt_id to the 409 and 422 bodies. The receiver follows TASK-08.
type errorResponse struct {
	RequestID        string   `json:"request_id"`
	ReasonCodes      []string `json:"reason_codes"`
	ReceiptAttemptID *string  `json:"receipt_attempt_id,omitempty"`
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	principal, ok := h.authorize(w, r, SubmitterSAN)
	if !ok {
		return
	}
	// The receiver key is checked after the SAN and before the body is read
	// or anything is written, so a rejected request leaves no attempt row.
	// A handler without a key set rejects every submission.
	version, ok := h.Keys.Match(r.Header)
	if !ok {
		writeError(w, http.StatusUnauthorized, ReasonReceiverKeyInvalid, nil)
		return
	}
	if h.Log != nil {
		h.Log.DebugContext(r.Context(), "receiver api key accepted", "key_version", version)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, ReasonSchemaInvalid, nil)
		return
	}
	if len(body) > MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, ReasonBodyTooLarge, nil)
		return
	}
	key, okKey := headerUUID(r.Header, HeaderIdempotencyKey)
	attempt, okAttempt := headerUUID(r.Header, HeaderAttemptID)
	if !okKey || !okAttempt {
		// A malformed or repeated header is a schema violation; there is no
		// action_key column value to record it under.
		writeError(w, http.StatusUnprocessableEntity, ReasonSchemaInvalid, nil)
		return
	}
	sub := Submission{
		Mode:            h.Cfg.Mode,
		ActionKey:       key,
		ClientAttemptID: attempt,
		ClientPrincipal: principal,
		WireBodyDigest:  canonical.WireBodyDigest(body),
		BodyBytes:       len(body),
	}

	// SPEC-QUESTION: TASK-08 3.1 does not order "missing key" and "body schema
	// violation". A keyless submission in idempotent mode is recorded as
	// key_missing_rejected before the body is looked at.
	if h.Cfg.Mode == ModeIdempotent && key == nil {
		id, err := h.Store.RecordKeyMissing(r.Context(), sub)
		if err != nil {
			h.storeFailed(w, r.Context(), err)
			return
		}
		writeError(w, http.StatusUnprocessableEntity, ReasonSchemaInvalid, &id)
		return
	}

	// SPEC-QUESTION: TASK-08 3.1 answers a body schema violation with
	// {reason_codes, receipt_attempt_id}, but receiver_attempts.outcome has no
	// value for it. Such a submission is rejected without an attempt row and
	// without receipt_attempt_id until the outcome set is decided.
	if err := validatePayload(body); err != nil {
		writeError(w, http.StatusUnprocessableEntity, ReasonSchemaInvalid, nil)
		return
	}
	if d, err := canonical.CanonicalDigestJSON(body); err == nil {
		sub.ContentDigestServer = &d
	}

	res, err := h.Store.Submit(r.Context(), sub)
	if err != nil {
		h.storeFailed(w, r.Context(), err)
		return
	}
	switch res.Outcome {
	case OutcomeEffectCreated:
		writeJSON(w, http.StatusCreated, toSubmissionResponse(res, false))
	case OutcomeDuplicateReturned:
		writeJSON(w, http.StatusOK, toSubmissionResponse(res, true))
	case OutcomeKeyBodyConflict:
		id := res.ReceiptAttemptID
		writeError(w, http.StatusConflict, ReasonTargetKeyBodyConflict, &id)
	default:
		h.storeFailed(w, r.Context(), errors.New("store returned outcome "+res.Outcome))
	}
}

func toSubmissionResponse(res SubmitResult, duplicate bool) submissionResponse {
	return submissionResponse{
		ReceiptAttemptID: res.ReceiptAttemptID,
		EffectID:         res.EffectID,
		ActionKey:        res.ActionKey,
		WireBodyDigest:   res.WireBodyDigest,
		BodyBytes:        res.BodyBytes,
		Duplicate:        duplicate,
	}
}

// Receipt is the GET /test/v1/receipts/{action_id} body (TASK-08 4). It never
// carries body content. Optional fields are null, not omitted, so the
// collector's JCS receipt_digest has one form.
type Receipt struct {
	ActionKey        string               `json:"action_key"`
	TargetIdentity   string               `json:"target_identity"`
	Route            string               `json:"route"`
	ReceiverMode     Mode                 `json:"receiver_mode"`
	Effects          []receiptEffectJSON  `json:"effects"`
	EffectCount      int                  `json:"effect_count"`
	ReceiverAttempts []receiptAttemptJSON `json:"receiver_attempts"`
	TargetVersion    string               `json:"target_version"`
}

type receiptEffectJSON struct {
	EffectID            string  `json:"effect_id"`
	WireBodyDigest      string  `json:"wire_body_digest"`
	ContentDigestServer *string `json:"content_digest_server"`
	BodyBytes           int     `json:"body_bytes"`
	CommittedAt         string  `json:"committed_at"`
}

type receiptAttemptJSON struct {
	ReceiptAttemptID string  `json:"receipt_attempt_id"`
	ClientAttemptID  *string `json:"client_attempt_id"`
	ReceivedAt       string  `json:"received_at"`
	WireBodyDigest   string  `json:"wire_body_digest"`
	Outcome          string  `json:"outcome"`
}

func (h *Handler) receipt(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authorize(w, r, ReceiptReaderSAN); !ok {
		return
	}
	key, ok := canonicalUUID(r.PathValue("action_id"))
	if !ok {
		writeError(w, http.StatusNotFound, ReasonResourceNotFound, nil)
		return
	}
	recs, err := h.Store.Receipt(r.Context(), key)
	if err != nil {
		h.storeFailed(w, r.Context(), err)
		return
	}
	// An action_key with no rows is answered with empty lists, not 404: the
	// collector's fixed probe key must succeed, and "zero received attempts" is the
	// R5 input either way.
	out := Receipt{
		ActionKey:        key,
		TargetIdentity:   h.Cfg.TargetID,
		Route:            h.Cfg.RouteID,
		ReceiverMode:     h.Cfg.Mode,
		Effects:          make([]receiptEffectJSON, 0, len(recs.Effects)),
		EffectCount:      len(recs.Effects),
		ReceiverAttempts: make([]receiptAttemptJSON, 0, len(recs.Attempts)),
		TargetVersion:    h.Cfg.TargetVersion,
	}
	for _, e := range recs.Effects {
		out.Effects = append(out.Effects, receiptEffectJSON{
			EffectID:            e.EffectID,
			WireBodyDigest:      e.WireBodyDigest,
			ContentDigestServer: e.ContentDigestServer,
			BodyBytes:           e.BodyBytes,
			CommittedAt:         formatTime(e.CommittedAt),
		})
	}
	for _, a := range recs.Attempts {
		out.ReceiverAttempts = append(out.ReceiverAttempts, receiptAttemptJSON{
			ReceiptAttemptID: a.ReceiptAttemptID,
			ClientAttemptID:  a.ClientAttemptID,
			ReceivedAt:       formatTime(a.ReceivedAt),
			WireBodyDigest:   a.WireBodyDigest,
			Outcome:          a.Outcome,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func formatTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// authorize admits only a verified client certificate whose single URI SAN
// is want.
//
// SPEC-QUESTION: an authenticated caller other than the allowed one gets
// 401 AUTH_REQUIRED, as the TASK-03 coordinator does. COMMON maps
// permission failures to 403 but its reason code table has no 403 code for
// "caller not allowed for this API".
//
// SPEC-QUESTION: the receiver has no grant on identity.issued_certificates,
// so it checks the chain against the trust bundle and the SAN but cannot see
// a revocation recorded by TASK-03.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, want string) (string, bool) {
	san, ok := peerSAN(r)
	if !ok || san != want {
		writeError(w, http.StatusUnauthorized, ReasonAuthRequired, nil)
		return "", false
	}
	return san, true
}

func peerSAN(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if leaf == nil || len(leaf.URIs) != 1 {
		return "", false
	}
	return leaf.URIs[0].String(), true
}

// headerUUID returns nil when the header is absent and false when it is
// repeated or not a UUID in the 8-4-4-4-12 form. The value is returned in
// lower case.
func headerUUID(h http.Header, name string) (*string, bool) {
	vals := h.Values(name)
	switch len(vals) {
	case 0:
		return nil, true
	case 1:
		s, ok := canonicalUUID(vals[0])
		if !ok {
			return nil, false
		}
		return &s, true
	default:
		return nil, false
	}
}

func canonicalUUID(s string) (string, bool) {
	if len(s) != 36 {
		return "", false
	}
	u, err := uuid.Parse(s)
	if err != nil {
		return "", false
	}
	out := u.String()
	if out != strings.ToLower(s) {
		return "", false
	}
	return out, true
}

func (h *Handler) storeFailed(w http.ResponseWriter, ctx context.Context, err error) {
	if h.Log != nil {
		h.Log.ErrorContext(ctx, "receiver store failed", "err", err)
	}
	w.Header().Set("Retry-After", "2")
	writeError(w, http.StatusServiceUnavailable, ReasonStateStoreUnavailable, nil)
}

func writeError(w http.ResponseWriter, status int, code string, receiptAttemptID *string) {
	writeJSON(w, status, errorResponse{
		RequestID:        uuid.NewString(),
		ReasonCodes:      []string{code},
		ReceiptAttemptID: receiptAttemptID,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
