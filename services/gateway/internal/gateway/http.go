package gateway

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// MaxReevaluateBody bounds the :reevaluate body.
const MaxReevaluateBody = 4 << 10

// Handler routes the typed action API (TASK-04 chapter 4). Callers connect with
// their own workload certificate (mTLS) and a session or service-session
// token in Authorization: Bearer.
// The runtime relays are in relay.go.
// SPEC-QUESTION / not in this PR: console callers (Google ID token or the
// identity BFF), POST /v1/runtime/work-events and rate limits.
type Handler struct {
	Svc *Service
	// peer returns the verified client certificate. Tests replace it; the
	// default reads the TLS connection state.
	peer func(*http.Request) *x509.Certificate
}

// Register adds the routes to mux. /v1/actions/{action_id}:reevaluate has
// ':' inside one path segment, so POST /v1/actions/{tail} splits the suffix
// itself (TASK-04 chapter 2).
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/actions", h.submit)
	mux.HandleFunc("POST /v1/actions/{tail}", h.reevaluate)
	mux.HandleFunc("GET /v1/actions/{action_id}", h.get)
	mux.HandleFunc("GET /v1/actions/{action_id}/result", h.result)
}

func (h *Handler) caller(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	leaf := h.peerCert(r)
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if leaf == nil || !ok || tok == "" {
		writeError(w, &Error{Status: http.StatusUnauthorized, Code: "AUTH_REQUIRED"})
		return Caller{}, false
	}
	c, err := h.Svc.Authenticate(r.Context(), leaf, tok)
	if err != nil {
		h.fail(w, err)
		return Caller{}, false
	}
	return c, true
}

func (h *Handler) peerCert(r *http.Request) *x509.Certificate {
	if h.peer != nil {
		return h.peer(r)
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

func readinessRef(r *http.Request) ReadinessRef {
	return ReadinessRef{WorkRunID: r.Header.Get(WorkRunHeader), CheckID: r.Header.Get(ReadinessCheckHeader)}
}

func (h *Handler) submit(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if !jsonType(r) {
		writeError(w, &Error{Status: http.StatusUnsupportedMediaType, Code: "SCHEMA_INVALID"})
		return
	}
	// Read one byte past the limit so DecodeClientAction sees the oversize
	// body and answers 413 BODY_TOO_LARGE.
	raw, err := io.ReadAll(io.LimitReader(r.Body, canonical.MaxBodyBytes+1))
	if err != nil {
		writeError(w, &Error{Status: http.StatusUnprocessableEntity, Code: "SCHEMA_INVALID"})
		return
	}
	out, status, err := h.Svc.Submit(r.Context(), c, raw, readinessRef(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, status, out)
}

func (h *Handler) reevaluate(w http.ResponseWriter, r *http.Request) {
	id, verb, ok := strings.Cut(r.PathValue("tail"), ":")
	if !ok || verb != "reevaluate" || id == "" {
		writeError(w, notFound)
		return
	}
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if !jsonType(r) {
		writeError(w, &Error{Status: http.StatusUnsupportedMediaType, Code: "SCHEMA_INVALID"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxReevaluateBody+1))
	if err != nil || len(body) > MaxReevaluateBody {
		writeError(w, &Error{Status: http.StatusRequestEntityTooLarge, Code: "BODY_TOO_LARGE"})
		return
	}
	var req ReevaluateRequest
	if err := strictInto(body, &req); err != nil {
		writeError(w, &Error{Status: http.StatusUnprocessableEntity, Code: "SCHEMA_INVALID"})
		return
	}
	out, status, err := h.Svc.Reevaluate(r.Context(), c, id, req, readinessRef(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, status, out)
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	out, err := h.Svc.GetAction(r.Context(), c, r.PathValue("action_id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) result(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	out, status, err := h.Svc.GetResult(r.Context(), c, r.PathValue("action_id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, status, out)
}

func jsonType(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// strictInto reads a strict JSON body (COMMON Go strict JSON): the canonical
// pre-check, exact-case keys from v's json tags, and no unknown fields.
func strictInto(body []byte, v any) error {
	if err := canonical.CheckStrictJSON(body); err != nil {
		return err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(body, &keys); err != nil {
		return err
	}
	allowed := map[string]bool{}
	t := reflect.TypeOf(v).Elem()
	for i := 0; i < t.NumField(); i++ {
		if tag, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); tag != "" {
			allowed[tag] = true
		}
	}
	for k := range keys {
		if !allowed[k] {
			return fmt.Errorf("unknown field %q", k)
		}
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// errorBody is the COMMON error body: request_id, reason_codes and, when
// known, action_id and decision_id.
type errorBody struct {
	RequestID   string   `json:"request_id"`
	ActionID    string   `json:"action_id,omitempty"`
	DecisionID  string   `json:"decision_id,omitempty"`
	ReasonCodes []string `json:"reason_codes"`
}

// fail logs errors that carry no reason code, then answers. Anything that is
// not an *Error is 503 STATE_STORE_UNAVAILABLE without detail.
func (h *Handler) fail(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		h.Svc.log().Error("gateway request failed", "err", err)
		e = &Error{Status: http.StatusServiceUnavailable, Code: "STATE_STORE_UNAVAILABLE"}
	} else if e.Status >= 500 {
		h.Svc.log().Warn("gateway request unavailable", "code", e.Code, "msg", e.Msg)
	}
	writeError(w, e)
}

// writeError writes the error body. 503 and 429 carry Retry-After: 2
// (COMMON error defaults).
func writeError(w http.ResponseWriter, e *Error) {
	writeJSON(w, e.Status, errorBody{RequestID: uuid.NewString(), ActionID: e.ActionID, DecisionID: e.DecisionID, ReasonCodes: []string{e.Code}})
}

// writeJSON writes v. 503 and 429, including a 503 deny, carry
// Retry-After: 2 (COMMON error defaults).
func writeJSON(w http.ResponseWriter, status int, v any) {
	if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "2")
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
