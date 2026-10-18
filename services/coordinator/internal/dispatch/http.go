package dispatch

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Handler routes the dispatch APIs. Adapters and the TASK-14 releaser
// connect with their own certificate; nothing is relayed.
type Handler struct {
	Svc *Service
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/dispatch/reservations", h.reserve)
	mux.HandleFunc("POST /internal/dispatch/permits/{permit_id}/check", h.check)
	mux.HandleFunc("POST /internal/dispatch/attempts/{attempt_id}/outcome", h.outcome)
	mux.HandleFunc("POST /internal/dispatch/activation-probes", h.probe)
}

func (h *Handler) reserve(w http.ResponseWriter, r *http.Request) {
	a, ok := h.adapter(w, r)
	if !ok {
		return
	}
	var req ReserveRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := h.Svc.Reserve(r.Context(), a, req)
	h.reply(w, http.StatusCreated, out, err)
}

func (h *Handler) check(w http.ResponseWriter, r *http.Request) {
	a, ok := h.adapter(w, r)
	if !ok {
		return
	}
	var req CheckRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := h.Svc.Check(r.Context(), a, r.PathValue("permit_id"), req)
	h.reply(w, http.StatusOK, out, err)
}

// OutcomeRequest is the POST /internal/dispatch/attempts/{attempt_id}/outcome
// body: transition, AdapterObservation and reason_codes (COMMON API implementation contract).
type OutcomeRequest struct {
	Transition  string          `json:"transition"`
	Observation json.RawMessage `json:"observation"`
	ReasonCodes []string        `json:"reason_codes"`
}

func (h *Handler) outcome(w http.ResponseWriter, r *http.Request) {
	a, ok := h.adapter(w, r)
	if !ok {
		return
	}
	var req OutcomeRequest
	if !decode(w, r, &req) {
		return
	}
	id := r.PathValue("attempt_id")
	switch req.Transition {
	case "released":
		// A release happens before any socket exists, so it carries no
		// observation.
		if !isUUID(id) || !validReleaseReasons(req.ReasonCodes) || !(len(req.Observation) == 0 || string(req.Observation) == "null") {
			writeError(w, http.StatusUnprocessableEntity, []string{"SCHEMA_INVALID"})
			return
		}
		out, err := h.Svc.release(r.Context(), id, ByAdapter, req.ReasonCodes, &a)
		h.reply(w, http.StatusOK, out, err)
	case "dispatched", "response_received", "failed", "unknown":
		var o Observation
		if len(req.Observation) == 0 || string(req.Observation) == "null" || strictInto(req.Observation, &o) != nil {
			writeError(w, http.StatusUnprocessableEntity, []string{"SCHEMA_INVALID"})
			return
		}
		out, err := h.Svc.Outcome(r.Context(), a, id, req.Transition, o, req.ReasonCodes)
		h.reply(w, http.StatusOK, out, err)
	default:
		writeError(w, http.StatusUnprocessableEntity, []string{"SCHEMA_INVALID"})
	}
}

// probe registers an activation probe for the TASK-14 releaser: its
// service certificate plus the activation_probe service-session token
// (Authorization: Bearer). 201 for a new registration, 200 for a replay.
func (h *Handler) probe(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return
	}
	c, err := h.Svc.AuthenticateService(r.Context(), r.TLS.VerifiedChains[0][0], token)
	if err != nil {
		h.reply(w, 0, nil, err)
		return
	}
	var req ProbeRequest
	if !decode(w, r, &req) {
		return
	}
	out, created, err := h.Svc.RegisterProbe(r.Context(), c, req)
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	h.reply(w, status, out, err)
}

func (h *Handler) adapter(w http.ResponseWriter, r *http.Request) (Adapter, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return Adapter{}, false
	}
	a, err := h.Svc.Authenticate(r.Context(), r.TLS.VerifiedChains[0][0])
	if err != nil {
		h.reply(w, 0, nil, err)
		return Adapter{}, false
	}
	return a, true
}

// ---- JSON -------------------------------------------------------------------

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isDigest(s string) bool { return digestRE.MatchString(s) }

// isUUID accepts the canonical lower-case form only, so the same ID always
// has one spelling.
func isUUID(s string) bool {
	u, err := uuid.Parse(s)
	return err == nil && u.String() == s
}

// decode reads a strict JSON body (COMMON Go strict JSON): the canonical
// pre-check, exact-case keys from v's json tags, and no unknown fields.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, []string{"SCHEMA_INVALID"})
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, []string{"BODY_TOO_LARGE"})
		return false
	}
	if err := strictInto(body, v); err != nil {
		writeError(w, http.StatusUnprocessableEntity, []string{"SCHEMA_INVALID"})
		return false
	}
	return true
}

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

type errorBody struct {
	RequestID   string   `json:"request_id"`
	ReasonCodes []string `json:"reason_codes"`
}

func writeError(w http.ResponseWriter, status int, codes []string) {
	if codes == nil {
		codes = []string{}
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{RequestID: hex.EncodeToString(b), ReasonCodes: codes})
}

// reply logs errors that carry no reason code before answering.
func (h *Handler) reply(w http.ResponseWriter, status int, out any, err error) {
	var e *Error
	if err != nil && !errors.As(err, &e) {
		h.Svc.log().Error("dispatch request failed", "err", err)
	}
	reply(w, status, out, err)
}

// reply writes out with status, or maps err: *Error to its status and code,
// anything else to 503 STATE_STORE_UNAVAILABLE without detail. 503 carries
// Retry-After (COMMON error defaults).
func reply(w http.ResponseWriter, status int, out any, err error) {
	var e *Error
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(out)
	case errors.As(err, &e):
		if e.Status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "2")
		}
		writeError(w, e.Status, []string{e.Code})
	default:
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, []string{"STATE_STORE_UNAVAILABLE"})
	}
}
