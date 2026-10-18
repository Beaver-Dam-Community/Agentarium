package sessions

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
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/jackc/pgx/v5/pgconn"
)

// MaxBodyBytes bounds request bodies (task_statement is at most 4000 chars).
const MaxBodyBytes = 64 << 10

// PeerIdentityHeader is set by the gateway on relayed runtime requests
// (COMMON header table). It is trusted only on a connection whose verified client
// certificate is the gateway's.
const PeerIdentityHeader = "X-Agentarium-Peer-Identity"

// ConsoleAuth authenticates a console request (the BFF session, PR D).
type ConsoleAuth interface {
	Authenticate(r *http.Request) (Actor, error)
}

// Handler routes the session APIs.
type Handler struct {
	Svc *Service
	// Console authenticates console callers. If nil, every console route
	// answers 401: there is no unauthenticated fallback.
	Console ConsoleAuth
	// GatewaySAN is the gateway's service SAN. Only a connection presenting
	// it may supply PeerIdentityHeader.
	GatewaySAN string
}

// Register adds the routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/sessions", h.create)
	mux.HandleFunc("POST /v1/sessions/{action}", h.sessionAction) // {id}:claim | :refresh | :revoke
	mux.HandleFunc("GET /v1/runtime/assignments", h.assignments)
	mux.HandleFunc("POST /internal/service-sessions", h.service)
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.console(w, r)
	if !ok {
		return
	}
	var req CreateRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := h.Svc.Create(r.Context(), actor, req)
	reply(w, out, err)
}

func (h *Handler) sessionAction(w http.ResponseWriter, r *http.Request) {
	id, verb, ok := strings.Cut(r.PathValue("action"), ":")
	if !ok || id == "" {
		writeError(w, http.StatusNotFound, nil)
		return
	}
	switch verb {
	case "claim":
		p, ok := h.runtime(w, r)
		if !ok {
			return
		}
		var req struct {
			ClaimCode string `json:"claim_code"`
		}
		if !decode(w, r, &req) {
			return
		}
		out, err := h.Svc.Claim(r.Context(), p, id, req.ClaimCode)
		reply(w, out, err)
	case "refresh":
		p, ok := h.runtime(w, r)
		if !ok {
			return
		}
		tok, ok := bearer(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
			return
		}
		out, err := h.Svc.Refresh(r.Context(), p, id, tok)
		reply(w, out, err)
	case "revoke":
		actor, ok := h.console(w, r)
		if !ok {
			return
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if !decode(w, r, &req) {
			return
		}
		out, err := h.Svc.Revoke(r.Context(), actor, id, req.Reason)
		reply(w, out, err)
	default:
		writeError(w, http.StatusNotFound, nil)
	}
}

func (h *Handler) assignments(w http.ResponseWriter, r *http.Request) {
	p, ok := h.runtime(w, r)
	if !ok {
		return
	}
	out, err := h.Svc.Assignments(r.Context(), p)
	reply(w, map[string]any{"assignments": out}, err)
}

func (h *Handler) service(w http.ResponseWriter, r *http.Request) {
	// Service callers connect directly with their own certificate; the
	// gateway does not relay this route.
	p, err := directPeer(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return
	}
	var req ServiceRequest
	if !decode(w, r, &req) {
		return
	}
	out, err := h.Svc.CreateService(r.Context(), p, req)
	reply(w, out, err)
}

// ---- principals -------------------------------------------------------------

func (h *Handler) console(w http.ResponseWriter, r *http.Request) (Actor, bool) {
	if h.Console == nil {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return Actor{}, false
	}
	a, err := h.Console.Authenticate(r)
	if err != nil || a.AuthenticatedActor == "" {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return Actor{}, false
	}
	return a, true
}

// runtime returns the workload principal: the SAN the gateway forwarded when
// the connection is the gateway's, otherwise the caller's own certificate.
// A forwarded header on any other connection is ignored.
func (h *Handler) runtime(w http.ResponseWriter, r *http.Request) (RuntimePrincipal, bool) {
	p, err := directPeer(r)
	if err == nil && h.GatewaySAN != "" && p.SAN == h.GatewaySAN {
		p, err = ParseSAN(r.Header.Get(PeerIdentityHeader))
	}
	if err != nil {
		writeError(w, http.StatusUnauthorized, []string{"AUTH_REQUIRED"})
		return RuntimePrincipal{}, false
	}
	return p, true
}

// directPeer returns the principal of the verified client certificate.
func directPeer(r *http.Request) (RuntimePrincipal, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return RuntimePrincipal{}, errors.New("no verified client certificate")
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return RuntimePrincipal{}, errors.New("client certificate needs exactly one URI SAN")
	}
	return ParseSAN(leaf.URIs[0].String())
}

// ParseSAN reads spiffe://agentarium.internal/ns/<ns>/sa/<ksa>[/pod/<uid>].
func ParseSAN(san string) (RuntimePrincipal, error) {
	const prefix = "spiffe://agentarium.internal/ns/"
	rest, ok := strings.CutPrefix(san, prefix)
	if !ok {
		return RuntimePrincipal{}, fmt.Errorf("SAN %q is not a workload SAN", san)
	}
	parts := strings.Split(rest, "/")
	if !(len(parts) == 3 || len(parts) == 5) || parts[1] != "sa" || parts[0] == "" || parts[2] == "" ||
		(len(parts) == 5 && (parts[3] != "pod" || parts[4] == "")) {
		return RuntimePrincipal{}, fmt.Errorf("SAN %q is malformed", san)
	}
	return RuntimePrincipal{SAN: san, Namespace: parts[0], KSA: parts[2]}, nil
}

func bearer(r *http.Request) (string, bool) {
	t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return t, ok && t != ""
}

// ---- JSON -------------------------------------------------------------------

// decode reads a strict JSON body (COMMON Go strict JSON): the canonical
// pre-check, then exact-case keys from v's json tags, then a decoder that
// rejects unknown fields.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, []string{"SCHEMA_INVALID"})
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil || len(body) > MaxBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, []string{"SCHEMA_INVALID"})
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
	if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "2")
	}
	if codes == nil {
		codes = []string{}
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{RequestID: hex.EncodeToString(b), ReasonCodes: codes})
}

// reply writes out or maps err: *Error to its status and code, the unwired
// auditor and anything else to 503 without detail. Database errors use the
// existing STATE_STORE_UNAVAILABLE code without exposing SQL diagnostics.
func reply(w http.ResponseWriter, out any, err error) {
	var se *Error
	var dbErr *pgconn.PgError
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	case errors.As(err, &se):
		writeError(w, se.Status, []string{se.Code})
	case errors.As(err, &dbErr):
		writeError(w, http.StatusServiceUnavailable, []string{"STATE_STORE_UNAVAILABLE"})
	default:
		writeError(w, http.StatusServiceUnavailable, nil)
	}
}

// Decode, Reply and WriteError let other identity packages share the strict
// JSON body rules and the error format.
func Decode(w http.ResponseWriter, r *http.Request, v any) bool    { return decode(w, r, v) }
func Reply(w http.ResponseWriter, out any, err error)              { reply(w, out, err) }
func WriteError(w http.ResponseWriter, status int, codes []string) { writeError(w, status, codes) }

// ConsoleActor authenticates a console request with h.Console, writing 401
// when there is no authenticator or the request is not authenticated.
func ConsoleActor(auth ConsoleAuth, w http.ResponseWriter, r *http.Request) (Actor, bool) {
	return (&Handler{Console: auth}).console(w, r)
}
