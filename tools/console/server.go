package main

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

//go:embed static/index.html static/app.js static/logic.mjs static/style.css
var staticFiles embed.FS

// keyHeader carries the per-process key on every local API request.
const keyHeader = "X-Console-Key"

// maxLocalBody bounds a browser request body.
const maxLocalBody = 64 << 10

// approvalTokenMaxAge is the ID token age the console allows before an
// approval POST. Identity requires iat (or auth_time) within 5 minutes; one
// minute is left for clock skew and the request itself.
const approvalTokenMaxAge = 4 * time.Minute

// csp allows only the embedded page's own script, style and API.
const csp = "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

// checkLoopbackListen requires addr to be an IP literal on a loopback
// interface; an empty host would listen on every interface.
func checkLoopbackListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("-listen %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("-listen %q: must be a loopback IP such as 127.0.0.1", addr)
	}
	return nil
}

// server is the local console: the embedded page and a small JSON API that
// proxies to identity.
type server struct {
	key      string
	port     string // the port actually listened on; Host must use it
	identity *identityClient
	logger   *log.Logger
}

func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("POST /api/sessions", s.createSession)
	mux.HandleFunc("GET /api/pending", s.pending)
	mux.HandleFunc("GET /api/actions/{action_id}/contract", s.contract)
	mux.HandleFunc("POST /api/approvals", s.approve)
	mux.HandleFunc("POST /api/approvals/{approval_id}/revoke", s.revoke)
	return s.guard(mux)
}

// guard rejects requests whose Host is not this loopback listener (DNS
// rebinding), whose Origin is not this page (CSRF), and API requests without
// the per-process key.
func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if !s.hostOK(r.Host) {
			localError(w, http.StatusForbidden, "LOCAL_HOST_REJECTED")
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "http://"+r.Host {
			localError(w, http.StatusForbidden, "LOCAL_ORIGIN_REJECTED")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if r.Method != http.MethodGet && origin == "" {
				localError(w, http.StatusForbidden, "LOCAL_ORIGIN_REJECTED")
				return
			}
			got := r.Header.Get(keyHeader)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.key)) != 1 {
				localError(w, http.StatusForbidden, "LOCAL_KEY_REJECTED")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// hostOK accepts a loopback IP literal or localhost on the listening port.
func (s *server) hostOK(host string) bool {
	name, port, err := net.SplitHostPort(host)
	if err != nil || port != s.port {
		return false
	}
	if name == "localhost" {
		return true
	}
	ip := net.ParseIP(name)
	return ip != nil && ip.IsLoopback()
}

// localError is the identity error shape, so the page reads both alike.
func localError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"reason_codes": []string{code}})
}

// decodeStrict reads one JSON object into v, rejecting unknown fields and
// trailing data, so only the fields identity defines are forwarded.
func decodeStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLocalBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		localError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		localError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return false
	}
	return true
}

// forward sends one identity request and relays its status and JSON body.
// Only the body is relayed; identity response headers are not.
func (s *server) forward(w http.ResponseWriter, r *http.Request, method, path string, query url.Values, body any, tokenMaxAge time.Duration) {
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			localError(w, http.StatusInternalServerError, "LOCAL_ENCODE_FAILED")
			return
		}
	}
	status, ctype, out, err := s.identity.do(r.Context(), method, path, query, raw, tokenMaxAge)
	if err != nil {
		s.logger.Printf("%s %s: %v", method, path, err)
		if errors.Is(err, errToken) {
			localError(w, http.StatusServiceUnavailable, "TOKEN_UNAVAILABLE")
			return
		}
		localError(w, http.StatusBadGateway, "IDENTITY_UNREACHABLE")
		return
	}
	if !strings.HasPrefix(ctype, "application/json") || !json.Valid(out) {
		s.logger.Printf("%s %s: identity answered %d with a non-JSON body", method, path, status)
		localError(w, http.StatusBadGateway, "IDENTITY_BAD_RESPONSE")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.Copy(w, bytes.NewReader(out))
}

// createRequest is the COMMON POST /v1/sessions body.
type createRequest struct {
	WorkloadID     string `json:"workload_id"`
	TaskStatement  string `json:"task_statement"`
	RequestedScope struct {
		OperationIDs []string `json:"operation_ids"`
		TargetIDs    []string `json:"target_ids"`
	} `json:"requested_scope"`
}

func (s *server) createSession(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	s.forward(w, r, http.MethodPost, "/v1/sessions", nil, req, 0)
}

func (s *server) pending(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.URL.Query().Get("session_id"))
	if err != nil {
		localError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return
	}
	s.forward(w, r, http.MethodGet, "/v1/approvals/pending", url.Values{"session_id": {id.String()}}, nil, 0)
}

func (s *server) contract(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "action_id")
	if !ok {
		return
	}
	s.forward(w, r, http.MethodGet, "/v1/actions/"+id+"/approval-contract", nil, nil, 0)
}

// approveRequest is the COMMON POST /v1/approvals body. The page copies
// displayed_contract_digest and nonce verbatim from the contract response it
// displayed; identity re-renders the contract and compares. max_actions is
// deliberately absent: identity sets it to 1 itself (TASK-03 3.1) and accepts
// the field only for older clients, so a page sending it is rejected here.
type approveRequest struct {
	ActionID                string   `json:"action_id"`
	DisplayedContractDigest string   `json:"displayed_contract_digest"`
	Nonce                   string   `json:"nonce"`
	AcknowledgedFindings    []string `json:"acknowledged_findings"`
}

func (s *server) approve(w http.ResponseWriter, r *http.Request) {
	var req approveRequest
	if !decodeStrict(w, r, &req) {
		return
	}
	action, err := uuid.Parse(req.ActionID)
	if err != nil || req.DisplayedContractDigest == "" || req.Nonce == "" {
		localError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return
	}
	req.ActionID = action.String()
	if req.AcknowledgedFindings == nil {
		req.AcknowledgedFindings = []string{}
	}
	s.forward(w, r, http.MethodPost, "/v1/approvals", nil, req, approvalTokenMaxAge)
}

func (s *server) revoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "approval_id")
	if !ok {
		return
	}
	s.forward(w, r, http.MethodPost, "/v1/approvals/"+id+"/revoke", nil, nil, 0)
}

// pathUUID returns the canonical form of a UUID path value, so nothing else
// reaches the identity path.
func pathUUID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		localError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return "", false
	}
	return id.String(), true
}
