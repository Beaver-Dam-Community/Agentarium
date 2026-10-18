package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// Runtime relays (TASK-04 chapter 4 relay row, TASK-03 3.3, TASK-06 call allow table,
// COMMON internal API table and header X-Agentarium-Peer-Identity). The execution
// Pods' only egress is gateway 8443, so the gateway takes these public paths
// and forwards them over its own management mTLS:
//
//	POST /internal/workload-certificates        → identity (no client certificate)
//	GET  /v1/runtime/assignments                → identity
//	POST /v1/sessions/{session_id}:claim        → identity
//	POST /v1/sessions/{session_id}:refresh      → identity (bearer token forwarded)
//	POST /v1/runtime/session-workers            → control-health /internal/control-health/session-workers
//	GET  /v1/runtime/session-workers/{id}       → control-health .../session-workers/{id}
//	POST /v1/runtime/session-workers/{id}:close → control-health .../session-workers/{id}:close
//	POST /v1/runtime/work-readiness/checks      → control-health /internal/control-health/work-readiness/checks
//	GET  /v1/runtime/work-readiness/checks/{id} → control-health .../work-readiness/checks/{id}
//	POST /v1/runtime/probe-reports              → control-health /internal/control-health/probe-results
//	POST /v1/runtime/work-events                → audit-writer /internal/audit/work-events (workevents.go)
//
// No client header is forwarded except Content-Type and, on :refresh only,
// Authorization. The client's X-Agentarium-Peer-Identity is never copied; on
// every mTLS path the gateway sets it to the SAN of the verified, issued and
// unrevoked client certificate. The bootstrap path carries no identity
// header at all: identity derives the SAN from the token review alone.
// Relays do not read holds (TASK-04: readiness and recovery relays stay
// available during a hold and execute no action).

// AuditWriterSAN is the TASK-07 audit-writer service identity.
const AuditWriterSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"

// Relay limits. Request bodies follow the upstream limits (identity
// MaxBodyBytes 64 KiB, control-health canonical.MaxBodyBytes).
// SPEC-QUESTION: the specs give no relay timeout or response limit.
const (
	RelayTimeout          = 10 * time.Second
	maxIdentityRelayBody  = 64 << 10
	maxHealthRelayBody    = canonical.MaxBodyBytes
	maxRelayResponseBytes = 1 << 20
)

// ExecNamespace is the execution-area Namespace (COMMON Namespace table).
const ExecNamespace = "agent-exec"

// ProbeRunnerKSA is the TASK-10 probe runner KSA in agent-exec (TASK-06 KSA
// table, COMMON probe-reports row).
const ProbeRunnerKSA = "probe-runner"

// Relay serves the runtime relays. Every field is required; a nil client
// answers 503.
type Relay struct {
	IdentityURL string // https origin of workload-identity
	Identity    *http.Client
	HealthURL   string // https origin of control-health
	Health      *http.Client
	AuditURL    string // https origin of audit-writer
	Audit       *http.Client
	// Live checks that the verified client certificate is an issued,
	// unexpired, unrevoked certificate of an enabled registered workload
	// (Service.LiveCertificate).
	Live func(context.Context, *x509.Certificate) error
	// Auth maps certificate and session token to a Caller
	// (Service.Authenticate).
	Auth func(context.Context, *x509.Certificate, string) (Caller, error)
	Log  *slog.Logger
	// peer returns the verified client certificate; tests replace it.
	peer func(*http.Request) *x509.Certificate
}

// Register adds the relay routes to mux.
func (rl *Relay) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+BootstrapPath, rl.bootstrap)
	mux.HandleFunc("GET /v1/runtime/assignments", rl.assignments)
	mux.HandleFunc("POST /v1/sessions/{tail}", rl.session)
	mux.HandleFunc("POST /v1/runtime/session-workers", rl.registerWorker)
	mux.HandleFunc("GET /v1/runtime/session-workers/{id}", rl.getWorker)
	mux.HandleFunc("POST /v1/runtime/session-workers/{tail}", rl.closeWorker)
	mux.HandleFunc("POST /v1/runtime/work-readiness/checks", rl.requestCheck)
	mux.HandleFunc("GET /v1/runtime/work-readiness/checks/{id}", rl.getCheck)
	mux.HandleFunc("POST /v1/runtime/probe-reports", rl.probeReport)
	mux.HandleFunc("POST /v1/runtime/work-events", rl.workEvent)
}

func verifiedLeaf(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return nil
	}
	return r.TLS.VerifiedChains[0][0]
}

// NewRelayClient is the gateway's management mTLS client for one internal
// service: it presents the gateway certificate and accepts only serverSAN
// (ServiceClientTLS). No redirects, keep-alive or HTTP/2, like the adapter
// client.
func NewRelayClient(roots *x509.CertPool, serverSAN string,
	clientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*http.Client, error) {
	cfg, err := ServiceClientTLS(roots, serverSAN, clientCert)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: RelayTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// upstream is one relay target.
type upstream int

const (
	toIdentity upstream = iota
	toHealth
	toAudit
)

var (
	schemaInvalid       = fail(http.StatusUnprocessableEntity, "SCHEMA_INVALID", "invalid relay request")
	unsupportedType     = fail(http.StatusUnsupportedMediaType, "SCHEMA_INVALID", "content type must be application/json")
	bodyTooLarge        = fail(http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE", "relay body too large")
	sessionMismatch     = fail(http.StatusForbidden, "SESSION_BINDING_INVALID", "resource belongs to another session")
	identityUnavailable = unavailable("STATE_STORE_UNAVAILABLE", "identity relay failed")
	healthUnavailable   = unavailable("CONTROL_HEALTH_UNAVAILABLE", "control-health relay failed")
	auditUnavailable    = unavailable("STATE_STORE_UNAVAILABLE", "audit relay failed")
)

func (rl *Relay) log() *slog.Logger {
	if rl.Log != nil {
		return rl.Log
	}
	return slog.Default()
}

func (rl *Relay) leaf(r *http.Request) *x509.Certificate {
	if rl.peer != nil {
		return rl.peer(r)
	}
	return verifiedLeaf(r)
}

// workload returns the SAN of a verified, live client certificate whose
// namespace is agent-exec. ksa, when set, must match too.
func (rl *Relay) workload(w http.ResponseWriter, r *http.Request, ksa string) (string, bool) {
	leaf := rl.leaf(r)
	if leaf == nil || len(leaf.URIs) != 1 || rl.Live == nil {
		writeError(w, authRequired)
		return "", false
	}
	san := leaf.URIs[0].String()
	ns, k, pod, err := parseSAN(san)
	if err != nil || ns != ExecNamespace || !pod || (ksa != "" && k != ksa) {
		writeError(w, authRequired)
		return "", false
	}
	if err := rl.Live(r.Context(), leaf); err != nil {
		rl.fail(w, err)
		return "", false
	}
	return san, true
}

// runtimeSession authenticates a runtime user session: verified certificate plus
// the claimed session's bearer token (TASK-04 chapter 4 relay row).
func (rl *Relay) runtimeSession(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	leaf := rl.leaf(r)
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if leaf == nil || !ok || tok == "" || rl.Auth == nil {
		writeError(w, authRequired)
		return Caller{}, false
	}
	c, err := rl.Auth(r.Context(), leaf, tok)
	if err != nil {
		rl.fail(w, err)
		return Caller{}, false
	}
	if c.Kind != KindUser || c.Namespace != ExecNamespace {
		writeError(w, authRequired)
		return Caller{}, false
	}
	return c, true
}

func (rl *Relay) fail(w http.ResponseWriter, err error) {
	var e *Error
	if !errors.As(err, &e) {
		rl.log().Error("gateway relay failed", "err", err)
		e = &Error{Status: http.StatusServiceUnavailable, Code: "STATE_STORE_UNAVAILABLE"}
	}
	writeError(w, e)
}

// readBody reads a JSON request body of at most limit bytes.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	if !jsonType(r) {
		writeError(w, unsupportedType)
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		writeError(w, schemaInvalid)
		return nil, false
	}
	if int64(len(body)) > limit {
		writeError(w, bodyTooLarge)
		return nil, false
	}
	return body, true
}

// noQuery rejects a query string: no relayed API defines one.
func noQuery(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, schemaInvalid)
		return false
	}
	return true
}

// sessionBody validates the public JSON object without rewriting it. The
// verified session is forwarded only in X-Agentarium-Peer-Session.
func sessionBody(body []byte) ([]byte, error) {
	if err := canonical.CheckStrictJSON(body); err != nil {
		return nil, schemaInvalid
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		return nil, schemaInvalid
	}
	// Go's decoder matches keys case-insensitively, so any case variant of
	// session_id is refused as well.
	for k := range obj {
		if strings.EqualFold(k, "session_id") {
			return nil, schemaInvalid
		}
	}
	return body, nil
}

// forward sends one relayed request and returns the upstream status, body
// and Retry-After. peerSAN, when set, is the only identity header; token,
// when set, is the only Authorization.
func (rl *Relay) forward(ctx context.Context, to upstream, method, path string, body []byte, peerSAN, token, peerSession, peerSerial string) (int, []byte, string, error) {
	base, client, down := rl.IdentityURL, rl.Identity, identityUnavailable
	switch to {
	case toHealth:
		base, client, down = rl.HealthURL, rl.Health, healthUnavailable
	case toAudit:
		base, client, down = rl.AuditURL, rl.Audit, auditUnavailable
	}
	if client == nil || base == "" {
		return 0, nil, "", down
	}
	ctx, cancel := context.WithTimeout(ctx, RelayTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(base, "/")+path, rd)
	if err != nil {
		return 0, nil, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if peerSAN != "" {
		req.Header.Set(PeerIdentityHeader, peerSAN)
	}
	if to == toHealth && peerSession != "" {
		req.Header.Set("X-Agentarium-Peer-Session", peerSession)
	}
	if to == toHealth && peerSerial != "" {
		req.Header.Set("X-Agentarium-Peer-Certificate-Serial", peerSerial)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		rl.log().Warn("gateway relay upstream unreachable", "path", path, "err", err)
		return 0, nil, "", down
	}
	defer res.Body.Close()
	out, err := io.ReadAll(io.LimitReader(res.Body, maxRelayResponseBytes+1))
	if err != nil || len(out) > maxRelayResponseBytes {
		rl.log().Warn("gateway relay upstream response unreadable", "path", path, "status", res.StatusCode)
		return 0, nil, "", down
	}
	// A 401 from control-health or audit-writer rejects the gateway's own
	// certificate, not the runtime's: it is a relay failure. identity's 401
	// is about the relayed principal or token and passes through.
	if to != toIdentity && res.StatusCode == http.StatusUnauthorized {
		rl.log().Warn("upstream rejected the gateway relay connection", "path", path)
		return 0, nil, "", down
	}
	if res.StatusCode >= 500 && !json.Valid(out) {
		return 0, nil, "", down
	}
	return res.StatusCode, out, res.Header.Get("Retry-After"), nil
}

// relay forwards and copies the upstream answer. Upstream bodies are COMMON
// envelopes or the resource; status and body pass through, and every 503 or
// 429 carries Retry-After (the upstream value, else 2).
func (rl *Relay) relay(w http.ResponseWriter, r *http.Request, to upstream, method, path string, body []byte, peerSAN, token, peerSession, peerSerial string) {
	status, out, retry, err := rl.forward(r.Context(), to, method, path, body, peerSAN, token, peerSession, peerSerial)
	if err != nil {
		rl.fail(w, err)
		return
	}
	copyAnswer(w, status, out, retry)
}

func copyAnswer(w http.ResponseWriter, status int, out []byte, retry string) {
	if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
		if retry == "" {
			retry = "2"
		}
		w.Header().Set("Retry-After", retry)
	}
	if len(out) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(out)
}

// ---- identity ---------------------------------------------------------------

// bootstrap relays the CSR and projected token unchanged (TASK-03 3.3). No
// client certificate is needed and no identity header is sent.
func (rl *Relay) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !noQuery(w, r) {
		return
	}
	body, ok := readBody(w, r, maxIdentityRelayBody)
	if !ok {
		return
	}
	rl.relay(w, r, toIdentity, http.MethodPost, BootstrapPath, body, "", "", "", "")
}

func (rl *Relay) assignments(w http.ResponseWriter, r *http.Request) {
	if !noQuery(w, r) {
		return
	}
	san, ok := rl.workload(w, r, "")
	if !ok {
		return
	}
	rl.relay(w, r, toIdentity, http.MethodGet, "/v1/runtime/assignments", nil, san, "", "", "")
}

// session relays {session_id}:claim (mTLS + claim_code body) and
// {session_id}:refresh (mTLS + current token). :revoke and session creation
// are console APIs and are not relayed.
func (rl *Relay) session(w http.ResponseWriter, r *http.Request) {
	id, verb, ok := strings.Cut(r.PathValue("tail"), ":")
	if !ok || (verb != "claim" && verb != "refresh") {
		writeError(w, notFound)
		return
	}
	if !noQuery(w, r) {
		return
	}
	if !canonicalUUID(id) {
		writeError(w, schemaInvalid)
		return
	}
	san, ok := rl.workload(w, r, "")
	if !ok {
		return
	}
	token := ""
	if verb == "refresh" {
		t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || t == "" {
			writeError(w, authRequired)
			return
		}
		token = t
	}
	body, ok := readBody(w, r, maxIdentityRelayBody)
	if !ok {
		return
	}
	rl.relay(w, r, toIdentity, http.MethodPost, "/v1/sessions/"+id+":"+verb, body, san, token, "", "")
}

// ---- control-health ---------------------------------------------------------

const (
	internalWorkers = "/internal/control-health/session-workers"
	internalChecks  = "/internal/control-health/work-readiness/checks"
)

func (rl *Relay) registerWorker(w http.ResponseWriter, r *http.Request) {
	rl.postWithSession(w, r, internalWorkers)
}

func (rl *Relay) requestCheck(w http.ResponseWriter, r *http.Request) {
	rl.postWithSession(w, r, internalChecks)
}

func (rl *Relay) postWithSession(w http.ResponseWriter, r *http.Request, path string) {
	if !noQuery(w, r) {
		return
	}
	c, ok := rl.runtimeSession(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, maxHealthRelayBody)
	if !ok {
		return
	}
	fwd, err := sessionBody(body)
	if err != nil {
		rl.fail(w, err)
		return
	}
	rl.relay(w, r, toHealth, http.MethodPost, path, fwd, c.SAN, "", c.SessionID, "")
}

func (rl *Relay) getWorker(w http.ResponseWriter, r *http.Request) {
	rl.getOwned(w, r, internalWorkers, sessionMismatch)
}

func (rl *Relay) getCheck(w http.ResponseWriter, r *http.Request) {
	rl.getOwned(w, r, internalChecks, readinessMismatch)
}

// getOwned reads a binding or check and answers it only to its own session:
// control-health scopes the GET by the forwarded SAN, and the gateway also
// requires the resource's session_id to be the token's (COMMON: a result GET is allowed
// only for a caller with the same mTLS identity and session).
func (rl *Relay) getOwned(w http.ResponseWriter, r *http.Request, base string, mismatch *Error) {
	id := r.PathValue("id")
	if !noQuery(w, r) {
		return
	}
	if !canonicalUUID(id) {
		writeError(w, schemaInvalid)
		return
	}
	c, ok := rl.runtimeSession(w, r)
	if !ok {
		return
	}
	status, out, retry, ok := rl.owned(w, r, base+"/"+id, c, mismatch)
	if !ok {
		return
	}
	copyAnswer(w, status, out, retry)
}

// owned GETs path; on 200 the body's session_id must be c's.
func (rl *Relay) owned(w http.ResponseWriter, r *http.Request, path string, c Caller, mismatch *Error) (int, []byte, string, bool) {
	status, out, retry, err := rl.forward(r.Context(), toHealth, http.MethodGet, path, nil, c.SAN, "", c.SessionID, "")
	if err != nil {
		rl.fail(w, err)
		return 0, nil, "", false
	}
	if status == http.StatusOK {
		var res struct {
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(out, &res) != nil {
			rl.fail(w, healthUnavailable)
			return 0, nil, "", false
		}
		if res.SessionID != c.SessionID {
			writeError(w, mismatch)
			return 0, nil, "", false
		}
	}
	return status, out, retry, true
}

// closeWorker closes a binding of the caller's own session: the gateway
// reads the binding first and refuses another session's (TASK-04: referencing another
// session is 403), then relays the close body unchanged.
func (rl *Relay) closeWorker(w http.ResponseWriter, r *http.Request) {
	id, verb, ok := strings.Cut(r.PathValue("tail"), ":")
	if !ok || verb != "close" {
		writeError(w, notFound)
		return
	}
	if !noQuery(w, r) {
		return
	}
	if !canonicalUUID(id) {
		writeError(w, schemaInvalid)
		return
	}
	c, ok := rl.runtimeSession(w, r)
	if !ok {
		return
	}
	body, ok := readBody(w, r, maxHealthRelayBody)
	if !ok {
		return
	}
	status, out, retry, ok := rl.owned(w, r, internalWorkers+"/"+id, c, sessionMismatch)
	if !ok {
		return
	}
	if status != http.StatusOK {
		copyAnswer(w, status, out, retry)
		return
	}
	rl.relay(w, r, toHealth, http.MethodPost, internalWorkers+"/"+url.PathEscape(id)+":close", body, c.SAN, "", c.SessionID, "")
}

// probeReport relays a probe runner's result to
// /internal/control-health/probe-results (COMMON probe-reports row). Only
// agent-exec/probe-runner may call it.
// SPEC-QUESTION: COMMON says the lease is reported "through the same relay"
// but names one upstream path; lease relay is not implemented here.
func (rl *Relay) probeReport(w http.ResponseWriter, r *http.Request) {
	if !noQuery(w, r) {
		return
	}
	san, ok := rl.workload(w, r, ProbeRunnerKSA)
	if !ok {
		return
	}
	body, ok := readBody(w, r, maxHealthRelayBody)
	if !ok {
		return
	}
	rl.relay(w, r, toHealth, http.MethodPost, "/internal/control-health/probe-results", body, san, "", "", hex.EncodeToString(r.TLS.PeerCertificates[0].SerialNumber.Bytes()))
}
