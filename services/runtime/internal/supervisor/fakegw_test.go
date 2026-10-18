package supervisor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Beaver-Dam-Community/Agentarium/services/runtime/internal/gwclient"
)

// testPKI is a CA, a gateway server certificate and a CSR signer standing
// in for workload-identity.
type testPKI struct {
	caKey  *ecdsa.PrivateKey
	ca     *x509.Certificate
	roots  *x509.CertPool
	server tls.Certificate
}

const gatewaySAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	p := &testPKI{caKey: key, ca: ca, roots: x509.NewCertPool()}
	p.roots.AddCert(ca)
	skey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(gatewaySAN)
	sder := p.sign(t, &skey.PublicKey, u, x509.ExtKeyUsageServerAuth)
	p.server = tls.Certificate{Certificate: [][]byte{sder}, PrivateKey: skey}
	return p
}

func (p *testPKI) sign(t *testing.T, pub any, san *url.URL, eku x509.ExtKeyUsage) []byte {
	t.Helper()
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: sn, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		URIs: []*url.URL{san}, ExtKeyUsage: []x509.ExtKeyUsage{eku}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeGateway imitates the gateway public routes the runtime uses (#230
// relay paths and bodies, #228 control-health answers, TASK-04 actions).
type fakeGateway struct {
	t   *testing.T
	pki *testPKI
	srv *httptest.Server

	mu              sync.Mutex
	podSAN          string
	sessionID       string
	claimCode       string
	token           string
	claims          int
	registrations   []map[string]json.RawMessage
	binding         gwclient.WorkerBinding
	workerGets      int
	observeAfter    int // GET count before observed
	checks          map[string]*gwclient.ReadinessCheck
	checkGets       map[string]int
	readyAfter      int
	checkState      string // final state other than ready, when set
	events          []string
	workEvents404   bool
	workEventAck    int // when set, answer this status without a TASK-07 ack
	submits         []submitRecord
	approvalMode    bool
	approved        bool
	reevals         []submitRecord
	actionID        string
	resultBody      json.RawMessage
	resultGets      int
	closes          []string
	reevaluateError string // optional persistent error injected after resume readiness
	submit503       int    // number of leading 503 WORK_READINESS_EXPIRED answers
	onRegister      func(map[string]json.RawMessage)
}

type submitRecord struct {
	WorkRunID, CheckID, Checkpoint, ClientKey, SessionID string
	Body                                                 map[string]json.RawMessage
}

func newFakeGateway(t *testing.T, pki *testPKI) *fakeGateway {
	g := &fakeGateway{t: t, pki: pki, sessionID: uuid.NewString(), claimCode: "code-" + uuid.NewString(),
		checks: map[string]*gwclient.ReadinessCheck{}, checkGets: map[string]int{}, observeAfter: 2, readyAfter: 1}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /internal/workload-certificates", g.bootstrap)
	mux.HandleFunc("GET /v1/runtime/assignments", g.mtls(g.assignments))
	mux.HandleFunc("POST /v1/sessions/{tail}", g.mtls(g.session))
	mux.HandleFunc("POST /v1/runtime/session-workers", g.sess(g.register))
	mux.HandleFunc("GET /v1/runtime/session-workers/{id}", g.sess(g.getWorker))
	mux.HandleFunc("POST /v1/runtime/session-workers/{tail}", g.sess(g.closeWorker))
	mux.HandleFunc("POST /v1/runtime/work-readiness/checks", g.sess(g.requestCheck))
	mux.HandleFunc("GET /v1/runtime/work-readiness/checks/{id}", g.sess(g.getCheck))
	mux.HandleFunc("POST /v1/runtime/work-events", g.sess(g.workEvent))
	mux.HandleFunc("POST /v1/actions", g.sess(g.submit))
	mux.HandleFunc("POST /v1/actions/{tail}", g.sess(g.reevaluate))
	mux.HandleFunc("GET /v1/actions/{id}", g.sess(g.getAction))
	mux.HandleFunc("GET /v1/actions/{id}/result", g.sess(g.getResult))
	g.srv = httptest.NewUnstartedServer(mux)
	g.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pki.server}, ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs: pki.roots, MinVersion: tls.VersionTLS13}
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	return g
}

func (g *fakeGateway) writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	if status == 503 {
		w.Header().Set("Retry-After", "2")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"request_id": uuid.NewString(), "reason_codes": []string{code}})
}

func (g *fakeGateway) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeBody(r *http.Request) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	_ = json.NewDecoder(r.Body).Decode(&m)
	return m
}

// mtls requires the issued runtime certificate (RequireClientCert).
func (g *fakeGateway) mtls(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			g.writeErr(w, 401, "AUTH_REQUIRED")
			return
		}
		g.mu.Lock()
		ok := r.TLS.VerifiedChains[0][0].URIs[0].String() == g.podSAN
		g.mu.Unlock()
		if !ok {
			g.writeErr(w, 401, "AUTH_REQUIRED")
			return
		}
		h(w, r)
	}
}

// sess requires mTLS plus the claimed session token.
func (g *fakeGateway) sess(h http.HandlerFunc) http.HandlerFunc {
	return g.mtls(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		ok := g.token != "" && r.Header.Get("Authorization") == "Bearer "+g.token
		g.mu.Unlock()
		if !ok {
			g.writeErr(w, 401, "AUTH_REQUIRED")
			return
		}
		h(w, r)
	})
}

func (g *fakeGateway) bootstrap(w http.ResponseWriter, r *http.Request) {
	var req gwclient.CertRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != "projected-token" {
		g.writeErr(w, 401, "AUTH_REQUIRED")
		return
	}
	b, _ := pem.Decode([]byte(req.CSR))
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		g.writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	san, _ := url.Parse("spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + uuid.NewString())
	der := g.pki.sign(g.t, csr.PublicKey, san, x509.ExtKeyUsageClientAuth)
	g.mu.Lock()
	g.podSAN = san.String()
	g.mu.Unlock()
	g.reply(w, 200, gwclient.CertResponse{
		Certificate:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		CertificateChain: []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: g.pki.ca.Raw}))},
		Serial:           "01", ExpiresAt: time.Now().Add(24 * time.Hour),
	})
}

func (g *fakeGateway) assignments(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := []gwclient.Assignment{}
	if g.token == "" {
		out = append(out, gwclient.Assignment{SessionID: g.sessionID, ClaimCode: g.claimCode,
			ClaimExpiresAt: time.Now().Add(60 * time.Second), TaskStatement: "요약만 전달"})
	}
	g.reply(w, 200, map[string]any{"assignments": out})
}

func (g *fakeGateway) session(w http.ResponseWriter, r *http.Request) {
	id, verb, _ := strings.Cut(r.PathValue("tail"), ":")
	g.mu.Lock()
	defer g.mu.Unlock()
	switch verb {
	case "claim":
		body := decodeBody(r)
		var code string
		_ = json.Unmarshal(body["claim_code"], &code)
		g.claims++
		if id != g.sessionID || code != g.claimCode || g.token != "" {
			g.writeErr(w, 403, "CLAIM_CODE_INVALID")
			return
		}
		g.token = "tok-" + uuid.NewString()
		g.reply(w, 200, gwclient.SessionToken{Token: g.token, ExpiresAt: time.Now().Add(30 * time.Minute)})
	case "refresh":
		g.reply(w, 200, gwclient.SessionToken{Token: g.token, ExpiresAt: time.Now().Add(30 * time.Minute)})
	default:
		g.writeErr(w, 404, "RESOURCE_NOT_FOUND")
	}
}

func (g *fakeGateway) register(w http.ResponseWriter, r *http.Request) {
	body := decodeBody(r)
	if _, ok := body["session_id"]; ok {
		g.writeErr(w, 422, "SCHEMA_INVALID") // the relay refuses a client session_id
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.onRegister != nil {
		g.onRegister(body)
	}
	g.registrations = append(g.registrations, body)
	var wid, epoch string
	_ = json.Unmarshal(body["worker_instance_id"], &wid)
	_ = json.Unmarshal(body["runtime_process_epoch"], &epoch)
	g.binding = gwclient.WorkerBinding{WorkerBindingID: uuid.NewString(), WorkerInstanceID: wid, SessionID: g.sessionID,
		RuntimeProcessEpoch: epoch, State: "pending", ReasonCodes: []string{}}
	g.reply(w, 202, g.binding)
}

func (g *fakeGateway) getWorker(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.PathValue("id") != g.binding.WorkerBindingID {
		g.writeErr(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	g.workerGets++
	if g.workerGets > g.observeAfter && g.binding.State == "pending" {
		root := "root-exec-1"
		g.binding.State, g.binding.RootExecID = "observed", &root
	}
	g.reply(w, 200, g.binding)
}

func (g *fakeGateway) closeWorker(w http.ResponseWriter, r *http.Request) {
	id, verb, _ := strings.Cut(r.PathValue("tail"), ":")
	body := decodeBody(r)
	var reason string
	_ = json.Unmarshal(body["reason"], &reason)
	g.mu.Lock()
	defer g.mu.Unlock()
	if verb != "close" || id != g.binding.WorkerBindingID {
		g.writeErr(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	g.closes = append(g.closes, reason)
	g.binding.State = "closed"
	g.reply(w, 200, g.binding)
}

func (g *fakeGateway) requestCheck(w http.ResponseWriter, r *http.Request) {
	var req gwclient.ReadinessRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	g.mu.Lock()
	defer g.mu.Unlock()
	if req.WorkerBindingID != g.binding.WorkerBindingID || g.binding.State != "observed" {
		g.writeErr(w, 403, "WORKER_BINDING_MISMATCH")
		return
	}
	c := &gwclient.ReadinessCheck{CheckID: uuid.NewString(), WorkRunID: req.WorkRunID, Checkpoint: req.Checkpoint,
		SessionID: g.sessionID, WorkerInstanceID: req.WorkerInstanceID, WorkerBindingID: req.WorkerBindingID,
		State: "pending", ReasonCodes: []string{}}
	g.checks[c.CheckID] = c
	g.reply(w, 202, c)
}

func (g *fakeGateway) getCheck(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	c, ok := g.checks[r.PathValue("id")]
	if !ok {
		g.writeErr(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	g.checkGets[c.CheckID]++
	if c.State == "pending" && g.checkGets[c.CheckID] > g.readyAfter {
		if g.checkState != "" {
			c.State, c.ReasonCodes = g.checkState, []string{"POD_OBSERVATION_NOT_READY"}
		} else {
			c.State, c.RemainingValidMS = "ready", 3000
		}
	}
	g.reply(w, 200, c)
}

// workEvent follows the #234 follow-up gateway relay: strict body (a
// session_id or any producer field is 422), the check must be this
// session's, and the answer is the TASK-07 ack.
func (g *fakeGateway) workEvent(w http.ResponseWriter, r *http.Request) {
	var ev gwclient.WorkEvent
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	err := d.Decode(&ev)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.workEvents404 {
		g.writeErr(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	if err != nil || ev.SourceVersion == "" || ev.SourceTime.IsZero() {
		g.writeErr(w, 422, "SCHEMA_INVALID")
		return
	}
	if c := g.checks[ev.SafePayload.CheckID]; c == nil || c.SessionID != g.sessionID || c.WorkRunID != ev.SafePayload.WorkRunID {
		g.writeErr(w, 403, "WORK_READINESS_BINDING_MISMATCH")
		return
	}
	if g.workEventAck != 0 {
		g.reply(w, g.workEventAck, map[string]string{"event_id": ev.EventID})
		return
	}
	g.events = append(g.events, ev.EventType)
	g.reply(w, 201, gwclient.WorkEventAck{EventID: ev.EventID, Result: "created", ReceivedAt: time.Now().UTC()})
}

// readyRef checks the runtime headers against a ready check, like
// gateway HTTPReadiness.
func (g *fakeGateway) readyRef(r *http.Request) (submitRecord, bool) {
	rec := submitRecord{WorkRunID: r.Header.Get(gwclient.WorkRunHeader), CheckID: r.Header.Get(gwclient.ReadinessCheckHeader)}
	c, ok := g.checks[rec.CheckID]
	if !ok || c.WorkRunID != rec.WorkRunID || c.State != "ready" {
		return rec, false
	}
	rec.Checkpoint = c.Checkpoint
	return rec, true
}

func (g *fakeGateway) submit(w http.ResponseWriter, r *http.Request) {
	body := decodeBody(r)
	g.mu.Lock()
	defer g.mu.Unlock()
	rec, ok := g.readyRef(r)
	_ = json.Unmarshal(body["client_request_key"], &rec.ClientKey)
	_ = json.Unmarshal(body["session_id"], &rec.SessionID)
	rec.Body = body
	g.submits = append(g.submits, rec)
	if !ok {
		g.writeErr(w, 503, "WORK_READINESS_EXPIRED")
		return
	}
	if g.submit503 > 0 {
		g.submit503--
		g.writeErr(w, 503, "WORK_READINESS_EXPIRED")
		return
	}
	if g.actionID == "" {
		g.actionID = uuid.NewString()
	}
	verdict := "allow"
	if g.approvalMode {
		verdict = "approval_required"
	}
	g.reply(w, 202, gwclient.ActionResponse{RequestID: uuid.NewString(), ActionID: g.actionID, DecisionID: uuid.NewString(),
		Verdict: verdict, ExecutionAllowed: verdict == "allow", ReasonCodes: []string{}})
}

func (g *fakeGateway) reevaluate(w http.ResponseWriter, r *http.Request) {
	id, verb, _ := strings.Cut(r.PathValue("tail"), ":")
	body := decodeBody(r)
	g.mu.Lock()
	defer g.mu.Unlock()
	if verb != "reevaluate" || id != g.actionID {
		g.writeErr(w, 404, "RESOURCE_NOT_FOUND")
		return
	}
	var digest string
	_ = json.Unmarshal(body["expected_action_digest"], &digest)
	if digest != "digest-1" {
		g.writeErr(w, 409, "ACTION_DIGEST_MISMATCH")
		return
	}
	rec, ok := g.readyRef(r)
	g.reevals = append(g.reevals, rec)
	if !ok {
		g.writeErr(w, 503, "WORK_READINESS_EXPIRED")
		return
	}
	if g.reevaluateError != "" {
		status := 503
		if g.reevaluateError == "POLICY_EPOCH_STALE" {
			status = 409
		}
		g.writeErr(w, status, g.reevaluateError)
		return
	}
	verdict := "approval_required"
	if g.approved {
		verdict, g.approvalMode = "allow", false
	}
	g.reply(w, 202, gwclient.ActionResponse{ActionID: g.actionID, DecisionID: uuid.NewString(), Verdict: verdict,
		ExecutionAllowed: verdict == "allow", ReasonCodes: []string{}})
}

func (g *fakeGateway) getAction(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	d := "digest-1"
	state := "dispatch_pending"
	verdict := "allow"
	if g.approvalMode {
		state, verdict = "approval_pending", "approval_required"
	}
	g.reply(w, 200, gwclient.ActionView{ActionID: g.actionID, ActionDigest: &d, Verdict: verdict, ExecutionState: state, ReasonCodes: []string{}})
}

func (g *fakeGateway) getResult(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.resultGets++
	if g.resultGets < 2 {
		g.reply(w, 202, map[string]string{"action_id": g.actionID, "execution_state": "dispatched"})
		return
	}
	g.reply(w, 200, map[string]any{"action_id": g.actionID, "execution_state": "effect_verified", "evidence_level": "effect_verified", "result_body": g.resultBody})
}

func tokenFile(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte("projected-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
