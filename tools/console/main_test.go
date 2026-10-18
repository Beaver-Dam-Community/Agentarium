package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

const (
	testKey    = "test-key-0123456789"
	testPort   = "18080"
	actionID   = "8c1e0000-0000-4000-8000-000000000001"
	approvalID = "9d2f0000-0000-4000-8000-000000000002"
	sessionID  = "7b0d0000-0000-4000-8000-000000000003"
)

// fakeJWT builds an unsigned token with the given exp and iat; the console
// never verifies it, identity does.
func fakeJWT(exp, iat time.Time, nonce string) string {
	enc := base64.RawURLEncoding.EncodeToString
	payload, _ := json.Marshal(map[string]any{"exp": exp.Unix(), "iat": iat.Unix(), "n": nonce})
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc(payload) + "." + enc([]byte("sig"))
}

// fakeTokens returns a token source whose command is counted and prints a
// fresh token valid for an hour from the test clock.
func fakeTokens(clock *time.Time) (*tokenSource, *int) {
	runs := 0
	ts := &tokenSource{argv: []string{"fake"}, now: func() time.Time { return *clock }}
	ts.run = func(context.Context, []string) ([]byte, error) {
		runs++
		return []byte(fakeJWT(clock.Add(time.Hour), *clock, fmt.Sprint(runs)) + "\n"), nil
	}
	return ts, &runs
}

// ---- local API guards ---------------------------------------------------------

func TestCheckLoopbackListen(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:0", "127.0.0.1:8080", "[::1]:0", "127.1.2.3:9"} {
		if err := checkLoopbackListen(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{":0", "0.0.0.0:8080", "[::]:0", "192.168.1.10:8080", "localhost:8080", "example.com:80", "127.0.0.1"} {
		if err := checkLoopbackListen(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := run([]string{"-listen", "0.0.0.0:0", "-ca-file", "/nonexistent"}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("run with a non-loopback -listen: %v", err)
	}
}

// guardServer is a local server whose identity calls never succeed; guard
// tests only look at whether a request reaches a handler.
func guardServer(t *testing.T) http.Handler {
	t.Helper()
	clock := time.Now()
	ts, _ := fakeTokens(&clock)
	ic, err := newIdentityClient("https://identity.invalid:1", x509.NewCertPool(), workloadcert.IdentitySAN, "127.0.0.1:1", ts)
	if err != nil {
		t.Fatal(err)
	}
	return (&server{key: testKey, port: testPort, identity: ic, logger: log.New(io.Discard, "", 0)}).handler()
}

func localRequest(method, path, host, origin, key string, body string) *http.Request {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if key != "" {
		req.Header.Set(keyHeader, key)
	}
	return req
}

func reasonCodes(t *testing.T, raw []byte) []string {
	t.Helper()
	var e struct {
		ReasonCodes []string `json:"reason_codes"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("error body %q: %v", raw, err)
	}
	return e.ReasonCodes
}

func TestGuardRejects(t *testing.T) {
	h := guardServer(t)
	good := "127.0.0.1:" + testPort
	pending := "/api/pending?session_id=" + sessionID
	approve := `{"action_id":"` + actionID + `","displayed_contract_digest":"d","nonce":"n","acknowledged_findings":[]}`
	cases := []struct {
		name string
		req  *http.Request
		code string
	}{
		{"missing key", localRequest("GET", pending, good, "", "", ""), "LOCAL_KEY_REJECTED"},
		{"wrong key", localRequest("GET", pending, good, "", "wrong-key", ""), "LOCAL_KEY_REJECTED"},
		{"key prefix", localRequest("GET", pending, good, "", testKey[:5], ""), "LOCAL_KEY_REJECTED"},
		{"rebound host", localRequest("GET", pending, "evil.example:"+testPort, "", testKey, ""), "LOCAL_HOST_REJECTED"},
		{"other port", localRequest("GET", pending, "127.0.0.1:9999", "", testKey, ""), "LOCAL_HOST_REJECTED"},
		{"lan host", localRequest("GET", pending, "192.168.1.10:"+testPort, "", testKey, ""), "LOCAL_HOST_REJECTED"},
		{"host without port", localRequest("GET", pending, "127.0.0.1", "", testKey, ""), "LOCAL_HOST_REJECTED"},
		{"static on rebound host", localRequest("GET", "/", "evil.example:"+testPort, "", "", ""), "LOCAL_HOST_REJECTED"},
		{"cross origin", localRequest("POST", "/api/approvals", good, "http://evil.example", testKey, approve), "LOCAL_ORIGIN_REJECTED"},
		{"other localhost origin", localRequest("POST", "/api/approvals", good, "http://localhost:"+testPort, testKey, approve), "LOCAL_ORIGIN_REJECTED"},
		{"null origin", localRequest("GET", pending, good, "null", testKey, ""), "LOCAL_ORIGIN_REJECTED"},
		{"post without origin", localRequest("POST", "/api/approvals", good, "", testKey, approve), "LOCAL_ORIGIN_REJECTED"},
		{"post without key", localRequest("POST", "/api/approvals", good, "http://"+good, "", approve), "LOCAL_KEY_REJECTED"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.req)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", c.name, w.Code)
			continue
		}
		if got := reasonCodes(t, w.Body.Bytes()); len(got) != 1 || got[0] != c.code {
			t.Errorf("%s: codes %v, want %s", c.name, got, c.code)
		}
	}
}

func TestGuardAllowsPageAndKeyedAPI(t *testing.T) {
	h := guardServer(t)
	for _, host := range []string{"127.0.0.1:" + testPort, "localhost:" + testPort, "[::1]:" + testPort} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, localRequest("GET", "/", host, "", "", ""))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "approval console") {
			t.Fatalf("page on %s: %d", host, w.Code)
		}
		if got := w.Header().Get("Content-Security-Policy"); !strings.HasPrefix(got, "default-src 'self'") {
			t.Fatalf("CSP %q", got)
		}
	}
	for _, p := range []string{"/app.js", "/logic.mjs", "/style.css"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, localRequest("GET", p, "127.0.0.1:"+testPort, "", "", ""))
		if w.Code != 200 {
			t.Fatalf("%s: %d", p, w.Code)
		}
		// nosniff: a module script needs a JavaScript MIME type.
		if ct := w.Header().Get("Content-Type"); strings.HasSuffix(p, "js") && !strings.HasPrefix(ct, "text/javascript") {
			t.Fatalf("%s: Content-Type %q", p, ct)
		}
	}
	// The node test file is not embedded.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, localRequest("GET", "/logic.test.mjs", "127.0.0.1:"+testPort, "", "", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("/logic.test.mjs: %d", w.Code)
	}
	// A keyed request with the right Host and Origin passes the guard and
	// reaches the handler, which fails only on the unreachable identity.
	good := "127.0.0.1:" + testPort
	w = httptest.NewRecorder()
	h.ServeHTTP(w, localRequest("GET", "/api/pending?session_id="+sessionID, good, "http://"+good, testKey, ""))
	if got := reasonCodes(t, w.Body.Bytes()); w.Code != http.StatusBadGateway || got[0] != "IDENTITY_UNREACHABLE" {
		t.Fatalf("keyed request: %d %v", w.Code, got)
	}
}

func TestTokenFailureIsReported(t *testing.T) {
	pki := newPKI(t)
	srv, got, mu := fakeIdentity(t, pki.leaf(t, workloadcert.IdentitySAN))
	ts := &tokenSource{argv: []string{"fake"}, now: time.Now,
		run: func(context.Context, []string) ([]byte, error) { return nil, errors.New("gcloud: not logged in") }}
	h := localConsole(t, pki.roots, srv, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, keyed("GET", "/api/pending?session_id="+sessionID, ""))
	if w.Code != http.StatusServiceUnavailable || reasonCodes(t, w.Body.Bytes())[0] != "TOKEN_UNAVAILABLE" {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 0 {
		t.Fatal("request without a token reached identity")
	}
}

func TestPageUsesTextContentOnly(t *testing.T) {
	for _, name := range []string{"static/app.js", "static/logic.mjs", "static/index.html"} {
		raw, err := staticFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "http://", "https://"} {
			if strings.Contains(string(raw), bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
}

// ---- token cache --------------------------------------------------------------

func TestTokenCache(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	ts, runs := fakeTokens(&clock)
	ctx := context.Background()

	t1, err := ts.Token(ctx, 0)
	if err != nil || *runs != 1 {
		t.Fatalf("first token: %v runs=%d", err, *runs)
	}
	clock = clock.Add(30 * time.Minute)
	if t2, _ := ts.Token(ctx, 0); t2 != t1 || *runs != 1 {
		t.Fatalf("cached token was not reused (runs=%d)", *runs)
	}
	// Within refreshBefore of exp the command runs again.
	clock = clock.Add(29 * time.Minute)
	t3, err := ts.Token(ctx, 0)
	if err != nil || t3 == t1 || *runs != 2 {
		t.Fatalf("near exp: %v runs=%d", err, *runs)
	}
	// An approval needs a token issued within approvalTokenMaxAge.
	clock = clock.Add(approvalTokenMaxAge - time.Second)
	if t4, _ := ts.Token(ctx, approvalTokenMaxAge); t4 != t3 || *runs != 2 {
		t.Fatalf("young token refreshed (runs=%d)", *runs)
	}
	clock = clock.Add(2 * time.Second)
	if t5, _ := ts.Token(ctx, approvalTokenMaxAge); t5 == t3 || *runs != 3 {
		t.Fatalf("old token reused for approval (runs=%d)", *runs)
	}
}

func TestTokenCommandOutputRejected(t *testing.T) {
	clock := time.Unix(1_800_000_000, 0)
	secret := "ya29.not-a-jwt-secret"
	for name, out := range map[string]string{
		"not a jwt": secret,
		"expired":   fakeJWT(clock.Add(-time.Minute), clock.Add(-time.Hour), secret),
		"no exp":    "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"iat":1,"s":"`+secret+`"}`)) + ".c2ln",
	} {
		ts := &tokenSource{argv: []string{"fake"}, now: func() time.Time { return clock },
			run: func(context.Context, []string) ([]byte, error) { return []byte(out), nil }}
		_, err := ts.Token(context.Background(), 0)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaks the command output: %v", name, err)
		}
	}
	ts := &tokenSource{argv: []string{"fake"}, now: func() time.Time { return clock },
		run: func(context.Context, []string) ([]byte, error) { return nil, errors.New("boom") }}
	if _, err := ts.Token(context.Background(), 0); err == nil {
		t.Fatal("command failure accepted")
	}
	if _, err := newTokenSource("   "); err == nil {
		t.Fatal("empty command accepted")
	}
}

func TestRunCommandNoShell(t *testing.T) {
	ts, err := newTokenSource("echo " + fakeJWT(time.Now().Add(time.Hour), time.Now(), "x") + " ;rm")
	if err != nil {
		t.Fatal(err)
	}
	// Without a shell ";rm" is an argument to echo, so the output is not a
	// single JWT and is rejected.
	if _, err := ts.Token(context.Background(), 0); err == nil {
		t.Fatal("shell syntax was interpreted")
	}
}

// ---- proxy to identity over SAN-verified TLS -----------------------------------

type testPKI struct {
	roots  *x509.CertPool
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return &testPKI{roots: roots, caCert: ca, caKey: key}
}

// leaf issues a server certificate whose only SAN is the URI san (no DNS
// name, like the workload certificates).
func (p *testPKI) leaf(t *testing.T, san string) tls.Certificate {
	return p.leafWith(t, []string{san}, x509.ExtKeyUsageServerAuth)
}

// leafWith issues a server certificate with the given URI SANs and EKU; mods
// adjust the template before signing.
func (p *testPKI) leafWith(t *testing.T, sans []string, eku x509.ExtKeyUsage, mods ...func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var uris []*url.URL
	for _, san := range sans {
		u, _ := url.Parse(san)
		uris = append(uris, u)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: uris}
	for _, mod := range mods {
		mod(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type seen struct {
	method, path, query, auth, body string
}

// fakeIdentity is an identity TLS server with cert that answers the console
// routes and records every request.
func fakeIdentity(t *testing.T, cert tls.Certificate) (*httptest.Server, *[]seen, *sync.Mutex) {
	t.Helper()
	var mu sync.Mutex
	var got []seen
	mux := http.NewServeMux()
	reply := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			got = append(got, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), string(b)})
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Set-Cookie", "identity=1")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	mux.HandleFunc("POST /v1/sessions", reply(201, `{"session_id":"`+sessionID+`","claim_code":"c","allowed_operation_ids":["receiver.submit"]}`))
	mux.HandleFunc("GET /v1/approvals/pending", reply(200, `{"actions":[{"action_id":"`+actionID+`","session_id":"`+sessionID+`","operation_id":"receiver.submit"}]}`))
	mux.HandleFunc("GET /v1/actions/{id}/approval-contract", reply(200, `{"contract":{"action_id":"`+actionID+`","operation_id":"receiver.submit"},"contract_digest":"`+strings.Repeat("a", 64)+`","nonce":"nonce-1","intent_check":{"intent_check_status":"not_run","findings":[]}}`))
	mux.HandleFunc("POST /v1/approvals", reply(200, `{"approval_id":"`+approvalID+`","revision":1,"contract_digest":"`+strings.Repeat("a", 64)+`","policy_epoch":3,"expires_at":"2026-10-18T00:05:00Z"}`))
	mux.HandleFunc("POST /v1/approvals/{id}/revoke", reply(200, `{"approval_id":"`+approvalID+`","revoke_reason":"user_revoked"}`))
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &got, &mu
}

// localConsole is the local server proxying to identity at the in-cluster
// URL, dialed at srv through the -identity-dial override.
func localConsole(t *testing.T, roots *x509.CertPool, srv *httptest.Server, ts *tokenSource) http.Handler {
	t.Helper()
	dial := strings.TrimPrefix(srv.URL, "https://")
	ic, err := newIdentityClient("https://workload-identity.agent-control.svc:18443", roots, workloadcert.IdentitySAN, dial, ts)
	if err != nil {
		t.Fatal(err)
	}
	return (&server{key: testKey, port: testPort, identity: ic, logger: log.New(io.Discard, "", 0)}).handler()
}

func keyed(method, path, body string) *http.Request {
	host := "127.0.0.1:" + testPort
	return localRequest(method, path, host, "http://"+host, testKey, body)
}

func TestProxyToIdentity(t *testing.T) {
	pki := newPKI(t)
	srv, got, mu := fakeIdentity(t, pki.leaf(t, workloadcert.IdentitySAN))
	clock := time.Now()
	ts, runs := fakeTokens(&clock)
	h := localConsole(t, pki.roots, srv, ts)

	approve := `{"action_id":"` + actionID + `","displayed_contract_digest":"` + strings.Repeat("a", 64) + `","nonce":"nonce-1","acknowledged_findings":["f1"]}`
	steps := []struct {
		req                *http.Request
		status             int
		method, path, body string
		query              string
	}{
		{keyed("POST", "/api/sessions", `{"workload_id":"agent-exec/agent-runtime","task_statement":"t","requested_scope":{"operation_ids":["receiver.submit"],"target_ids":["receiver-primary"]}}`),
			201, "POST", "/v1/sessions", `{"workload_id":"agent-exec/agent-runtime","task_statement":"t","requested_scope":{"operation_ids":["receiver.submit"],"target_ids":["receiver-primary"]}}`, ""},
		{keyed("GET", "/api/pending?session_id="+sessionID, ""), 200, "GET", "/v1/approvals/pending", "", "session_id=" + sessionID},
		{keyed("GET", "/api/actions/"+actionID+"/contract", ""), 200, "GET", "/v1/actions/" + actionID + "/approval-contract", "", ""},
		{keyed("POST", "/api/approvals", approve), 200, "POST", "/v1/approvals", approve, ""},
		{keyed("POST", "/api/approvals/"+approvalID+"/revoke", ""), 200, "POST", "/v1/approvals/" + approvalID + "/revoke", "", ""},
	}
	var tokens []string
	for i, s := range steps {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, s.req)
		if w.Code != s.status {
			t.Fatalf("step %d %s: status %d body %s", i, s.path, w.Code, w.Body)
		}
		if w.Header().Get("Set-Cookie") != "" {
			t.Fatalf("step %d: identity header relayed", i)
		}
		mu.Lock()
		last := (*got)[len(*got)-1]
		mu.Unlock()
		if len(*got) != i+1 || last.method != s.method || last.path != s.path || last.query != s.query {
			t.Fatalf("step %d: identity saw %+v", i, last)
		}
		if s.body != "" && last.body != s.body {
			t.Fatalf("step %d: forwarded body %s, want %s", i, last.body, s.body)
		}
		tok := strings.TrimPrefix(last.auth, "Bearer ")
		if tok == last.auth || tok == "" {
			t.Fatalf("step %d: no bearer token sent to identity", i)
		}
		tokens = append(tokens, tok)
		for _, tk := range tokens {
			if strings.Contains(w.Body.String(), tk) || strings.Contains(fmt.Sprint(w.Header()), tk) {
				t.Fatalf("step %d: token reached the browser", i)
			}
		}
	}
	if *runs != 1 {
		t.Fatalf("token command ran %d times, want 1", *runs)
	}
}

func TestProxyRejectsBadInput(t *testing.T) {
	pki := newPKI(t)
	srv, got, mu := fakeIdentity(t, pki.leaf(t, workloadcert.IdentitySAN))
	clock := time.Now()
	ts, _ := fakeTokens(&clock)
	h := localConsole(t, pki.roots, srv, ts)
	for name, c := range map[string]struct {
		req    *http.Request
		status int
	}{
		"max_actions sent":      {keyed("POST", "/api/approvals", `{"action_id":"`+actionID+`","displayed_contract_digest":"d","nonce":"n","acknowledged_findings":[],"max_actions":1}`), 422},
		"missing nonce":         {keyed("POST", "/api/approvals", `{"action_id":"`+actionID+`","displayed_contract_digest":"d","acknowledged_findings":[]}`), 422},
		"bad approve action id": {keyed("POST", "/api/approvals", `{"action_id":"x","displayed_contract_digest":"d","nonce":"n"}`), 422},
		"trailing data":         {keyed("POST", "/api/approvals", `{"action_id":"`+actionID+`","displayed_contract_digest":"d","nonce":"n"} {}`), 422},
		"bad action id":         {keyed("GET", "/api/actions/..%2Fsessions/contract", ""), 422},
		"bad approval id":       {keyed("POST", "/api/approvals/x/revoke", ""), 422},
		"bad session id":        {keyed("GET", "/api/pending?session_id=x%26y", ""), 422},
		"unknown session field": {keyed("POST", "/api/sessions", `{"workload_id":"a/b","tenant":"other"}`), 422},
		"unknown route":         {keyed("GET", "/api/approvals/"+approvalID, ""), 404},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.req)
		if w.Code != c.status {
			t.Errorf("%s: status %d, want %d", name, w.Code, c.status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 0 {
		t.Fatalf("bad input reached identity: %+v", *got)
	}
}

// TestApproveRefreshesOldToken: an approval is never sent with a token
// issued more than approvalTokenMaxAge ago.
func TestApproveRefreshesOldToken(t *testing.T) {
	pki := newPKI(t)
	srv, got, mu := fakeIdentity(t, pki.leaf(t, workloadcert.IdentitySAN))
	clock := time.Now()
	ts, runs := fakeTokens(&clock)
	h := localConsole(t, pki.roots, srv, ts)

	h.ServeHTTP(httptest.NewRecorder(), keyed("GET", "/api/pending?session_id="+sessionID, ""))
	clock = clock.Add(approvalTokenMaxAge + time.Second)
	h.ServeHTTP(httptest.NewRecorder(), keyed("GET", "/api/pending?session_id="+sessionID, ""))
	if *runs != 1 {
		t.Fatalf("reads refreshed the token (runs=%d)", *runs)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, keyed("POST", "/api/approvals", `{"action_id":"`+actionID+`","displayed_contract_digest":"d","nonce":"n","acknowledged_findings":[]}`))
	if w.Code != 200 || *runs != 2 {
		t.Fatalf("approve: %d runs=%d", w.Code, *runs)
	}
	mu.Lock()
	defer mu.Unlock()
	if (*got)[1].auth == (*got)[2].auth {
		t.Fatal("approval sent with the old token")
	}
}

func TestIdentityTLSVerification(t *testing.T) {
	pki := newPKI(t)
	other := newPKI(t)
	for name, c := range map[string]struct {
		cert  tls.Certificate
		roots *x509.CertPool
	}{
		"wrong SAN":    {pki.leaf(t, "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"), pki.roots},
		"SAN prefix":   {pki.leaf(t, workloadcert.IdentitySAN+"-x"), pki.roots},
		"untrusted CA": {other.leaf(t, workloadcert.IdentitySAN), pki.roots},
		"two URI SANs": {pki.leafWith(t, []string{workloadcert.IdentitySAN, "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"},
			x509.ExtKeyUsageServerAuth), pki.roots},
		"no ServerAuth EKU": {pki.leafWith(t, []string{workloadcert.IdentitySAN}, x509.ExtKeyUsageClientAuth), pki.roots},
		"CA leaf": {pki.leafWith(t, []string{workloadcert.IdentitySAN}, x509.ExtKeyUsageServerAuth, func(c *x509.Certificate) {
			c.IsCA, c.BasicConstraintsValid = true, true
			c.KeyUsage |= x509.KeyUsageCertSign
		}), pki.roots},
		"extra DNS SAN": {pki.leafWith(t, []string{workloadcert.IdentitySAN}, x509.ExtKeyUsageServerAuth, func(c *x509.Certificate) {
			c.DNSNames = []string{"workload-identity.agent-control.svc"}
		}), pki.roots},
		"default test TLS": {}, // httptest's own certificate: DNS names, untrusted
	} {
		var srv *httptest.Server
		var got *[]seen
		var mu *sync.Mutex
		if c.roots == nil {
			srv = httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Errorf("%s: request reached the server", name) }))
			t.Cleanup(srv.Close)
			c.roots = pki.roots
		} else {
			srv, got, mu = fakeIdentity(t, c.cert)
		}
		clock := time.Now()
		ts, _ := fakeTokens(&clock)
		h := localConsole(t, c.roots, srv, ts)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, keyed("GET", "/api/pending?session_id="+sessionID, ""))
		if w.Code != http.StatusBadGateway || reasonCodes(t, w.Body.Bytes())[0] != "IDENTITY_UNREACHABLE" {
			t.Errorf("%s: status %d body %s", name, w.Code, w.Body)
		}
		if got != nil {
			mu.Lock()
			if len(*got) != 0 {
				t.Errorf("%s: request (with token) reached the server", name)
			}
			mu.Unlock()
		}
	}
}

// TestProxyCanonicalizesIDs: IDs reach identity in canonical UUID form.
func TestProxyCanonicalizesIDs(t *testing.T) {
	pki := newPKI(t)
	srv, got, mu := fakeIdentity(t, pki.leaf(t, workloadcert.IdentitySAN))
	clock := time.Now()
	ts, _ := fakeTokens(&clock)
	h := localConsole(t, pki.roots, srv, ts)
	up := strings.ToUpper
	for _, req := range []*http.Request{
		keyed("GET", "/api/pending?session_id="+up(sessionID), ""),
		keyed("GET", "/api/actions/"+up(actionID)+"/contract", ""),
		keyed("POST", "/api/approvals", `{"action_id":"`+up(actionID)+`","displayed_contract_digest":"d","nonce":"n","acknowledged_findings":[]}`),
		keyed("POST", "/api/approvals/"+up(approvalID)+"/revoke", ""),
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("%s: %d", req.URL, w.Code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"session_id=" + sessionID, "/v1/actions/" + actionID + "/approval-contract", `"action_id":"` + actionID + `"`, "/v1/approvals/" + approvalID + "/revoke"}
	for i, s := range *got {
		if !strings.Contains(s.query+s.path+s.body, want[i]) {
			t.Errorf("request %d not canonical: %+v", i, s)
		}
	}
}

// TestApproveRefusesStaleToken: when the command keeps returning a token
// issued too long ago, the approval is refused locally and identity is not
// called.
func TestApproveRefusesStaleToken(t *testing.T) {
	pki := newPKI(t)
	srv, got, mu := fakeIdentity(t, pki.leaf(t, workloadcert.IdentitySAN))
	clock := time.Now()
	issued := clock.Add(-10 * time.Minute)
	runs := 0
	ts := &tokenSource{argv: []string{"fake"}, now: func() time.Time { return clock },
		run: func(context.Context, []string) ([]byte, error) {
			runs++
			return []byte(fakeJWT(clock.Add(time.Hour), issued, "cached")), nil
		}}
	h := localConsole(t, pki.roots, srv, ts)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, keyed("POST", "/api/approvals", `{"action_id":"`+actionID+`","displayed_contract_digest":"d","nonce":"n","acknowledged_findings":[]}`))
	if w.Code != http.StatusServiceUnavailable || reasonCodes(t, w.Body.Bytes())[0] != "TOKEN_UNAVAILABLE" || runs != 1 {
		t.Fatalf("approve with stale token: %d %s runs=%d", w.Code, w.Body, runs)
	}
	mu.Lock()
	if len(*got) != 0 {
		t.Fatal("stale-token approval reached identity")
	}
	mu.Unlock()
	if _, err := ts.Token(context.Background(), approvalTokenMaxAge); err == nil || !strings.Contains(err.Error(), "gcloud auth login") {
		t.Fatalf("stale token error: %v", err)
	}
	// The same token still serves reads.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, keyed("GET", "/api/pending?session_id="+sessionID, ""))
	if w.Code != 200 {
		t.Fatalf("read with the cached token: %d", w.Code)
	}
}

// TestTokenSingleFlight: concurrent callers share one command run, and a
// caller whose cached token is usable does not wait for a refresh.
func TestTokenSingleFlight(t *testing.T) {
	var mu sync.Mutex
	clock := time.Now()
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }
	release := make(chan struct{})
	started := make(chan struct{}, 10)
	var runs int32
	var runsMu sync.Mutex
	ts := &tokenSource{argv: []string{"fake"}, now: now,
		run: func(context.Context, []string) ([]byte, error) {
			runsMu.Lock()
			runs++
			n := runs
			runsMu.Unlock()
			started <- struct{}{}
			if n > 1 {
				<-release
			}
			c := now()
			return []byte(fakeJWT(c.Add(time.Hour), c, fmt.Sprint(n))), nil
		}}
	ctx := context.Background()
	first, err := ts.Token(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	<-started
	mu.Lock()
	clock = clock.Add(approvalTokenMaxAge + time.Second)
	mu.Unlock()

	// Two approvals need a fresh token; the command runs once and blocks.
	results := make(chan string, 2)
	for range 2 {
		go func() {
			tok, err := ts.Token(ctx, approvalTokenMaxAge)
			if err != nil {
				t.Error(err)
			}
			results <- tok
		}()
	}
	<-started
	// A read meanwhile returns the cached token at once.
	done := make(chan string)
	go func() { tok, _ := ts.Token(ctx, 0); done <- tok }()
	select {
	case tok := <-done:
		if tok != first {
			t.Fatal("read did not get the cached token")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read waited for the refresh")
	}
	close(release)
	a, b := <-results, <-results
	if a != b || a == first {
		t.Fatalf("approvals got %q and %q", a, b)
	}
	runsMu.Lock()
	defer runsMu.Unlock()
	if runs != 2 {
		t.Fatalf("command ran %d times, want 2", runs)
	}
}

func TestIdentityURLValidation(t *testing.T) {
	ts := &tokenSource{}
	for _, bad := range []string{"http://workload-identity.agent-control.svc:18443", "https://", "https://h:1/v1", "https://h:1?x=1"} {
		if _, err := newIdentityClient(bad, x509.NewCertPool(), workloadcert.IdentitySAN, "", ts); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// TestRunRejectsEmptyDial: an empty -identity-dial would dial the
// -identity-url host on the port-forward port instead of the Service port.
func TestRunRejectsEmptyDial(t *testing.T) {
	for _, dial := range []string{"", ":", "127.0.0.1", ":18443"} {
		err := run([]string{"-ca-file", "unused.pem", "-identity-dial", dial})
		if err == nil || !strings.Contains(err.Error(), "-identity-dial") {
			t.Errorf("dial %q: err %v", dial, err)
		}
	}
}
