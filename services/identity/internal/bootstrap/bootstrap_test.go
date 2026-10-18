package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
)

const (
	podUID  = "11111111-2222-3333-4444-555555555555"
	nodeUID = "99999999-8888-7777-6666-555555555555"
)

type fakeCluster struct {
	review    TokenReview
	reviewErr error
	pods      map[string]Pod
	nodes     map[string]Node
	podErr    error
	nodeErr   error
	gotAud    []string
}

func (f *fakeCluster) ReviewToken(_ context.Context, token string, aud []string) (TokenReview, error) {
	f.gotAud = aud
	if f.reviewErr != nil {
		return TokenReview{}, f.reviewErr
	}
	if token != "good-token" {
		return TokenReview{Authenticated: false}, nil
	}
	return f.review, nil
}

func (f *fakeCluster) GetPod(_ context.Context, ns, name string) (Pod, error) {
	if f.podErr != nil {
		return Pod{}, f.podErr
	}
	p, ok := f.pods[ns+"/"+name]
	if !ok {
		return Pod{}, ErrNotFound
	}
	return p, nil
}

func (f *fakeCluster) GetNode(_ context.Context, name string) (Node, error) {
	if f.nodeErr != nil {
		return Node{}, f.nodeErr
	}
	n, ok := f.nodes[name]
	if !ok {
		return Node{}, ErrNotFound
	}
	return n, nil
}

type fakeStore struct {
	workloads map[string]Workload
	recorded  []IssuedRecord
	recordErr error
	lookupErr error
}

func (f *fakeStore) Workload(_ context.Context, ns, ksa string) (Workload, bool, error) {
	if f.lookupErr != nil {
		return Workload{}, false, f.lookupErr
	}
	w, ok := f.workloads[ns+"/"+ksa]
	return w, ok, nil
}

func (f *fakeStore) RecordIssued(_ context.Context, r IssuedRecord) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.recorded = append(f.recorded, r)
	return nil
}

type fakeIssuer struct {
	got []issuer.Request
	err error
}

func (f *fakeIssuer) Issue(_ context.Context, r issuer.Request) (issuer.Certificate, error) {
	f.got = append(f.got, r)
	if f.err != nil {
		return issuer.Certificate{}, f.err
	}
	return issuer.Certificate{LeafPEM: "LEAF", Serial: "0a", NotAfter: time.Date(2026, 10, 15, 15, 0, 0, 0, time.UTC)}, nil
}

func newCSR(t *testing.T, sans ...string) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var us []*url.URL
	for _, s := range sans {
		u, _ := url.Parse(s)
		us = append(us, u)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}, URIs: us}, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

type env struct {
	svc *Service
	cl  *fakeCluster
	st  *fakeStore
	is  *fakeIssuer
}

func newEnv(ns, ksa string, role pki.Role) *env {
	cl := &fakeCluster{
		review: TokenReview{Authenticated: true, Audiences: []string{Audience},
			Username: "system:serviceaccount:" + ns + ":" + ksa,
			Extra:    map[string][]string{extraPodUID: {podUID}, extraPodName: {"p-0"}}},
		pods:  map[string]Pod{ns + "/p-0": {UID: podUID, Namespace: ns, Name: "p-0", ServiceAccount: ksa, NodeName: "n1"}},
		nodes: map[string]Node{"n1": {UID: nodeUID, BootID: "boot-1"}},
	}
	st := &fakeStore{workloads: map[string]Workload{ns + "/" + ksa: {Namespace: ns, KSA: ksa, Role: role, Enabled: true}}}
	is := &fakeIssuer{}
	return &env{svc: &Service{Cluster: cl, Store: st, Issuer: is, NewID: func() string { return "id" }}, cl: cl, st: st, is: is}
}

func TestIssueRuntime(t *testing.T) {
	e := newEnv("agent-exec", "agent-runtime", pki.RoleRuntime)
	// The CSR asks for the identity service's own SAN; it must be ignored.
	csr := newCSR(t, "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity")
	if _, err := e.svc.Issue(context.Background(), "good-token", csr); err != nil {
		t.Fatal(err)
	}
	if len(e.cl.gotAud) != 1 || e.cl.gotAud[0] != Audience {
		t.Fatalf("audiences = %v", e.cl.gotAud)
	}
	req := e.is.got[0]
	want := "spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + podUID
	if req.SAN != want || !req.ClientOnly {
		t.Fatalf("issuer request = %+v", req)
	}
	rec := e.st.recorded[0]
	if rec.PodUID != podUID || rec.NodeUID != nodeUID || rec.BootID != "boot-1" || rec.SAN != want || rec.Serial != "0a" {
		t.Fatalf("record = %+v", rec)
	}
}

func TestIssueService(t *testing.T) {
	e := newEnv("agent-control", "policy-gateway", pki.RoleService)
	if _, err := e.svc.Issue(context.Background(), "good-token", newCSR(t)); err != nil {
		t.Fatal(err)
	}
	if r := e.is.got[0]; r.SAN != "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway" || r.ClientOnly {
		t.Fatalf("issuer request = %+v", r)
	}
	if e.st.recorded[0].PodUID != "" {
		t.Fatal("service certificate recorded with a pod uid")
	}
}

// The lifecycle sources (COMMON "Lifecycle source authentication and epoch") keep the
// service SAN and EKU but record the Pod UID, so the revoker revokes their
// certificates when the Pod is deleted.
func TestIssueLifecycleSourceService(t *testing.T) {
	for _, w := range [][2]string{{"agent-sensors", "lifecycle-recorder"}, {"agent-observe", "pod-watcher"}} {
		e := newEnv(w[0], w[1], pki.RoleService)
		if _, err := e.svc.Issue(context.Background(), "good-token", newCSR(t)); err != nil {
			t.Fatalf("%s/%s: %v", w[0], w[1], err)
		}
		want := "spiffe://agentarium.internal/ns/" + w[0] + "/sa/" + w[1]
		if r := e.is.got[0]; r.SAN != want || r.ClientOnly {
			t.Fatalf("%s/%s: issuer request = %+v", w[0], w[1], r)
		}
		rec := e.st.recorded[0]
		if rec.PodUID != podUID || rec.NodeUID != nodeUID || rec.BootID != "boot-1" || rec.SAN != want {
			t.Fatalf("%s/%s: record = %+v", w[0], w[1], rec)
		}
	}
}

func TestPodBound(t *testing.T) {
	cases := []struct {
		role    pki.Role
		ns, ksa string
		want    bool
	}{
		{pki.RoleRuntime, "agent-exec", "agent-runtime", true},
		{pki.RoleProbe, "agent-adapters", "probe-runner", true},
		{pki.RoleService, "agent-sensors", "lifecycle-recorder", true},
		{pki.RoleService, "agent-observe", "pod-watcher", true},
		{pki.RoleService, "agent-observe", "control-health", false},
		{pki.RoleService, "agent-sensors", "runtime-guard", false},
		// The KSA name alone does not bind: the namespace must match too.
		{pki.RoleService, "agent-observe", "lifecycle-recorder", false},
		{pki.RoleService, "agent-sensors", "pod-watcher", false},
		// A lifecycle source KSA registered with another role keeps that role's rule.
		{pki.RoleAdapter, "agent-sensors", "lifecycle-recorder", false},
		{pki.RoleAdapter, "agent-adapters", "model-adapter", false},
	}
	for _, c := range cases {
		if got := PodBound(c.role, c.ns, c.ksa); got != c.want {
			t.Errorf("PodBound(%s, %s/%s) = %v, want %v", c.role, c.ns, c.ksa, got, c.want)
		}
	}
}

// TASK-03 chapter 7 "certificate issuance": expired token, other audience, deleted Pod,
// unregistered SA, CSR SAN forgery are all refused.
func TestIssueRejects(t *testing.T) {
	cases := map[string]struct {
		token  string
		mutate func(e *env)
		want   error
	}{
		"invalid or expired token": {token: "expired", want: ErrUnauthenticated},
		"other audience":           {mutate: func(e *env) { e.cl.review.Audiences = []string{"https://kubernetes.default.svc"} }, want: ErrUnauthenticated},
		"not a service account":    {mutate: func(e *env) { e.cl.review.Username = "alice@example.com" }, want: ErrUnauthenticated},
		"no pod-uid extra":         {mutate: func(e *env) { delete(e.cl.review.Extra, extraPodUID) }, want: ErrUnauthenticated},
		"two pod-uid values":       {mutate: func(e *env) { e.cl.review.Extra[extraPodUID] = []string{podUID, podUID} }, want: ErrUnauthenticated},
		"deleted pod":              {mutate: func(e *env) { e.cl.pods = map[string]Pod{} }, want: ErrUnauthenticated},
		"pod being deleted": {mutate: func(e *env) {
			p := e.cl.pods["agent-exec/p-0"]
			p.Deleting = true
			e.cl.pods["agent-exec/p-0"] = p
		}, want: ErrUnauthenticated},
		"recreated pod with other uid": {mutate: func(e *env) {
			p := e.cl.pods["agent-exec/p-0"]
			p.UID = "22222222-2222-3333-4444-555555555555"
			e.cl.pods["agent-exec/p-0"] = p
		}, want: ErrUnauthenticated},
		"pod runs as other sa": {mutate: func(e *env) {
			p := e.cl.pods["agent-exec/p-0"]
			p.ServiceAccount = "probe-runner"
			e.cl.pods["agent-exec/p-0"] = p
		}, want: ErrUnauthenticated},
		"unregistered sa": {mutate: func(e *env) { e.st.workloads = map[string]Workload{} }, want: ErrUnauthenticated},
		"disabled workload": {mutate: func(e *env) {
			w := e.st.workloads["agent-exec/agent-runtime"]
			w.Enabled = false
			e.st.workloads["agent-exec/agent-runtime"] = w
		}, want: ErrUnauthenticated},
		"unscheduled pod":   {mutate: func(e *env) { p := e.cl.pods["agent-exec/p-0"]; p.NodeName = ""; e.cl.pods["agent-exec/p-0"] = p }, want: ErrUnauthenticated},
		"node gone":         {mutate: func(e *env) { e.cl.nodes = map[string]Node{} }, want: ErrUnauthenticated},
		"node without boot": {mutate: func(e *env) { e.cl.nodes["n1"] = Node{UID: nodeUID} }, want: ErrUnauthenticated},
		"node bridge closed": {mutate: func(e *env) {
			w := e.st.workloads["agent-exec/agent-runtime"]
			w.Role = pki.RoleNodeBridge
			e.st.workloads["agent-exec/agent-runtime"] = w
		}, want: ErrUnauthenticated},
		"token review down": {mutate: func(e *env) { e.cl.reviewErr = errors.New("api down") }, want: ErrClusterUnavailable},
		"pod get fails":     {mutate: func(e *env) { e.cl.podErr = errors.New("api down") }, want: ErrClusterUnavailable},
		"node get fails":    {mutate: func(e *env) { e.cl.nodeErr = errors.New("api down") }, want: ErrClusterUnavailable},
		"db read fails":     {mutate: func(e *env) { e.st.lookupErr = errors.New("db down") }, want: ErrStoreUnavailable},
		"ca down":           {mutate: func(e *env) { e.is.err = errors.New("cas down") }, want: ErrIssuerUnavailable},
		"db write fails":    {mutate: func(e *env) { e.st.recordErr = errors.New("db down") }, want: ErrStoreUnavailable},
	}
	for name, c := range cases {
		e := newEnv("agent-exec", "agent-runtime", pki.RoleRuntime)
		if c.mutate != nil {
			c.mutate(e)
		}
		token := c.token
		if token == "" {
			token = "good-token"
		}
		cert, err := e.svc.Issue(context.Background(), token, newCSR(t))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
		if c.want != ErrUnauthenticated && !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s: err = %v does not match ErrUnavailable", name, err)
		}
		if cert.LeafPEM != "" {
			t.Errorf("%s: certificate returned", name)
		}
		if c.want == ErrUnauthenticated && len(e.is.got) != 0 {
			t.Errorf("%s: CA called for an unauthenticated caller", name)
		}
	}
}

func post(t *testing.T, h http.Handler, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/internal/workload-certificates", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHandler(t *testing.T) {
	e := newEnv("agent-exec", "agent-runtime", pki.RoleRuntime)
	h := e.svc.Handler()
	csr, _ := json.Marshal(string(newCSR(t)))

	// A forged peer identity header is ignored; the SAN comes from the token.
	w := post(t, h, `{"csr":`+string(csr)+`,"token":"good-token"}`,
		map[string]string{"X-Agentarium-Peer-Identity": "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["certificate"] != "LEAF" || out["expires_at"] != "2026-10-15T15:00:00Z" {
		t.Fatalf("body = %v", out)
	}
	if !strings.HasSuffix(e.is.got[0].SAN, "/pod/"+podUID) {
		t.Fatalf("SAN = %s", e.is.got[0].SAN)
	}

	bad := map[string]struct {
		body string
		code int
	}{
		"unknown field":   {`{"csr":` + string(csr) + `,"token":"good-token","san":"x"}`, 422},
		"duplicate field": {`{"csr":` + string(csr) + `,"token":"a","token":"good-token"}`, 422},
		"case variant":    {`{"CSR":` + string(csr) + `,"token":"good-token"}`, 422},
		"missing field":   {`{"token":"good-token"}`, 422},
		"trailing data":   {`{"csr":` + string(csr) + `,"token":"good-token"} {}`, 422},
		"not an object":   {`[]`, 422},
		"bad csr":         {`{"csr":"nope","token":"good-token"}`, 422},
		"bad token":       {`{"csr":` + string(csr) + `,"token":"other"}`, 401},
		"too large":       {`{"csr":"` + strings.Repeat("a", MaxBodyBytes) + `","token":"x"}`, 413},
	}
	for name, c := range bad {
		if w := post(t, h, c.body, nil); w.Code != c.code {
			t.Errorf("%s: status %d, want %d (%s)", name, w.Code, c.code, w.Body)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("connection reset") }

func decodeError(t *testing.T, w *httptest.ResponseRecorder) errorBody {
	t.Helper()
	var b errorBody
	dec := json.NewDecoder(w.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		t.Fatalf("error body: %v", err)
	}
	if len(b.RequestID) != 32 {
		t.Errorf("request_id = %q", b.RequestID)
	}
	if b.ReasonCodes == nil {
		t.Error("reason_codes is null")
	}
	return b
}

// TestHandlerReasonCodes pins the status, reason_codes and Retry-After of
// every error the handler returns.
func TestHandlerReasonCodes(t *testing.T) {
	csr, _ := json.Marshal(string(newCSR(t)))
	good := `{"csr":` + string(csr) + `,"token":"good-token"}`
	// A valid CSR padded with trailing newlines to one byte over 8 KiB, so
	// only the size limit rejects it.
	raw := newCSR(t)
	bigCSR, _ := json.Marshal(string(raw) + strings.Repeat("\n", pki.MaxCSRBytes+1-len(raw)))

	cases := map[string]struct {
		mutate     func(e *env)
		req        func() *http.Request
		status     int
		codes      []string
		retryAfter string
	}{
		"token review down": {mutate: func(e *env) { e.cl.reviewErr = errors.New("api down") }, status: 503, codes: []string{"STATE_STORE_UNAVAILABLE"}, retryAfter: "2"},
		"pod get fails":     {mutate: func(e *env) { e.cl.podErr = errors.New("api down") }, status: 503, codes: []string{"STATE_STORE_UNAVAILABLE"}, retryAfter: "2"},
		"node get fails":    {mutate: func(e *env) { e.cl.nodeErr = errors.New("api down") }, status: 503, codes: []string{"STATE_STORE_UNAVAILABLE"}, retryAfter: "2"},
		"db read fails":     {mutate: func(e *env) { e.st.lookupErr = errors.New("db down") }, status: 503, codes: []string{"STATE_STORE_UNAVAILABLE"}, retryAfter: "2"},
		"db write fails":    {mutate: func(e *env) { e.st.recordErr = errors.New("db down") }, status: 503, codes: []string{"STATE_STORE_UNAVAILABLE"}, retryAfter: "2"},
		"ca down":           {mutate: func(e *env) { e.is.err = errors.New("cas down") }, status: 503, codes: []string{"CREDENTIAL_UNAVAILABLE"}, retryAfter: "2"},

		"bad token":       {req: func() *http.Request { return jsonReq(`{"csr":` + string(csr) + `,"token":"other"}`) }, status: 401, codes: []string{"AUTH_REQUIRED"}},
		"empty token":     {req: func() *http.Request { return jsonReq(`{"csr":"nope","token":""}`) }, status: 401, codes: []string{"AUTH_REQUIRED"}},
		"unregistered sa": {mutate: func(e *env) { e.st.workloads = map[string]Workload{} }, status: 401, codes: []string{"AUTH_REQUIRED"}},
		"bad csr":         {req: func() *http.Request { return jsonReq(`{"csr":"nope","token":"good-token"}`) }, status: 422, codes: []string{"SCHEMA_INVALID"}},
		"csr over 8KiB":   {req: func() *http.Request { return jsonReq(`{"csr":` + string(bigCSR) + `,"token":"good-token"}`) }, status: 422, codes: []string{"SCHEMA_INVALID"}},
		"unknown field":   {req: func() *http.Request { return jsonReq(`{"csr":"x","token":"y","san":"z"}`) }, status: 422, codes: []string{"SCHEMA_INVALID"}},
		"body over 64KiB": {req: func() *http.Request {
			return jsonReq(`{"csr":"` + strings.Repeat("a", MaxBodyBytes) + `","token":"x"}`)
		}, status: 413, codes: []string{"BODY_TOO_LARGE"}},
		"get": {req: func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/internal/workload-certificates", nil)
		}, status: 405, codes: []string{}},
		"text/plain": {req: func() *http.Request {
			r := jsonReq(good)
			r.Header.Set("Content-Type", "text/plain")
			return r
		}, status: 415, codes: []string{"SCHEMA_INVALID"}},
		"no content type": {req: func() *http.Request {
			r := jsonReq(good)
			r.Header.Del("Content-Type")
			return r
		}, status: 415, codes: []string{"SCHEMA_INVALID"}},
		"body read fails": {req: func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/internal/workload-certificates", errReader{})
			r.Header.Set("Content-Type", "application/json")
			return r
		}, status: 400, codes: []string{"SCHEMA_INVALID"}},
	}
	for name, c := range cases {
		e := newEnv("agent-exec", "agent-runtime", pki.RoleRuntime)
		if c.mutate != nil {
			c.mutate(e)
		}
		r := jsonReq(good)
		if c.req != nil {
			r = c.req()
		}
		w := httptest.NewRecorder()
		e.svc.Handler().ServeHTTP(w, r)
		if w.Code != c.status {
			t.Errorf("%s: status %d, want %d (%s)", name, w.Code, c.status, w.Body)
			continue
		}
		if ct := w.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: Content-Type %q", name, ct)
		}
		if got := w.Header().Get("Retry-After"); got != c.retryAfter {
			t.Errorf("%s: Retry-After %q, want %q", name, got, c.retryAfter)
		}
		b := decodeError(t, w)
		if strings.Join(b.ReasonCodes, ",") != strings.Join(c.codes, ",") {
			t.Errorf("%s: reason_codes %v, want %v", name, b.ReasonCodes, c.codes)
		}
	}
}

func TestUnavailableCodeFallback(t *testing.T) {
	if got := unavailableCode(errors.New("unclassified")); got != "STATE_STORE_UNAVAILABLE" {
		t.Fatalf("got %s", got)
	}
}

func jsonReq(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/internal/workload-certificates", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}
