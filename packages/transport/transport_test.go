package transport_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

const host = "receiver.agent-targets.svc"

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, network, h string) ([]netip.Addr, error) {
	if network != "ip4" {
		return nil, &net.DNSError{Err: "not ip4", Name: h}
	}
	a, ok := f[h]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}
	}
	return a, nil
}

type target struct {
	srv   *httptest.Server
	ca    *testpki.CA
	port  string
	count atomic.Int32
	last  atomic.Pointer[http.Request]
	body  atomic.Pointer[[]byte]
}

func newTarget(t *testing.T, h http.HandlerFunc) *target {
	t.Helper()
	tg := &target{ca: testpki.NewCA(t, "target-ca")}
	leaf := tg.ca.Issue(t, []string{host}, nil, nil)
	tg.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tg.count.Add(1)
		b, _ := io.ReadAll(r.Body)
		tg.body.Store(&b)
		tg.last.Store(r)
		h(w, r)
	}))
	tg.srv.EnableHTTP2 = true
	tg.srv.TLS = &tls.Config{Certificates: []tls.Certificate{leaf.TLS}, NextProtos: []string{"h2", "http/1.1"}}
	tg.srv.StartTLS()
	t.Cleanup(tg.srv.Close)
	_, tg.port, _ = net.SplitHostPort(tg.srv.Listener.Addr().String())
	return tg
}

func (tg *target) request(body string) transport.Request {
	b := []byte(body)
	return transport.Request{
		Plan: canonical.WirePlan{
			Method: "POST", OriginID: "https://" + host + ":" + tg.port, Route: "/test/v1/submissions",
			SafeHeaders:    map[string]string{"Idempotency-Key": "8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f", "User-Agent": "agentarium-adapter/test", "Content-Type": "application/json"},
			BodyBytes:      b,
			WireBodyDigest: canonical.WireBodyDigest(b),
			ResponseLimit:  1024, Timeout: 3 * time.Second,
			ExpectedTLSName: host, AllowedCIDRs: []string{"127.0.0.0/8"},
		},
		AttemptID: "11111111-2222-4333-8444-555555555555",
		CARef:     "cluster",
		RootCAs:   tg.ca.Pool,
	}
}

func loopback() fakeResolver {
	return fakeResolver{host: {netip.MustParseAddr("127.0.0.1")}}
}

func TestSuccessRecordsObservation(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1") // must be ignored (Proxy nil)
	tg := newTarget(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Audit-Id", "audit-1")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"effect_id":"e1"}`))
	})
	var wrote atomic.Int32
	r := transport.Do(context.Background(), transport.Config{Resolver: loopback(), OnWroteHeaders: func(o transport.Observation) {
		if o.SendStartedAt == nil || o.LocalAddr == nil {
			t.Error("OnWroteHeaders observation lacks send_started_at/local_addr")
		}
		wrote.Add(1)
	}}, tg.request(`{"email":null,"summary":"x"}`))
	if !r.Responded || r.StatusCode != 201 || string(r.Body) != `{"effect_id":"e1"}` {
		t.Fatalf("result %+v err %v", r, r.Err)
	}
	if wrote.Load() != 1 || !r.WroteHeaders {
		t.Fatal("WroteHeaders hook not called once")
	}
	o := r.Observation
	for name, v := range map[string]bool{
		"local_addr": o.LocalAddr != nil, "local_port": o.LocalPort != nil, "peer_addr": o.PeerAddr != nil,
		"dialed_addr": o.DialedAddr != nil, "peer_addr_kind": o.PeerAddrKind != nil, "connect_started_at": o.ConnectStartedAt != nil,
		"send_started_at": o.SendStartedAt != nil, "send_finished_at": o.SendFinishedAt != nil, "response_at": o.ResponseAt != nil,
		"k8s_audit_id": o.K8sAuditID != nil, "wire_body_digest": o.WireBodyDigest != nil,
	} {
		if !v {
			t.Errorf("observation %s missing", name)
		}
	}
	if *o.DialedAddr != "127.0.0.1" || *o.PeerAddrKind != transport.PeerServiceVIP {
		t.Errorf("dialed %s kind %s", *o.DialedAddr, *o.PeerAddrKind)
	}
	req := tg.last.Load()
	if req.Proto != "HTTP/1.1" || !req.Close {
		t.Errorf("proto %s close %v: want HTTP/1.1 without keep-alive", req.Proto, req.Close)
	}
	if req.Header.Get("X-Agentarium-Attempt-Id") != "11111111-2222-4333-8444-555555555555" || req.Header.Get("Accept-Encoding") != "" {
		t.Errorf("headers %v", req.Header)
	}
	if got := *tg.body.Load(); string(got) != `{"email":null,"summary":"x"}` {
		t.Errorf("body %q", got)
	}
}

func TestDestinationOutsideCIDRNotDialed(t *testing.T) {
	tg := newTarget(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	for name, res := range map[string]fakeResolver{
		"outside": {host: {netip.MustParseAddr("10.0.0.9")}},
		"mixed":   {host: {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("192.0.2.1")}},
	} {
		r := transport.Do(context.Background(), transport.Config{Resolver: res}, tg.request("{}"))
		if !r.Failed() || r.Stage != transport.StageCIDR || r.ReasonCodes[0] != "DESTINATION_NOT_ALLOWED" {
			t.Errorf("%s: %+v", name, r)
		}
		if r.Observation.LocalAddr != nil || r.Observation.NetnsInode != nil {
			t.Errorf("%s: a connection was made", name)
		}
	}
	if tg.count.Load() != 0 {
		t.Fatal("target received a request")
	}
}

func TestTLSNameMismatchFails(t *testing.T) {
	tg := newTarget(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	req := tg.request("{}")
	req.Plan.ExpectedTLSName = "other.agent-targets.svc"
	r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, req)
	if !r.Failed() || r.Stage != transport.StageTLS || r.ReasonCodes[0] != "TLS_VERIFY_FAILED" {
		t.Fatalf("%+v", r)
	}
	if tg.count.Load() != 0 {
		t.Fatal("target received a request")
	}
}

func TestConnectRefusedFails(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(l.Addr().String())
	l.Close()
	tg := &target{ca: testpki.NewCA(t, "x"), port: port}
	r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, tg.request("{}"))
	if !r.Failed() || r.Stage != transport.StageConnect || r.WroteHeaders {
		t.Fatalf("%+v", r)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	tg := newTarget(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+host+"/elsewhere", http.StatusFound)
	})
	r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, tg.request("{}"))
	if !r.Responded || r.StatusCode != 302 || tg.count.Load() != 1 {
		t.Fatalf("status %d count %d", r.StatusCode, tg.count.Load())
	}
}

func TestOversizeResponse(t *testing.T) {
	tg := newTarget(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 2000)))
	})
	r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, tg.request("{}"))
	if !r.Responded || !r.Oversize || len(r.Body) != 1024 {
		t.Fatalf("oversize %v len %d", r.Oversize, len(r.Body))
	}
}

// After WroteHeaders the target closes the connection without a response:
// unknown, sent once, never retried.
func TestNoResponseAfterHeadersIsUnknown(t *testing.T) {
	tg := newTarget(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
	})
	r := transport.Do(context.Background(), transport.Config{Resolver: loopback()}, tg.request(`{"a":1}`))
	if !r.Unknown() || r.Stage != transport.StageResponse {
		t.Fatalf("%+v err %v", r, r.Err)
	}
	if r.Observation.ResponseAt != nil || r.Observation.SendStartedAt == nil {
		t.Fatal("unknown must carry send_started_at and no response_at")
	}
	if tg.count.Load() != 1 {
		t.Fatalf("target saw %d requests, want 1 (no retry)", tg.count.Load())
	}
}

func TestHeaderBudget(t *testing.T) {
	tg := &target{ca: testpki.NewCA(t, "x"), port: "8443"}
	req := tg.request("{}")
	req.CredentialHeader, req.CredentialHeaderValue = "X-Api-Key", strings.Repeat("k", 2100)
	if err := transport.Validate(req); err == nil {
		t.Fatal("2KiB header budget not enforced")
	}
	req.CredentialHeaderValue = "k"
	if err := transport.Validate(req); err != nil {
		t.Fatal(err)
	}
	req.Plan.BodyBytes = []byte(`{"changed":1}`)
	if err := transport.Validate(req); err == nil {
		t.Fatal("body that does not match wire_body_digest accepted")
	}
}

// HeaderBytes must match what net/http writes for the request line and headers.
func TestHeaderBytesMatchesWire(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://"+host+":8443/test/v1/submissions", strings.NewReader("{}"))
	r.ContentLength = 2
	r.Header.Set("User-Agent", "agentarium-adapter/test")
	r.Header.Set("Idempotency-Key", "k")
	r.Close = false
	var sb strings.Builder
	w := bufio.NewWriter(&sb)
	if err := r.Write(w); err != nil {
		t.Fatal(err)
	}
	w.Flush()
	head, _, _ := strings.Cut(sb.String(), "\r\n\r\n")
	if got, want := transport.HeaderBytes(r), len(head)+4; got != want {
		t.Fatalf("HeaderBytes %d, wire %d (%s)", got, want, strconv.Quote(head))
	}
}
