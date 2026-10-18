package healthreport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tlsFixture(t *testing.T, handler http.Handler, serverIdentity string, usage x509.ExtKeyUsage, expired bool) (*httptest.Server, *x509.CertPool, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, identity string, eku x509.ExtKeyUsage, expired bool) tls.Certificate {
		u, err := url.Parse(identity)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{u}}
		if expired {
			cert.NotAfter = now.Add(-time.Minute)
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf(2, serverIdentity, usage, expired)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s, pool, leaf(3, "spiffe://agentarium.internal/ns/agent-sensors/sa/kernel-exporter", x509.ExtKeyUsageClientAuth, false)
}

func clientFor(t *testing.T, s *httptest.Server, roots *x509.CertPool, cert tls.Certificate) *Client {
	t.Helper()
	c, err := NewClient(s.URL, roots, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestMutualTLSFailureReportingWire(t *testing.T) {
	var leases, holds atomic.Int32
	s, roots, cert := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.TLS.VerifiedChains) == 0 || req.Method != "POST" || req.Header.Get("Content-Type") != "application/json" {
			t.Error("unauthenticated or incorrect request")
		}
		switch req.URL.Path {
		case "/internal/control-health/leases":
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(req.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			if len(raw) != 12 || string(raw["active_bundle_revision"]) != "null" || string(raw["canonical_version"]) != "null" || string(raw["observed_state"]) != `"unhealthy"` {
				t.Errorf("invalid lease: %v", raw)
			}
			var until time.Time
			if err := json.Unmarshal(raw["lease_until"], &until); err != nil {
				t.Error(err)
			}
			leases.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"lease_until": until, "scope_state": "unhealthy"})
		case "/internal/holds":
			var raw map[string]json.RawMessage
			if err := json.NewDecoder(req.Body).Decode(&raw); err != nil {
				t.Error(err)
			}
			if len(raw) != 4 || string(raw["reason"]) != `"sensor_degraded"` || string(raw["evidence_refs"]) != `[]` {
				t.Errorf("invalid hold: %v", raw)
			}
			holds.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"hold_id":"284f92a1-65d9-4e81-a295-271e0af59cc8","decision":"created","reason_codes":[]}`)
		default:
			t.Error(req.URL.Path)
			http.NotFound(w, req)
		}
	}), healthSAN, x509.ExtKeyUsageServerAuth, false)
	m := NewMonitor()
	m.DurabilityFailed()
	r := reporter(t, m, clientFor(t, s, roots, cert))
	if err := r.Report(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := r.Report(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if leases.Load() != 2 || holds.Load() != 1 {
		t.Fatalf("lease=%d hold=%d", leases.Load(), holds.Load())
	}
}

func TestTLSRejectsWrongPeerAndMissingClient(t *testing.T) {
	for _, name := range []string{"wrong-san", "client-eku", "expired", "untrusted", "missing-client"} {
		t.Run(name, func(t *testing.T) {
			identity, usage := healthSAN, x509.ExtKeyUsageServerAuth
			if name == "wrong-san" {
				identity = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
			}
			if name == "client-eku" {
				usage = x509.ExtKeyUsageClientAuth
			}
			var calls atomic.Int32
			s, roots, cert := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), identity, usage, name == "expired")
			if name == "untrusted" {
				roots = x509.NewCertPool()
			}
			if name == "missing-client" {
				cert = tls.Certificate{}
			}
			c := clientFor(t, s, roots, cert)
			if c.RequestHold(context.Background(), Hold{}) == nil || calls.Load() != 0 {
				t.Fatal("TLS boundary accepted incorrect credentials")
			}
		})
	}
}

func TestBadHoldAcknowledgementsRetry(t *testing.T) {
	for _, body := range []string{
		`{"hold_id":"284f92a1-65d9-4e81-a295-271e0af59cc8","decision":"rejected","reason_codes":["FORBIDDEN"]}`,
		`{"hold_id":"","decision":"created","reason_codes":[]}`,
		`{"hold_id":"284f92a1-65d9-4e81-a295-271e0af59cc8","decision":"created","decision":"existing","reason_codes":[]}`,
		`{"hold_id":"284f92a1-65d9-4e81-a295-271e0af59cc8","decision":"created","extra":true}`,
		`{"hold_id":"284f92a1-65d9-4e81-a295-271e0af59cc8","decision":"created"} {}`,
		strings.Repeat("x", (1<<20)+1),
	} {
		s, roots, cert := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }), healthSAN, x509.ExtKeyUsageServerAuth, false)
		if clientFor(t, s, roots, cert).RequestHold(context.Background(), Hold{}) == nil {
			t.Fatal("accepted invalid acknowledgement")
		}
	}
}

func TestRedirectAndHTTPErrorDoNotReachOtherOrigin(t *testing.T) {
	var reached atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1) }))
	defer target.Close()
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusForbidden, http.StatusServiceUnavailable} {
		s, roots, cert := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", target.URL)
			w.WriteHeader(status)
		}), healthSAN, x509.ExtKeyUsageServerAuth, false)
		if clientFor(t, s, roots, cert).RequestHold(context.Background(), Hold{}) == nil {
			t.Fatal("accepted HTTP error")
		}
	}
	if reached.Load() != 0 {
		t.Fatal("followed redirect")
	}
}

func TestLeaseAcknowledgementMustFitRequestedInterval(t *testing.T) {
	now := time.Now().UTC()
	lease := Lease{ReportedAt: now, LeaseUntil: now.Add(15 * time.Second)}
	for _, tc := range []struct {
		until time.Time
		state string
	}{
		{now, "unhealthy"},
		{now.Add(16 * time.Second), "unhealthy"},
		{now.Add(15 * time.Second), "unknown"},
		{time.Time{}, "healthy"},
	} {
		s, roots, cert := tlsFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"lease_until": tc.until, "scope_state": tc.state})
		}), healthSAN, x509.ExtKeyUsageServerAuth, false)
		if clientFor(t, s, roots, cert).ReportLease(context.Background(), lease) == nil {
			t.Fatalf("accepted invalid lease acknowledgement: %+v", tc)
		}
	}
}
