package healthreport

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

func TestServicePeerTLS(t *testing.T) {
	const san = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
	ca := testpki.NewCA(t, "audit test root")
	otherCA := testpki.NewCA(t, "untrusted root")
	caFile := ca.WritePEM(t)
	clientCert := ca.Issue(t, nil, nil, []string{"spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"})
	cases := []struct {
		name      string
		mutate    func(*x509.Certificate)
		untrusted bool
	}{
		{name: "valid"},
		{name: "wrong_uri", mutate: func(c *x509.Certificate) { c.URIs[0], _ = url.Parse(workloadcert.IdentitySAN) }},
		{name: "extra_uri", mutate: func(c *x509.Certificate) { u, _ := url.Parse(workloadcert.IdentitySAN); c.URIs = append(c.URIs, u) }},
		{name: "dns_san", mutate: func(c *x509.Certificate) { c.DNSNames = []string{"control-health"} }},
		{name: "ip_san", mutate: func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }},
		{name: "email_san", mutate: func(c *x509.Certificate) { c.EmailAddresses = []string{"test@example.test"} }},
		{name: "no_eku", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = nil }},
		{name: "any_eku", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }},
		{name: "client_only", mutate: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
		{name: "ca_leaf", mutate: func(c *x509.Certificate) {
			c.IsCA = true
			c.BasicConstraintsValid = true
			c.KeyUsage |= x509.KeyUsageCertSign
		}},
		{name: "expired", mutate: func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Minute) }},
		{name: "future", mutate: func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) }},
		{name: "untrusted", untrusted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(san)
			leaf := &x509.Certificate{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour), URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
			if tc.mutate != nil {
				tc.mutate(leaf)
			}
			issuer := ca
			if tc.untrusted {
				issuer = otherCA
			}
			cert := issuer.IssueTemplate(t, leaf)
			for _, mode := range []string{"file", "managed"} {
				t.Run(mode, func(t *testing.T) {
					var requests atomic.Int32
					srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						requests.Add(1)
						if mode == "file" && len(r.TLS.PeerCertificates) != 1 {
							t.Error("client certificate not presented")
						}
						w.WriteHeader(http.StatusNoContent)
					}))
					srv.Config.ErrorLog = log.New(io.Discard, "", 0)
					srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert.TLS}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
					srv.StartTLS()
					defer srv.Close()
					var client *http.Client
					if mode == "file" {
						var err error
						client, err = Client(srv.URL, clientCert.CertFile, clientCert.KeyFile, caFile)
						if err != nil {
							t.Fatal(err)
						}
					} else {
						client = (&workloadcert.Manager{CAFile: caFile}).Client(san, false)
					}
					defer client.CloseIdleConnections()
					resp, err := client.Post(srv.URL, "application/json", nil)
					if resp != nil {
						resp.Body.Close()
					}
					if tc.name == "valid" {
						if err != nil || requests.Load() != 1 {
							t.Fatalf("valid peer: err=%v requests=%d", err, requests.Load())
						}
					} else if err == nil || requests.Load() != 0 {
						t.Fatalf("invalid peer accepted: err=%v requests=%d", err, requests.Load())
					}
				})
			}
		})
	}
}
