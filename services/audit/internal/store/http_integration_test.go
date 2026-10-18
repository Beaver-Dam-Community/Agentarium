package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/audit/internal/ingest"
	"github.com/jackc/pgx/v5"
)

// Called inside the disposable PostgreSQL test after actual identity/audit
// migrations and writer grants. The CA is local; no identity/CAS service is
// simulated as verified. HTTP, authorizer, SQL and COMMIT are the real path.
func testMutualTLSPostgres(t *testing.T, store Store, auth *Authorizer, db *pgx.Conn, event func() ([]byte, ingest.Event)) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "local integration CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	issue := func(name, san string, serial int64, usage x509.ExtKeyUsage) (tls.Certificate, string, string) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(san)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, DNSNames: []string{"localhost"}, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		certPath, keyPath := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
		if err := os.WriteFile(certPath, cp, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, kp, 0600); err != nil {
			t.Fatal(err)
		}
		cert, err := tls.X509KeyPair(cp, kp)
		if err != nil {
			t.Fatal(err)
		}
		return cert, certPath, keyPath
	}
	_, certPath, keyPath := issue("server", "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer", 2, x509.ExtKeyUsageServerAuth)
	caller, _, _ := issue("caller", "spiffe://agentarium.internal/ns/agent-control/sa/coordinator", 3, x509.ExtKeyUsageClientAuth)
	other, _, _ := issue("other", "spiffe://agentarium.internal/ns/agent-control/sa/other", 4, x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(ingest.Handler{Store: store, Authorizer: auth})
	server.TLS, err = ingest.LoadTLS(certPath, keyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := func(certs []tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: certs, MinVersion: tls.VersionTLS13}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	trusted := client([]tls.Certificate{caller})
	post := func(c *http.Client, body []byte, expected int) ingest.Ack {
		t.Helper()
		resp, err := c.Post(server.URL+"/internal/audit/events", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != expected {
			t.Fatalf("HTTP %d, expected %d", resp.StatusCode, expected)
		}
		var ack ingest.Ack
		if expected == 200 || expected == 201 {
			if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
				t.Fatal(err)
			}
		} else if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
		return ack
	}
	count := func(table, column, id string, expected int) {
		t.Helper()
		var actual int
		if err := db.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE "+column+"=$1", id).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if actual != expected {
			t.Fatalf("%s count %d, expected %d", table, actual, expected)
		}
	}
	_, nul := event()
	nul.SafePayload["revoke_reason"] = json.RawMessage(`"nul\u0000value"`)
	nulRaw, nul := signed(t, nul)
	post(trusted, nulRaw, 422)
	count("audit.audit_events", "event_id", nul.EventID, 0)
	count("audit.audit_outbox", "record_id", nul.EventID, 0)
	raw, e := event()
	created := post(trusted, raw, 201)
	if created.EventID != e.EventID || created.Result != "created" || created.ReceivedAt.IsZero() {
		t.Fatal("invalid committed acknowledgement")
	}
	count("audit.audit_events", "event_id", e.EventID, 1)
	count("audit.audit_outbox", "record_id", e.EventID, 1)
	duplicate := post(trusted, raw, 200)
	if duplicate.Result != "duplicate" || !duplicate.ReceivedAt.Equal(created.ReceivedAt) {
		t.Fatal("duplicate changed original receipt")
	}
	count("audit.audit_outbox", "record_id", e.EventID, 1)
	e.SafePayload["revoke_reason"] = json.RawMessage(`"different"`)
	raw, e = signed(t, e)
	post(trusted, raw, 409)
	count("audit.event_conflicts", "record_id", e.EventID, 1)
	count("audit.audit_outbox", "record_id", e.EventID, 1)
	deniedRaw, denied := event()
	post(client([]tls.Certificate{other}), deniedRaw, 403)
	count("audit.audit_events", "event_id", denied.EventID, 0)
	if resp, err := client(nil).Post(server.URL+"/internal/audit/events", "application/json", bytes.NewReader(deniedRaw)); err == nil {
		resp.Body.Close()
		t.Fatal("missing client certificate reached API")
	}
	denied.SourceID = "source-b"
	deniedRaw, denied = signed(t, denied)
	post(trusted, deniedRaw, 403)
	count("audit.audit_events", "event_id", denied.EventID, 0)
	if _, err := db.Exec(ctx, "UPDATE identity.registered_workloads SET enabled=false WHERE namespace='agent-control' AND ksa='coordinator'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(ctx, "UPDATE identity.registered_workloads SET enabled=true WHERE namespace='agent-control' AND ksa='coordinator'"); err != nil {
			t.Error(err)
		}
	}()
	deniedRaw, denied = event()
	post(trusted, deniedRaw, 403) // same transport: registration is checked per request.
	count("audit.audit_events", "event_id", denied.EventID, 0)
	count("audit.audit_outbox", "record_id", denied.EventID, 0)
}
