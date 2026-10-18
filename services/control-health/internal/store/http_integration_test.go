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

	"github.com/Beaver-Dam-Community/Agentarium/services/control-health/internal/health"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The CA is local; HTTP, certificate serial authorization, migrations and DB
// are real. This does not claim CAS issuance or GKE deployment verification.
type healthHTTPRequest func(string, string, []byte, int, any)

func healthHTTPFixture(t *testing.T, store *Store) (healthHTTPRequest, *http.Client, string) {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "local integration CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
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
	_, certPath, keyPath := issue("server", "spiffe://agentarium.internal/ns/agent-observe/sa/control-health", 101, x509.ExtKeyUsageServerAuth)
	caller, _, _ := issue("caller", "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway", 1, x509.ExtKeyUsageClientAuth)
	server := httptest.NewUnstartedServer(health.Handler{Backend: store})
	server.TLS, err = health.LoadTLS(certPath, keyPath, caPath)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client := func(certs []tls.Certificate) *http.Client {
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", Certificates: certs, MinVersion: tls.VersionTLS13}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 3 * time.Second}
	}
	trusted := client([]tls.Certificate{caller})
	request := func(method, path string, body []byte, expected int, result any) {
		t.Helper()
		req, err := http.NewRequest(method, server.URL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := trusted.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != expected {
			t.Fatalf("HTTP %d, expected %d", resp.StatusCode, expected)
		}
		if result != nil {
			if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
				t.Fatal(err)
			}
		} else if _, err := io.Copy(io.Discard, resp.Body); err != nil {
			t.Fatal(err)
		}
	}
	return request, client(nil), server.URL
}

func testHealthHTTPPostgres(t *testing.T, store *Store, db *pgx.Conn, lease health.Lease) {
	t.Helper()
	ctx := context.Background()
	request, untrusted, serverURL := healthHTTPFixture(t, store)
	raw, err := json.Marshal(lease)
	if err != nil {
		t.Fatal(err)
	}
	var ack health.LeaseAck
	request("POST", "/internal/control-health/leases", raw, 200, &ack)
	if ack.LeaseUntil.IsZero() || ack.ScopeState != "unhealthy" {
		t.Fatal("unexpected partial global scope acknowledgement")
	}
	var observed string
	if err := db.QueryRow(ctx, "SELECT observed_state FROM health.control_health_leases WHERE source_id='gateway-1'").Scan(&observed); err != nil || observed != "healthy" {
		t.Fatalf("lease not committed: %s %v", observed, err)
	}
	request("POST", "/internal/control-health/leases", raw, 422, nil)
	var snapshot health.Snapshot
	request("GET", "/internal/control-health?scope=global&scope_id=*", nil, 200, &snapshot)
	if len(snapshot.Leases) != 1 || len(snapshot.MissingComponents) != 4 {
		t.Fatalf("incomplete snapshot %+v", snapshot)
	}
	var fields map[string]json.RawMessage
	request("GET", "/internal/control-health?scope=global&scope_id=*", nil, 200, &fields)
	for _, key := range []string{"leases", "missing_components", "open_holds", "probes", "open_gaps", "startup_capture", "bundle_ack", "pending_work_readiness_challenges", "pending_worker_observation_challenges"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("missing wire key %s", key)
		}
	}
	// A reader must not receive a healthy-looking snapshot from an arbitrarily
	// selected boot when persisted current-node facts disagree.
	node := uuid.NewString()
	if _, err := db.Exec(ctx, `INSERT INTO health.node_boot_generation(node_uid,boot_id,startup_capture,state,updated_at,startup_capture_measurement) VALUES($1,'http-a','unsupported','ready',now(),'not_measured'),($1,'http-b','guarded','ready',now(),'measured')`, node); err != nil {
		t.Fatal(err)
	}
	request("GET", "/internal/control-health?scope=node&scope_id="+node, nil, 503, nil)
	if _, err := db.Exec(ctx, `UPDATE health.node_boot_generation SET state='retired' WHERE node_uid=$1 AND boot_id='http-b'`, node); err != nil {
		t.Fatal(err)
	}
	request("GET", "/internal/control-health?scope=node&scope_id="+node, nil, 200, &snapshot)
	if snapshot.StartupCapture == nil || *snapshot.StartupCapture != "unsupported" {
		t.Fatal("single current boot snapshot lost")
	}
	if _, err := db.Exec(ctx, `DELETE FROM health.node_boot_generation WHERE node_uid=$1`, node); err != nil {
		t.Fatal(err)
	}
	request("GET", "/internal/control-health?scope=node&scope_id="+node, nil, 200, &snapshot)
	if snapshot.StartupCapture != nil {
		t.Fatal("missing current boot manufactured a startup capture")
	}
	if resp, err := untrusted.Get(serverURL + "/internal/control-health?scope=global&scope_id=*"); err == nil {
		resp.Body.Close()
		t.Fatal("accepted no client certificate")
	}
	if _, err := db.Exec(ctx, "UPDATE identity.issued_certificates SET revoked_at=now() WHERE serial='01'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := db.Exec(ctx, "UPDATE identity.issued_certificates SET revoked_at=NULL WHERE serial='01'"); err != nil {
			t.Error(err)
		}
	}()
	request("GET", "/internal/control-health?scope=global&scope_id=*", nil, 403, nil)
	request("POST", "/internal/control-health/leases", raw, 403, nil)
}
