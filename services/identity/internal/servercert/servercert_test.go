package servercert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
)

// selfIssuer signs the requested public key with a throwaway CA.
type selfIssuer struct{ now time.Time }

func (s selfIssuer) Issue(_ context.Context, r issuer.Request) (issuer.Certificate, error) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: s.now.Add(-time.Hour), NotAfter: s.now.Add(48 * time.Hour)}
	pub, err := x509.ParsePKIXPublicKey(r.PublicKeyDER)
	if err != nil {
		return issuer.Certificate{}, err
	}
	u, _ := url.Parse(r.SAN)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(7), URIs: []*url.URL{u}, NotBefore: s.now, NotAfter: s.now.Add(r.Lifetime),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, pub, caKey)
	if err != nil {
		return issuer.Certificate{}, err
	}
	p := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return issuer.Certificate{LeafPEM: p, Serial: "07", NotBefore: s.now, NotAfter: s.now.Add(r.Lifetime)}, nil
}

type recorder struct {
	err  error
	recs []bootstrap.IssuedRecord
}

func (r *recorder) RecordIssued(_ context.Context, rec bootstrap.IssuedRecord) error {
	if r.err != nil {
		return r.err
	}
	r.recs = append(r.recs, rec)
	return nil
}

func TestRefreshRecordsBeforeActivating(t *testing.T) {
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	rec := &recorder{err: errors.New("db down")}
	m := &Manager{Issuer: selfIssuer{now}, Recorder: rec, Namespace: "agent-control", KSA: "workload-identity",
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return now }}

	if err := m.Refresh(context.Background()); err == nil {
		t.Fatal("refresh succeeded although the record failed")
	}
	if m.Ready() {
		t.Fatal("certificate activated without an issuance record")
	}
	if got := m.NextWait(true); got != RetryAfterFailure {
		t.Fatalf("wait after failure = %v", got)
	}

	rec.err = nil
	if err := m.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.Ready() || len(rec.recs) != 1 {
		t.Fatalf("ready=%v records=%d", m.Ready(), len(rec.recs))
	}
	r := rec.recs[0]
	if r.SAN != "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity" || r.Serial != "07" || r.PodUID != "" {
		t.Fatalf("record = %+v", r)
	}
	if got := m.NextWait(false); got != 12*time.Hour {
		t.Fatalf("wait after success = %v, want 12h (50%% of 24h)", got)
	}
	if _, err := m.GetCertificate(nil); err != nil {
		t.Fatal(err)
	}
}
