// Package servercert keeps the identity service's own server certificate.
// TASK-03 3.3.1: identity asks CAS for it directly with its Workload Identity
// at start, and renews at 50% of the lifetime like every other service. The
// private key never leaves process memory.
package servercert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/issuer"
	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/pki"
)

// Recorder stores the issued certificate (identity.issued_certificates).
type Recorder interface {
	RecordIssued(ctx context.Context, r bootstrap.IssuedRecord) error
}

// RetryAfterFailure is the wait after a failed issue or record.
const RetryAfterFailure = 30 * time.Second

// Manager holds the current server certificate and renews it.
type Manager struct {
	Issuer    issuer.Issuer
	Recorder  Recorder
	Namespace string // agent-control
	KSA       string // workload-identity
	Log       *slog.Logger
	Now       func() time.Time

	cur      atomic.Pointer[tls.Certificate]
	notAfter atomic.Int64
	issuedAt atomic.Int64
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Refresh issues a new key and certificate and swaps it in atomically.
func (m *Manager) Refresh(ctx context.Context) error {
	san, err := pki.ServiceSAN(m.Namespace, m.KSA)
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	c, err := m.Issuer.Issue(ctx, issuer.Request{
		RequestID: hex.EncodeToString(id[:]), PublicKeyDER: pub, SAN: san, ClientOnly: false, Lifetime: pki.Lifetime,
	})
	if err != nil {
		return fmt.Errorf("issue server certificate: %w", err)
	}
	chain := c.LeafPEM + strings.Join(c.ChainPEM, "")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	tc, err := tls.X509KeyPair([]byte(chain), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return err
	}
	// Same invariant as the bootstrap route: a certificate is used only after
	// its issuance record is committed.
	if err := m.Recorder.RecordIssued(ctx, bootstrap.IssuedRecord{
		Serial: c.Serial, SAN: san, Namespace: m.Namespace, KSA: m.KSA,
		IssuedAt: m.now(), ExpiresAt: c.NotAfter,
	}); err != nil {
		return fmt.Errorf("record server certificate: %w", err)
	}
	m.cur.Store(&tc)
	m.notAfter.Store(c.NotAfter.Unix())
	m.issuedAt.Store(m.now().Unix())
	m.Log.Info("server certificate issued", "san", san, "serial", c.Serial, "not_after", c.NotAfter)
	return nil
}

// Ready reports whether a valid certificate is loaded (readiness probe).
func (m *Manager) Ready() bool {
	return m.cur.Load() != nil && m.now().Before(time.Unix(m.notAfter.Load(), 0))
}

// GetCertificate is the tls.Config hook.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c := m.cur.Load()
	if c == nil {
		return nil, errors.New("server certificate not ready")
	}
	return c, nil
}

// NextWait is how long Run sleeps before the next Refresh: until 50% of the
// current certificate's lifetime after a success, RetryAfterFailure after a
// failure or while no valid certificate is loaded.
func (m *Manager) NextWait(lastFailed bool) time.Duration {
	if lastFailed || !m.Ready() {
		return RetryAfterFailure
	}
	issued := time.Unix(m.issuedAt.Load(), 0)
	renewAt := issued.Add(time.Unix(m.notAfter.Load(), 0).Sub(issued) / 2)
	if d := renewAt.Sub(m.now()); d > 0 {
		return d
	}
	return 0
}

// Run renews at 50% of the lifetime and retries failures every
// RetryAfterFailure until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	failed := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(m.NextWait(failed)):
		}
		if err := m.Refresh(ctx); err != nil {
			failed = true
			m.Log.Error("server certificate renewal failed", "err", err)
			continue
		}
		failed = false
	}
}
