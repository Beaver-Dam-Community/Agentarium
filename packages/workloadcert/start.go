package workloadcert

import (
	"context"
	"crypto/tls"
	"errors"
	"time"
)

// Start performs the first bootstrap and then renews in the background with
// Run. A failed first bootstrap is returned and nothing is started, so the
// caller stops instead of serving without a certificate (fail closed).
func (m *Manager) Start(ctx context.Context, onError func()) error {
	if m.URL == "" || m.TokenFile == "" || m.CAFile == "" || m.SAN == "" {
		return errors.New("identity URL, bootstrap token file, trust bundle and SAN are required")
	}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	err := m.Refresh(call)
	cancel()
	if err != nil {
		return err
	}
	go m.Run(ctx, onError)
	return nil
}

// GetCertificate adapts Certificate to tls.Config.GetCertificate.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.Certificate()
}

// GetClientCertificate adapts Certificate to tls.Config.GetClientCertificate.
func (m *Manager) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.Certificate()
}
