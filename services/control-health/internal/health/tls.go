package health

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// LoadTLS rereads both the server keypair and trust bundle on each handshake,
// allowing atomic certificate/root rotation without disabling verification.
func LoadTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	load := func() (*tls.Config, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("empty trust bundle")
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, NextProtos: []string{"http/1.1"}}, nil
	}
	cfg, err := load()
	if err != nil {
		return nil, err
	}
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return load() }
	return cfg, nil
}
