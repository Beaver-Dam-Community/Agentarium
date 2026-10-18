package healthreport

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

// Identity provides outbound mTLS clients for exact peer service SANs, either
// from the identity bootstrap (in-memory keys, renewed) or from PEM files.
type Identity struct {
	manager       *workloadcert.Manager
	cert, key, ca string
}

// LoadIdentity uses the identity bootstrap when identityURL is set; otherwise
// it uses the certificate files (test and break-glass mode).
func LoadIdentity(ctx context.Context, identityURL, tokenFile, ca, cert, key, san string) (Identity, error) {
	if identityURL == "" {
		if cert == "" || key == "" || ca == "" {
			return Identity{}, errors.New("TLS material required")
		}
		return Identity{cert: cert, key: key, ca: ca}, nil
	}
	m := &workloadcert.Manager{URL: identityURL, TokenFile: tokenFile, CAFile: ca, SAN: san}
	call, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := m.Refresh(call); err != nil {
		return Identity{}, err
	}
	go m.Run(ctx, func() { log.Print("service certificate renewal failed") })
	return Identity{manager: m}, nil
}

// Client returns an mTLS client for base that accepts only peerSAN.
func (i Identity) Client(base, peerSAN string) (*http.Client, error) {
	if i.manager != nil {
		return i.manager.Client(peerSAN, true), nil
	}
	return ServiceClient(base, i.cert, i.key, i.ca, peerSAN)
}
