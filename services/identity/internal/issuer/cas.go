package issuer

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	privateca "cloud.google.com/go/security/privateca/apiv1"
	"cloud.google.com/go/security/privateca/apiv1/privatecapb"
	"google.golang.org/protobuf/types/known/durationpb"
)

// CASClient is the part of the Certificate Authority Service client this
// package uses, so tests can substitute it.
type CASClient interface {
	CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error)
	FetchCaCerts(ctx context.Context, req *privatecapb.FetchCaCertsRequest) (*privatecapb.FetchCaCertsResponse, error)
}

// GoogleCAS adapts *privateca.CertificateAuthorityClient to CASClient. The
// client authenticates with the identity service's Workload Identity
// (TASK-03 3.3.1: only KSA workload-identity may request certificates).
type GoogleCAS struct {
	C *privateca.CertificateAuthorityClient
}

func (g GoogleCAS) CreateCertificate(ctx context.Context, req *privatecapb.CreateCertificateRequest) (*privatecapb.Certificate, error) {
	return g.C.CreateCertificate(ctx, req)
}

func (g GoogleCAS) FetchCaCerts(ctx context.Context, req *privatecapb.FetchCaCertsRequest) (*privatecapb.FetchCaCertsResponse, error) {
	return g.C.FetchCaCerts(ctx, req)
}

// CAS issues config-based certificates from one CA pool
// ("projects/<p>/locations/<l>/caPools/<pool>").
type CAS struct {
	Client          CASClient
	Pool            string
	ServiceTemplate string
	ClientTemplate  string
	Now             func() time.Time
}

// ValidateIssuanceConfig checks trusted installation inputs before any CAS
// issuance. Trust-bundle fetching alone does not require these templates.
func (c CAS) ValidateIssuanceConfig() error {
	poolLocation, ok := resourceLocation(c.Pool, "caPools")
	if !ok {
		return errors.New("cas: invalid pool resource name")
	}
	for _, template := range []string{c.ServiceTemplate, c.ClientTemplate} {
		location, ok := resourceLocation(template, "certificateTemplates")
		if !ok {
			return errors.New("cas: both certificate template resource names are required and must be valid")
		}
		if location != poolLocation {
			return errors.New("cas: certificate templates must match the pool project and location")
		}
	}
	if c.ServiceTemplate == c.ClientTemplate {
		return errors.New("cas: service and client certificate templates must differ")
	}
	return nil
}

func resourceLocation(name, collection string) (string, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != collection {
		return "", false
	}
	for _, part := range []string{parts[1], parts[3], parts[5]} {
		if !validCertificateID(part) {
			return "", false
		}
	}
	return strings.Join(parts[:4], "/"), true
}

// Issue sends a config-based CreateCertificate. RequestID is used both as the
// CAS certificate ID and as the request ID, so a retry of the same request
// returns the same certificate instead of issuing a second one.
func (c CAS) Issue(ctx context.Context, req Request) (Certificate, error) {
	if err := c.ValidateIssuanceConfig(); err != nil {
		return Certificate{}, err
	}
	if c.Client == nil {
		return Certificate{}, errors.New("cas: client not set")
	}
	if !validCertificateID(req.RequestID) {
		return Certificate{}, fmt.Errorf("cas: invalid request id %q", req.RequestID)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: req.PublicKeyDER})
	// ClientOnly comes from the verified role, never a CSR or caller-selected
	// template. There is no template-free fallback if CAS rejects this request.
	template := c.ServiceTemplate
	if req.ClientOnly {
		template = c.ClientTemplate
	}
	cert := &privatecapb.Certificate{
		Lifetime:            durationpb.New(req.Lifetime),
		CertificateTemplate: template,
		CertificateConfig: &privatecapb.Certificate_Config{Config: &privatecapb.CertificateConfig{
			SubjectConfig: &privatecapb.CertificateConfig_SubjectConfig{
				SubjectAltName: &privatecapb.SubjectAltNames{Uris: []string{req.SAN}},
			},
			X509Config: &privatecapb.X509Parameters{
				// The selected template owns digitalSignature and the exact EKU.
				CaOptions: &privatecapb.X509Parameters_CaOptions{IsCa: proto(false)},
			},
			PublicKey: &privatecapb.PublicKey{Key: keyPEM, Format: privatecapb.PublicKey_PEM},
		}},
	}
	got, err := c.Client.CreateCertificate(ctx, &privatecapb.CreateCertificateRequest{
		Parent:        c.Pool,
		CertificateId: req.RequestID,
		RequestId:     uuidFromID(req.RequestID),
		Certificate:   cert,
	})
	if err != nil {
		return Certificate{}, fmt.Errorf("cas: create certificate: %w", err)
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	out, err := Verify(req, got.GetPemCertificate(), now())
	if err != nil {
		return Certificate{}, fmt.Errorf("cas: %w", err)
	}
	out.ChainPEM = append([]string(nil), got.GetPemCertificateChain()...)
	return out, nil
}

// TrustBundle returns the PEM CA certificates of the pool, de-duplicated and
// sorted so the same set always renders the same bytes. Rotation overlap
// (old and new root together, TASK-03 3.3.1) comes from CAS returning every
// enabled CA of the pool.
func (c CAS) TrustBundle(ctx context.Context) (string, error) {
	resp, err := c.Client.FetchCaCerts(ctx, &privatecapb.FetchCaCertsRequest{CaPool: c.Pool})
	if err != nil {
		return "", fmt.Errorf("cas: fetch ca certs: %w", err)
	}
	seen := map[string]bool{}
	var certs []string
	for _, chain := range resp.GetCaCerts() {
		for _, p := range chain.GetCertificates() {
			block, _ := pem.Decode([]byte(p))
			if block == nil || block.Type != "CERTIFICATE" {
				return "", errors.New("cas: ca cert is not PEM")
			}
			norm := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
			if !seen[norm] {
				seen[norm] = true
				certs = append(certs, norm)
			}
		}
	}
	if len(certs) == 0 {
		return "", errors.New("cas: pool returned no ca certs")
	}
	sort.Strings(certs)
	return strings.Join(certs, ""), nil
}

func proto(b bool) *bool { return &b }

// validCertificateID matches the CAS certificate ID rule ([a-zA-Z0-9_-]{1,63}).
func validCertificateID(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// uuidFromID formats a 32-hex-character request ID as a UUID, which is the
// form the CAS request_id field expects; other IDs are passed unchanged.
func uuidFromID(id string) string {
	if len(id) != 32 {
		return id
	}
	return id[0:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:32]
}
