package execute

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/internal/strictjson"
)

// GatewaySAN is the only caller of the execute API (COMMON internal API responsibilities,
// service PKI: agent-control/policy-gateway).
const GatewaySAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"

const maxExecuteBody = 16 << 10

// ExecuteRequest is the POST /internal/adapter/{adapter_id}/execute body. The
// gateway sends only the IDs; the adapter reads the stored values itself.
type ExecuteRequest struct {
	DecisionID string `json:"decision_id"`
	ActionID   string `json:"action_id"`
}

// ExecuteResponse is the 202 body: the adapter_executions row's current state.
type ExecuteResponse struct {
	DecisionID string `json:"decision_id"`
	ActionID   string `json:"action_id"`
	State      string `json:"state"`
}

// Handler serves the execute API for one engine.
type Handler struct {
	Engine *Engine
	// CallerSAN is the accepted client URI SAN; GatewaySAN when empty.
	CallerSAN string
	Logger    *slog.Logger
}

// Register adds the route to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/adapter/{adapter_id}/execute", h.execute)
}

func (h *Handler) execute(w http.ResponseWriter, r *http.Request) {
	want := h.CallerSAN
	if want == "" {
		want = GatewaySAN
	}
	// SPEC-QUESTION: COMMON maps 401 to missing authentication and 403 to
	// policy; a verified certificate of another service is answered 401
	// AUTH_REQUIRED as well, since no reason code names a wrong caller.
	if !callerIs(r, want) {
		writeError(w, http.StatusUnauthorized, "AUTH_REQUIRED")
		return
	}
	if r.PathValue("adapter_id") != h.Engine.cfg.Adapter.ID() {
		writeError(w, http.StatusNotFound, "RESOURCE_NOT_FOUND")
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxExecuteBody+1))
	if err != nil || len(body) > maxExecuteBody {
		writeError(w, http.StatusRequestEntityTooLarge, "BODY_TOO_LARGE")
		return
	}
	var req ExecuteRequest
	if err := strictjson.Decode(body, &req); err != nil || !ValidUUID(req.DecisionID) || !ValidUUID(req.ActionID) {
		writeError(w, http.StatusUnprocessableEntity, "SCHEMA_INVALID")
		return
	}
	row, _, err := h.Engine.Submit(r.Context(), req.DecisionID, req.ActionID)
	if err != nil {
		h.log().Error("execute: store unavailable", "decision_id", req.DecisionID, "err", err)
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusServiceUnavailable, "STATE_STORE_UNAVAILABLE")
		return
	}
	// SPEC-QUESTION: the same decision_id with another action_id is not
	// described; it is refused instead of reporting the other action's state.
	if row.ActionID != req.ActionID {
		writeError(w, http.StatusConflict, "PREFLIGHT_MISMATCH")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ExecuteResponse{DecisionID: row.DecisionID, ActionID: row.ActionID, State: row.State})
}

func (h *Handler) log() *slog.Logger {
	if h.Logger != nil {
		return h.Logger
	}
	return slog.Default()
}

// callerIs checks that the verified client certificate is a service client
// certificate (checkLeaf with clientAuth) whose only URI SAN is san. The
// check is repeated here so that the handler stays strict when it is served
// with a tls.Config other than ServerTLSConfig.
func callerIs(r *http.Request, san string) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	return checkLeaf(r.TLS.VerifiedChains[0][0], x509.ExtKeyUsageClientAuth, san) == nil
}

type errorBody struct {
	RequestID   string   `json:"request_id"`
	ReasonCodes []string `json:"reason_codes"`
}

// writeError writes the COMMON error body (request_id, reason_codes).
func writeError(w http.ResponseWriter, status int, code string) {
	id := newUUID()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{RequestID: id, ReasonCodes: []string{code}})
}

// TLSFiles points at the mTLS material issued by TASK-03 (identity service).
type TLSFiles struct {
	CertFile string
	KeyFile  string
	CAFile   string // agentarium-trust bundle
}

// CertSource returns the current service key pair: re-read from files, or
// held in memory by a packages/workloadcert Manager.
type CertSource func() (*tls.Certificate, error)

// FileCertSource re-reads the key pair from f on every call, so rotation
// needs no restart.
func FileCertSource(f TLSFiles) CertSource {
	return func() (*tls.Certificate, error) {
		c, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
		if err != nil {
			return nil, err
		}
		return &c, nil
	}
}

// ServerTLSConfig requires a client certificate that chains to the trust
// bundle and allows clientAuth (Go's own check), and that is also a service
// client certificate: the leaf lists clientAuth itself, is not a CA, and has
// exactly one URI SAN and no DNS, IP or email SAN. Which URI SAN is accepted
// is the handler's decision (Handler.CallerSAN). The key pair is re-read on
// every handshake so rotation needs no restart.
func ServerTLSConfig(f TLSFiles) (*tls.Config, error) {
	return ServerTLSConfigFrom(f.CAFile, FileCertSource(f))
}

// ServerTLSConfigFrom is ServerTLSConfig with the server key pair taken from
// cert on every handshake. cert must return a key pair now.
func ServerTLSConfigFrom(caFile string, cert CertSource) (*tls.Config, error) {
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	if _, err := cert(); err != nil {
		return nil, fmt.Errorf("execute: load server key pair: %w", err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
		// Runs after Go has verified the chain (RequireAndVerifyClientCert).
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
				return errors.New("execute: client certificate was not verified")
			}
			if err := checkLeaf(cs.VerifiedChains[0][0], x509.ExtKeyUsageClientAuth, ""); err != nil {
				return fmt.Errorf("execute: client certificate: %w", err)
			}
			return nil
		},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert() },
	}, nil
}

// ClientTLSConfig presents the adapter certificate to an internal service
// and accepts only a server whose certificate verifyPeer accepts: a chain to
// the trust bundle that allows serverAuth, a leaf that lists serverAuth
// itself and is not a CA, and exactly one URI SAN, equal to serverSAN, with
// no DNS, IP or email SAN.
func ClientTLSConfig(f TLSFiles, serverSAN string) (*tls.Config, error) {
	return ClientTLSConfigFrom(f.CAFile, FileCertSource(f), serverSAN)
}

// ClientTLSConfigFrom is ClientTLSConfig with the client key pair taken from
// cert on every handshake. cert must return a key pair now.
func ClientTLSConfigFrom(caFile string, cert CertSource, serverSAN string) (*tls.Config, error) {
	pool, err := loadPool(caFile)
	if err != nil {
		return nil, err
	}
	if _, err := cert(); err != nil {
		return nil, fmt.Errorf("execute: load client key pair: %w", err)
	}
	return &tls.Config{
		MinVersion:           tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return cert() },
		// Internal service identity is the SPIFFE URI SAN, not a DNS name.
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyPeer(cs.PeerCertificates, pool, serverSAN)
		},
	}, nil
}

func verifyPeer(chain []*x509.Certificate, roots *x509.CertPool, san string) error {
	if len(chain) == 0 {
		return errors.New("execute: server presented no certificate")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("execute: verify server chain: %w", err)
	}
	if err := checkLeaf(chain[0], x509.ExtKeyUsageServerAuth, san); err != nil {
		return fmt.Errorf("execute: server certificate: %w", err)
	}
	return nil
}

// checkLeaf applies the TASK-03 service certificate rules to a leaf whose
// chain is already verified for eku:
//   - the leaf itself lists eku (a leaf without an EKU extension, which x509
//     treats as any usage, is refused);
//   - the leaf is not a CA;
//   - the leaf has no DNS, IP or email SAN and exactly one URI SAN, which
//     must equal san unless san is empty.
func checkLeaf(leaf *x509.Certificate, eku x509.ExtKeyUsage, san string) error {
	if !slices.Contains(leaf.ExtKeyUsage, eku) {
		return fmt.Errorf("certificate does not list extended key usage %d", eku)
	}
	if leaf.IsCA {
		return errors.New("certificate is a CA certificate")
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("certificate has a DNS, IP or email SAN")
	}
	if len(leaf.URIs) != 1 {
		return fmt.Errorf("certificate has %d URI SANs, want exactly one", len(leaf.URIs))
	}
	if san != "" && leaf.URIs[0].String() != san {
		return fmt.Errorf("certificate URI SAN is not %q", san)
	}
	return nil
}

func loadPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, errors.New("execute: CA bundle path is required")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("execute: read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("execute: CA bundle has no PEM certificates")
	}
	return pool, nil
}

// FileTLSMaterial is TLSMaterial from files: the adapter key pair and one CA
// bundle per catalog ca_ref. ca_ref "system" uses the system pool.
type FileTLSMaterial struct {
	Files TLSFiles
	// CARefFiles maps ca_ref (cluster, agentarium-trust) to a PEM bundle.
	CARefFiles map[string]string
}

func (m FileTLSMaterial) ClientCertificate() (*tls.Certificate, error) {
	return FileCertSource(m.Files)()
}

func (m FileTLSMaterial) RootCAs(caRef string) (*x509.CertPool, error) {
	return caRefPool(m.CARefFiles, caRef)
}

// SourceTLSMaterial is TLSMaterial with the adapter key pair from Cert (for
// example a packages/workloadcert Manager) and one CA bundle per catalog
// ca_ref, as in FileTLSMaterial.
type SourceTLSMaterial struct {
	Cert       CertSource
	CARefFiles map[string]string
}

func (m SourceTLSMaterial) ClientCertificate() (*tls.Certificate, error) { return m.Cert() }

func (m SourceTLSMaterial) RootCAs(caRef string) (*x509.CertPool, error) {
	return caRefPool(m.CARefFiles, caRef)
}

func caRefPool(files map[string]string, caRef string) (*x509.CertPool, error) {
	if caRef == "system" {
		return nil, nil
	}
	path, ok := files[caRef]
	if !ok {
		return nil, fmt.Errorf("execute: no CA bundle configured for ca_ref %q", caRef)
	}
	return loadPool(path)
}
