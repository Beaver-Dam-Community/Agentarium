package gateway

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// BootstrapPath is the certificate bootstrap route the gateway relays to the
// identity service (TASK-03 3.3.2). Execution Pods and hostNetwork node
// components reach only gateway 8443, so they bootstrap through it.
const BootstrapPath = "/internal/workload-certificates"

// IdentitySAN is the service SAN of the identity service (KSA
// workload-identity in agent-control).
const IdentitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"

// MaxBootstrapBody bounds both the relayed request body and the identity
// response body. It equals the identity service's own request limit.
const MaxBootstrapBody = 64 << 10

// BootstrapTimeout bounds one relayed request, from dialing the identity
// service to reading its whole response.
const BootstrapTimeout = 10 * time.Second

// NewIdentityClient returns the client the bootstrap relay uses. It presents
// the gateway certificate (clientCert) and accepts only a server certificate
// with exactly wantSAN. Like the adapter clients it follows no redirects and
// uses neither keep-alive nor HTTP/2.
func NewIdentityClient(roots *x509.CertPool, wantSAN string,
	clientCert func(*tls.CertificateRequestInfo) (*tls.Certificate, error)) (*http.Client, error) {
	cfg, err := ServiceClientTLS(roots, wantSAN, clientCert)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout: BootstrapTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   cfg,
			DisableKeepAlives: true,
			ForceAttemptHTTP2: false,
			TLSNextProto:      map[string]func(string, *tls.Conn) http.RoundTripper{},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// BootstrapRelay serves POST /internal/workload-certificates on the gateway.
// It needs no client certificate: the caller proves who it is with the
// projected token inside the body, and the identity service checks it
// (TokenReview, Pod, Node, registered_workloads). The gateway cannot tell
// callers apart, so which sources may reach this route is decided by the
// gateway ingress NetworkPolicy (TASK-06 3.1), not here.
//
// The body goes to the identity service byte for byte. No inbound header is
// copied, so a client-supplied X-Agentarium-Peer-Identity, Authorization or
// forwarding header never reaches the identity service, and the relay adds
// no peer identity of its own: a bootstrap has no verified SAN (TASK-03
// 3.3.2).
type BootstrapRelay struct {
	// IdentityURL is the identity service origin, https://host[:port].
	IdentityURL string
	// Client is the mTLS client from NewIdentityClient.
	Client *http.Client
	Log    *slog.Logger
}

func (b *BootstrapRelay) log() *slog.Logger {
	if b.Log == nil {
		return slog.Default()
	}
	return b.Log
}

func (b *BootstrapRelay) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The checks below answer as the identity service would for the same
	// request, so a caller sees one behavior directly and through the relay.
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorBody{RequestID: uuid.NewString(), ReasonCodes: []string{}})
		return
	}
	if !jsonType(r) {
		writeError(w, &Error{Status: http.StatusUnsupportedMediaType, Code: "SCHEMA_INVALID"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBootstrapBody+1))
	if err != nil {
		writeError(w, &Error{Status: http.StatusBadRequest, Code: "SCHEMA_INVALID"})
		return
	}
	if len(body) > MaxBootstrapBody {
		writeError(w, &Error{Status: http.StatusRequestEntityTooLarge, Code: "BODY_TOO_LARGE"})
		return
	}

	up, err := http.NewRequestWithContext(r.Context(), http.MethodPost, b.IdentityURL+BootstrapPath, bytes.NewReader(body))
	if err != nil {
		b.unavailable(w, "build identity request", err)
		return
	}
	up.Header = http.Header{"Content-Type": {"application/json"}}
	res, err := b.Client.Do(up)
	if err != nil {
		b.unavailable(w, "identity request", err)
		return
	}
	defer res.Body.Close()
	// The whole response is read before anything is written, so an oversize
	// or broken response still becomes a clean 503 instead of a partial one.
	out, err := io.ReadAll(io.LimitReader(res.Body, MaxBootstrapBody+1))
	if err != nil {
		b.unavailable(w, "read identity response", err)
		return
	}
	if len(out) > MaxBootstrapBody {
		b.unavailable(w, "identity response too large", nil)
		return
	}
	// Only these headers are passed back; Set-Cookie, Location and the rest
	// of the identity response headers are dropped.
	for _, h := range []string{"Content-Type", "Retry-After"} {
		if v := res.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(out)
}

// unavailable answers a relay failure (connection, TLS peer, timeout or an
// unusable response) with 503 STATE_STORE_UNAVAILABLE, the code the identity
// service uses for a failed dependency it does not classify (COMMON error codes).
func (b *BootstrapRelay) unavailable(w http.ResponseWriter, what string, err error) {
	b.log().Warn("bootstrap relay unavailable", "step", what, "err", err)
	writeError(w, unavailable("STATE_STORE_UNAVAILABLE", what))
}

// RequireClientCert answers 401 AUTH_REQUIRED to every request without a
// verified client certificate, except POST BootstrapPath (TASK-03 3.3). The
// path must be exactly BootstrapPath: an encoded or uncleaned variant needs a
// certificate.
func RequireClientCert(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bootstrap := r.Method == http.MethodPost && r.URL.Path == BootstrapPath && r.URL.RawPath == ""
		if !bootstrap && verifiedLeaf(r) == nil {
			writeError(w, authRequired)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func verifiedPeer(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0
}
