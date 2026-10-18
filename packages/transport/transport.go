// Package transport is the TASK-05 3.2 per-attempt HTTP transport and the
// adapter transport recorder.
//
// Every attempt gets a new http.Transport and http.Client: no proxy, no
// keep-alive, HTTP/1.1 only, no transparent compression, no redirects. The
// dialer resolves the origin host itself (IPv4, no cache), refuses to connect
// unless every answer is inside the target's allowed_cidrs, and records the
// dialed address. TLS pins ServerName to expected_tls_name; an
// agentarium-trust target is verified by its exact service URI SAN instead
// of the hostname (TLSConfig). httptrace fills
// the AdapterObservation timestamps, and WroteHeaders is the failed/unknown
// boundary of COMMON failure classification: a failure before it is Failed, after it
// without a complete response is Unknown.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
)

// MaxHeaderBytes is the request header budget (TASK-05 3.2 WriteBufferSize):
// the request line, Host, Content-Length, every header and the final CRLF must
// fit, so no byte reaches the socket before WroteHeaders.
const MaxHeaderBytes = 2048

// AttemptHeader carries the attempt ID (COMMON WirePlan safe_headers).
const AttemptHeader = "X-Agentarium-Attempt-Id"

// Failure stages before WroteHeaders (attempt_failed.stage is connect, tls or
// write_headers; dns and cidr failures are reported as connect).
const (
	StageDNS          = "dns"
	StageCIDR         = "cidr"
	StageConnect      = "connect"
	StageTLS          = "tls"
	StageWriteHeaders = "write_headers"
	// StageResponse is a failure after WroteHeaders while waiting for or
	// reading the response.
	StageResponse = "response"
)

// Resolver is net.Resolver.LookupNetIP; tests inject answers.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Request is one attempt: the immutable plan plus what was bound after the
// reservation (attempt ID, credential header, TLS material).
type Request struct {
	Plan      canonical.WirePlan
	AttemptID string
	// CredentialHeader is added at send time and is never part of the plan,
	// its digest or any record (WirePlan: added at the credential step).
	CredentialHeader      string
	CredentialHeaderValue string
	// CARef is the target's catalog ca_ref (system, cluster or
	// agentarium-trust). It selects the server certificate check; see
	// TLSConfig.
	CARef      string
	RootCAs    *x509.CertPool // nil means the system pool (ca_ref system only)
	ClientCert *tls.Certificate
	PodUID     string
}

// Config holds what tests replace. The zero value uses net.DefaultResolver,
// a 5s dial timeout and the system clock.
type Config struct {
	Resolver Resolver
	Dialer   *net.Dialer
	Now      func() time.Time
	// Netns returns the netns_inode; NetnsInode when nil. Tests on hosts
	// without /proc inject a value.
	Netns func() *uint64
	// OnWroteHeaders runs in the transport goroutine right after the request
	// headers are written, with a copy of the observation so far. It must not
	// block; the adapter starts its dispatched report from here.
	OnWroteHeaders func(Observation)
}

// Result is what the attempt produced.
type Result struct {
	Observation Observation
	// WroteHeaders reports whether httptrace WroteHeaders ran.
	WroteHeaders bool
	// Stage and ReasonCodes describe a failure; empty when a response arrived.
	Stage       string
	ReasonCodes []string
	Err         error
	// Response fields, set only when a complete (bounded) response arrived.
	Responded  bool
	StatusCode int
	Header     http.Header
	Body       []byte
	// Oversize: the body was longer than the plan response_limit; Body holds
	// the first response_limit bytes.
	Oversize bool
}

// Failed reports a failure before WroteHeaders (attempt failed).
func (r Result) Failed() bool { return !r.Responded && !r.WroteHeaders }

// Unknown reports a failure after WroteHeaders without a complete response.
func (r Result) Unknown() bool { return !r.Responded && r.WroteHeaders }

// recorder collects the observation from the dial, TLS and trace hooks, which
// run on transport goroutines.
type recorder struct {
	mu           sync.Mutex
	obs          Observation
	stage        string
	reasons      []string
	wroteHeaders bool
	now          func() time.Time
}

func (r *recorder) fail(stage string, reasons ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stage == "" {
		r.stage, r.reasons = stage, reasons
	}
}

func (r *recorder) snapshot() Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.obs
}

// Do runs one attempt. It never retries and never follows redirects.
func Do(ctx context.Context, cfg Config, req Request) Result {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	netns := cfg.Netns
	if netns == nil {
		netns = NetnsInode
	}
	rec := &recorder{now: now}
	rec.obs.AttemptID = req.AttemptID
	if req.PodUID != "" {
		rec.obs.PodUID = ptr(req.PodUID)
	}
	if req.Plan.WireBodyDigest != "" {
		rec.obs.WireBodyDigest = ptr(req.Plan.WireBodyDigest)
	}

	httpReq, origin, err := buildRequest(req)
	if err != nil {
		return Result{Observation: rec.snapshot(), Stage: StageWriteHeaders, ReasonCodes: []string{"PREFLIGHT_MISMATCH"}, Err: err}
	}
	allowed, err := parseCIDRs(req.Plan.AllowedCIDRs)
	if err != nil {
		return Result{Observation: rec.snapshot(), Stage: StageCIDR, ReasonCodes: []string{"DESTINATION_NOT_ALLOWED"}, Err: err}
	}
	tlsCfg, err := TLSConfig(req, now)
	if err != nil {
		// Nothing was dialed: the server certificate cannot be checked as the
		// catalog requires, so the attempt is not made.
		return Result{Observation: rec.snapshot(), Stage: StageTLS, ReasonCodes: []string{"TLS_VERIFY_FAILED"}, Err: err}
	}

	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 5 * time.Second}
	}
	wantAddr := net.JoinHostPort(origin.host, origin.port)

	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != wantAddr {
				rec.fail(StageConnect, "DESTINATION_NOT_ALLOWED")
				return nil, fmt.Errorf("transport: dial address %q is not the plan origin %q", addr, wantAddr)
			}
			ips, err := resolver.LookupNetIP(ctx, "ip4", origin.host)
			if err != nil || len(ips) == 0 {
				rec.fail(StageDNS, "TARGET_UNAVAILABLE")
				if err == nil {
					err = errors.New("no IPv4 answer")
				}
				return nil, fmt.Errorf("transport: resolve %s: %w", origin.host, err)
			}
			for _, ip := range ips {
				if !inAny(ip.Unmap(), allowed) {
					rec.fail(StageCIDR, "DESTINATION_NOT_ALLOWED")
					return nil, fmt.Errorf("transport: %s resolved to %s outside allowed_cidrs", origin.host, ip)
				}
			}
			dialed := net.JoinHostPort(ips[0].Unmap().String(), origin.port)
			rec.mu.Lock()
			rec.obs.DialedAddr = ptr(ips[0].Unmap().String())
			rec.mu.Unlock()
			conn, err := dialer.DialContext(ctx, "tcp4", dialed)
			if err != nil {
				rec.fail(StageConnect, "TARGET_UNAVAILABLE")
				return nil, err
			}
			rec.mu.Lock()
			// local_addr, local_port and netns_inode are the kernel
			// connection key and appear together, only once a socket exists.
			if la, ok := conn.LocalAddr().(*net.TCPAddr); ok {
				rec.obs.LocalAddr, rec.obs.LocalPort = ptr(la.IP.String()), ptr(la.Port)
				rec.obs.NetnsInode = netns()
			}
			if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				rec.obs.PeerAddr, rec.obs.PeerPort = ptr(ra.IP.String()), ptr(ra.Port)
				rec.obs.PeerAddrKind = ptr(peerKind(origin.host, net.IP(ips[0].Unmap().AsSlice()), ra.IP))
			}
			rec.mu.Unlock()
			return conn, nil
		},
		TLSClientConfig:    tlsCfg,
		DisableKeepAlives:  true,
		ForceAttemptHTTP2:  false,
		DisableCompression: true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	trace := &httptrace.ClientTrace{
		ConnectStart: func(string, string) {
			rec.mu.Lock()
			if rec.obs.ConnectStartedAt == nil {
				rec.obs.ConnectStartedAt = ptr(now())
			}
			rec.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err != nil {
				rec.fail(StageTLS, "TLS_VERIFY_FAILED")
			}
		},
		WroteHeaders: func() {
			rec.mu.Lock()
			rec.wroteHeaders = true
			rec.obs.SendStartedAt = ptr(now())
			obs := rec.obs
			rec.mu.Unlock()
			if cfg.OnWroteHeaders != nil {
				cfg.OnWroteHeaders(obs)
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) {
			rec.mu.Lock()
			rec.obs.SendFinishedAt = ptr(now())
			rec.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			rec.mu.Lock()
			rec.obs.ResponseAt = ptr(now())
			rec.mu.Unlock()
		},
	}

	tctx, cancel := context.WithTimeout(ctx, req.Plan.Timeout)
	defer cancel()
	httpReq = httpReq.WithContext(httptrace.WithClientTrace(tctx, trace))

	resp, err := client.Do(httpReq)
	if err != nil {
		return finish(rec, err, nil)
	}
	defer resp.Body.Close()
	limit := req.Plan.ResponseLimit
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if rerr != nil {
		return finish(rec, rerr, nil)
	}
	res := finish(rec, nil, resp)
	if int64(len(body)) > limit {
		res.Oversize = true
		body = body[:limit]
	}
	res.Body = body
	return res
}

// Validate builds the request without sending it. The adapter calls it before
// the permit claim, so a malformed plan or an oversize header is found while
// the attempt can still be released.
func Validate(req Request) error {
	if _, _, err := buildRequest(req); err != nil {
		return err
	}
	if err := checkCARef(req.CARef, req.Plan.ExpectedURISAN); err != nil {
		return err
	}
	_, err := parseCIDRs(req.Plan.AllowedCIDRs)
	return err
}

// checkCARef checks the plan-level TLS selection: a known ca_ref, and an
// expected URI SAN that is present (and well-formed) exactly for
// agentarium-trust.
func checkCARef(caRef, uriSAN string) error {
	switch caRef {
	case canonical.CARefAgentariumTrust:
		if uriSAN == "" {
			return errors.New("transport: ca_ref agentarium-trust needs expected_uri_san")
		}
		if !canonical.ValidServiceURISAN(uriSAN) {
			return fmt.Errorf("transport: expected_uri_san %q is not a service URI SAN", uriSAN)
		}
	case "system", "cluster":
		if uriSAN != "" {
			return fmt.Errorf("transport: expected_uri_san is set for ca_ref %q", caRef)
		}
	default:
		return fmt.Errorf("transport: ca_ref %q is not system, cluster or agentarium-trust", caRef)
	}
	return nil
}

// VerifyError is a server certificate refusal from VerifyConnection.
type VerifyError struct{ Err error }

func (e *VerifyError) Error() string { return "transport: server certificate: " + e.Err.Error() }
func (e *VerifyError) Unwrap() error { return e.Err }

// TLSConfig is the per-attempt client TLS configuration for req (TASK-05
// 3.2). ServerName is always expected_tls_name, so SNI names the target.
//
//   - ca_ref system or cluster: Go's standard verification, chain to RootCAs
//     (the system pool for system) and the hostname expected_tls_name.
//   - ca_ref agentarium-trust: the hostname check is replaced. Go's built-in
//     verification is turned off (InsecureSkipVerify) and VerifyConnection,
//     which is always set on this path, verifies the presented chain with
//     x509.Verify against the trust bundle (intermediates from the
//     handshake, serverAuth, the current time) and then requires the leaf to
//     be a service certificate whose only SAN is the URI SAN
//     expected_uri_san. There is no way to build this configuration without
//     a well-formed expected_uri_san and a non-nil trust pool.
//
// Both paths refuse a negotiated protocol other than HTTP/1.1.
func TLSConfig(req Request, now func() time.Time) (*tls.Config, error) {
	if now == nil {
		now = time.Now
	}
	if err := checkCARef(req.CARef, req.Plan.ExpectedURISAN); err != nil {
		return nil, err
	}
	if req.Plan.ExpectedTLSName == "" {
		return nil, errors.New("transport: expected_tls_name is empty")
	}
	if req.CARef != "system" && req.RootCAs == nil {
		return nil, fmt.Errorf("transport: ca_ref %q needs its CA pool", req.CARef)
	}
	cfg := &tls.Config{
		ServerName: req.Plan.ExpectedTLSName,
		RootCAs:    req.RootCAs,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if req.ClientCert == nil {
				return &tls.Certificate{}, nil
			}
			return req.ClientCert, nil
		},
	}
	if req.CARef != canonical.CARefAgentariumTrust {
		// VerifyConnection runs after the normal chain and name check; an
		// error here aborts the handshake.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 {
				return &VerifyError{errors.New("no verified chain")}
			}
			return checkProtocol(cs)
		}
		return cfg, nil
	}
	roots, want := req.RootCAs, req.Plan.ExpectedURISAN
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := VerifyServiceCertificate(cs.PeerCertificates, roots, want, now()); err != nil {
			return &VerifyError{err}
		}
		return checkProtocol(cs)
	}
	return cfg, nil
}

func checkProtocol(cs tls.ConnectionState) error {
	if cs.NegotiatedProtocol != "" && cs.NegotiatedProtocol != "http/1.1" {
		return fmt.Errorf("transport: negotiated %q", cs.NegotiatedProtocol)
	}
	return nil
}

// VerifyServiceCertificate checks an agentarium-trust server chain as
// presented in the handshake (leaf first): x509.Verify against roots with
// the rest of the chain as intermediates, KeyUsages serverAuth and
// CurrentTime at; then the leaf itself lists serverAuth (a leaf without an
// EKU extension, which x509 treats as any usage, is refused), is not a CA,
// has no DNS, IP or email SAN, and has exactly one URI SAN equal to uriSAN.
//
// The DNS/IP/email and CA rules are the TASK-03 service certificate shape
// (services/identity issues URI-only leaves); they are not written in TASK-05
// 3.2 itself.
func VerifyServiceCertificate(chain []*x509.Certificate, roots *x509.CertPool, uriSAN string, at time.Time) error {
	if roots == nil {
		return errors.New("no trust pool")
	}
	if uriSAN == "" {
		return errors.New("no expected URI SAN")
	}
	if len(chain) == 0 {
		return errors.New("no certificate presented")
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	leaf := chain[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inter, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return err
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return errors.New("leaf does not list extended key usage serverAuth")
	}
	if leaf.IsCA {
		return errors.New("leaf is a CA certificate")
	}
	if len(leaf.DNSNames)+len(leaf.IPAddresses)+len(leaf.EmailAddresses) != 0 {
		return errors.New("leaf has a DNS, IP or email SAN")
	}
	if len(leaf.URIs) != 1 {
		return fmt.Errorf("leaf has %d URI SANs, want exactly one", len(leaf.URIs))
	}
	if got := leaf.URIs[0].String(); got != uriSAN {
		return fmt.Errorf("leaf URI SAN %q is not %q", got, uriSAN)
	}
	return nil
}

func finish(rec *recorder, err error, resp *http.Response) Result {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	res := Result{Observation: rec.obs, WroteHeaders: rec.wroteHeaders, Err: err}
	if resp != nil {
		res.Responded = true
		res.StatusCode = resp.StatusCode
		res.Header = resp.Header.Clone()
		if v := resp.Header.Get("Audit-Id"); v != "" {
			res.Observation.K8sAuditID = ptr(v)
		}
		return res
	}
	switch {
	case rec.wroteHeaders:
		res.Stage = StageResponse
		res.ReasonCodes = []string{"TARGET_UNAVAILABLE"}
		// unknown carries no response_at (TASK-03 outcome contract): a first
		// response byte without a complete response is not a response.
		res.Observation.ResponseAt = nil
	case rec.stage != "":
		res.Stage, res.ReasonCodes = rec.stage, rec.reasons
	default:
		// No hook recorded a cause: the TLS handshake or the header write
		// failed (for example a certificate error reported before
		// TLSHandshakeDone, or a context deadline).
		var cerr *tls.CertificateVerificationError
		var herr x509.HostnameError
		var uerr x509.UnknownAuthorityError
		var verr *VerifyError
		if errors.As(err, &cerr) || errors.As(err, &herr) || errors.As(err, &uerr) || errors.As(err, &verr) {
			res.Stage, res.ReasonCodes = StageTLS, []string{"TLS_VERIFY_FAILED"}
		} else {
			res.Stage, res.ReasonCodes = StageWriteHeaders, []string{"TARGET_UNAVAILABLE"}
		}
	}
	return res
}

type originParts struct{ scheme, host, port string }

// buildRequest builds the request from the plan. The URL is origin + route
// only; the user never supplies a raw URL. It enforces the header budget.
func buildRequest(req Request) (*http.Request, originParts, error) {
	p := req.Plan
	u, err := url.Parse(p.OriginID)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
		return nil, originParts{}, fmt.Errorf("transport: origin %q is not https://host:port", p.OriginID)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	if len(p.Route) == 0 || p.Route[0] != '/' {
		return nil, originParts{}, fmt.Errorf("transport: route %q", p.Route)
	}
	if p.Timeout <= 0 || p.ResponseLimit <= 0 {
		return nil, originParts{}, errors.New("transport: plan timeout and response_limit must be positive")
	}
	if p.ExpectedTLSName == "" {
		return nil, originParts{}, errors.New("transport: expected_tls_name is empty")
	}
	if canonical.WireBodyDigest(p.BodyBytes) != p.WireBodyDigest {
		return nil, originParts{}, errors.New("transport: body does not match wire_body_digest")
	}
	r, err := http.NewRequest(p.Method, "https://"+net.JoinHostPort(host, port)+p.Route, bytes.NewReader(p.BodyBytes))
	if err != nil {
		return nil, originParts{}, err
	}
	r.ContentLength = int64(len(p.BodyBytes))
	for k, v := range p.SafeHeaders {
		r.Header.Set(k, v)
	}
	if req.AttemptID != "" {
		r.Header.Set(AttemptHeader, req.AttemptID)
	}
	if req.CredentialHeader != "" {
		r.Header.Set(req.CredentialHeader, req.CredentialHeaderValue)
	}
	if r.Header.Get("User-Agent") == "" {
		return nil, originParts{}, errors.New("transport: User-Agent must be explicit")
	}
	if n := HeaderBytes(r); n > MaxHeaderBytes {
		return nil, originParts{}, fmt.Errorf("transport: request headers are %d bytes, limit %d", n, MaxHeaderBytes)
	}
	return r, originParts{scheme: u.Scheme, host: host, port: port}, nil
}

// HeaderBytes is the HTTP/1.1 size of the request line and headers as
// net/http writes them (Host and Content-Length included).
func HeaderBytes(r *http.Request) int {
	n := len(r.Method) + 1 + len(r.URL.RequestURI()) + len(" HTTP/1.1\r\n")
	n += len("Host: ") + len(r.URL.Host) + 2
	if r.ContentLength > 0 {
		n += len("Content-Length: ") + len(strconv.FormatInt(r.ContentLength, 10)) + 2
	}
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			n += len(k) + 2 + len(v) + 2
		}
	}
	return n + 2
}

func parseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, errors.New("transport: allowed_cidrs is empty")
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("transport: allowed_cidrs %q: %w", c, err)
		}
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("transport: allowed_cidrs %q is not IPv4", c)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func inAny(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
