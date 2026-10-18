package execute

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

// maxTokenFileBytes bounds a projected token file read.
const maxTokenFileBytes = 16 << 10

// forbiddenCredentialHeaders are names a credential may not set: they are
// written by net/http or are part of the plan.
var forbiddenCredentialHeaders = []string{"Host", "Content-Length", "Transfer-Encoding", "Connection", "Expect", "Te", "Trailer", "Upgrade", "Proxy-Authorization", "Proxy-Connection", "User-Agent", "Content-Type", "Idempotency-Key", http.CanonicalHeaderKey(transport.AttemptHeader), "Traceparent", "Tracestate", "Baggage"}

// credential obtains the attempt's credential with the configured strategy
// (TASK-05 3.1). It runs after the reservation and before the permit claim;
// any error is reported as released CREDENTIAL_UNAVAILABLE. The returned
// header is checked against forbiddenCredentialHeaders and for characters
// net/http would refuse only at send time, and must not be expired.
func (e *Engine) credential(ctx context.Context, attemptID, binding string) (Credential, error) {
	var (
		c   Credential
		err error
	)
	switch e.cfg.Credential.Kind {
	case CredentialNone:
		return Credential{}, nil
	case CredentialBroker:
		cctx, cancel := e.call(ctx)
		c, err = e.cfg.Credentials.Resolve(cctx, attemptID, e.cfg.Adapter.ID(), binding)
		cancel()
	case CredentialTokenFile:
		c, err = tokenFileCredential(e.cfg.Credential.TokenFile)
	case CredentialTokenSource:
		cctx, cancel := e.call(ctx)
		var tok AccessToken
		tok, err = e.cfg.Credential.TokenSource.Token(cctx)
		cancel()
		if err == nil {
			c, err = bearer(tok)
		}
	default:
		err = fmt.Errorf("credential strategy %q", e.cfg.Credential.Kind)
	}
	if err != nil {
		return Credential{}, err
	}
	if err := checkCredentialHeader(c); err != nil {
		return Credential{}, err
	}
	if !c.ExpiresAt.After(e.now()) {
		return Credential{}, errors.New("credential already expired")
	}
	return c, nil
}

func checkCredentialHeader(c Credential) error {
	if !validHeaderName(c.HeaderName) {
		return fmt.Errorf("credential header_name %q is not a header name", c.HeaderName)
	}
	if slices.Contains(forbiddenCredentialHeaders, http.CanonicalHeaderKey(c.HeaderName)) {
		return fmt.Errorf("credential header_name %q is reserved", c.HeaderName)
	}
	if c.HeaderValue == "" {
		return errors.New("credential header value is empty")
	}
	for i := 0; i < len(c.HeaderValue); i++ {
		if b := c.HeaderValue[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return errors.New("credential header value has a control character")
		}
	}
	return nil
}

// validToken68 reports the RFC 9110 token68 form of a bearer token.
func validToken68(s string) bool {
	t := strings.TrimRight(s, "=")
	if t == "" {
		return false
	}
	for i := 0; i < len(t); i++ {
		b := t[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.IndexByte("-._~+/", b) >= 0) {
			return false
		}
	}
	return true
}

// bearer turns a token source answer into an Authorization header. The
// expiry is required: a token without one cannot be checked again before
// the send.
func bearer(t AccessToken) (Credential, error) {
	if t.Type != "" && !strings.EqualFold(t.Type, "Bearer") {
		return Credential{}, fmt.Errorf("token type %q is not Bearer", t.Type)
	}
	if !validToken68(t.Value) {
		return Credential{}, errors.New("access token is empty or not a bearer token")
	}
	if t.Expiry.IsZero() {
		return Credential{}, errors.New("access token has no expiry")
	}
	return Credential{HeaderName: "Authorization", HeaderValue: "Bearer " + t.Value, ExpiresAt: t.Expiry}, nil
}

// tokenFileCredential reads the projected ServiceAccount token on every
// attempt (the kubelet rotates the file) and uses its exp claim as the
// expiry. The token is not verified here; the API server does that. A file
// that is not a JWT with a numeric exp is refused.
func tokenFileCredential(path string) (Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return Credential{}, fmt.Errorf("read token file: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFileBytes+1))
	if err != nil {
		return Credential{}, fmt.Errorf("read token file: %w", err)
	}
	if len(b) > maxTokenFileBytes {
		return Credential{}, errors.New("token file is too large")
	}
	tok := string(bytes.TrimRight(b, "\r\n"))
	exp, err := jwtExpiry(tok)
	if err != nil {
		return Credential{}, fmt.Errorf("token file: %w", err)
	}
	return bearer(AccessToken{Value: tok, Type: "Bearer", Expiry: exp})
}

func jwtExpiry(tok string) (time.Time, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return time.Time{}, errors.New("not a compact JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, errors.New("JWT payload is not base64url")
	}
	var claims struct {
		Exp json.RawMessage `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, errors.New("JWT payload is not a JSON object")
	}
	// exp is a JSON number (RFC 7519 NumericDate); a string is refused.
	if len(claims.Exp) == 0 || claims.Exp[0] < '0' || claims.Exp[0] > '9' {
		return time.Time{}, errors.New("JWT has no numeric exp claim")
	}
	f, err := strconv.ParseFloat(string(claims.Exp), 64)
	if err != nil || !(f > 0 && f < 1e12) {
		return time.Time{}, errors.New("JWT exp is not a time")
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), nil
}
