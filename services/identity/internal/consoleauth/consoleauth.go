// Package consoleauth authenticates console requests with a Google OIDC ID
// token (TASK-03 3.1 OIDC(Google)). The caller sends the ID token as
// `Authorization: Bearer <token>`.
//
// Verify checks the RS256 signature against Google's JWKS
// (https://www.googleapis.com/oauth2/v3/certs, static configuration, no
// runtime discovery), iss (https://accounts.google.com or
// accounts.google.com), aud (one of the installed audiences; azp too when the
// token has several audiences), exp and iat with a small clock skew, and the
// hd claim against the allowed Workspace domains (the verified email must be
// in that domain too). The actor is `google:<sub>` (COMMON service actor table),
// and the tenant and roles come from the installed role map.
//
// The accepted audiences are an install input, not necessarily a console
// OAuth client: for the M3-1 CLI demonstration it is the client ID that
// `gcloud auth print-identity-token` uses, so no OAuth client is created.
// SPEC-QUESTION: TASK-03 3.1 fixes aud to the installed console client ID and
// describes only the Authorization Code + PKCE browser login.
//
// Not covered here: the browser login (oidc_login_states, state/nonce, PKCE,
// the session cookie and its CSRF/Origin checks). A bearer token is not sent
// automatically by a browser, so the cookie CSRF threat does not apply to
// this transport.
package consoleauth

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/sessions"
)

// Google endpoints (TASK-03 3.1: static, not discovered at runtime).
const (
	GoogleJWKSURL = "https://www.googleapis.com/oauth2/v3/certs"
	// ClockSkew is the allowance for exp and iat.
	ClockSkew = 30 * time.Second
	// jwksMinRefresh bounds refetches triggered by an unknown kid.
	jwksMinRefresh = 30 * time.Second
	jwksDefaultTTL = time.Hour
	jwksMaxTTL     = 24 * time.Hour
	maxTokenBytes  = 16 << 10
	maxJWKSBytes   = 1 << 20
)

var googleIssuers = map[string]bool{"https://accounts.google.com": true, "accounts.google.com": true}

// Roles is the COMMON operating role enum (COMMON user roles).
var Roles = map[string]bool{"operator": true, "approver": true, "release_operator": true, "viewer": true}

// RoleMap is the installed user → role mapping (TASK-03 2: operating role group
// mapping, an install input). A user must be listed to use the console; an
// empty roles list is a plain console user (session owner and approver of
// their own actions).
//
// SPEC-QUESTION: TASK-03 maps IdP group membership to roles. A Google ID
// token carries no groups, and reading groups needs the Admin SDK Directory
// API, which is not in the identity egress/IAM tables. Until that is decided,
// the install input lists users by verified email.
type RoleMap struct {
	Tenant string     `yaml:"tenant"`
	Users  []RoleUser `yaml:"users"`
}

// RoleUser is one RoleMap entry.
type RoleUser struct {
	Email string   `yaml:"email"`
	Roles []string `yaml:"roles"`
}

// LoadRoleMap reads and validates a RoleMap YAML file.
func LoadRoleMap(path string) (RoleMap, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return RoleMap{}, err
	}
	var m RoleMap
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return RoleMap{}, fmt.Errorf("role map: %w", err)
	}
	return m, m.validate()
}

func (m RoleMap) validate() error {
	if m.Tenant == "" {
		return errors.New("role map: tenant is required")
	}
	seen := map[string]bool{}
	for _, u := range m.Users {
		e := strings.ToLower(u.Email)
		if e == "" || strings.Count(e, "@") != 1 || strings.HasPrefix(e, "@") || strings.HasSuffix(e, "@") || seen[e] {
			return fmt.Errorf("role map: bad or duplicate email %q", u.Email)
		}
		seen[e] = true
		for _, r := range u.Roles {
			if !Roles[r] {
				return fmt.Errorf("role map: unknown role %q for %s", r, u.Email)
			}
		}
	}
	return nil
}

func (m RoleMap) lookup(email string) ([]string, bool) {
	for _, u := range m.Users {
		if strings.EqualFold(u.Email, email) {
			return append([]string{}, u.Roles...), true
		}
	}
	return nil, false
}

// KeySource returns the RSA public key for kid.
type KeySource interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// Config is the verifier's install input.
type Config struct {
	// Audiences are the accepted aud values (--oidc-audience).
	Audiences []string
	// AllowedDomains are the accepted hd values (--oidc-allowed-hd).
	AllowedDomains []string
	// Roles is the role map (--oidc-role-map).
	Roles RoleMap
	// Keys verifies signatures: *JWKS against GoogleJWKSURL in production.
	Keys KeySource
	// Now defaults to time.Now.
	Now func() time.Time
}

// Verifier verifies Google ID tokens and implements sessions.ConsoleAuth.
type Verifier struct {
	audiences map[string]bool
	domains   map[string]bool
	roles     RoleMap
	keys      KeySource
	now       func() time.Time
}

var _ sessions.ConsoleAuth = (*Verifier)(nil)

// New validates cfg. Every input is required: there is no default audience,
// domain or user.
func New(cfg Config) (*Verifier, error) {
	if len(cfg.Audiences) == 0 || len(cfg.AllowedDomains) == 0 || cfg.Keys == nil {
		return nil, errors.New("consoleauth: an audience, an allowed hd and a key source are required")
	}
	v := &Verifier{audiences: map[string]bool{}, domains: map[string]bool{}, roles: cfg.Roles, keys: cfg.Keys, now: cfg.Now}
	for _, a := range cfg.Audiences {
		if a == "" {
			return nil, errors.New("consoleauth: empty audience")
		}
		v.audiences[a] = true
	}
	for _, d := range cfg.AllowedDomains {
		d = strings.ToLower(d)
		if d == "" || strings.ContainsAny(d, "@/ ") {
			return nil, fmt.Errorf("consoleauth: bad allowed hd %q", d)
		}
		v.domains[d] = true
	}
	if err := cfg.Roles.validate(); err != nil {
		return nil, err
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v, nil
}

// ErrUnauthenticated is every verification failure; handlers answer 401
// AUTH_REQUIRED.
var ErrUnauthenticated = errors.New("consoleauth: unauthenticated")

// Authenticate reads the bearer ID token and maps it to an Actor.
func (v *Verifier) Authenticate(r *http.Request) (sessions.Actor, error) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return sessions.Actor{}, ErrUnauthenticated
	}
	return v.Verify(r.Context(), tok)
}

type claims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	Exp           *json.Number    `json:"exp"`
	Iat           *json.Number    `json:"iat"`
	AuthTime      *json.Number    `json:"auth_time"`
	Hd            string          `json:"hd"`
	Email         string          `json:"email"`
	EmailVerified any             `json:"email_verified"`
}

func unauth(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrUnauthenticated, fmt.Sprintf(format, a...))
}

// Verify checks a compact JWS Google ID token and returns its Actor.
func (v *Verifier) Verify(ctx context.Context, token string) (sessions.Actor, error) {
	if len(token) > maxTokenBytes {
		return sessions.Actor{}, unauth("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return sessions.Actor{}, unauth("not a compact JWS")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return sessions.Actor{}, unauth("header: %v", err)
	}
	// Only RS256: Google signs ID tokens with RS256; alg=none, HS256 and any
	// other algorithm are refused before a key is looked up.
	if hdr.Alg != "RS256" || hdr.Kid == "" {
		return sessions.Actor{}, unauth("alg %q kid %q", hdr.Alg, hdr.Kid)
	}
	key, err := v.keys.Key(ctx, hdr.Kid)
	if err != nil {
		return sessions.Actor{}, unauth("key %q: %v", hdr.Kid, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return sessions.Actor{}, unauth("signature encoding")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return sessions.Actor{}, unauth("bad signature")
	}
	var c claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return sessions.Actor{}, unauth("claims: %v", err)
	}
	now := v.now()
	if !googleIssuers[c.Iss] {
		return sessions.Actor{}, unauth("iss %q", c.Iss)
	}
	auds, err := audiences(c.Aud)
	if err != nil {
		return sessions.Actor{}, unauth("aud")
	}
	accepted := false
	for _, a := range auds {
		accepted = accepted || v.audiences[a]
	}
	if !accepted {
		return sessions.Actor{}, unauth("aud")
	}
	if len(auds) > 1 && !v.audiences[c.Azp] {
		return sessions.Actor{}, unauth("azp")
	}
	exp, err := unix(c.Exp)
	if err != nil || !now.Before(exp.Add(ClockSkew)) {
		return sessions.Actor{}, unauth("expired")
	}
	iat, err := unix(c.Iat)
	if err != nil || iat.After(now.Add(ClockSkew)) {
		return sessions.Actor{}, unauth("iat")
	}
	hd := strings.ToLower(c.Hd)
	if hd == "" || !v.domains[hd] {
		return sessions.Actor{}, unauth("hd %q", c.Hd)
	}
	if c.Sub == "" {
		return sessions.Actor{}, unauth("no sub")
	}
	if verified, _ := c.EmailVerified.(bool); !verified || c.Email == "" {
		return sessions.Actor{}, unauth("email not verified")
	}
	if at := strings.LastIndex(c.Email, "@"); at < 0 || !strings.EqualFold(c.Email[at+1:], hd) {
		return sessions.Actor{}, unauth("email domain is not hd")
	}
	roles, ok := v.roles.lookup(c.Email)
	if !ok {
		return sessions.Actor{}, unauth("user not in role map")
	}
	actor := sessions.Actor{AuthenticatedActor: "google:" + c.Sub, Tenant: v.roles.Tenant, Roles: roles}
	// AuthTime proves recency of authentication for the approval re-auth
	// window. Browser PKCE console tokens carry auth_time; CLI ID tokens from
	// `gcloud auth print-identity-token` do not, so fall back to iat, which
	// gcloud refreshes on each call. A caller re-runs the command just before
	// approving, as it would re-authenticate in the console (TASK-03 3.x,
	// review #220).
	actor.AuthTime = iat
	if c.AuthTime != nil {
		if at, err := unix(c.AuthTime); err == nil {
			actor.AuthTime = at
		}
	}
	return actor, nil
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber()
	return dec.Decode(v)
}

func audiences(raw json.RawMessage) ([]string, error) {
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}, nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil || len(many) == 0 {
		return nil, errors.New("aud")
	}
	return many, nil
}

func unix(n *json.Number) (time.Time, error) {
	if n == nil {
		return time.Time{}, errors.New("missing")
	}
	i, err := n.Int64()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(i, 0), nil
}

// JWKS fetches and caches an RSA JWK set (Google's by default). It refetches
// after the response's Cache-Control max-age (at most 24 hours), or on an
// unknown kid at most once per jwksMinRefresh, so a key rotation is picked up
// without a restart. An expired set that cannot be refetched is not used.
type JWKS struct {
	URL    string // empty: GoogleJWKSURL
	Client *http.Client
	Now    func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	expires   time.Time
	lastFetch time.Time
}

var _ KeySource = (*JWKS)(nil)

func (j *JWKS) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	if j.Now != nil {
		now = j.Now()
	}
	if k, ok := j.keys[kid]; ok && now.Before(j.expires) {
		return k, nil
	}
	if j.keys == nil || !now.Before(j.expires) || now.Sub(j.lastFetch) >= jwksMinRefresh {
		if err := j.fetch(ctx, now); err != nil {
			return nil, err
		}
	}
	if k, ok := j.keys[kid]; ok {
		return k, nil
	}
	return nil, errors.New("unknown kid")
}

func (j *JWKS) fetch(ctx context.Context, now time.Time) error {
	j.lastFetch = now
	url := j.URL
	if url == "" {
		url = GoogleJWKSURL
	}
	c := j.Client
	if c == nil {
		c = &http.Client{Timeout: 5 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes))
	if err != nil {
		return err
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	j.keys = keys
	j.expires = now.Add(maxAge(resp.Header.Get("Cache-Control")))
	return nil
}

func maxAge(cc string) time.Duration {
	for _, d := range strings.Split(cc, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(d), "max-age="); ok {
			if s, err := strconv.Atoi(v); err == nil && s > 0 {
				return min(time.Duration(s)*time.Second, jwksMaxTTL)
			}
		}
	}
	return jwksDefaultTTL
}

// ParseJWKS reads the RS256 signing keys of a JWK set.
func ParseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < 2048 || pub.E < 3 {
			continue
		}
		out[k.Kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks: no RS256 keys")
	}
	return out, nil
}
