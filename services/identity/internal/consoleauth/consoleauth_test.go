package consoleauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// gcloudAudience is the client ID in `gcloud auth print-identity-token`
	// tokens, the M3-1 demonstration audience.
	gcloudAudience = "32555940559.apps.googleusercontent.com"
	otherAudience  = "123-console.apps.googleusercontent.com"
	domain         = "example.org"
)

var now = time.Unix(1_800_000_000, 0)

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func jwk(kid string, k *rsa.PrivateKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

// jwksServer serves a replaceable JWK set and counts fetches.
type jwksServer struct {
	mu      sync.Mutex
	keys    []map[string]string
	fetches int
	fail    bool
	srv     *httptest.Server
}

func newJWKSServer(t *testing.T, keys ...map[string]string) *jwksServer {
	s := &jwksServer{keys: keys}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.fetches++
		if s.fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=600")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": s.keys})
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *jwksServer) set(keys ...map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys = keys
}

type fixture struct {
	key, other *rsa.PrivateKey
	jwks       *JWKS
	server     *jwksServer
	clock      *time.Time
	v          *Verifier
}

// newFixture points the production JWKS fetcher at a local JWK set and
// injects it through Config.Keys.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{key: newKey(t), other: newKey(t)}
	clock := now
	f.clock = &clock
	f.server = newJWKSServer(t, jwk("k1", f.key))
	f.jwks = &JWKS{URL: f.server.srv.URL, Client: f.server.srv.Client(), Now: func() time.Time { return *f.clock }}
	v, err := New(Config{
		Audiences: []string{gcloudAudience, otherAudience}, AllowedDomains: []string{domain},
		Roles: RoleMap{Tenant: "hackathon", Users: []RoleUser{{Email: "alice@example.org", Roles: []string{"operator"}}}},
		Keys:  f.jwks, Now: func() time.Time { return *f.clock },
	})
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	return f
}

// baseClaims is the shape of a gcloud user ID token.
func baseClaims() map[string]any {
	return map[string]any{
		"iss": "https://accounts.google.com", "sub": "1001", "aud": gcloudAudience, "azp": gcloudAudience,
		"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		"hd": domain, "email": "alice@example.org", "email_verified": true, "at_hash": "x",
	}
}

func sign(t *testing.T, key *rsa.PrivateKey, hdr, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func rs256(kid string) map[string]any {
	return map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
}

func TestValidToken(t *testing.T) {
	f := newFixture(t)
	r := httptest.NewRequest("GET", "/v1/approvals/pending", nil)
	r.Header.Set("Authorization", "Bearer "+sign(t, f.key, rs256("k1"), baseClaims()))
	a, err := f.v.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	// A CLI ID token carries no auth_time, so AuthTime falls back to iat
	// (review #220) — here iat is now-1m from baseClaims.
	if a.AuthenticatedActor != "google:1001" || a.Tenant != "hackathon" || !a.HasRole("operator") || !a.AuthTime.Equal(now.Add(-time.Minute)) {
		t.Fatalf("actor %+v", a)
	}
	// The legacy issuer form, a second configured audience, auth_time and
	// an upper-case email are accepted.
	c := baseClaims()
	c["iss"], c["aud"], c["azp"] = "accounts.google.com", otherAudience, otherAudience
	c["auth_time"], c["email"] = now.Add(-2*time.Minute).Unix(), "Alice@Example.org"
	a, err = f.v.Verify(context.Background(), sign(t, f.key, rs256("k1"), c))
	if err != nil || !a.AuthTime.Equal(now.Add(-2*time.Minute)) {
		t.Fatal(a, err)
	}
	// Within the clock skew.
	c = baseClaims()
	c["exp"], c["iat"] = now.Add(-10*time.Second).Unix(), now.Add(10*time.Second).Unix()
	if _, err := f.v.Verify(context.Background(), sign(t, f.key, rs256("k1"), c)); err != nil {
		t.Fatal(err)
	}
	// Several audiences with an accepted azp.
	c = baseClaims()
	c["aud"] = []string{gcloudAudience, "x"}
	if _, err := f.v.Verify(context.Background(), sign(t, f.key, rs256("k1"), c)); err != nil {
		t.Fatal(err)
	}
}

func TestRejected(t *testing.T) {
	f := newFixture(t)
	mod := func(kv ...any) map[string]any {
		c := baseClaims()
		for i := 0; i < len(kv); i += 2 {
			if kv[i+1] == nil {
				delete(c, kv[i].(string))
			} else {
				c[kv[i].(string)] = kv[i+1]
			}
		}
		return c
	}
	cases := map[string]string{
		"wrong aud":          sign(t, f.key, rs256("k1"), mod("aud", "other-client", "azp", "other-client")),
		"empty aud list":     sign(t, f.key, rs256("k1"), mod("aud", []string{})),
		"missing aud":        sign(t, f.key, rs256("k1"), mod("aud", nil)),
		"multi aud bad azp":  sign(t, f.key, rs256("k1"), mod("aud", []string{gcloudAudience, "x"}, "azp", "x")),
		"expired":            sign(t, f.key, rs256("k1"), mod("exp", now.Add(-time.Minute).Unix())),
		"missing exp":        sign(t, f.key, rs256("k1"), mod("exp", nil)),
		"future iat":         sign(t, f.key, rs256("k1"), mod("iat", now.Add(time.Hour).Unix())),
		"missing iat":        sign(t, f.key, rs256("k1"), mod("iat", nil)),
		"bad signature":      sign(t, f.other, rs256("k1"), baseClaims()),
		"wrong iss":          sign(t, f.key, rs256("k1"), mod("iss", "https://evil.example")),
		"wrong hd":           sign(t, f.key, rs256("k1"), mod("hd", "gmail.com", "email", "alice@gmail.com")),
		"missing hd":         sign(t, f.key, rs256("k1"), mod("hd", nil)),
		"email not in hd":    sign(t, f.key, rs256("k1"), mod("email", "alice@evil.example")),
		"unverified email":   sign(t, f.key, rs256("k1"), mod("email_verified", false)),
		"string verified":    sign(t, f.key, rs256("k1"), mod("email_verified", "true")),
		"no sub":             sign(t, f.key, rs256("k1"), mod("sub", nil)),
		"not in role map":    sign(t, f.key, rs256("k1"), mod("email", "mallory@example.org")),
		"unknown kid":        sign(t, f.key, rs256("k2"), baseClaims()),
		"HS256":              sign(t, f.key, map[string]any{"alg": "HS256", "kid": "k1"}, baseClaims()),
		"tampered claims":    tamper(sign(t, f.key, rs256("k1"), baseClaims())),
		"alg none":           none(baseClaims()),
		"not a jws":          "abc.def",
		"oversized":          strings.Repeat("a", maxTokenBytes+1),
		"garbage segments":   "a.b.c",
		"signature encoding": sign(t, f.key, rs256("k1"), baseClaims()) + "*",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := f.v.Verify(context.Background(), tok); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestMissingToken(t *testing.T) {
	f := newFixture(t)
	for _, h := range []string{"", "Bearer ", "Basic abc", "bearer " + sign(t, f.key, rs256("k1"), baseClaims())} {
		r := httptest.NewRequest("GET", "/", nil)
		if h != "" {
			r.Header.Set("Authorization", h)
		}
		if _, err := f.v.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("%q accepted", h)
		}
	}
}

// A rotated key is fetched on first sight of its kid (rate limited), the
// removed key stops verifying, and an expired set that cannot be refetched
// is not used.
func TestJWKSRotation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.v.Verify(ctx, sign(t, f.key, rs256("k1"), baseClaims())); err != nil {
		t.Fatal(err)
	}
	next := newKey(t)
	f.server.set(jwk("k2", next))
	// Within jwksMinRefresh of the first fetch an unknown kid is not refetched.
	*f.clock = now.Add(10 * time.Second)
	if _, err := f.v.Verify(ctx, sign(t, next, rs256("k2"), baseClaims())); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("unknown kid accepted before refresh")
	}
	if f.server.fetches != 1 {
		t.Fatalf("fetches %d", f.server.fetches)
	}
	*f.clock = now.Add(jwksMinRefresh + time.Second)
	if _, err := f.v.Verify(ctx, sign(t, next, rs256("k2"), baseClaims())); err != nil {
		t.Fatal("rotated key rejected:", err)
	}
	if f.server.fetches != 2 {
		t.Fatalf("fetches %d", f.server.fetches)
	}
	// k1 left the set: no longer accepted after the refresh.
	*f.clock = now.Add(2*jwksMinRefresh + 2*time.Second)
	if _, err := f.v.Verify(ctx, sign(t, f.key, rs256("k1"), baseClaims())); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("removed key accepted")
	}
	// Cached keys are used until max-age; after that a failed fetch fails closed.
	f.server.mu.Lock()
	f.server.fail = true
	f.server.mu.Unlock()
	*f.clock = now.Add(5 * time.Minute)
	c := baseClaims()
	c["exp"] = now.Add(2 * time.Hour).Unix()
	if _, err := f.v.Verify(ctx, sign(t, next, rs256("k2"), c)); err != nil {
		t.Fatal("cached key rejected:", err)
	}
	*f.clock = now.Add(time.Hour)
	if _, err := f.v.Verify(ctx, sign(t, next, rs256("k2"), c)); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("expired JWKS used")
	}
}

func TestNewRequiresInputs(t *testing.T) {
	roles := RoleMap{Tenant: "t"}
	keys := &JWKS{}
	for name, cfg := range map[string]Config{
		"no audience":  {AllowedDomains: []string{domain}, Roles: roles, Keys: keys},
		"empty aud":    {Audiences: []string{""}, AllowedDomains: []string{domain}, Roles: roles, Keys: keys},
		"no domain":    {Audiences: []string{gcloudAudience}, Roles: roles, Keys: keys},
		"bad domain":   {Audiences: []string{gcloudAudience}, AllowedDomains: []string{"a@b"}, Roles: roles, Keys: keys},
		"no keys":      {Audiences: []string{gcloudAudience}, AllowedDomains: []string{domain}, Roles: roles},
		"no role map":  {Audiences: []string{gcloudAudience}, AllowedDomains: []string{domain}, Keys: keys},
		"unknown role": {Audiences: []string{gcloudAudience}, AllowedDomains: []string{domain}, Keys: keys, Roles: RoleMap{Tenant: "t", Users: []RoleUser{{Email: "a@b.c", Roles: []string{"admin"}}}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func tamper(tok string) string {
	p := strings.Split(tok, ".")
	c, _ := json.Marshal(map[string]any{"sub": "evil"})
	return p[0] + "." + base64.RawURLEncoding.EncodeToString(c) + "." + p[2]
}

func none(claims map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "k1"})
	c, _ := json.Marshal(claims)
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + "."
}

func TestLoadRoleMap(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.yaml")
	if err := os.WriteFile(good, []byte("tenant: hackathon\nusers:\n  - email: a@example.org\n    roles: [operator, approver]\n  - email: b@example.org\n    roles: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadRoleMap(good)
	if err != nil || len(m.Users) != 2 {
		t.Fatal(m, err)
	}
	for name, body := range map[string]string{
		"unknown role":  "tenant: t\nusers:\n  - email: a@example.org\n    roles: [admin]\n",
		"no tenant":     "users: []\n",
		"unknown field": "tenant: t\ngroups: []\n",
		"duplicate":     "tenant: t\nusers:\n  - email: a@example.org\n  - email: A@example.org\n",
		"bad email":     "tenant: t\nusers:\n  - email: a@\n",
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".yaml")
		_ = os.WriteFile(p, []byte(body), 0o600)
		if _, err := LoadRoleMap(p); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := LoadRoleMap(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}
