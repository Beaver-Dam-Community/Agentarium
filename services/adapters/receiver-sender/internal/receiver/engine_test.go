package receiver_test

// Shared-engine behaviour (packages/adapters/execute) that receiver-sender
// itself does not use: the Resolver step, the non-broker credential
// strategies and the agentarium-trust URI SAN rule end to end. The receiver
// harness provides the coordinator, the TLS target and the commit order; the
// adapters below wrap receiver.Adapter.

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/services/adapters/receiver-sender/internal/receiver"
)

// unboundAdapter is receiver.Adapter for an operation without a
// credential_binding (the kubernetes-reader, model and evidence-reader
// shape). It records the Resolved value Prepare saw.
type unboundAdapter struct {
	receiver.Adapter
	mu       *sync.Mutex
	resolved *[]any
}

func newUnbound() unboundAdapter {
	return unboundAdapter{mu: &sync.Mutex{}, resolved: &[]any{}}
}

func (a unboundAdapter) Prepare(in execute.Inputs, b *execute.Bundle) (execute.Prepared, *execute.Rejection) {
	a.mu.Lock()
	*a.resolved = append(*a.resolved, in.Resolved)
	a.mu.Unlock()
	p, rej := a.Adapter.Prepare(in, b)
	p.CredentialBinding = ""
	return p, rej
}

func (a unboundAdapter) seen() []any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]any(nil), *a.resolved...)
}

// resolvingAdapter reads one referenced action result. It ignores a refs
// error on purpose (ignore=true) to show the engine rejects anyway.
type resolvingAdapter struct {
	unboundAdapter
	ref    string
	ignore bool
}

func (a resolvingAdapter) ResolveRefs(ctx context.Context, _ execute.Inputs, _ *execute.Bundle, refs execute.RefStore) (any, *execute.Rejection, error) {
	r, err := refs.ActionResult(ctx, a.ref)
	if err != nil && !a.ignore {
		return nil, nil, err
	}
	return r, nil, nil
}

type refStore struct {
	results map[string]execute.RefResult
	err     error
	calls   int
}

func (s *refStore) ActionResult(_ context.Context, id string) (execute.RefResult, error) {
	s.calls++
	if s.err != nil {
		return execute.RefResult{}, s.err
	}
	r, ok := s.results[id]
	if !ok {
		return execute.RefResult{}, execute.ErrNotFound
	}
	return r, nil
}

func (s *refStore) ModelTurn(context.Context, string, int64) (execute.RefModelTurn, error) {
	return execute.RefModelTurn{}, execute.ErrNotFound
}

// rebuild replaces the harness engine with one built from cfg.
func (h *harness) rebuild(f func(*execute.Config)) {
	h.t.Helper()
	cfg := h.cfg
	f(&cfg)
	e, err := execute.New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.cfg, h.engine = cfg, e
}

func (h *harness) wantRejected(row execute.Execution, code, field string) {
	h.t.Helper()
	if row.State != execute.StatePreflightRejected {
		h.t.Fatalf("state %s, ops %v", row.State, h.log.list())
	}
	if h.coord.reservations != 0 || h.recv.count.Load() != 0 {
		h.t.Fatalf("reserved %d sent %d", h.coord.reservations, h.recv.count.Load())
	}
	ev := h.audit.find("preflight_rejected")
	if ev == nil || !slices.Contains(ev.Payload["reason_codes"].([]string), code) || !slices.Contains(ev.Payload["compared_fields"].([]string), field) {
		h.t.Fatalf("preflight_rejected %+v", ev)
	}
}

func (h *harness) wantReleased(row execute.Execution) {
	h.t.Helper()
	if row.State != execute.StateFailed || h.recv.count.Load() != 0 {
		h.t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
	}
	o := h.coord.last()
	if o.Transition != "released" || !slices.Equal(o.ReasonCodes, []string{"CREDENTIAL_UNAVAILABLE"}) || o.Observation != nil {
		h.t.Fatalf("outcome %+v", o)
	}
	if slices.Contains(h.log.list(), "claim") {
		h.t.Fatal("permit claimed after a credential failure")
	}
}

const sessionID = "51ab2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d" // h.action's user session

func refResult(id, session string) execute.RefResult {
	return execute.RefResult{Result: execute.ActionResult{ActionID: id, ExecutionState: "accepted"}, Session: execute.RefSession{Kind: "user", ID: session}}
}

func TestResolverResultReachesPrepare(t *testing.T) {
	h := newHarness(t)
	ref := newUUID()
	refs := &refStore{results: map[string]execute.RefResult{ref: refResult(ref, sessionID)}}
	ad := resolvingAdapter{unboundAdapter: newUnbound(), ref: ref}
	h.rebuild(func(c *execute.Config) {
		c.Adapter, c.Refs, c.Credential = ad, refs, execute.CredentialStrategy{Kind: execute.CredentialNone}
	})
	d, a := h.action(okPayload)
	if row := h.run(d, a); row.State != execute.StateCompleted {
		t.Fatalf("state %s ops %v", row.State, h.log.list())
	}
	seen := ad.seen()
	if len(seen) != 1 {
		t.Fatalf("Prepare calls %d", len(seen))
	}
	if r, ok := seen[0].(execute.RefResult); !ok || r.Result.ActionID != ref {
		t.Fatalf("Prepare saw Resolved %#v", seen[0])
	}
}

func TestResolverOwnershipRejects(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		t.Run("ignore error "+strconv.FormatBool(ignore), func(t *testing.T) {
			h := newHarness(t)
			ref := newUUID()
			refs := &refStore{results: map[string]execute.RefResult{ref: refResult(ref, "7e3b1c2d-0000-4000-8000-000000000001")}}
			ad := resolvingAdapter{unboundAdapter: newUnbound(), ref: ref, ignore: ignore}
			h.rebuild(func(c *execute.Config) {
				c.Adapter, c.Refs, c.Credential = ad, refs, execute.CredentialStrategy{Kind: execute.CredentialNone}
			})
			d, a := h.action(okPayload)
			h.wantRejected(h.run(d, a), "PREFLIGHT_MISMATCH", "references")
			if len(ad.seen()) != 0 {
				t.Fatal("Prepare ran after an ownership failure")
			}
		})
	}
	t.Run("service session kind differs", func(t *testing.T) {
		h := newHarness(t)
		ref := newUUID()
		r := refResult(ref, sessionID)
		r.Session.Kind = "service"
		ad := resolvingAdapter{unboundAdapter: newUnbound(), ref: ref}
		h.rebuild(func(c *execute.Config) {
			c.Adapter, c.Refs, c.Credential = ad, &refStore{results: map[string]execute.RefResult{ref: r}}, execute.CredentialStrategy{Kind: execute.CredentialNone}
		})
		d, a := h.action(okPayload)
		h.wantRejected(h.run(d, a), "PREFLIGHT_MISMATCH", "references")
	})
}

func TestResolverMissingRowRejects(t *testing.T) {
	h := newHarness(t)
	ad := resolvingAdapter{unboundAdapter: newUnbound(), ref: newUUID()}
	h.rebuild(func(c *execute.Config) {
		c.Adapter, c.Refs, c.Credential = ad, &refStore{}, execute.CredentialStrategy{Kind: execute.CredentialNone}
	})
	d, a := h.action(okPayload)
	h.wantRejected(h.run(d, a), "PREFLIGHT_MISMATCH", "references")
}

// An unreadable store (and the Unwired default) is not a preflight result:
// the execution stays received with nothing reserved.
func TestResolverStoreUnavailableStaysReceived(t *testing.T) {
	for name, refs := range map[string]execute.RefStore{"unwired default": nil, "store error": &refStore{err: errors.New("db down")}} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			ad := resolvingAdapter{unboundAdapter: newUnbound(), ref: newUUID()}
			h.rebuild(func(c *execute.Config) {
				c.Adapter, c.Refs, c.Credential = ad, refs, execute.CredentialStrategy{Kind: execute.CredentialNone}
			})
			d, a := h.action(okPayload)
			if row := h.run(d, a); row.State != execute.StateReceived || h.coord.reservations != 0 || len(h.audit.types()) != 0 {
				t.Fatalf("state %s reserved %d events %v", row.State, h.coord.reservations, h.audit.types())
			}
		})
	}
}

// The adapter's strategy and the catalog credential_binding must agree.
func TestCredentialStrategyMatchesBinding(t *testing.T) {
	t.Run("token_file with a binding", func(t *testing.T) {
		h := newHarness(t)
		h.rebuild(func(c *execute.Config) {
			c.Credential = execute.CredentialStrategy{Kind: execute.CredentialTokenFile, TokenFile: "/nonexistent"}
		})
		d, a := h.action(okPayload)
		h.wantRejected(h.run(d, a), "PREFLIGHT_MISMATCH", "credential_binding")
	})
	t.Run("broker without a binding", func(t *testing.T) {
		h := newHarness(t)
		h.rebuild(func(c *execute.Config) { c.Adapter = newUnbound() })
		d, a := h.action(okPayload)
		h.wantRejected(h.run(d, a), "PREFLIGHT_MISMATCH", "credential_binding")
		if h.broker.calls.Load() != 0 {
			t.Fatal("broker called")
		}
	})
}

func TestNewRejectsCredentialStrategy(t *testing.T) {
	h := newHarness(t)
	for name, s := range map[string]execute.CredentialStrategy{
		"empty kind":          {},
		"unknown kind":        {Kind: "wif"},
		"token_file w/o path": {Kind: execute.CredentialTokenFile},
	} {
		cfg := h.cfg
		cfg.Credential = s
		if _, err := execute.New(cfg); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestCredentialNoneSendsNoCredentialHeader(t *testing.T) {
	h := newHarness(t)
	h.rebuild(func(c *execute.Config) {
		c.Adapter, c.Credential = newUnbound(), execute.CredentialStrategy{Kind: execute.CredentialNone}
	})
	d, a := h.action(okPayload)
	if row := h.run(d, a); row.State != execute.StateCompleted {
		t.Fatalf("state %s", row.State)
	}
	hd := h.recv.headers[0]
	if hd.Get("Authorization") != "" || hd.Get(apiKeyHeader) != "" || h.broker.calls.Load() != 0 {
		t.Fatalf("credential header sent: %v", hd)
	}
}

func jwt(t *testing.T, payload string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","kid":"k"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("signature"))
}

func TestCredentialTokenFile(t *testing.T) {
	future := strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10)
	past := strconv.FormatInt(time.Now().Add(-time.Minute).Unix(), 10)
	good := jwt(t, `{"aud":["https://kubernetes.default.svc"],"exp":`+future+`}`)

	run := func(t *testing.T, content *string) (*harness, execute.Execution) {
		h := newHarness(t)
		path := filepath.Join(t.TempDir(), "token")
		if content != nil {
			if err := os.WriteFile(path, []byte(*content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		h.rebuild(func(c *execute.Config) {
			c.Adapter, c.Credential = newUnbound(), execute.CredentialStrategy{Kind: execute.CredentialTokenFile, TokenFile: path}
		})
		d, a := h.action(okPayload)
		return h, h.run(d, a)
	}

	t.Run("projected token sent as bearer", func(t *testing.T) {
		withNL := good + "\n"
		h, row := run(t, &withNL)
		if row.State != execute.StateCompleted {
			t.Fatalf("state %s", row.State)
		}
		if got := h.recv.headers[0].Get("Authorization"); got != "Bearer "+good {
			t.Fatalf("Authorization %q", got)
		}
	})
	bad := map[string]*string{
		"missing file":    nil,
		"expired exp":     ptr(jwt(t, `{"exp":`+past+`}`)),
		"no exp":          ptr(jwt(t, `{"aud":"x"}`)),
		"string exp":      ptr(jwt(t, `{"exp":"`+future+`"}`)),
		"not a JWT":       ptr("opaque-token"),
		"empty":           ptr(""),
		"header splitter": ptr(good + "\r\nX-Injected: 1"),
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			h, row := run(t, content)
			h.wantReleased(row)
		})
	}
}

func ptr(s string) *string { return &s }

type tokenSource struct {
	tok   execute.AccessToken
	err   error
	calls int
}

func (s *tokenSource) Token(context.Context) (execute.AccessToken, error) {
	s.calls++
	return s.tok, s.err
}

func TestCredentialTokenSource(t *testing.T) {
	run := func(t *testing.T, ts execute.TokenSource) (*harness, execute.Execution) {
		h := newHarness(t)
		h.rebuild(func(c *execute.Config) {
			c.Adapter, c.Credential = newUnbound(), execute.CredentialStrategy{Kind: execute.CredentialTokenSource, TokenSource: ts}
		})
		d, a := h.action(okPayload)
		return h, h.run(d, a)
	}
	t.Run("WIF token sent as bearer", func(t *testing.T) {
		ts := &tokenSource{tok: execute.AccessToken{Value: "ya29.c.synthetic-token", Type: "Bearer", Expiry: time.Now().Add(time.Hour)}}
		h, row := run(t, ts)
		if row.State != execute.StateCompleted || ts.calls != 1 {
			t.Fatalf("state %s calls %d", row.State, ts.calls)
		}
		if got := h.recv.headers[0].Get("Authorization"); got != "Bearer ya29.c.synthetic-token" {
			t.Fatalf("Authorization %q", got)
		}
	})
	exp := time.Now().Add(time.Hour)
	for name, ts := range map[string]execute.TokenSource{
		"unwired default": nil,
		"source error":    &tokenSource{err: errors.New("metadata server unavailable")},
		"no expiry":       &tokenSource{tok: execute.AccessToken{Value: "t", Type: "Bearer"}},
		"expired":         &tokenSource{tok: execute.AccessToken{Value: "t", Expiry: time.Now().Add(-time.Second)}},
		"not bearer":      &tokenSource{tok: execute.AccessToken{Value: "t", Type: "MAC", Expiry: exp}},
		"empty token":     &tokenSource{tok: execute.AccessToken{Expiry: exp}},
		"space in token":  &tokenSource{tok: execute.AccessToken{Value: "a b", Expiry: exp}},
		"CRLF in token":   &tokenSource{tok: execute.AccessToken{Value: "a\r\nHost: x", Expiry: exp}},
	} {
		t.Run(name, func(t *testing.T) {
			h, row := run(t, ts)
			h.wantReleased(row)
		})
	}
}

// A broker answer may not set a reserved or malformed header.
func TestBrokerHeaderRulesKept(t *testing.T) {
	for name, cred := range map[string]execute.Credential{
		"reserved name":    {SecretVersion: "3", HeaderName: "Host", HeaderValue: "x", ExpiresAt: time.Now().Add(time.Minute)},
		"attempt header":   {SecretVersion: "3", HeaderName: "x-agentarium-attempt-id", HeaderValue: "x", ExpiresAt: time.Now().Add(time.Minute)},
		"control in value": {SecretVersion: "3", HeaderName: apiKeyHeader, HeaderValue: "a\nb", ExpiresAt: time.Now().Add(time.Minute)},
		"expired":          {SecretVersion: "3", HeaderName: apiKeyHeader, HeaderValue: "x", ExpiresAt: time.Now().Add(-time.Second)},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.rebuild(func(c *execute.Config) { c.Credentials = fixedBroker{cred} })
			d, a := h.action(okPayload)
			h.wantReleased(h.run(d, a))
		})
	}
}

type fixedBroker struct{ c execute.Credential }

func (b fixedBroker) Resolve(context.Context, string, string, string) (execute.Credential, error) {
	return b.c, nil
}

func TestCredentialNeverFormatted(t *testing.T) {
	c := execute.Credential{SecretVersion: "3", HeaderName: apiKeyHeader, HeaderValue: apiKeyValue, ExpiresAt: time.Now()}
	for _, s := range []string{c.String(), c.GoString(), c.LogValue().String()} {
		if strings.Contains(s, apiKeyValue) {
			t.Fatalf("credential value in %q", s)
		}
	}
	if _, err := c.MarshalJSON(); err == nil {
		t.Fatal("credential serialized")
	}
}

// agentarium-trust end to end: the catalog expected_uri_san reaches the
// transport, a receiver certificate with another URI SAN fails the attempt
// with TLS_VERIFY_FAILED before anything is sent, and a trust target without
// expected_uri_san is rejected in preflight.
func TestTrustTargetURISAN(t *testing.T) {
	setSAN := func(san *string) option {
		return func(cat *canonical.Catalog) {
			tg := cat.Targets["receiver-primary"]
			tg.ExpectedURISAN = san
			cat.Targets["receiver-primary"] = tg
		}
	}
	t.Run("other URI SAN", func(t *testing.T) {
		h := newHarness(t, setSAN(ptr("spiffe://agentarium.internal/ns/agent-targets/sa/receiver-probe")))
		d, a := h.action(okPayload)
		row := h.run(d, a)
		if row.State != execute.StateFailed || h.recv.count.Load() != 0 {
			t.Fatalf("state %s sends %d", row.State, h.recv.count.Load())
		}
		if o := h.coord.last(); o.Transition != "failed" || !slices.Equal(o.ReasonCodes, []string{"TLS_VERIFY_FAILED"}) {
			t.Fatalf("outcome %+v", o)
		}
		if ev := h.audit.find("attempt_failed"); ev == nil || ev.Payload["stage"] != "tls" {
			t.Fatalf("attempt_failed %+v", ev)
		}
	})
	t.Run("no expected_uri_san", func(t *testing.T) {
		h := newHarness(t, setSAN(nil))
		d, a := h.action(okPayload)
		h.wantRejected(h.run(d, a), "PREFLIGHT_MISMATCH", "wire_plan")
	})
}
