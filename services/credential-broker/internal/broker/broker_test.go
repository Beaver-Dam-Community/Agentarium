package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type repo struct {
	binding Binding
	deny    bool
	calls   int
}

func (r *repo) Resolve(_ context.Context, ns, ksa string, q Request) (Binding, error) {
	r.calls++
	if r.deny || ns != "agent-adapters" || ksa != "receiver-sender" || q.AdapterID != "receiver-sender" || q.Binding != "receiver-api-key" {
		return Binding{}, ErrUnavailable
	}
	return r.binding, nil
}

type secret struct {
	calls int
	value []byte
	err   error
	after func()
}

func (s *secret) Access(context.Context, string) ([]byte, error) {
	s.calls++
	if s.after != nil {
		s.after()
	}
	return append([]byte(nil), s.value...), s.err
}
func fixture() (Service, *repo, *secret, Request) {
	r := &repo{binding: Binding{"projects/123/secrets/receiver", "1", "Authorization", "bearer"}}
	s := &secret{value: []byte("synthetic-token")}
	return Service{Repo: r, Secrets: s}, r, s, Request{"61041562-9572-4f87-a24c-f4842fe35177", "receiver-sender", "receiver-api-key"}
}
func TestCacheExpiryRotationAndAuthorization(t *testing.T) {
	service, r, s, q := fixture()
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	service.Now = func() time.Time { return now }
	run := func() (Response, error) {
		return service.Resolve(context.Background(), "agent-adapters", "receiver-sender", q)
	}
	first, e := run()
	if e != nil || first.HeaderValue != "Bearer synthetic-token" || !first.ExpiresAt.Equal(now.Add(60*time.Second)) {
		t.Fatal(first, e)
	}
	now = now.Add(59 * time.Second)
	again, e := run()
	if e != nil || s.calls != 1 || again.ExpiresAt != first.ExpiresAt {
		t.Fatal(again, e, s.calls)
	}
	r.deny = true
	if _, e = run(); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cache bypassed authorization")
	}
	r.deny = false
	r.binding.Version = "2"
	if v, e := run(); e != nil || v.Version != "2" || s.calls != 2 {
		t.Fatal(v, e, s.calls)
	}
	now = now.Add(60 * time.Second)
	service.PurgeExpired()
	if len(service.cache) != 0 {
		t.Fatal("expired values retained")
	}
	s.err = errors.New("provider failure includes synthetic-secret")
	if _, e = run(); e != ErrUnavailable {
		t.Fatal("provider details leaked")
	}
}
func TestRevalidationAndHeaderInjection(t *testing.T) {
	service, r, s, q := fixture()
	s.after = func() { r.deny = true }
	if _, e := service.Resolve(context.Background(), "agent-adapters", "receiver-sender", q); e == nil {
		t.Fatal("revoked authorization during fetch accepted")
	}
	for _, value := range [][]byte{[]byte("secret\r\nX-Injected: true"), []byte(""), []byte(strings.Repeat("a", 2048)), {255}} {
		service, _, s, q = fixture()
		s.value = value
		if _, e := service.Resolve(context.Background(), "agent-adapters", "receiver-sender", q); e == nil {
			t.Fatal("invalid header accepted")
		}
	}
	service, r, s, q = fixture()
	r.binding.Version = "latest"
	if _, e := service.Resolve(context.Background(), "agent-adapters", "receiver-sender", q); e == nil || s.calls != 0 {
		t.Fatal("alias fetched")
	}
	service, r, s, q = fixture()
	r.binding.HeaderName = "X-Bad\r\n"
	if _, e := service.Resolve(context.Background(), "agent-adapters", "receiver-sender", q); e == nil || s.calls != 0 {
		t.Fatal("bad header fetched")
	}
}
func TestHTTPTLSAndStrictInput(t *testing.T) {
	for _, mode := range []string{"valid", "header-only", "wrong-san", "other-adapter", "unknown", "duplicate", "bad-json"} {
		t.Run(mode, func(t *testing.T) {
			service, _, secret, q := fixture()
			body, _ := json.Marshal(q)
			san := "spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"
			if mode == "wrong-san" {
				san = "spiffe://agentarium.internal/ns/agent-exec/sa/receiver-sender"
			}
			if mode == "other-adapter" {
				q.AdapterID = "model-adapter"
				body, _ = json.Marshal(q)
			}
			if mode == "unknown" {
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"secret_resource":"projects/evil/secrets/token"}`)
			}
			if mode == "duplicate" {
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"adapter_id":"receiver-sender"}`)
			}
			if mode == "bad-json" {
				body = []byte(`{`)
			}
			request := httptest.NewRequest("POST", "https://broker/internal/credentials:resolve", strings.NewReader(string(body)))
			u, _ := url.Parse(san)
			if mode != "header-only" {
				request.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{u}}}}}
			}
			request.Header.Set("X-Agentarium-Peer-Identity", san)
			response := httptest.NewRecorder()
			Handler{&service}.ServeHTTP(response, request)
			want := 503
			if mode == "valid" {
				want = 200
			}
			if mode == "unknown" || mode == "duplicate" || mode == "bad-json" {
				want = 422
			}
			if response.Code != want {
				t.Fatalf("status %d want %d", response.Code, want)
			}
			if mode != "valid" && (secret.calls != 0 || strings.Contains(response.Body.String(), "synthetic-token")) {
				t.Fatal("secret fetched or leaked on denial")
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("cacheable credential response")
			}
		})
	}
}

// The observation boundary must not receive upstream error text or secret data.
func TestFailureObservationsContainOnlyFixedCategories(t *testing.T) {
	for _, mode := range []string{"database_or_binding", "secret_manager", "invalid_secret_header", "revalidation"} {
		t.Run(mode, func(t *testing.T) {
			service, r, secret, request := fixture()
			switch mode {
			case "database_or_binding":
				r.deny = true
			case "secret_manager":
				secret.err = errors.New("provider detail synthetic-token")
			case "invalid_secret_header":
				secret.value = []byte("synthetic-token\r\nInjected: value")
			case "revalidation":
				secret.after = func() { r.deny = true }
			}
			var observations []string
			service.ObserveFailure = func(category string) { observations = append(observations, category) }
			response, err := service.Resolve(context.Background(), "agent-adapters", "receiver-sender", request)
			if err != ErrUnavailable || response.HeaderValue != "" {
				t.Fatal("failure exposed details")
			}
			if len(observations) != 1 || observations[0] != mode {
				t.Fatalf("observations = %q, want only %q", observations, mode)
			}
		})
	}
	service, _, _, request := fixture()
	service.ObserveFailure = func(string) { t.Error("success reported as failure") }
	if _, err := service.Resolve(context.Background(), "agent-adapters", "receiver-sender", request); err != nil {
		t.Fatal(err)
	}
}
