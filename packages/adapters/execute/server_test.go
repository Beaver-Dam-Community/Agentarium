package execute_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/execute"
	"github.com/Beaver-Dam-Community/Agentarium/packages/adapters/testpki"
	"github.com/Beaver-Dam-Community/Agentarium/packages/transport"
)

type stubAdapter struct{}

func (stubAdapter) ID() string { return "receiver-sender" }
func (stubAdapter) Prepare(execute.Inputs, *execute.Bundle) (execute.Prepared, *execute.Rejection) {
	return execute.Prepared{}, &execute.Rejection{ReasonCodes: []string{"PREFLIGHT_MISMATCH"}}
}
func (stubAdapter) MapResponse(transport.Result) execute.Mapping { return execute.Mapping{} }

type rowStore struct {
	mu   sync.Mutex
	rows map[string]execute.Execution
}

func (s *rowStore) Begin(_ context.Context, d, a, ad string) (execute.Execution, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.rows[d]; ok {
		return r, false, nil
	}
	r := execute.Execution{DecisionID: d, ActionID: a, AdapterID: ad, State: execute.StateReceived}
	s.rows[d] = r
	return r, true, nil
}
func (s *rowStore) SetState(_ context.Context, d string, from []string, to, at string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.rows[d]
	r.State = to
	s.rows[d] = r
	return true, nil
}
func (s *rowStore) Unfinished(context.Context, string) ([]execute.Execution, error) { return nil, nil }
func (s *rowStore) SavePending(context.Context, execute.PendingOutcome, *execute.DataStateRaise) error {
	return nil
}
func (s *rowStore) Pending(context.Context, string) (execute.PendingOutcome, error) {
	return execute.PendingOutcome{}, execute.ErrNotFound
}
func (s *rowStore) InsertResult(context.Context, execute.ActionResult) error  { return nil }
func (s *rowStore) EventID(_ context.Context, _, _, c string) (string, error) { return c, nil }

func TestExecuteHandler(t *testing.T) {
	ca := testpki.NewCA(t, "trust")
	server := ca.Issue(t, []string{"receiver-sender.agent-adapters.svc"}, nil, []string{"spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender"})
	gateway := ca.Issue(t, nil, nil, []string{execute.GatewaySAN})
	other := ca.Issue(t, nil, nil, []string{"spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime"})
	gatewayDNS := ca.Issue(t, []string{"policy-gateway.agent-control.svc"}, nil, []string{execute.GatewaySAN})

	// Unwired dependencies: the execution stops before the reservation.
	eng, err := execute.New(execute.Config{Adapter: stubAdapter{}, Store: &rowStore{rows: map[string]execute.Execution{}},
		Credential: execute.CredentialStrategy{Kind: execute.CredentialBroker}, PodUID: "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&execute.Handler{Engine: eng}).Register(mux)
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{server.TLS}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: ca.Pool}
	srv.StartTLS()
	defer srv.Close()

	client := func(l testpki.Leaf) *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: ca.Pool, ServerName: "receiver-sender.agent-adapters.svc", Certificates: []tls.Certificate{l.TLS}}}}
	}
	post := func(c *http.Client, path, body string) (int, map[string]any) {
		resp, err := c.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return resp.StatusCode, m
	}
	const path = "/internal/adapter/receiver-sender/execute"
	body := `{"decision_id":"11111111-2222-4333-8444-555555555555","action_id":"8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f"}`

	if code, m := post(client(other), path, body); code != 401 || m["reason_codes"].([]any)[0] != "AUTH_REQUIRED" {
		t.Fatalf("other caller: %d %v", code, m)
	}
	// srv.TLS is not ServerTLSConfig, so only the handler's own leaf check
	// refuses a gateway SAN that comes with a DNS SAN.
	if code, _ := post(client(gatewayDNS), path, body); code != 401 {
		t.Fatalf("gateway SAN with DNS SAN: %d", code)
	}
	gw := client(gateway)
	if code, _ := post(gw, "/internal/adapter/model/execute", body); code != 404 {
		t.Fatalf("other adapter path: %d", code)
	}
	for _, bad := range []string{
		`{"decision_id":"11111111-2222-4333-8444-555555555555"}`,
		`{"decision_id":"11111111-2222-4333-8444-555555555555","action_id":"8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f","envelope":{}}`,
		`{"Decision_id":"11111111-2222-4333-8444-555555555555","action_id":"8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f"}`,
		`{"decision_id":"11111111-2222-4333-8444-555555555555","decision_id":"11111111-2222-4333-8444-555555555556","action_id":"8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f"}`,
		`{"decision_id":"not-a-uuid","action_id":"8c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f"}`,
	} {
		if code, _ := post(gw, path, bad); code != 422 {
			t.Fatalf("bad body %s: %d", bad, code)
		}
	}
	code, m := post(gw, path, body)
	if code != 202 || m["state"] != execute.StateReceived || m["decision_id"] != "11111111-2222-4333-8444-555555555555" {
		t.Fatalf("first: %d %v", code, m)
	}
	eng.Wait()
	// Unwired bundle source: still received, nothing reserved; the replay
	// returns the current state.
	if code, m := post(gw, path, body); code != 202 || m["state"] != execute.StateReceived {
		t.Fatalf("replay: %d %v", code, m)
	}
	other2 := `{"decision_id":"11111111-2222-4333-8444-555555555555","action_id":"9c1e6f2a-1b2c-4d3e-8f40-5a6b7c8d9e0f"}`
	if code, _ := post(gw, path, other2); code != 409 {
		t.Fatalf("same decision, other action: %d", code)
	}
}

func TestHTTPBroker(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/credentials:resolve" {
			w.WriteHeader(404)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["credential_binding"] == "deny" {
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"request_id":"x","reason_codes":["CREDENTIAL_UNAVAILABLE"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"secret_version":"3","header_name":"X-Receiver-Api-Key","header_value":"v","expires_at":"2099-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	b := &execute.HTTPBroker{BaseURL: srv.URL, Client: srv.Client()}
	c, err := b.Resolve(context.Background(), "a1", "receiver-sender", "receiver-api-key")
	if err != nil || c.HeaderName != "X-Receiver-Api-Key" || c.SecretVersion != "3" {
		t.Fatalf("%+v %v", c, err)
	}
	if got["attempt_id"] != "a1" || got["adapter_id"] != "receiver-sender" || len(got) != 3 {
		t.Fatalf("request %v", got)
	}
	if _, err := b.Resolve(context.Background(), "a1", "receiver-sender", "deny"); err == nil {
		t.Fatal("broker refusal accepted")
	}
}

func TestNewRequiresPodUID(t *testing.T) {
	for _, pod := range []string{"", "pod-1", "6F1C2D3E-4B5A-4C6D-8E7F-0A1B2C3D4E5F"} {
		if _, err := execute.New(execute.Config{Adapter: stubAdapter{}, Store: &rowStore{}, Credential: execute.CredentialStrategy{Kind: execute.CredentialNone}, PodUID: pod}); err == nil {
			t.Errorf("PodUID %q accepted", pod)
		}
	}
}
