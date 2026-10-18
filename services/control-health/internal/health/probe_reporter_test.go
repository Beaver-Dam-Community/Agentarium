package health

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

const testRunnerPod = "3b0f2c39-5d0b-4b0e-9a5e-0c5f0d1e2a3b"

func peerTLS(t *testing.T, san string) *tls.ConnectionState {
	t.Helper()
	u, err := url.Parse(san)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(0x2a), URIs: []*url.URL{u}}
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
}

func TestVerifiedPeerPodBoundSAN(t *testing.T) {
	adapters := "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + testRunnerPod
	p, err := VerifiedPeer(peerTLS(t, adapters))
	if err != nil || p.SAN != adapters || p.Serial != "2a" || p.PodUID != testRunnerPod {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := VerifiedPeer(peerTLS(t, "spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter")); err != nil || p.PodUID != "" {
		t.Fatalf("service SAN: %+v %v", p, err)
	}
	for _, bad := range []string{
		// agent-exec never connects directly, Pod-bound or not.
		"spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/" + testRunnerPod,
		"spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner",
		"spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/",
		"spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/not-a-uuid",
		"spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + strings.ToUpper(testRunnerPod),
		"spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/node/" + testRunnerPod,
		"spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + testRunnerPod + "/x",
	} {
		if _, err := VerifiedPeer(peerTLS(t, bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestProbeRunnerSAN(t *testing.T) {
	for ns, want := range map[string]string{
		"agent-exec":     "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner",
		"agent-adapters": "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner",
	} {
		got, pod, principal, ok := ProbeRunnerSAN("spiffe://agentarium.internal/ns/" + ns + "/sa/probe-runner/pod/" + testRunnerPod)
		if !ok || got != ns || pod != testRunnerPod || principal != want {
			t.Fatalf("%s: %s %s %s %v", ns, got, pod, principal, ok)
		}
	}
	for _, bad := range []string{
		"spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner",
		"spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime/pod/" + testRunnerPod,
		"spiffe://agentarium.internal/ns/agent-observe/sa/probe-runner/pod/" + testRunnerPod,
		"spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender/pod/" + testRunnerPod,
		"spiffe://other/ns/agent-exec/sa/probe-runner/pod/" + testRunnerPod,
	} {
		if _, _, _, ok := ProbeRunnerSAN(bad); ok {
			t.Errorf("accepted %s", bad)
		}
	}
}

type probeBackend struct {
	Backend
	peer  Peer
	relay ProbeRelay
	calls int
}

func (b *probeBackend) ReportProbe(_ context.Context, p Peer, r ProbeRelay, _ ProbeReport) (ProbeAck, error) {
	b.peer, b.relay, b.calls = p, r, b.calls+1
	return ProbeAck{ProbeResultID: "11111111-1111-4111-8111-111111111111"}, nil
}

const testProbeBody = `{"probe_kind":"process","node_uid":"6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f","boot_id":"b1","stimulus_at":"2026-10-18T00:00:00Z","outcome":"pass","evidence_refs":["probe_stimulus:process:2026-10-18T00:00:00Z"]}`

// The handler hands every received relay header value to the store, which
// decides by the TLS peer's principal whether they count (TASK-10 3.2).
func TestProbeResultsPassRelayHeaders(t *testing.T) {
	b := &probeBackend{}
	r := httptest.NewRequest("POST", "/internal/control-health/probe-results", strings.NewReader(testProbeBody))
	r.TLS = peerTLS(t, "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway")
	r.Header.Add(PeerIdentityHeader, "spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner/pod/"+testRunnerPod)
	r.Header.Add(PeerSerialHeader, "0a")
	r.Header.Add(PeerSerialHeader, "0b")
	w := httptest.NewRecorder()
	Handler{Backend: b}.ServeHTTP(w, r)
	if w.Code != 201 || b.calls != 1 {
		t.Fatalf("HTTP %d calls=%d %s", w.Code, b.calls, w.Body.String())
	}
	if len(b.relay.SAN) != 1 || !slices.Equal(b.relay.Serial, []string{"0a", "0b"}) || b.peer.SAN != "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway" {
		t.Fatalf("relay %+v peer %+v", b.relay, b.peer)
	}
}

// A Pod-bound peer reaches only the probe-results route.
func TestPodBoundPeerOnlyReportsProbes(t *testing.T) {
	san := "spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner/pod/" + testRunnerPod
	b := &probeBackend{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/internal/control-health/probe-results", strings.NewReader(testProbeBody))
	r.TLS = peerTLS(t, san)
	Handler{Backend: b}.ServeHTTP(w, r)
	if w.Code != 201 || b.peer.PodUID != testRunnerPod {
		t.Fatalf("probe report HTTP %d %+v", w.Code, b.peer)
	}
	for _, c := range []struct{ method, path string }{
		{"POST", "/internal/control-health/leases"},
		{"GET", "/internal/control-health?scope=node&scope_id=6f1c2b8e-1d2a-4c3b-9e8f-0a1b2c3d4e5f"},
		{"POST", "/internal/holds"},
		{"GET", "/internal/holds?owner_component=probe-runner"},
		{"GET", "/internal/control-health/probe-results"},
		{"POST", "/internal/control-health/session-workers"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
		r.TLS = peerTLS(t, san)
		Handler{Backend: b}.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Errorf("%s %s: HTTP %d", c.method, c.path, w.Code)
		}
	}
	if b.calls != 1 {
		t.Fatalf("backend called %d times", b.calls)
	}
}
