//go:build integration

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Beaver-Dam-Community/Agentarium/packages/healthlease"
)

// TestRelayPostgres runs the relays with the database-backed LiveCertificate
// and Authenticate as gateway_app: the session_id the gateway forwards is the
// token's, and a revoked or unknown certificate never reaches an upstream.
func TestRelayPostgres(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	p := newPKI(t)
	identity, health := p.upstream(t, IdentitySAN), p.upstream(t, healthlease.ControlHealthSAN)
	idc, err := NewRelayClient(p.roots, IdentitySAN, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	hc, err := NewRelayClient(p.roots, healthlease.ControlHealthSAN, p.clientCert)
	if err != nil {
		t.Fatal(err)
	}
	rl := &Relay{IdentityURL: identity.srv.URL, Identity: idc, HealthURL: health.srv.URL, Health: hc,
		Live: e.svc.LiveCertificate, Auth: e.svc.Authenticate, peer: testPeer}
	mux := http.NewServeMux()
	rl.Register(mux)
	do := func(w who, method, path, body string, bearer bool) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-SAN", w.san)
		req.Header.Set("X-Test-Serial", w.serial)
		req.Header.Set(PeerIdentityHeader, relaySpoof)
		if bearer {
			req.Header.Set("Authorization", "Bearer "+w.token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if st := do(e.asUser(), "GET", "/v1/runtime/assignments", "", false); st != 200 {
		t.Fatalf("assignments = %d", st)
	}
	if got := identity.got(); len(got) != 1 || got[0].peer[0] != runtimeSAN {
		t.Fatalf("assignments forwarded %+v", got)
	}
	if st := do(e.asUser(), "POST", "/v1/runtime/work-readiness/checks", `{"checkpoint":"start"}`, true); st != 200 {
		t.Fatalf("check = %d", st)
	}
	got := health.got()
	if len(got) != 1 || got[0].peer[0] != runtimeSAN || got[0].peerSession != e.user || string(got[0].body) != `{"checkpoint":"start"}` {
		t.Fatalf("check forwarded %+v %s", got, got[0].body)
	}
	// A service session token is not a runtime session.
	if st := do(e.asService(), "POST", "/v1/runtime/session-workers", `{}`, true); st != 401 {
		t.Fatalf("service session = %d", st)
	}
	// The user's token on another Pod's certificate is refused.
	w := e.asOther()
	w.token = e.userTok
	if st := do(w, "POST", "/v1/runtime/session-workers", `{}`, true); st != 401 {
		t.Fatalf("token on another SAN = %d", st)
	}
	// Revoked certificate: refused on the mTLS-only path too.
	if _, err := e.admin.Exec(ctx, `UPDATE identity.issued_certificates SET revoked_at = now() WHERE serial = $1`, runtimeSerial); err != nil {
		t.Fatal(err)
	}
	if st := do(e.asUser(), "GET", "/v1/runtime/assignments", "", false); st != 401 {
		t.Fatalf("revoked assignments = %d", st)
	}
	// Disabled workload.
	if _, err := e.admin.Exec(ctx, `UPDATE identity.registered_workloads SET enabled = false WHERE ksa = 'agent-runtime'`); err != nil {
		t.Fatal(err)
	}
	if st := do(e.asOther(), "POST", "/v1/sessions/"+e.user+":claim", `{"claim_code":"x"}`, false); st != 401 {
		t.Fatalf("disabled workload claim = %d", st)
	}
	if n := len(identity.got()) + len(health.got()); n != 2 {
		t.Fatalf("refused requests reached an upstream: %d", n-2)
	}
}
