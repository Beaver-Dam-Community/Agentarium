package ingest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

func lifecycleWire(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	m := map[string]any{"batch_id": uuid.NewString(), "source_epoch": "epoch", "records": []any{json.RawMessage(lifecycleRecordWire(t, nil))}, "sequence_range_abandoned": []any{}}
	if mutate != nil {
		mutate(m)
	}
	digest, err := canonical.CanonicalDigest(m)
	if err != nil {
		t.Fatal(err)
	}
	m["batch_digest"] = digest
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestLifecycleEnvelope(t *testing.T) {
	raw := lifecycleWire(t, nil)
	b, err := DecodeLifecycleEnvelope(raw)
	if err != nil || len(CheckLifecycleIdentities("source-a", b)) != 0 {
		t.Fatalf("valid envelope: %v", err)
	}
	for name, bad := range map[string][]byte{
		"duplicate key":   bytes.Replace(raw, []byte(`"source_epoch":"epoch"`), []byte(`"source_epoch":"epoch","source_epoch":"epoch"`), 1),
		"case duplicate":  bytes.Replace(raw, []byte(`"batch_id":`), []byte(`"BATCH_ID":"bad","batch_id":`), 1),
		"digest mutation": bytes.Replace(raw, []byte(`"source_sequence":1`), []byte(`"source_sequence":2`), 1),
		"trailing":        append(append([]byte{}, raw...), []byte(` {}`)...),
		"unknown":         lifecycleWire(t, func(m map[string]any) { m["caller"] = "admin" }),
		"case alias":      lifecycleWire(t, func(m map[string]any) { m["BATCH_ID"] = m["batch_id"]; delete(m, "batch_id") }),
		"null epoch":      lifecycleWire(t, func(m map[string]any) { m["source_epoch"] = nil }),
		"cursor case alias": lifecycleWire(t, func(m map[string]any) {
			m["cursor"] = map[string]any{"Scope": "namespace/agent-exec", "resource_version": "opaque"}
		}),
		"missing array": lifecycleWire(t, func(m map[string]any) { delete(m, "records") }),
		"too many":      lifecycleWire(t, func(m map[string]any) { m["records"] = make([]any, 101) }),
		"large":         []byte(`{"x":"` + strings.Repeat("a", canonical.MaxBodyBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLifecycleEnvelope(bad); !errors.Is(err, ErrSchema) {
				t.Fatalf("accepted malformed envelope: %v", err)
			}
		})
	}
	// An invalid record ID is an individual rejection, with a valid envelope digest.
	raw = lifecycleWire(t, func(m map[string]any) {
		m["records"] = []any{map[string]any{"lifecycle_event_id": uuid.NewString(), "source_id": "source-a", "source_epoch": "epoch", "source_sequence": 1}}
	})
	b, err = DecodeLifecycleEnvelope(raw)
	if err != nil || len(CheckLifecycleIdentities("source-a", b)) != 1 {
		t.Fatalf("individual ID rejection: %v", err)
	}
	d, _ := canonical.AbandonedRangeDigest("source-a", "lifecycle", "epoch", 2, 4, "record_rejected")
	raw = lifecycleWire(t, func(m map[string]any) { m["sequence_range_abandoned"] = []LifecycleRange{{2, 4, "record_rejected", d}} })
	b, err = DecodeLifecycleEnvelope(raw)
	if err != nil || len(CheckLifecycleIdentities("source-a", b)) != 0 {
		t.Fatalf("range: %v", err)
	}
	if len(CheckLifecycleIdentities("source-b", b)) != 2 {
		t.Fatal("source substitution accepted")
	}
	b.Abandoned[0].To = 5
	if len(CheckLifecycleIdentities("source-a", b)) != 1 {
		t.Fatal("range digest mutation accepted")
	}
}

type identityFixture func(context.Context, *x509.Certificate, netip.Addr) (LifecycleSource, error)

func (f identityFixture) ResolveLifecycle(c context.Context, s *x509.Certificate, a netip.Addr) (LifecycleSource, error) {
	return f(c, s, a)
}

type validatorFixture func(context.Context, LifecycleSource, LifecycleEnvelope) error

func (f validatorFixture) ValidateLifecycle(c context.Context, s LifecycleSource, b LifecycleEnvelope) error {
	return f(c, s, b)
}

func (f lifecycleStoreFixture) LifecycleCheckpoint(context.Context, string, string) (LifecycleCheckpointResult, error) {
	return LifecycleCheckpointResult{}, ErrLifecycleCheckpointNotFound
}

type checkpointStoreFixture struct{ lifecycleStoreFixture }

func (f checkpointStoreFixture) LifecycleCheckpoint(_ context.Context, source, scope string) (LifecycleCheckpointResult, error) {
	if source != "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher" {
		return LifecycleCheckpointResult{}, ErrForbidden
	}
	if scope == "namespace/missing" {
		return LifecycleCheckpointResult{}, ErrLifecycleCheckpointNotFound
	}
	return LifecycleCheckpointResult{Scope: scope, ResourceVersion: "opaque-rv", Revision: 7, CommittedAt: time.Date(2026, 10, 16, 1, 2, 3, 0, time.UTC)}, nil
}

type lifecycleStoreFixture func(context.Context, LifecycleSource, []byte) (json.RawMessage, error)

func (f lifecycleStoreFixture) IngestLifecycle(c context.Context, s LifecycleSource, b []byte) (json.RawMessage, error) {
	return f(c, s, b)
}

// Real TLS handshakes; identity resolution, record validator and storage are
// explicitly fixtures. This is not proof of SQL ingestion or CAS provisioning.
func TestLifecycleMutualTLS(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issue := func(serial int64, san string, usage x509.ExtKeyUsage) tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		u, _ := url.Parse(san)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, URIs: []*url.URL{u}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverURI := "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	watcherURI := "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"
	recorderURI := "spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder"
	watcher := issue(3, watcherURI, x509.ExtKeyUsageClientAuth)
	recorder := issue(5, recorderURI, x509.ExtKeyUsageClientAuth)
	var calls atomic.Int32
	h := LifecycleHandler{
		NodeCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Identity: identityFixture(func(_ context.Context, cert *x509.Certificate, ip netip.Addr) (LifecycleSource, error) {
			if cert.URIs[0].String() == recorderURI && cert.SerialNumber.Int64() == 5 && ip.IsLoopback() {
				return LifecycleSource{SourceID: recorderURI, Kind: "runtime", NodeUID: "17d3e81e-65f8-462e-b681-670a14d57f88", BootID: "current-boot"}, nil
			}
			if cert.URIs[0].String() != watcherURI || cert.SerialNumber.Int64() != 3 || !ip.IsLoopback() {
				return LifecycleSource{}, ErrForbidden
			}
			return LifecycleSource{SourceID: watcherURI, Kind: "pod_watcher"}, nil
		}),
		Validator: validatorFixture(func(_ context.Context, s LifecycleSource, b LifecycleEnvelope) error {
			if s.Kind == "pod_watcher" && b.Scope != "namespace/agent-exec" && b.Scope != "namespace/missing" {
				return ErrForbidden
			}
			if len(CheckLifecycleIdentities("source-a", b)) != 0 {
				return errors.New("fixture record rejection")
			}
			for _, raw := range b.Records {
				if _, err := DecodeLifecycleRecord(raw, "source-a", b.Epoch); err != nil {
					return errors.New("fixture record rejection")
				}
			}
			return nil
		}),
		Store: lifecycleStoreFixture(func(_ context.Context, source LifecycleSource, raw []byte) (json.RawMessage, error) {
			calls.Add(1)
			if source.ExactSAN != source.SourceID || (source.Kind == "pod_watcher" && source.CertificateSerial != "03") || (source.Kind == "runtime" && source.CertificateSerial != "05") {
				t.Errorf("trusted certificate metadata lost: %+v", source)
				return nil, ErrForbidden
			}
			b, _ := DecodeLifecycleEnvelope(raw)
			var ids []string
			for _, r := range b.Records {
				var v struct {
					ID string `json:"lifecycle_event_id"`
				}
				_ = json.Unmarshal(r, &v)
				ids = append(ids, v.ID)
			}
			return json.Marshal(map[string]any{"batch_id": b.BatchID, "accepted_ids": ids, "duplicate_ids": []string{}, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": b.Epoch, "acked_through": 1}}, "checkpoint": nil})
		}),
	}
	h.Store = checkpointStoreFixture{h.Store.(lifecycleStoreFixture)}
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{issue(2, serverURI, x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	requestTo := func(method, address string, pair *tls.Certificate, raw []byte) (int, error) {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true} // URI SAN verification replaces DNS matching below.
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			leaf := cs.PeerCertificates[0]
			_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			if err != nil {
				return err
			}
			if len(leaf.URIs) != 1 || leaf.URIs[0].String() != serverURI {
				return errors.New("wrong server identity")
			}
			return nil
		}
		if pair != nil {
			cfg.Certificates = []tls.Certificate{*pair}
		}
		tr := &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
		req, _ := http.NewRequest(method, address, bytes.NewReader(raw))
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		response, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}
	postTo := func(baseURL string, pair *tls.Certificate, raw []byte) (int, error) {
		return requestTo(http.MethodPost, baseURL+"/internal/lifecycle/events:batch", pair, raw)
	}
	post := func(pair *tls.Certificate, raw []byte) (int, error) { return postTo(server.URL, pair, raw) }
	raw := lifecycleWire(t, func(m map[string]any) { m["scope"] = "namespace/agent-exec" })
	if code, err := post(&watcher, raw); err != nil || code != 200 {
		t.Fatalf("watcher outside node CIDR with URI-only mTLS: %d %v", code, err)
	}
	if code, err := post(&recorder, raw); err != nil || code != 403 {
		t.Fatalf("recorder outside node CIDR: %d %v", code, err)
	}
	if _, err := post(nil, raw); err == nil {
		t.Fatal("missing client certificate accepted")
	}
	wrong := issue(4, "spiffe://agentarium.internal/ns/agent-control/sa/coordinator", x509.ExtKeyUsageClientAuth)
	if code, err := post(&wrong, raw); err != nil || code != 403 {
		t.Fatalf("wrong service: %d %v", code, err)
	}
	if code, err := post(&watcher, bytes.Replace(raw, []byte(`"source_sequence":1`), []byte(`"source_sequence":2`), 1)); err != nil || code != 422 {
		t.Fatalf("digest: %d %v", code, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected storage calls: %d", calls.Load())
	}
	// Prove the recorder denial above came from the direct peer CIDR gate,
	// not an unrelated fixture authorization failure. X-Forwarded-For always
	// claims 10.0.0.1 and must not bypass the first server's exclusion.
	allowed := h
	allowed.NodeCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	allowedServer := httptest.NewUnstartedServer(allowed)
	allowedServer.TLS = server.TLS.Clone()
	allowedServer.StartTLS()
	defer allowedServer.Close()
	if code, err := postTo(allowedServer.URL, &recorder, lifecycleWire(t, nil)); err != nil || code != 200 {
		t.Fatalf("recorder inside node CIDR: %d %v", code, err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expected watcher and allowed recorder storage calls: %d", calls.Load())
	}

	// A valid digest and authenticated watcher cannot bypass TASK-07 JSON
	// limits through opaque record evidence. Reject before storage is invoked.
	oversized := lifecycleWire(t, func(m map[string]any) {
		m["scope"] = "namespace/agent-exec"
		m["records"] = []any{json.RawMessage(lifecycleRecordWire(t, func(record map[string]any) {
			record["evidence_refs"] = []any{map[string]any{"ref": strings.Repeat("x", 16385)}}
		}))}
	})
	if code, err := postTo(server.URL, &watcher, oversized); err != nil || code != 422 {
		t.Fatalf("oversized authenticated batch: %d %v", code, err)
	}
	if calls.Load() != 2 {
		t.Fatal("oversized batch reached storage")
	}

	// Test independent fail-closed dependencies with verified TLS state from a
	// fixture cert. Real certificate-chain enforcement was exercised above.
	leaf, _ := x509.ParseCertificate(watcher.Certificate[0])
	for name, change := range map[string]func(*LifecycleHandler){
		"missing identity":  func(h *LifecycleHandler) { h.Identity = nil },
		"missing validator": func(h *LifecycleHandler) { h.Validator = nil },
		"missing store":     func(h *LifecycleHandler) { h.Store = nil },
		"stale boot": func(h *LifecycleHandler) {
			h.Identity = identityFixture(func(context.Context, *x509.Certificate, netip.Addr) (LifecycleSource, error) {
				return LifecycleSource{}, ErrForbidden
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			copy := h
			change(&copy)
			r := httptest.NewRequest("POST", "/internal/lifecycle/events:batch", bytes.NewReader(raw))
			r.RemoteAddr = "127.0.0.1:1234"
			r.Header.Set("X-Forwarded-For", "10.0.0.1")
			r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, ca}}}
			w := httptest.NewRecorder()
			copy.ServeHTTP(w, r)
			want := 503
			if name == "stale boot" {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
	if calls.Load() != 2 {
		t.Fatal("fail-closed gate called store")
	}
	// Checkpoint GET uses the same live TLS authentication and scope gate. Storage
	// remains an explicit fixture; these checks do not prove PostgreSQL CAS.
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"scope=namespace%2Fagent-exec", 200},
		{"scope=namespace%2Fmissing", 404},
		{"scope=namespace%2Fforbidden", 404},
		{"scope=namespace%2Fagent-exec&scope=namespace%2Fforbidden", 404},
		{"scope=namespace%2Fagent-exec&source_id=other", 404},
	} {
		code, err := requestTo(http.MethodGet, server.URL+"/internal/lifecycle/checkpoints?"+tc.query, &watcher, nil)
		if err != nil || code != tc.want {
			t.Fatalf("GET %s: %d %v", tc.query, code, err)
		}
	}
	if code, err := post(&watcher, lifecycleWire(t, func(m map[string]any) { m["scope"] = "namespace/forbidden" })); err != nil || code != 403 {
		t.Fatalf("forbidden POST scope: %d %v", code, err)
	}
	if code, err := requestTo(http.MethodPost, server.URL+"/internal/lifecycle/checkpoints?scope=namespace%2Fagent-exec", &watcher, nil); err != nil || code != 405 {
		t.Fatalf("checkpoint method: %d %v", code, err)
	}

}

func TestLifecycleCheckpointWire(t *testing.T) {
	raw := lifecycleWire(t, func(m map[string]any) {
		m["scope"] = "namespace/agent-exec"
		m["cursor"] = map[string]any{"scope": "namespace/agent-exec", "resource_version": "opaque", "expected_checkpoint_revision": 3}
	})
	b, err := DecodeLifecycleEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		ID string `json:"lifecycle_event_id"`
	}
	_ = json.Unmarshal(b.Records[0], &record)
	ack := map[string]any{"batch_id": b.BatchID, "accepted_ids": []string{record.ID}, "duplicate_ids": []string{}, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": b.Epoch, "acked_through": 1}}, "checkpoint": map[string]any{"scope": b.Scope, "resource_version": "opaque", "checkpoint_revision": 4}}
	data, _ := json.Marshal(ack)
	if err := ValidateLifecycleAck(data, b); err != nil {
		t.Fatal(err)
	}
	for _, revision := range []int64{0, 3, 5, 9007199254740992} {
		ack["checkpoint"].(map[string]any)["checkpoint_revision"] = revision
		data, _ := json.Marshal(ack)
		if ValidateLifecycleAck(data, b) == nil {
			t.Fatalf("accepted invalid revision %d", revision)
		}
	}
	ack["checkpoint"] = nil
	data, _ = json.Marshal(ack)
	if err := ValidateLifecycleAck(data, b); err != nil {
		t.Fatalf("stale checkpoint must allow records: %v", err)
	}
	for _, bad := range []func(map[string]any){
		func(m map[string]any) { m["cursor"] = nil },
		func(m map[string]any) { m["scope"] = nil },
		func(m map[string]any) {
			m["scope"] = "namespace/agent-exec"
			m["cursor"] = map[string]any{"scope": "namespace/agent-exec", "resource_version": "rv"}
		},
		func(m map[string]any) {
			m["scope"] = "namespace/agent-exec"
			m["cursor"] = map[string]any{"scope": "namespace/other", "resource_version": "rv", "expected_checkpoint_revision": 0}
		},
		func(m map[string]any) {
			m["scope"] = "namespace/agent-exec"
			m["cursor"] = map[string]any{"scope": "namespace/agent-exec", "resource_version": "rv", "expected_checkpoint_revision": -1}
		},
	} {
		if _, err := DecodeLifecycleEnvelope(lifecycleWire(t, bad)); err == nil {
			t.Fatal("malformed cursor accepted")
		}
	}
}
