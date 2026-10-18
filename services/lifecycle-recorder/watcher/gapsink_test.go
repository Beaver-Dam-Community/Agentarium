package watcher

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"k8s.io/apimachinery/pkg/watch"
)

// gapReceiver enforces TASK-10 3.6 "receiving watch history gaps" (#178): exact
// pod-watcher SAN, scope allowlist, only ObservationGap fields with the fixed
// values, gap_id idempotency by body digest, and ACK after "COMMIT".
type gapReceiver struct {
	mu          sync.Mutex
	allowed     map[string]bool
	gaps        map[string]string // gap_id -> body digest
	bodies      []GapRequest
	unavailable atomic.Int32 // remaining 503 answers
	dropAfter   atomic.Int32 // commit, then answer 502 this many times
	violations  []string
}

func (g *gapReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if r.URL.Path != "/internal/control-health/observation-gaps" || r.Method != http.MethodPost {
		g.violations = append(g.violations, "path "+r.URL.Path)
		w.WriteHeader(404)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].URIs[0].String() != "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher" {
		w.WriteHeader(403)
		return
	}
	if g.unavailable.Load() > 0 {
		g.unavailable.Add(-1)
		w.WriteHeader(503)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var req GapRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil {
		g.violations = append(g.violations, "unknown fields")
		w.WriteHeader(422)
		return
	}
	var generic map[string]map[string]any
	_ = json.Unmarshal(raw, &generic)
	gb := req.Gap
	start, e1 := time.Parse(time.RFC3339Nano, gb.StartAt)
	end, e2 := time.Parse(time.RFC3339Nano, gb.EndAt)
	if gb.Stage != "lifecycle_capture" || gb.Reason != "WATCH_HISTORY_EXPIRED" || gb.CountQuality != "unknown" || gb.RecoveryState != "unrecoverable" || gb.LossCount != nil || gb.EvidenceRefs == nil || len(generic["gap"]) != 10 || e1 != nil || e2 != nil || end.Before(start) || gb.SourceEpoch == "" {
		g.violations = append(g.violations, fmt.Sprintf("gap fields %s", raw))
		w.WriteHeader(422)
		return
	}
	if !g.allowed[req.Scope] {
		w.WriteHeader(403)
		return
	}
	jcs, _ := canonical.JCS(raw)
	digest := fmt.Sprintf("%x", sha256.Sum256(jcs))
	code, result := 201, "created"
	if old, ok := g.gaps[gb.GapID]; ok {
		if old != digest {
			w.WriteHeader(409)
			return
		}
		code, result = 200, "existing"
	} else {
		g.gaps[gb.GapID] = digest
		g.bodies = append(g.bodies, req)
	}
	if g.dropAfter.Load() > 0 {
		g.dropAfter.Add(-1)
		w.WriteHeader(502)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"gap_id":%q,"recorded_at":%q,"result":%q}`, gb.GapID, time.Now().UTC().Format(time.RFC3339Nano), result)
}

func gapFixture(t *testing.T, scopes ...string) (*gapReceiver, *HTTPGapSink) {
	t.Helper()
	recv := &gapReceiver{allowed: map[string]bool{}, gaps: map[string]string{}}
	for _, s := range scopes {
		recv.allowed[s] = true
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	parsed, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	leaf := func(path string, usage x509.ExtKeyUsage) tls.Certificate {
		c := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{usage}, URIs: []*url.URL{{Scheme: "spiffe", Host: "agentarium.internal", Path: path}}}
		der, _ := x509.CreateCertificate(rand.Reader, c, parsed, &key.PublicKey, key)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	srv := httptest.NewUnstartedServer(recv)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf("/ns/agent-observe/sa/control-health", x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	client, err := NewControlHealthClient(&tls.Config{RootCAs: pool, Certificates: []tls.Certificate{leaf("/ns/agent-observe/sa/pod-watcher", x509.ExtKeyUsageClientAuth)}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return recv, &HTTPGapSink{Directory: dir, Origin: srv.URL, Client: client}
}

func testGap(start time.Time) Gap {
	return Gap{Scope: "namespace/agent-exec", Reason: "WATCH_HISTORY_EXPIRED", Epoch: "0123456789abcdef0123456789abcdef_1", LastCommittedAt: start, DetectedAt: start.Add(time.Minute)}
}

func TestGapSinkDeliversDurablyAndIdempotently(t *testing.T) {
	recv, sink := gapFixture(t, "namespace/agent-exec")
	recv.unavailable.Store(1) // first attempt: 503
	recv.dropAfter.Store(1)   // second attempt commits but loses the ACK
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now().Add(-time.Hour).UTC()
	if err := sink.Report(ctx, testGap(start)); err != nil {
		t.Fatal(err)
	}
	recv.mu.Lock()
	if len(recv.bodies) != 1 || len(recv.violations) != 0 || recv.bodies[0].Gap.StartAt != start.Format(time.RFC3339Nano) {
		t.Fatalf("bodies=%+v violations=%v", recv.bodies, recv.violations)
	}
	recv.mu.Unlock()
	if _, err := os.Stat(filepath.Join(sink.Directory, pendingGapFile)); !os.IsNotExist(err) {
		t.Fatal("pending gap must be removed only after ACK")
	}
	// A later, different detection is a new gap.
	if err := sink.Report(ctx, testGap(start.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	recv.mu.Lock()
	defer recv.mu.Unlock()
	if len(recv.bodies) != 2 || recv.bodies[0].Gap.GapID == recv.bodies[1].Gap.GapID {
		t.Fatalf("second gap: %+v", recv.bodies)
	}
}

func TestGapSinkResendsPendingAfterRestartAndKeepsItOnRefusal(t *testing.T) {
	recv, sink := gapFixture(t, "namespace/agent-exec")
	recv.unavailable.Store(1000)
	start := time.Now().Add(-time.Hour).UTC()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	if err := sink.Report(ctx, testGap(start)); err == nil {
		t.Fatal("unavailable control-health must not acknowledge")
	}
	cancel()
	pending, err := os.ReadFile(filepath.Join(sink.Directory, pendingGapFile))
	if err != nil {
		t.Fatal("gap must be durable before the first attempt", err)
	}
	// "Restart": a new sink over the same directory resends the same bytes.
	recv.unavailable.Store(0)
	restarted := &HTTPGapSink{Directory: sink.Directory, Origin: sink.Origin, Client: sink.Client}
	if err := restarted.Report(context.Background(), testGap(start)); err != nil {
		t.Fatal(err)
	}
	var sent GapRequest
	_ = json.Unmarshal(pending, &sent)
	recv.mu.Lock()
	if len(recv.bodies) != 1 || recv.bodies[0].Gap.GapID != sent.Gap.GapID {
		t.Fatalf("restart must reuse the pending gap_id: %+v", recv.bodies)
	}
	recv.mu.Unlock()

	// Scope outside the allowlist: permanent refusal, request retained.
	_, other := gapFixture(t)
	g := testGap(start)
	err = other.Report(context.Background(), g)
	var permanent *PermanentGapError
	if !errors.As(err, &permanent) || permanent.Status != 403 {
		t.Fatalf("scope refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other.Directory, pendingGapFile)); err != nil {
		t.Fatal("refused gap must stay on disk", err)
	}
	if err := other.Report(context.Background(), Gap{Scope: "namespace/agent-exec", Reason: "OTHER"}); err == nil {
		t.Fatal("invalid gap accepted")
	}
}

func TestMappingVersionOneNormalizer(t *testing.T) {
	p := pod(1, "rv")
	for _, c := range []struct {
		e    PodEvent
		want string
	}{{PodEvent{Pod: &p, Type: watch.Added, Snapshot: true}, "pod_snapshot"}, {PodEvent{Pod: &p, Type: watch.Added}, "pod_added"}, {PodEvent{Pod: &p, Type: watch.Modified}, "pod_modified"}, {PodEvent{Pod: &p, Type: watch.Deleted}, "pod_deleted"}} {
		facts, err := Normalize(context.Background(), c.e)
		if err != nil || len(facts) != 1 {
			t.Fatal(err)
		}
		f := facts[0]
		if f.Transition != c.want || f.MappingVersion != 1 || f.SourceTime != nil || f.EvidenceRefs == nil || len(f.EvidenceRefs) != 0 || f.NodeUID != nil || f.ContainerID != nil || f.MissingReason == nil || *f.MissingReason != MissingReason {
			t.Fatalf("%s: %+v", c.want, f)
		}
	}
	if _, err := Normalize(context.Background(), PodEvent{Pod: &p, Type: watch.Bookmark}); err == nil {
		t.Fatal("bookmark is not a lifecycle record")
	}
	if _, err := Normalize(context.Background(), PodEvent{Type: watch.Added}); err == nil {
		t.Fatal("missing Pod accepted")
	}
}

// End to end: a stream 410 is reported to the contract fixture with the
// production mapping, and the relist happens only after the gap ACK.
func TestRunRelistsOnlyAfterHTTPGapAck(t *testing.T) {
	recv, sink := gapFixture(t, "namespace/agent-exec")
	var lists, watches atomic.Int32
	cfg, collector := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			n := lists.Add(1)
			if n == 2 {
				recv.mu.Lock()
				sent := len(recv.bodies)
				recv.mu.Unlock()
				if sent != 0 {
					t.Error("gap reported before the relist was read")
				}
			}
			p := pod(int(n), fmt.Sprintf("p-%d", n))
			list(w, fmt.Sprintf("snapshot-%d", n), "", p)
			return
		}
		if watches.Add(1) == 1 {
			event(w, watch.Error, expired())
			return
		}
		<-r.Context().Done()
	}))
	cfg.Normalize = Normalize
	sink.Directory = cfg.Directory
	cfg.GapSink = func(ctx context.Context, g Gap) error {
		// The relist snapshot cursor is committed only after the gap ACK.
		if collector.checkpoint() == "snapshot-2" || lists.Load() != 2 {
			t.Error("cursor committed before the gap")
		}
		return sink.Report(ctx, g)
	}
	p := openTestProducer(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for collector.checkpoint() != "snapshot-2" {
		if time.Now().After(deadline) {
			t.Fatalf("no relist: lists=%d watches=%d", lists.Load(), watches.Load())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	recv.mu.Lock()
	defer recv.mu.Unlock()
	if len(recv.bodies) != 1 || len(recv.violations) != 0 || recv.bodies[0].Scope != "namespace/agent-exec" {
		t.Fatalf("gap: %+v %v", recv.bodies, recv.violations)
	}
	if collector.count() != 2 {
		t.Fatalf("records: %d", collector.count())
	}
}
