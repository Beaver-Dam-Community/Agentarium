package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/google/uuid"
)

const (
	watcherSAN  = "spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher"
	identitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"
	auditSAN    = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	healthSAN   = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
	clusterUID  = "00000000-0000-4000-8000-000000000001"
	scope       = "namespace/agent-exec"
)

var binary string

func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "pod-watcher-bin")
	binary = filepath.Join(dir, "pod-watcher")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type pki struct {
	ca   *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	pem  []byte
}

func newPKI() *pki {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca, key, pool, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *pki) issue(pub any, san string, usage x509.ExtKeyUsage, notAfter time.Time) []byte {
	u, _ := url.Parse(san)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}, p.ca, pub, p.key)
	if err != nil {
		panic(err)
	}
	return der
}

func (p *pki) server(t *testing.T, san string, h http.Handler, mutual bool) *httptest.Server {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{p.issue(&key.PublicKey, san, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))}, PrivateKey: key}}}
	if mutual {
		s.TLS.ClientAuth, s.TLS.ClientCAs = tls.RequireAndVerifyClientCert, p.pool
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func peer(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 {
		return ""
	}
	return r.TLS.PeerCertificates[0].URIs[0].String()
}

// lifecycleCollector enforces the TASK-07 3.3 lifecycle batch contract for
// the pod watcher: mTLS source, mandatory scope, batch_digest, canonical
// lifecycle_event_id and record_digest, the #178 mapping values, and the
// checkpoint revision CAS.
type lifecycleCollector struct {
	mu          sync.Mutex
	records     []map[string]any
	ids         map[string]string
	acked       map[string]uint64
	revision    uint64
	cursor      string
	committedAt time.Time
	commits     []time.Time
	violations  []string
}

func (c *lifecycleCollector) bad(f string, a ...any) {
	c.violations = append(c.violations, fmt.Sprintf(f, a...))
}

func (c *lifecycleCollector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if peer(r) != watcherSAN {
		c.bad("unregistered source %q", peer(r))
		w.WriteHeader(403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet && r.URL.Path == "/internal/lifecycle/checkpoints" {
		if r.URL.Query().Get("scope") != scope {
			c.bad("checkpoint scope %q", r.URL.Query().Get("scope"))
		}
		if c.revision == 0 {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"reason_codes":["RESOURCE_NOT_FOUND"]}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"scope": scope, "resource_version": c.cursor, "committed_at": c.committedAt.Format(time.RFC3339Nano), "checkpoint_revision": c.revision})
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/internal/lifecycle/events:batch" {
		c.bad("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(404)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var env struct {
		BatchID   string            `json:"batch_id"`
		Epoch     string            `json:"source_epoch"`
		Scope     string            `json:"scope"`
		Records   []json.RawMessage `json:"records"`
		Abandoned []json.RawMessage `json:"sequence_range_abandoned"`
		Cursor    *struct {
			Scope    string `json:"scope"`
			RV       string `json:"resource_version"`
			Expected uint64 `json:"expected_checkpoint_revision"`
		} `json:"cursor"`
		Digest string `json:"batch_digest"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&env) != nil || env.Scope != scope || uuid.Validate(env.BatchID) != nil {
		c.bad("envelope %s", raw)
		w.WriteHeader(422)
		return
	}
	var body map[string]json.RawMessage
	json.Unmarshal(raw, &body)
	delete(body, "batch_digest")
	unsigned, _ := json.Marshal(body)
	jcs, _ := canonical.JCS(unsigned)
	if canonical.SHA256Hex(jcs) != env.Digest {
		c.bad("batch_digest")
		w.WriteHeader(422)
		return
	}
	accepted, dups := []string{}, []string{}
	last := c.acked[env.Epoch]
	for _, rec := range env.Records {
		var m map[string]any
		dec := json.NewDecoder(bytes.NewReader(rec))
		dec.UseNumber()
		dec.Decode(&m)
		seq, _ := m["source_sequence"].(json.Number).Int64()
		id, _ := canonical.LifecycleEventID(watcherSAN, env.Epoch, seq)
		digest, _ := canonical.DigestWithoutKeys(rec, "record_digest", "received_at")
		mr, _ := m["missing_reason"].(string)
		refs, _ := m["evidence_refs"].([]any)
		switch {
		case m["lifecycle_event_id"] != id || m["source_id"] != watcherSAN || m["record_digest"] != digest || m["cluster_uid"] != clusterUID:
			c.bad("record identity %v", m["lifecycle_event_id"])
		case m["namespace"] != "agent-exec":
			c.bad("record namespace outside scope")
		case !map[string]bool{"pod_snapshot": true, "pod_added": true, "pod_modified": true, "pod_deleted": true}[fmt.Sprint(m["transition"])]:
			c.bad("transition %v", m["transition"])
		case m["mapping_version"] != json.Number("1") || m["source_time"] != nil || refs == nil || len(refs) != 0 || mr != "not_resolved_by_watcher" || m["node_uid"] != nil:
			c.bad("mapping fields %v", m)
		}
		if prev, ok := c.ids[id]; ok {
			if prev != digest {
				c.bad("EVENT_ID_CONFLICT")
			}
			dups = append(dups, id)
		} else {
			c.ids[id] = digest
			c.records = append(c.records, m)
			accepted = append(accepted, id)
		}
		if uint64(seq) > last {
			last = uint64(seq)
		}
	}
	c.acked[env.Epoch] = last
	var cp any
	if env.Cursor != nil {
		if env.Cursor.Scope != scope {
			c.bad("cursor scope")
		}
		if env.Cursor.Expected == c.revision {
			c.revision++
			c.cursor, c.committedAt = env.Cursor.RV, time.Now().UTC()
			c.commits = append(c.commits, c.committedAt)
			cp = map[string]any{"scope": scope, "resource_version": c.cursor, "checkpoint_revision": c.revision}
		}
	}
	json.NewEncoder(w).Encode(map[string]any{"batch_id": env.BatchID, "accepted_ids": accepted, "duplicate_ids": dups, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": env.Epoch, "acked_through": last}}, "checkpoint": cp})
}

type gaps struct {
	mu     sync.Mutex
	bodies []map[string]any
	at     []time.Time
	bad    []string
}

func (g *gaps) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var m map[string]any
	if peer(r) != watcherSAN || r.URL.Path != "/internal/control-health/observation-gaps" || json.NewDecoder(r.Body).Decode(&m) != nil {
		g.bad = append(g.bad, "gap request")
		w.WriteHeader(403)
		return
	}
	gap, _ := m["gap"].(map[string]any)
	if m["scope"] != scope || gap["reason"] != "WATCH_HISTORY_EXPIRED" || gap["stage"] != "lifecycle_capture" || gap["recovery_state"] != "unrecoverable" || gap["count_quality"] != "unknown" {
		g.bad = append(g.bad, fmt.Sprint(m))
	}
	g.bodies = append(g.bodies, m)
	g.at = append(g.at, time.Now().UTC())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	fmt.Fprintf(w, `{"gap_id":%q,"recorded_at":%q,"result":"created"}`, gap["gap_id"], time.Now().UTC().Format(time.RFC3339Nano))
}

// kube serves Pod LIST/WATCH for agent-exec and the coordination Lease.
type kube struct {
	mu       sync.Mutex
	pods     []map[string]any
	rv       int
	watches  int
	lease    map[string]any
	expireOn int // the watch number that answers with a 410 Error event
}

func pod(name, uid, rv string) map[string]any {
	return map[string]any{"kind": "Pod", "apiVersion": "v1", "metadata": map[string]any{"name": name, "namespace": "agent-exec", "uid": uid, "resourceVersion": rv}, "spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x", "command": []any{"/secret-arg"}}}}}
}

func (k *kube) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	k.mu.Lock()
	switch {
	case r.URL.Path == "/apis/coordination.k8s.io/v1/namespaces/agent-observe/leases/pod-watcher":
		defer k.mu.Unlock()
		if r.Method == http.MethodGet {
			if k.lease == nil {
				w.WriteHeader(404)
				fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"NotFound","code":404}`)
				return
			}
			json.NewEncoder(w).Encode(k.lease)
			return
		}
		json.NewDecoder(r.Body).Decode(&k.lease)
		k.lease["metadata"].(map[string]any)["resourceVersion"] = fmt.Sprint(time.Now().UnixNano())
		json.NewEncoder(w).Encode(k.lease)
	case r.URL.Path == "/apis/coordination.k8s.io/v1/namespaces/agent-observe/leases" && r.Method == http.MethodPost:
		defer k.mu.Unlock()
		json.NewDecoder(r.Body).Decode(&k.lease)
		k.lease["metadata"].(map[string]any)["resourceVersion"] = "1"
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(k.lease)
	case r.URL.Path == "/api/v1/namespaces/agent-exec/pods" && r.URL.Query().Get("watch") != "true":
		k.rv++
		json.NewEncoder(w).Encode(map[string]any{"kind": "PodList", "apiVersion": "v1", "metadata": map[string]any{"resourceVersion": fmt.Sprintf("snapshot-%d", k.rv)}, "items": k.pods})
		k.mu.Unlock()
	case r.URL.Path == "/api/v1/namespaces/agent-exec/pods":
		k.watches++
		n := k.watches
		k.mu.Unlock()
		flusher := w.(http.Flusher)
		send := func(kind string, obj any) {
			b, _ := json.Marshal(map[string]any{"type": kind, "object": obj})
			fmt.Fprintln(w, string(b))
			flusher.Flush()
		}
		if n == 1 {
			send("ADDED", pod("p3", "33333333-3333-4333-8333-333333333333", "w1"))
			send("MODIFIED", pod("p1", "11111111-1111-4111-8111-111111111111", "w2"))
			send("DELETED", pod("p2", "22222222-2222-4222-8222-222222222222", "w3"))
			time.Sleep(200 * time.Millisecond)
			send("ERROR", map[string]any{"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Expired", "code": 410, "message": "too old resource version"})
			return
		}
		flusher.Flush()
		<-r.Context().Done()
	default:
		k.mu.Unlock()
		http.Error(w, "forbidden", 403)
	}
}

func TestPodWatcherLeadsMapsAndReportsGapsInOrder(t *testing.T) {
	p := newPKI()
	dir := t.TempDir()
	token := "pod-watcher-token"
	identity := p.server(t, identitySAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, Token string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != token {
			w.WriteHeader(401)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)
		na := time.Now().Add(time.Hour).Truncate(time.Second)
		json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.issue(csr.PublicKey, watcherSAN, x509.ExtKeyUsageClientAuth, na)})), "certificate_chain": []string{}, "serial": "1", "expires_at": na})
	}), false)
	coll := &lifecycleCollector{ids: map[string]string{}, acked: map[string]uint64{}}
	collSrv := p.server(t, auditSAN, coll, true)
	g := &gaps{}
	gapSrv := p.server(t, healthSAN, g, true)
	k := &kube{pods: []map[string]any{pod("p1", "11111111-1111-4111-8111-111111111111", "1"), pod("p2", "22222222-2222-4222-8222-222222222222", "2")}}
	kubeSrv := httptest.NewServer(k)
	t.Cleanup(kubeSrv.Close)
	write := func(name string, b []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	spool := filepath.Join(dir, "spool")
	os.MkdirAll(spool, 0o700)
	kubeconfig := write("kubeconfig", []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: %q}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\ncurrent-context: c\nusers: [{name: u, user: {}}]\n", kubeSrv.URL)), 0o600)
	cfg, _ := json.Marshal(Config{Namespace: "agent-exec", ClusterUID: clusterUID, Directory: spool, CapacityBytes: 64 << 20, PageSize: 100,
		CollectorOrigin: collSrv.URL, HealthOrigin: gapSrv.URL, IdentityOrigin: identity.URL, TokenFile: write("token", []byte(token), 0o600), CAFile: write("ca.pem", p.pem, 0o644),
		LeaseNamespace: "agent-observe", LeaseName: "pod-watcher", Kubeconfig: kubeconfig})
	config := write("config.json", cfg, 0o600)
	var logs bytes.Buffer
	var logMu sync.Mutex
	cmd := exec.Command(binary, "--config", config)
	cmd.Env = append(os.Environ(), "POD_NAME=pod-watcher-0")
	w := writerFunc(func(b []byte) (int, error) { logMu.Lock(); defer logMu.Unlock(); return logs.Write(b) })
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		coll.mu.Lock()
		done := coll.cursor == "snapshot-2"
		coll.mu.Unlock()
		if done {
			break
		}
		if time.Now().After(deadline) {
			logMu.Lock()
			t.Fatalf("relist cursor not committed\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	// A second replica is a standby while the first holds the Lease. SIGTERM
	// must not manufacture a leadership-loss failure or open the shared spool.
	standby := exec.Command(binary, "--config", config)
	standby.Env = append(os.Environ(), "POD_NAME=pod-watcher-standby")
	var standbyLogs bytes.Buffer
	var standbyMu sync.Mutex
	standby.Stderr = writerFunc(func(b []byte) (int, error) { standbyMu.Lock(); defer standbyMu.Unlock(); return standbyLogs.Write(b) })
	if err := standby.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if standby.ProcessState == nil {
			standby.Process.Kill()
			standby.Wait()
		}
	})
	deadline = time.Now().Add(15 * time.Second)
	for {
		standbyMu.Lock()
		waiting := strings.Contains(standbyLogs.String(), "waiting for leadership")
		standbyMu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("standby did not reach election")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := standby.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := standby.Wait(); err != nil {
		t.Fatalf("standby SIGTERM: %v %s", err, standbyLogs.String())
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM: %v\n%s", err, logs.String())
	}
	coll.mu.Lock()
	defer coll.mu.Unlock()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(coll.violations) != 0 || len(g.bad) != 0 {
		t.Fatalf("contract: %v %v", coll.violations, g.bad)
	}
	transitions := []string{}
	for _, r := range coll.records {
		transitions = append(transitions, fmt.Sprint(r["transition"]))
		if strings.Contains(fmt.Sprint(r), "secret-arg") {
			t.Fatal("Pod spec leaked into a record")
		}
	}
	want := "pod_snapshot,pod_snapshot,pod_added,pod_modified,pod_deleted,pod_snapshot,pod_snapshot"
	if strings.Join(transitions, ",") != want {
		t.Fatalf("transitions %v", transitions)
	}
	// The gap was recorded after the relist was sent and before its cursor.
	// Commits: LIST 1 snapshot, three WATCH event cursors, then the relist
	// snapshot, which must follow the gap ACK.
	n := len(coll.commits)
	if len(g.bodies) != 1 || n != 5 || !g.at[0].Before(coll.commits[n-1]) || !g.at[0].After(coll.commits[n-2]) {
		t.Fatalf("gap=%d commits=%v gapAt=%v", len(g.bodies), coll.commits, g.at)
	}
	gap := g.bodies[0]["gap"].(map[string]any)
	start, _ := time.Parse(time.RFC3339Nano, gap["start_at"].(string))
	end, _ := time.Parse(time.RFC3339Nano, gap["end_at"].(string))
	if end.Before(start) {
		t.Fatalf("gap interval %v..%v", start, end)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if holder, _ := k.lease["spec"].(map[string]any)["holderIdentity"].(string); holder != "pod-watcher-0" && holder != "" {
		t.Fatalf("lease holder %q", holder)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }
