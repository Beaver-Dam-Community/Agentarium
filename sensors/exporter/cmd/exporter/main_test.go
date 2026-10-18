package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/capture"
	"github.com/google/uuid"
	sigsyaml "sigs.k8s.io/yaml"
)

// Evidence values from the real Q0 run (TASK-01 Q0, 20261015-task01-q0-min-2).
const (
	evidence       = "../../../../evidence/gcp/runs/20261015-task01-q0-min-2/raw/run3-events.relevant.jsonl"
	metricsFixture = "../../healthreport/testdata/tetragon-1.7.1.prom"
	evidenceNode   = "gke-agentarium-prod-exec-pool-eaf0304a-x10z"
	stimulusPodUID = "d7dafa84-b27f-4944-863f-e49e45c8d4a4"
	stimulusCID    = "866bba3230f127c9fd2035b57c32fd234ff3c0e86c7cf2930d66e770216b3587"
	stimulusIP     = "10.20.1.9"
	systemCID      = "5555555555555555555555555555555555555555555555555555555555555555"
	nodeUID        = "30000000-0000-4000-8000-000000000001"
	bootID         = "6f1d3d1c-1f5e-4a1b-9c7c-0c4f7d9e2a11"
	// The hostNetwork exporter bootstraps through the gateway relay (TASK-03 3.3).
	identitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	auditSAN    = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	healthSAN   = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "exporter-bin")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "exporter")
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

func newPKI(t *testing.T) *pki {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &pki{ca: ca, key: key, pool: pool, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *pki) issue(t *testing.T, pub any, san string, usage x509.ExtKeyUsage, notAfter time.Time) []byte {
	u, _ := url.Parse(san)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, pub, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (p *pki) server(t *testing.T, san string, h http.Handler, clientAuth bool) *httptest.Server {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der := p.issue(t, &key.PublicKey, san, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	if clientAuth {
		s.TLS.ClientAuth, s.TLS.ClientCAs = tls.RequireAndVerifyClientCert, p.pool
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// peerSAN enforces the registered exporter identity on every collector and
// health request (TASK-07 3.3: source_id comes from mTLS, never the body).
func peerSAN(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 {
		return ""
	}
	return r.TLS.PeerCertificates[0].URIs[0].String()
}

func strictDecode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

// collector enforces the TASK-07 3.3 kernel batch contract: mTLS source,
// envelope schema and batch_digest, per-record canonical ID/digest/epoch,
// duplicate-vs-conflict, and a contiguous per-epoch watermark.
type collector struct {
	t          *testing.T
	mu         sync.Mutex
	available  bool
	dropNext   bool
	records    map[string]map[string]any // source_event_id -> record
	digests    map[string]string
	seqs       map[string]map[uint64]bool // epoch -> stored sequences
	acked      map[string]uint64
	violations []string
}

func (c *collector) violate(format string, args ...any) {
	c.violations = append(c.violations, fmt.Sprintf(format, args...))
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.URL.Path != "/internal/kernel/events:batch" || r.Method != http.MethodPost {
		c.violate("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
		return
	}
	if san := peerSAN(r); san != SensorSAN {
		c.violate("unregistered source %q", san)
		w.WriteHeader(http.StatusForbidden)
		return
	}
	if !c.available {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		c.violate("oversized batch")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}
	var env struct {
		BatchID   string            `json:"batch_id"`
		Epoch     string            `json:"source_epoch"`
		Records   []json.RawMessage `json:"records"`
		Abandoned []json.RawMessage `json:"sequence_range_abandoned"`
		Digest    string            `json:"batch_digest"`
	}
	if strictDecode(raw, &env) != nil || uuid.Validate(env.BatchID) != nil || env.Epoch == "" || len(env.Records)+len(env.Abandoned) > 100 {
		c.violate("envelope schema")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	var body map[string]json.RawMessage
	_ = json.Unmarshal(raw, &body)
	delete(body, "batch_digest")
	unsigned, _ := json.Marshal(body)
	jcs, err := canonical.JCS(unsigned)
	if err != nil || canonical.SHA256Hex(jcs) != env.Digest {
		c.violate("batch_digest mismatch")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	if len(env.Abandoned) != 0 {
		c.violate("unexpected abandoned range")
	}
	var accepted, duplicates []string
	if c.seqs[env.Epoch] == nil {
		c.seqs[env.Epoch] = map[uint64]bool{}
	}
	for _, rec := range env.Records {
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(rec))
		d.UseNumber()
		if d.Decode(&m) != nil {
			c.violate("record JSON")
			continue
		}
		if _, ok := m["received_at"]; ok {
			c.violate("received_at sent by producer")
		}
		seqNum, _ := m["source_sequence"].(json.Number).Int64()
		id, _ := canonical.KernelEventID(SensorSAN, env.Epoch, seqNum)
		digest, _ := canonical.DigestWithoutKeys(rec, "record_digest", "received_at")
		if m["source_event_id"] != id || m["sensor_id"] != SensorSAN || m["source_epoch"] != env.Epoch || m["record_digest"] != digest || m["node_uid"] != nodeUID || m["boot_id"] != bootID {
			c.violate("record identity/digest %v", m["source_event_id"])
			continue
		}
		if old, ok := c.digests[id]; ok {
			if old != digest {
				c.violate("EVENT_ID_CONFLICT %s", id)
			}
			duplicates = append(duplicates, id)
			continue
		}
		c.digests[id], c.records[id] = digest, m
		c.seqs[env.Epoch][uint64(seqNum)] = true
		accepted = append(accepted, id)
	}
	for c.seqs[env.Epoch][c.acked[env.Epoch]+1] {
		c.acked[env.Epoch]++
	}
	resp := map[string]any{"batch_id": env.BatchID, "accepted_ids": nonNil(accepted), "duplicate_ids": nonNil(duplicates), "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": env.Epoch, "acked_through": c.acked[env.Epoch]}}}
	if c.dropNext {
		// COMMIT happened but the ACK is lost: the producer must resend the
		// same IDs and bytes.
		c.dropNext = false
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type health struct {
	mu        sync.Mutex
	leases    []map[string]any
	holds     int
	snapshots int
	bad       []string
}

func (h *health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if peerSAN(r) == SensorSAN && r.Method == http.MethodGet && r.URL.Path == "/internal/control-health" {
		// Node nonce poll: no pending challenges in this pipeline test.
		if r.URL.RawQuery != "scope=node&scope_id="+nodeUID {
			h.bad = append(h.bad, "snapshot query "+r.URL.RawQuery)
		}
		h.snapshots++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"scope":"node","scope_id":%q,"evaluated_at":"2026-10-18T00:00:00Z","state":"unhealthy","leases":[],"missing_components":[],"open_holds":[],"probes":[],"open_gaps":[],"bundle_ack":null,"startup_capture":null,"pending_work_readiness_challenges":[],"pending_worker_observation_challenges":[]}`, nodeUID)
		return
	}
	if peerSAN(r) != SensorSAN || r.Method != http.MethodPost {
		h.bad = append(h.bad, "unauthenticated health call")
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var m map[string]any
	if json.NewDecoder(r.Body).Decode(&m) != nil {
		h.bad = append(h.bad, "health JSON")
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/internal/control-health/leases":
		if m["component"] != "node-sensors" || m["scope"] != "node" || m["scope_id"] != nodeUID || m["source_id"] != "tetragon-node/"+nodeUID {
			h.bad = append(h.bad, fmt.Sprintf("lease %v", m))
		}
		h.leases = append(h.leases, m)
		fmt.Fprintf(w, `{"lease_until":%q,"scope_state":"unhealthy"}`, m["lease_until"])
	case "/internal/holds":
		if m["reason"] != "sensor_degraded" || m["scope_id"] != nodeUID {
			h.bad = append(h.bad, fmt.Sprintf("hold %v", m))
		}
		h.holds++
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"hold_id":%q,"decision":"created","reason_codes":[]}`, uuid.NewString())
	default:
		h.bad = append(h.bad, "path "+r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

// kubeAPI serves the Node and node-scoped Pod LIST/WatchList the exporter uses.
func kubeAPI(t *testing.T) *httptest.Server {
	pod := func(ns, name, uid, ip, cid string) map[string]any {
		return map[string]any{"metadata": map[string]any{"namespace": ns, "name": name, "uid": uid, "resourceVersion": "5"}, "spec": map[string]any{"nodeName": evidenceNode},
			"status": map[string]any{"podIPs": []any{map[string]any{"ip": ip}}, "containerStatuses": []any{map[string]any{"name": "main", "containerID": "containerd://" + cid}}}}
	}
	pods := []any{pod("agent-exec", "q0-stimulus-3", stimulusPodUID, stimulusIP, stimulusCID), pod("kube-system", "dns", "66666666-6666-4666-8666-666666666666", "10.20.1.30", systemCID)}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/nodes/"+evidenceNode:
			json.NewEncoder(w).Encode(map[string]any{"kind": "Node", "apiVersion": "v1", "metadata": map[string]any{"name": evidenceNode, "uid": nodeUID}, "spec": map[string]any{"podCIDRs": []string{"10.20.1.0/24"}}, "status": map[string]any{"nodeInfo": map[string]any{"bootID": bootID}}})
		case r.URL.Path == "/api/v1/pods" && r.URL.Query().Get("fieldSelector") == "spec.nodeName="+evidenceNode:
			if r.URL.Query().Get("watch") != "true" {
				json.NewEncoder(w).Encode(map[string]any{"kind": "PodList", "apiVersion": "v1", "metadata": map[string]any{"resourceVersion": "5"}, "items": pods})
				return
			}
			if r.URL.Query().Get("sendInitialEvents") == "true" {
				for _, p := range pods {
					b, _ := json.Marshal(map[string]any{"type": "ADDED", "object": p})
					fmt.Fprintln(w, string(b))
				}
				fmt.Fprintln(w, `{"type":"BOOKMARK","object":{"kind":"Pod","apiVersion":"v1","metadata":{"resourceVersion":"5","annotations":{"k8s.io/initial-events-end":"true"}}}}`)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case r.URL.Path == "/apis/cilium.io/v1alpha1/tracingpolicies" && r.URL.Query().Get("watch") == "":
			json.NewEncoder(w).Encode(map[string]any{"kind": "TracingPolicyList", "apiVersion": "cilium.io/v1alpha1", "metadata": map[string]any{"resourceVersion": "1"}, "items": policyObjects(t, true)})
		case r.URL.Path == "/apis/cilium.io/v1alpha1/tracingpoliciesnamespaced" && r.URL.Query().Get("watch") == "":
			json.NewEncoder(w).Encode(map[string]any{"kind": "TracingPolicyNamespacedList", "apiVersion": "cilium.io/v1alpha1", "metadata": map[string]any{"resourceVersion": "1"}, "items": policyObjects(t, false)})
		default:
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

// policyObjects renders the committed policy sources like render.py.
func policyObjects(t *testing.T, cluster bool) []map[string]any {
	var out []map[string]any
	for _, f := range []string{"network.yaml", "file-access.yaml", "tcp-state.yaml"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", "tetragon", "policies", f))
		if err != nil {
			t.Error(err)
			return nil
		}
		var m map[string]any
		if err := sigsyaml.Unmarshal(b, &m); err != nil {
			t.Error(err)
			return nil
		}
		if (m["kind"] == "TracingPolicy") != cluster {
			continue
		}
		if cluster {
			out = append(out, m)
			continue
		}
		for _, ns := range []string{"agent-exec", "agent-adapters"} {
			c := map[string]any{}
			for k, v := range m {
				c[k] = v
			}
			md := map[string]any{}
			for k, v := range m["metadata"].(map[string]any) {
				md[k] = v
			}
			md["namespace"] = ns
			c["metadata"] = md
			out = append(out, c)
		}
	}
	return out
}

// installedRuleHash returns the rule_hash of the committed policies (with the
// pinned CRD defaults, as deploy/gcp/sensors/render.py computes it) and the
// pinned 1.7.1 policymetrics rows for them.
func installedRuleHash(t *testing.T) (string, []string) {
	var elems []capture.Policy
	var rows []string
	for _, cluster := range []bool{true, false} {
		for _, m := range policyObjects(t, cluster) {
			md := m["metadata"].(map[string]any)
			ns, _ := md["namespace"].(string)
			spec, err := capture.ApplyCRDDefaults(m["kind"].(string), m["spec"])
			if err != nil {
				t.Fatal(err)
			}
			elems = append(elems, capture.Policy{Kind: m["kind"].(string), Namespace: ns, Name: md["name"].(string), Spec: spec})
			rows = append(rows, fmt.Sprintf("tetragon_tracingpolicy_kernel_memory_bytes{policy=%q,policy_namespace=%q} 4096", md["name"], ns))
		}
	}
	h, err := capture.RuleHash(elems)
	if err != nil {
		t.Fatal(err)
	}
	return h, rows
}

type env struct {
	t        *testing.T
	dir      string
	config   string
	export   string
	spool    string
	coll     *collector
	health   *health
	disabled atomic.Int32 // tetragon_tracingpolicy_loaded{state="disabled"}
	logs     *bytes.Buffer
	logMu    sync.Mutex
	process  *exec.Cmd
}

func setup(t *testing.T) *env {
	p := newPKI(t)
	dir := t.TempDir()
	e := &env{t: t, dir: dir, export: filepath.Join(dir, "export", "tetragon.log"), spool: filepath.Join(dir, "spool"), logs: &bytes.Buffer{}}
	e.coll = &collector{t: t, records: map[string]map[string]any{}, digests: map[string]string{}, seqs: map[string]map[uint64]bool{}, acked: map[string]uint64{}}
	e.health = &health{}
	token := "projected-token-for-tetragon"
	identity := p.server(t, identitySAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, Token string }
		if r.URL.Path != "/internal/workload-certificates" || json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		notAfter := time.Now().Add(time.Hour).Truncate(time.Second)
		der := p.issue(t, csr.PublicKey, SensorSAN, x509.ExtKeyUsageClientAuth, notAfter)
		json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "certificate_chain": []string{}, "serial": "01", "expires_at": notAfter})
	}), false)
	coll := p.server(t, auditSAN, e.coll, true)
	hs := p.server(t, healthSAN, e.health, true)
	kube := kubeAPI(t)
	metricsBody, err := os.ReadFile(metricsFixture)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ruleHash, policyRows := installedRuleHash(t)
	metrics := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(metricsBody)
		fmt.Fprintln(w, "# TYPE tetragon_tracingpolicy_kernel_memory_bytes gauge")
		fmt.Fprintln(w, strings.Join(policyRows, "\n"))
		fmt.Fprintln(w, "# TYPE tetragon_tracingpolicy_loaded gauge")
		fmt.Fprintf(w, "tetragon_tracingpolicy_loaded{state=\"disabled\"} %d\ntetragon_tracingpolicy_loaded{state=\"enabled\"} %d\ntetragon_tracingpolicy_loaded{state=\"error\"} 0\ntetragon_tracingpolicy_loaded{state=\"load_error\"} 0\n", e.disabled.Load(), len(policyRows))
	})}
	go metrics.Serve(ln)
	t.Cleanup(func() { metrics.Close() })

	write := func(name string, b []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	configDir := filepath.Join(dir, "tetragon-config")
	settings := map[string]string{"export-filename": e.export, "export-file-max-size-mb": "10", "export-file-max-backups": "5", "export-allowlist": `{"event_set":["PROCESS_EXEC"]}`, "enable-policy-filter": "true", "metrics-label-filter": "namespace,workload,pod,binary"}
	for k, v := range capture.Invariants {
		settings[k] = v
	}
	for k, v := range settings {
		write(filepath.Join("tetragon-config", k), []byte(v), 0o444)
	}
	write(filepath.Join("tetragon-config", "debug"), []byte("false"), 0o444)
	kubeconfig := write("kubeconfig", []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: %q}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\ncurrent-context: c\nusers: [{name: u, user: {}}]\n", kube.URL)), 0o600)
	cfg := Config{Version: "test", ExportFile: e.export, ExportMaxFiles: 6, MaxLineBytes: 1 << 20, SpoolDir: e.spool, SpoolCapacityBytes: 64 << 20,
		BootIDPath: write("boot_id", []byte(bootID+"\n"), 0o444), Kubeconfig: kubeconfig,
		CollectorOrigin: coll.URL, HealthOrigin: hs.URL, IdentityOrigin: identity.URL, IdentityPeerSAN: identitySAN, TokenFile: write("token", []byte(token), 0o600), CAFile: write("ca.pem", p.pem, 0o644),
		MetricsEndpoint: "http://" + ln.Addr().String() + "/metrics", TetragonVersion: "1.7.1", SensorGeneration: 1, RuleHash: ruleHash,
		TetragonConfigDir: configDir, TetragonSettings: settings, NormalizationVersion: "test-normalization", RecoveryReason: "wal_segment_corrupt",
		AllowedBinaries: []string{"/app/bin/probe-runner"}, ProtectedPaths: []string{"/work/protected-fixture"}, ObservedNamespaces: []string{"agent-exec", "agent-adapters"},
		MetadataGraceSeconds: 2, PodRetentionSeconds: 600,
		ProcRoot: filepath.Join(dir, "proc"), CgroupRoot: filepath.Join(dir, "cgroup"), WorkerBinaries: []string{"/usr/local/bin/python3"}}
	raw, _ := json.Marshal(cfg)
	e.config = write("config.json", raw, 0o600)
	if err := os.MkdirAll(filepath.Dir(e.export), 0o700); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) append(lines [][]byte) {
	f, err := os.OpenFile(e.export, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	for _, l := range lines {
		f.Write(append(l, '\n'))
	}
	f.Sync()
}

type syncWriter struct{ e *env }

func (w syncWriter) Write(p []byte) (int, error) {
	w.e.logMu.Lock()
	defer w.e.logMu.Unlock()
	return w.e.logs.Write(p)
}

func (e *env) start() {
	cmd := exec.Command(binary, "--config", e.config)
	cmd.Env = append(os.Environ(), "NODE_NAME="+evidenceNode)
	cmd.Stdout, cmd.Stderr = syncWriter{e}, syncWriter{e}
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.process = cmd
	e.t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
}

func (e *env) waitFor(what string, cond func() bool) {
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.logMu.Lock()
			e.t.Fatalf("timeout waiting for %s\n%s", what, e.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *env) inspect() []map[string]any {
	out, err := exec.Command(binary, "inspect-wal", e.spool).Output()
	if err != nil {
		e.t.Fatal(err)
	}
	var recs []map[string]any
	s := bufio.NewScanner(bytes.NewReader(out))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		var m map[string]any
		if err := json.Unmarshal(s.Bytes(), &m); err != nil {
			e.t.Fatal(err)
		}
		recs = append(recs, m)
	}
	return recs
}

func readEvidence(t *testing.T) [][]byte {
	f, err := os.Open(evidence)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines [][]byte
	s := bufio.NewScanner(f)
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		lines = append(lines, append([]byte(nil), s.Bytes()...))
	}
	return lines
}

// excluded builds two events that must be filtered before sequencing: an exec
// in a kube-system container and a tcp_state whose tuple has no observed Pod.
func excluded(t *testing.T, lines [][]byte) [][]byte {
	var out [][]byte
	for _, l := range lines {
		var m map[string]any
		json.Unmarshal(l, &m)
		if p, ok := m["process_exec"].(map[string]any); ok && len(out) == 0 {
			p["process"].(map[string]any)["docker"] = systemCID[:31]
			b, _ := json.Marshal(m)
			out = append(out, b)
		}
		if k, ok := m["process_kprobe"].(map[string]any); ok && k["function_name"] == "tcp_set_state" && len(out) == 1 {
			s := k["args"].([]any)[0].(map[string]any)["sock_arg"].(map[string]any)
			s["saddr"], s["daddr"] = "10.20.9.9", "10.20.9.8"
			b, _ := json.Marshal(m)
			out = append(out, b)
		}
	}
	if len(out) != 2 {
		t.Fatal("cannot build exclusion fixtures")
	}
	return out
}

func TestExporterDeliversQ0EventsAcrossCrashWithContract(t *testing.T) {
	e := setup(t)
	lines := readEvidence(t)
	if len(lines) != 245 {
		t.Fatalf("evidence changed: %d lines", len(lines))
	}
	first, rest := lines[:120], lines[120:]
	extra := excluded(t, lines)
	e.append(first[:60])
	e.append(extra[:1])
	e.append(first[60:])

	// Phase 1: collector unavailable. Events must be fsynced to WAL first.
	e.start()
	e.waitFor("120 fsynced records in WAL", func() bool { return len(e.inspect()) == 120 })
	wal1 := e.inspect()
	e.waitFor("lease", func() bool {
		e.health.mu.Lock()
		defer e.health.mu.Unlock()
		return len(e.health.leases) > 0
	})
	if err := e.process.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	e.process.Wait()

	// Phase 2: collector up with one lost ACK; more input; a new process epoch.
	e.coll.mu.Lock()
	e.coll.available, e.coll.dropNext = true, true
	e.coll.mu.Unlock()
	e.append(extra[1:])
	e.append(rest)
	e.start()
	e.waitFor("245 committed records", func() bool {
		e.coll.mu.Lock()
		defer e.coll.mu.Unlock()
		var acked uint64
		for _, a := range e.coll.acked {
			acked += a
		}
		return len(e.coll.records) == 245 && acked == 245
	})
	e.waitFor("WAL drained after ack", func() bool { return len(e.inspect()) == 0 })
	// Capture check passes (loaded policies, rule hash, pinned settings) and
	// the backlog is acknowledged: the lease becomes healthy.
	e.waitFor("healthy lease", func() bool {
		e.health.mu.Lock()
		defer e.health.mu.Unlock()
		return len(e.health.leases) > 0 && e.health.leases[len(e.health.leases)-1]["observed_state"] == "healthy"
	})
	// A disabled policy makes the next lease unhealthy again.
	e.disabled.Store(1)
	e.waitFor("unhealthy after policy disabled", func() bool {
		e.health.mu.Lock()
		defer e.health.mu.Unlock()
		return e.health.leases[len(e.health.leases)-1]["observed_state"] == "unhealthy"
	})
	e.process.Process.Signal(syscall.SIGTERM)
	if err := e.process.Wait(); err != nil {
		t.Fatalf("graceful stop: %v\n%s", err, e.logs.String())
	}

	e.coll.mu.Lock()
	defer e.coll.mu.Unlock()
	if len(e.coll.violations) != 0 {
		t.Fatalf("contract violations: %v", e.coll.violations)
	}
	if len(e.coll.seqs) != 2 {
		t.Fatalf("expected the crashed epoch to replay plus one new epoch, got %d", len(e.coll.seqs))
	}
	// Original WAL bytes of the crashed epoch were replayed unchanged.
	for _, w := range wal1 {
		id := w["source_event_id"].(string)
		if e.coll.digests[id] != w["record_digest"] {
			t.Fatalf("replayed record changed: %s", id)
		}
	}
	counts := map[string]int{}
	for _, r := range e.coll.records {
		kind := r["event_type"].(string)
		counts[kind]++
		switch kind {
		case "tcp_state":
			if r["pod_uid"] != nil || r["container_id"] != nil || r["process_exec_id"] != nil || r["metadata_status"] != "tuple_scoped" {
				t.Fatalf("softirq state must not carry process/Pod fields: %v", r)
			}
		default:
			if r["pod_uid"] != stimulusPodUID || r["container_id"] != stimulusCID || r["docker_id_prefix"] != stimulusCID[:15] || r["metadata_status"] != "resolved" {
				t.Fatalf("process metadata must come from the Pod API: %v", r)
			}
		}
	}
	want := map[string]int{"process_exec": 31, "process_exit": 31, "tcp_connect": 30, "tcp_state": 61, "file_open": 31, "openat": 61}
	for k, v := range want {
		if counts[k] != v {
			t.Fatalf("%s: got %d want %d (%v)", k, counts[k], v, counts)
		}
	}
	// Sequences are contiguous from 1 in each epoch: filtered events got none.
	var total int
	for epoch, seqs := range e.coll.seqs {
		keys := make([]int, 0, len(seqs))
		for s := range seqs {
			keys = append(keys, int(s))
		}
		sort.Ints(keys)
		for i, s := range keys {
			if s != i+1 {
				t.Fatalf("epoch %s sequence gap at %d", epoch[:8], s)
			}
		}
		total += len(keys)
		sum := sha256.Sum256([]byte(bootID))
		if !strings.HasPrefix(epoch, "30000000000040008000000000000001"+hex.EncodeToString(sum[:])) {
			t.Fatalf("epoch does not bind node/boot: %s", epoch)
		}
	}
	if total != 245 {
		t.Fatalf("sequenced %d events, exclusions must not be sequenced", total)
	}
	e.health.mu.Lock()
	defer e.health.mu.Unlock()
	if len(e.health.bad) != 0 {
		t.Fatalf("health contract: %v", e.health.bad)
	}
	if e.health.snapshots == 0 {
		t.Fatal("exporter never polled its node challenges")
	}
}
