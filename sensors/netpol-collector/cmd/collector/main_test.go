package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	collector "github.com/Beaver-Dam-Community/Agentarium/sensors/netpol-collector"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/netpol-collector/internal/receivertest"
)

const (
	q0Log      = "../../../../evidence/gcp/runs/20261014-task01-q0-min/raw/netpol-policy_action.log"
	node       = "gke-agentarium-prod-exec-pool-eaf0304a-x10z"
	nodeUID    = "30000000-0000-4000-8000-000000000001"
	clusterUID = "11111111-1111-4111-8111-111111111111"
	bootID     = "6f1d3d1c-1f5e-4a1b-9c7c-0c4f7d9e2a11"
	// hostNetwork collectors bootstrap through the gateway relay (TASK-03 3.3).
	identSAN  = "spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"
	healthSAN = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
)

var binary string

func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "netpol-bin")
	binary = filepath.Join(dir, "collector")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type leases struct {
	mu  sync.Mutex
	all []map[string]any
	bad []string
}

func (l *leases) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var m map[string]any
	if r.URL.Path != "/internal/control-health/leases" || r.TLS == nil || r.TLS.PeerCertificates[0].URIs[0].String() != collector.CollectorSAN || json.NewDecoder(r.Body).Decode(&m) != nil {
		l.bad = append(l.bad, "lease request")
		w.WriteHeader(400)
		return
	}
	d, _ := m["details"].(map[string]any)
	if m["source_id"] != "netpol-node/"+nodeUID || m["component"] != "netpol-collector" || m["scope"] != "node" || m["scope_id"] != nodeUID || d == nil || d["source_epoch"] == nil || d["file_offset"] == nil || d["acked_through"] == nil || d["schema_rejected_count"] == nil {
		l.bad = append(l.bad, fmt.Sprintf("lease %v", m))
	}
	l.all = append(l.all, m)
	fmt.Fprintf(w, `{"lease_until":%q,"scope_state":"healthy"}`, m["lease_until"])
}

func (l *leases) last() map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.all) == 0 {
		return nil
	}
	return l.all[len(l.all)-1]
}

type env struct {
	t      *testing.T
	dir    string
	config string
	live   string
	recv   *receivertest.Receiver
	leases *leases
	logs   *syncBuf
	cmd    *exec.Cmd
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func setup(t *testing.T) *env {
	p := receivertest.NewPKI()
	dir := t.TempDir()
	e := &env{t: t, dir: dir, live: filepath.Join(dir, "network", "policy_action.log"), recv: receivertest.New(clusterUID), leases: &leases{}, logs: &syncBuf{}}
	token := "projected-netpol-token"
	identity := p.Server(identSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, Token string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != token {
			w.WriteHeader(401)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		na := time.Now().Add(time.Hour).Truncate(time.Second)
		json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Issue(csr.PublicKey, collector.CollectorSAN, x509.ExtKeyUsageClientAuth, na)})), "certificate_chain": []string{}, "serial": "1", "expires_at": na})
	}), false)
	recv := p.Server(collector.ReceiverSAN, e.recv, true)
	health := p.Server(healthSAN, e.leases, true)
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/"+node {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"kind": "Node", "apiVersion": "v1", "metadata": map[string]any{"name": node, "uid": nodeUID}, "spec": map[string]any{"podCIDRs": []string{"10.20.1.0/24"}}, "status": map[string]any{"nodeInfo": map[string]any{"bootID": bootID}}})
	}))
	t.Cleanup(func() { identity.Close(); recv.Close(); health.Close(); kube.Close() })
	write := func(name string, b []byte, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(path), 0o700)
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	kubeconfig := write("kubeconfig", []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: %q}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\ncurrent-context: c\nusers: [{name: u, user: {}}]\n", kube.URL)), 0o600)
	cfg := Config{Version: "test", LiveFile: e.live, MaxLineBytes: 1 << 20, SpoolDir: filepath.Join(dir, "spool"), SpoolCapacityBytes: 64 << 20, BootIDPath: write("boot_id", []byte(bootID), 0o444), Kubeconfig: kubeconfig,
		ClusterUID: clusterUID, NormalizationVersion: "test-v1", ReceiverOrigin: recv.URL, HealthOrigin: health.URL, IdentityOrigin: identity.URL, IdentityPeerSAN: identSAN,
		TokenFile: write("token", []byte(token), 0o600), CAFile: write("ca.pem", p.PEM, 0o644), FinalFlushSeconds: 20}
	raw, _ := json.Marshal(cfg)
	e.config = write("config.json", raw, 0o600)
	os.MkdirAll(filepath.Dir(e.live), 0o700)
	return e
}

func q0Lines(t *testing.T) [][]byte {
	b, err := os.ReadFile(q0Log)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	s := bufio.NewScanner(bytes.NewReader(b))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		out = append(out, append([]byte(nil), s.Bytes()...))
	}
	return out
}

func (e *env) append(lines [][]byte) {
	f, err := os.OpenFile(e.live, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, l := range lines {
		f.Write(append(l, '\n'))
	}
	f.Sync()
	f.Close()
}

func (e *env) start() {
	cmd := exec.Command(binary, "--config", e.config)
	cmd.Env = append(os.Environ(), "NODE_NAME="+node)
	cmd.Stdout, cmd.Stderr = e.logs, e.logs
	if err := cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	e.cmd = cmd
	e.t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
}

func (e *env) wait(what string, cond func() bool) {
	deadline := time.Now().Add(60 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.recv.Lock()
			e.t.Fatalf("timeout: %s\nrecords=%d acked=%v viol=%v batches=%d\n%s", what, len(e.recv.Records), e.recv.Acked, e.recv.Violations, e.recv.Batches, e.logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (e *env) recvState(f func(r *receivertest.Receiver) bool) func() bool {
	return func() bool { e.recv.Lock(); defer e.recv.Unlock(); return f(e.recv) }
}

func TestCollectorDeliversAcrossCrashAndFinalFlushes(t *testing.T) {
	e := setup(t)
	lines := q0Lines(t)
	if len(lines) != 5 {
		t.Fatalf("Q0 log changed: %d", len(lines))
	}
	e.append(lines[:3])
	// Phase 1: receiver down; lease still reports with details.
	e.start()
	e.wait("lease with details", func() bool { return e.leases.last() != nil })
	e.cmd.Process.Signal(syscall.SIGKILL)
	e.cmd.Wait()

	// Phase 2: receiver up with one lost ACK; new epoch replays old WAL first.
	e.recv.Lock()
	e.recv.Available, e.recv.DropNext = true, true
	e.recv.Unlock()
	e.append(lines[3:])
	e.start()
	// A SIGKILL between sequence reservation and fsync leaves an abandoned
	// range and the line is read again in the new epoch, so count distinct
	// source lines and require every epoch to be acknowledged to its end.
	e.wait("5 source lines acked", e.recvState(func(r *receivertest.Receiver) bool { return distinct(r) == 5 && settled(r) }))
	e.wait("caught_up_at in lease", func() bool {
		l := e.leases.last()
		d, _ := l["details"].(map[string]any)
		return d != nil && d["caught_up_at"] != nil
	})
	// Phase 3: two new source lines, then SIGTERM -> final flush.
	e.append(retimed(t, lines[:2]))
	e.cmd.Process.Signal(syscall.SIGTERM)
	if err := e.cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM exit: %v\n%s", err, e.logs.String())
	}
	e.recv.Lock()
	defer e.recv.Unlock()
	if len(e.recv.Violations) != 0 {
		t.Fatalf("contract: %v", e.recv.Violations)
	}
	if distinct(e.recv) != 7 || !settled(e.recv) || len(e.recv.Final) != 1 {
		t.Fatalf("records %d final %v\n%s", len(e.recv.Records), e.recv.Final, e.logs.String())
	}
	for epoch, through := range e.recv.Final {
		if e.recv.Acked[epoch] < through {
			t.Fatalf("final flush beyond watermark")
		}
	}
	e.leases.mu.Lock()
	defer e.leases.mu.Unlock()
	if len(e.leases.bad) != 0 {
		t.Fatalf("lease contract: %v", e.leases.bad)
	}
	if !strings.Contains(e.logs.String(), "final flush recorded") {
		t.Fatal("final flush not logged")
	}
}

func TestCollectorReportsRotationLossAndStops(t *testing.T) {
	e := setup(t)
	e.recv.Lock()
	e.recv.Available = true
	e.recv.Unlock()
	lines := q0Lines(t)
	e.append(lines[:3])
	e.start()
	e.wait("3 acked", e.recvState(func(r *receivertest.Receiver) bool { return len(r.Records) == 3 }))
	e.cmd.Process.Signal(syscall.SIGKILL)
	e.cmd.Wait()
	// While stopped, the file is rotated away (new inode, old content gone).
	os.Remove(e.live)
	e.append(lines[3:])
	e.start()
	e.wait("rotation_loss reported", e.recvState(func(r *receivertest.Receiver) bool { return len(r.Rotation) == 1 }))
	e.wait("unhealthy lease", func() bool {
		l := e.leases.last()
		return l != nil && l["observed_state"] == "unhealthy"
	})
	e.cmd.Process.Signal(syscall.SIGTERM)
	if err := e.cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM exit: %v\n%s", err, e.logs.String())
	}
	e.recv.Lock()
	defer e.recv.Unlock()
	if len(e.recv.Violations) != 0 || len(e.recv.Records) != 3 {
		t.Fatalf("records after loss must not be guessed: %d %v", len(e.recv.Records), e.recv.Violations)
	}
	if after, _ := e.recv.Rotation[0]["after_sequence"].(float64); after != 0 {
		// The new process epoch has allocated nothing before the loss.
		t.Fatalf("after_sequence %v", e.recv.Rotation[0])
	}
}

func distinct(r *receivertest.Receiver) int {
	seen := map[string]bool{}
	for _, rec := range r.Records {
		seen[fmt.Sprint(rec["source_time"], rec["src_ip"], rec["src_port"])] = true
	}
	return len(seen)
}

// settled: every epoch's watermark reached its highest stored sequence.
func settled(r *receivertest.Receiver) bool {
	high := map[string]uint64{}
	for _, rec := range r.Records {
		n, _ := rec["source_sequence"].(json.Number).Int64()
		ep := rec["source_epoch"].(string)
		high[ep] = max(high[ep], uint64(n))
	}
	for ep, h := range high {
		if r.Acked[ep] < h {
			return false
		}
	}
	return true
}

func retimed(t *testing.T, lines [][]byte) [][]byte {
	var out [][]byte
	for i, l := range lines {
		var m map[string]any
		if err := json.Unmarshal(l, &m); err != nil {
			t.Fatal(err)
		}
		m["timestamp"] = fmt.Sprintf("2026-10-14T14:00:0%d.000000001Z", i)
		b, _ := json.Marshal(m)
		out = append(out, b)
	}
	return out
}

// Review #175: the stall clock runs only while records are pending; a quiet
// node stays healthy and an unreachable receiver turns unhealthy.
func TestLeaseHealthFollowsPendingBacklog(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	epoch := strings.Repeat("a", 32) + strings.Repeat("b", 64) + strings.Repeat("c", 32)
	j, err := wal.Open(dir, epoch, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	st := &status{healthy: true}
	t0 := time.Now()
	st.observe(j, epoch, t0)
	if !st.leaseHealthy(t0.Add(10 * time.Minute)) {
		t.Fatal("quiet node with nothing pending must stay healthy")
	}
	if _, err := j.Append(func(e string, s uint64) ([]byte, error) {
		return []byte(fmt.Sprintf(`{"source_epoch":%q,"source_sequence":%d}`, e, s)), nil
	}, wal.Checkpoint{Inode: 1, Offset: 1}); err != nil {
		t.Fatal(err)
	}
	st.observe(j, epoch, t0)
	if !st.leaseHealthy(t0.Add(29 * time.Second)) {
		t.Fatal("fresh backlog is not stalled yet")
	}
	if st.leaseHealthy(t0.Add(31 * time.Second)) {
		t.Fatal("30 s backlog without ack must be unhealthy")
	}
	if err := j.Ack(epoch, 1); err != nil {
		t.Fatal(err)
	}
	st.observe(j, epoch, t0.Add(40*time.Second))
	if !st.leaseHealthy(t0.Add(41*time.Second)) || st.acked != 1 {
		t.Fatalf("acked backlog must clear the stall: acked=%d", st.acked)
	}
	// acked_through never decreases.
	st.observe(j, "other-epoch", t0.Add(42*time.Second))
	if st.acked != 1 {
		t.Fatal("acked_through lowered")
	}
	st.mu.Lock()
	st.missingSince = t0
	st.mu.Unlock()
	if st.leaseHealthy(t0.Add(11 * time.Second)) {
		t.Fatal("a missing live file for 10 s must be unhealthy")
	}
}

// An oversized line stops capture without a crash loop: the process keeps
// reporting an unhealthy lease and exits 0 on SIGTERM after sending its backlog.
func TestOversizedLineStopsCaptureNotProcess(t *testing.T) {
	e := setup(t)
	e.recv.Lock()
	e.recv.Available = true
	e.recv.Unlock()
	var cfg Config
	raw, _ := os.ReadFile(e.config)
	json.Unmarshal(raw, &cfg)
	cfg.MaxLineBytes = 4096
	raw, _ = json.Marshal(cfg)
	os.WriteFile(e.config, raw, 0o600)
	lines := q0Lines(t)
	e.append(lines[:2])
	e.append([][]byte{[]byte(`{"pad":"` + strings.Repeat("x", 8192) + `"}`)})
	e.start()
	e.wait("2 records then unhealthy lease", func() bool {
		e.recv.Lock()
		n := len(e.recv.Records)
		e.recv.Unlock()
		l := e.leases.last()
		return n == 2 && l != nil && l["observed_state"] == "unhealthy"
	})
	time.Sleep(time.Second)
	if e.cmd.ProcessState != nil {
		t.Fatal("collector exited instead of reporting unhealthy")
	}
	e.cmd.Process.Signal(syscall.SIGTERM)
	if err := e.cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM exit: %v\n%s", err, e.logs.String())
	}
}
