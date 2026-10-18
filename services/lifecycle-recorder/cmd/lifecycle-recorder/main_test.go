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
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/internal/ctrdtest"
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/recorder"
)

const (
	identitySAN = "spiffe://agentarium.internal/ns/agent-control/sa/workload-identity"
	auditSAN    = "spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer"
	healthSAN   = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
	nodeName    = "gke-exec-node-a"
	nodeUID     = "30000000-0000-4000-8000-000000000001"
	bootID      = "6f1d3d1c-1f5e-4a1b-9c7c-0c4f7d9e2a11"
	clusterUID  = "00000000-0000-4000-8000-000000000001"
	podUID      = "11111111-1111-4111-8111-111111111111"
)

var binary, proxyBinary string

func TestMain(m *testing.M) {
	dir, _ := os.MkdirTemp("", "recorder-bin")
	binary = filepath.Join(dir, "lifecycle-recorder")
	proxyBinary = filepath.Join(dir, "containerd-proxy")
	if out, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		panic(string(out))
	}
	if out, err := exec.Command("go", "build", "-o", proxyBinary, "../containerd-proxy").CombinedOutput(); err != nil {
		panic(string(out))
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	pem  []byte
}

func newCA() *ca {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &ca{c, key, pool, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (c *ca) issue(pub any, san string, usage x509.ExtKeyUsage, notAfter time.Time) []byte {
	u, _ := url.Parse(san)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: notAfter, URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage}}, c.cert, pub, c.key)
	return der
}

func (c *ca) server(t *testing.T, san string, h http.Handler, mutual bool) *httptest.Server {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{c.issue(&key.PublicKey, san, x509.ExtKeyUsageServerAuth, time.Now().Add(time.Hour))}, PrivateKey: key}}}
	if mutual {
		s.TLS.ClientAuth, s.TLS.ClientCAs = tls.RequireAndVerifyClientCert, c.pool
	}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func peer(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].URIs[0].String()
}

// TestRecorderCommand runs the binary: direct identity bootstrap, the
// containerd fixture behind the containerd-proxy binary, TASK-07 lifecycle batch, RUNTIME_RECORD_MISSING gap, and the
// lifecycle-recorder lease.
func TestRecorderCommand(t *testing.T) {
	c := newCA()
	dir := t.TempDir()
	token := "recorder-token"
	identity := c.server(t, identitySAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ CSR, Token string }
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.Token != token || r.URL.Path != "/internal/workload-certificates" {
			w.WriteHeader(401)
			return
		}
		block, _ := pem.Decode([]byte(req.CSR))
		csr, _ := x509.ParseCertificateRequest(block.Bytes)
		na := time.Now().Add(time.Hour).Truncate(time.Second)
		json.NewEncoder(w).Encode(map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.issue(csr.PublicKey, recorder.SourceSAN, x509.ExtKeyUsageClientAuth, na)})), "certificate_chain": []string{}, "serial": "1", "expires_at": na})
	}), false)
	var mu sync.Mutex
	var records []map[string]any
	var violations []string
	acked := map[string]uint64{}
	coll := c.server(t, auditSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		raw, _ := io.ReadAll(r.Body)
		var env struct {
			BatchID string            `json:"batch_id"`
			Epoch   string            `json:"source_epoch"`
			Records []json.RawMessage `json:"records"`
		}
		if peer(r) != recorder.SourceSAN || json.Unmarshal(raw, &env) != nil {
			violations = append(violations, "collector request")
			w.WriteHeader(403)
			return
		}
		ids := []string{}
		for _, rec := range env.Records {
			var m map[string]any
			d := json.NewDecoder(bytes.NewReader(rec))
			d.UseNumber()
			d.Decode(&m)
			seq, _ := m["source_sequence"].(json.Number).Int64()
			id, _ := canonical.LifecycleEventID(recorder.SourceSAN, env.Epoch, seq)
			digest, _ := canonical.DigestWithoutKeys(rec, "record_digest", "received_at")
			if m["lifecycle_event_id"] != id || m["record_digest"] != digest || m["node_uid"] != nodeUID {
				violations = append(violations, fmt.Sprint(m))
			}
			records = append(records, m)
			ids = append(ids, id)
			acked[env.Epoch] = max(acked[env.Epoch], uint64(seq))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"batch_id": env.BatchID, "accepted_ids": ids, "duplicate_ids": []string{}, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": env.Epoch, "acked_through": acked[env.Epoch]}}})
	}), true)
	var leases []map[string]any
	var gaps []map[string]any
	health := c.server(t, healthSAN, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var m map[string]any
		if peer(r) != recorder.SourceSAN || json.NewDecoder(r.Body).Decode(&m) != nil {
			violations = append(violations, "health request")
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/internal/control-health/leases":
			if m["component"] != "lifecycle-recorder" || m["source_id"] != "lifecycle-node/"+nodeUID || m["scope_id"] != nodeUID {
				violations = append(violations, fmt.Sprint(m))
			}
			leases = append(leases, m)
			fmt.Fprintf(w, `{"lease_until":%q,"scope_state":"healthy"}`, m["lease_until"])
		case "/internal/control-health/observation-gaps":
			gaps = append(gaps, m)
			gap := m["gap"].(map[string]any)
			w.WriteHeader(201)
			fmt.Fprintf(w, `{"gap_id":%q,"recorded_at":%q,"result":"created"}`, gap["gap_id"], time.Now().UTC().Format(time.RFC3339Nano))
		default:
			w.WriteHeader(404)
		}
	}), true)
	kube := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/nodes/"+nodeName {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"kind": "Node", "apiVersion": "v1", "metadata": map[string]any{"name": nodeName, "uid": nodeUID}, "spec": map[string]any{"podCIDRs": []string{"10.20.1.0/24"}}, "status": map[string]any{"nodeInfo": map[string]any{"bootID": bootID}}})
	}))
	t.Cleanup(kube.Close)
	fake := ctrdtest.New()
	cid := strings.Repeat("a", 64)
	fake.Containers[cid] = ctrdtest.PodContainer(cid, podUID, "main", "kubepods-pod11111111.slice:cri-containerd:"+cid, false)
	fake.Order = []string{cid}
	sockDir, _ := os.MkdirTemp("", "ctrd")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	upstream := fake.Serve(t, sockDir)
	sock := filepath.Join(sockDir, "proxy.sock")
	proxy := exec.Command(proxyBinary, "--upstream", upstream, "--listen", sock)
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Process.Kill(); proxy.Wait() })
	for i := 0; ; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		} else if i > 100 {
			t.Fatal("containerd-proxy did not listen")
		}
		time.Sleep(50 * time.Millisecond)
	}
	write := func(name string, b []byte, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, b, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cgroups := filepath.Join(dir, "cgroup")
	os.MkdirAll(cgroups, 0o755)
	cfg, _ := json.Marshal(Config{Version: "test", ContainerdSocket: sock, CgroupRoot: cgroups, SpoolDir: filepath.Join(dir, "spool"), SpoolCapacity: 64 << 20, BootIDPath: write("boot_id", []byte(bootID), 0o444),
		ClusterUID: clusterUID, CollectorOrigin: coll.URL, HealthOrigin: health.URL, IdentityOrigin: identity.URL, IdentityPeerSAN: identitySAN,
		TokenFile: write("token", []byte(token), 0o600), CAFile: write("ca.pem", c.pem, 0o644),
		Kubeconfig: write("kubeconfig", []byte(fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: %q}}]\ncontexts: [{name: c, context: {cluster: c, user: u}}]\ncurrent-context: c\nusers: [{name: u, user: {}}]\n", kube.URL)), 0o600)})
	var logs bytes.Buffer
	var logMu sync.Mutex
	cmd := exec.Command(binary, "--config", write("config.json", cfg, 0o600))
	cmd.Env = append(os.Environ(), "NODE_NAME="+nodeName)
	lw := writer(func(b []byte) (int, error) { logMu.Lock(); defer logMu.Unlock(); return logs.Write(b) })
	cmd.Stdout, cmd.Stderr = lw, lw
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
		mu.Lock()
		ok := len(records) >= 1 && len(gaps) == 1 && len(leases) > 0 && leases[len(leases)-1]["observed_state"] == "healthy"
		mu.Unlock()
		if ok {
			break
		}
		if time.Now().After(deadline) {
			logMu.Lock()
			t.Fatalf("recorder did not deliver, gap and lease\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("SIGTERM: %v\n%s", err, logs.String())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(violations) != 0 {
		t.Fatalf("contract: %v", violations)
	}
	if records[0]["transition"] != "container_present" || records[0]["image_id"] == nil {
		t.Fatalf("record %v", records[0])
	}
	// Everything the recorder asked of containerd went through the proxy's
	// allowlist.
	fake.Mu.Lock()
	for _, m := range fake.Calls {
		switch m {
		case "/containerd.services.events.v1.Events/Subscribe", "/containerd.services.containers.v1.Containers/Get", "/containerd.services.containers.v1.Containers/List", "/runtime.v1.RuntimeService/ContainerStatus":
		default:
			t.Errorf("unexpected upstream call %s", m)
		}
	}
	fake.Mu.Unlock()
	if g := gaps[0]["gap"].(map[string]any); gaps[0]["scope"] != "node/"+nodeUID || g["reason"] != "RUNTIME_RECORD_MISSING" || g["node_uid"] != nodeUID || g["boot_id"] != bootID {
		t.Fatalf("gap %v", gaps[0])
	}
}

type writer func([]byte) (int, error)

func (f writer) Write(b []byte) (int, error) { return f(b) }

// The spool-owner init mode re-owns an existing spool tree and makes the
// directory owner-only.
func TestPrepareSpool(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	os.MkdirAll(filepath.Join(dir, "wal"), 0o755)
	os.WriteFile(filepath.Join(dir, "wal", "segment"), []byte("x"), 0o600)
	uid := os.Getuid()
	if uid == 0 {
		uid = 65532
	}
	out, err := exec.Command(binary, "--prepare-spool", dir, "--spool-owner", fmt.Sprint(uid), "--spool-group", fmt.Sprint(os.Getgid())).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("spool mode %v %v", fi.Mode().Perm(), err)
	}
	for _, p := range []string{dir, filepath.Join(dir, "wal", "segment")} {
		fi, _ := os.Lstat(p)
		if st := fi.Sys().(*syscall.Stat_t); int(st.Uid) != uid {
			t.Fatalf("%s owner %d", p, st.Uid)
		}
	}
	if out, err := exec.Command(binary, "--prepare-spool", "relative/spool").CombinedOutput(); err == nil {
		t.Fatalf("relative spool accepted: %s", out)
	}
	if out, err := exec.Command(binary, "--prepare-spool", dir, "--spool-owner", "0").CombinedOutput(); err == nil {
		t.Fatalf("root spool owner accepted: %s", out)
	}
}
