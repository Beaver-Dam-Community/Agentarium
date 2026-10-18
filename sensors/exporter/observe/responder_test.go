package observe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/healthreport"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/podmeta"
	"github.com/google/uuid"
)

const (
	nodeUID    = "30000000-0000-4000-8000-000000000001"
	bootID     = "boot-1"
	podUID     = "40000000-0000-4000-8000-000000000002"
	clusterUID = "50000000-0000-4000-8000-000000000003"
	sensorSAN  = "spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon"
	healthSAN  = "spiffe://agentarium.internal/ns/agent-observe/sa/control-health"
	workerBin  = "/usr/local/bin/python3"
	pidNS      = 4026532001
	supHost    = 9000
	wrkHost    = 9001
	supTicks   = 1000
	wrkTicks   = 2000
	cgInode    = 4242
)

var (
	ruleHash    = strings.Repeat("a", 64)
	containerID = strings.Repeat("c", 64)
	testImage   = "sha256:" + strings.Repeat("e", 64)
	supExecRef  = uuid.NewSHA1(uuid.NameSpaceURL, []byte("sup")).String()
	wrkExecRef  = uuid.NewSHA1(uuid.NameSpaceURL, []byte("wrk")).String()
)

// fakeHealth is control-health's node challenge surface over real mTLS. It
// stores one evidence per nonce and treats a same-digest repost as a replay.
type fakeHealth struct {
	t         *testing.T
	mu        sync.Mutex
	worker    []map[string]any
	readiness []map[string]any
	stored    map[string]string // challenge -> body digest
	evidence  map[string]string // challenge -> evidence id
	posts     []posted
	drop      int // store, then lose this many responses
	busy      int // answer this many POSTs with 503 before storing
	gets      int
}

type posted struct {
	path string
	raw  []byte
	body map[string]any
}

func (f *fakeHealth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates[0].URIs) != 1 || r.TLS.PeerCertificates[0].URIs[0].String() != sensorSAN {
		f.t.Error("caller is not the sensor over mTLS")
		w.WriteHeader(403)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodGet {
		f.gets++
		if r.URL.Path != "/internal/control-health" || r.URL.Query().Get("scope") != "node" || r.URL.Query().Get("scope_id") != nodeUID || len(r.URL.Query()) != 2 {
			f.t.Errorf("snapshot request %s", r.URL)
		}
		pending := func(list []map[string]any) []map[string]any {
			out := []map[string]any{}
			for _, ch := range list {
				if _, ok := f.stored[ch["challenge_id"].(string)]; !ok {
					out = append(out, ch)
				}
			}
			return out
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"scope": "node", "scope_id": nodeUID, "evaluated_at": time.Now().UTC(), "state": "healthy", "leases": []any{},
			"missing_components": []any{}, "open_holds": []any{}, "probes": []any{}, "open_gaps": []any{}, "bundle_ack": nil, "startup_capture": nil,
			"pending_work_readiness_challenges": pending(f.readiness), "pending_worker_observation_challenges": pending(f.worker)})
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	if r.Header.Get("Content-Type") != "application/json" || canonical.CheckStrictJSON(raw) != nil || json.Unmarshal(raw, &body) != nil {
		f.t.Errorf("result body %s", raw)
	}
	f.posts = append(f.posts, posted{r.URL.Path, raw, body})
	if f.busy > 0 {
		f.busy--
		w.WriteHeader(503)
		fmt.Fprint(w, `{"request_id":"`+uuid.NewString()+`","reason_codes":["WORKER_OBSERVATION_NOT_READY"]}`)
		return
	}
	id, _ := body["challenge_id"].(string)
	sum := sha256.Sum256(canonicalize(f.t, raw))
	digest := hex.EncodeToString(sum[:])
	status, result := 201, "created"
	if prev, ok := f.stored[id]; ok {
		if prev != digest {
			w.WriteHeader(409)
			fmt.Fprint(w, `{"request_id":"`+uuid.NewString()+`","reason_codes":["EVENT_ID_CONFLICT"]}`)
			return
		}
		status, result = 200, "existing"
	} else {
		f.stored[id], f.evidence[id] = digest, uuid.NewString()
	}
	if f.drop > 0 {
		f.drop--
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
		return
	}
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"evidence_id":%q,"result":%q,"received_at":%q}`, f.evidence[id], result, time.Now().UTC().Format(time.RFC3339Nano))
}

func canonicalize(t *testing.T, raw []byte) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("bad JSON")
	}
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func mtls(t *testing.T, handler http.Handler) *healthreport.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(serial int64, identity string, eku x509.ExtKeyUsage) tls.Certificate {
		u, _ := url.Parse(identity)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{u}}
		der, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf(2, healthSAN, x509.ExtKeyUsageServerAuth)}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	client := leaf(3, sensorSAN, x509.ExtKeyUsageClientAuth)
	c, err := healthreport.NewClient(s.URL, pool, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &client, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

type fakeProcess struct {
	status Status
	ticks  int64
	cgroup string
}

type fakeProc struct {
	mu    sync.Mutex
	procs map[int64]fakeProcess
	inode map[string]int64
}

func (p *fakeProc) PIDs() ([]int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []int64
	for pid := range p.procs {
		out = append(out, pid)
	}
	return out, nil
}
func (p *fakeProc) get(pid int64) (fakeProcess, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f, ok := p.procs[pid]
	if !ok {
		return f, ErrUnavailable
	}
	return f, nil
}
func (p *fakeProc) Status(pid int64) (Status, error) { f, err := p.get(pid); return f.status, err }
func (p *fakeProc) StartTicks(pid int64) (int64, error) {
	f, err := p.get(pid)
	return f.ticks, err
}
func (p *fakeProc) Cgroup(pid int64) (string, error) { f, err := p.get(pid); return f.cgroup, err }
func (p *fakeProc) CgroupInode(id string) (int64, error) {
	if n, ok := p.inode[id]; ok {
		return n, nil
	}
	return 0, ErrUnavailable
}

type fakeContainers map[string]podmeta.Container

func (f fakeContainers) Container(id string) (podmeta.Container, bool) { c, ok := f[id]; return c, ok }

type fixture struct {
	t      *testing.T
	health *fakeHealth
	proc   *fakeProc
	pods   fakeContainers
	index  *Index
	ready  bool
	r      *Responder
}

func i64(n int64) *int64 { return &n }

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, health: &fakeHealth{t: t, stored: map[string]string{}, evidence: map[string]string{}}, ready: true, index: NewIndex(nil)}
	cg := "/../../kubepods.slice/kubepods-pod" + podUID + ".slice/cri-containerd-" + containerID + ".scope"
	caps := "0000000000000000"
	f.proc = &fakeProc{inode: map[string]int64{containerID: cgInode}, procs: map[int64]fakeProcess{
		1:       {status: Status{NSpid: []int64{1}, PPid: 0}, ticks: 1, cgroup: "/"},
		supHost: {status: Status{NSpid: []int64{supHost, 1}, PPid: 8000}, ticks: supTicks, cgroup: cg},
		wrkHost: {status: Status{NSpid: []int64{wrkHost, 7}, PPid: supHost, UID: []int64{10001, 10001, 10001, 10001}, NoNewPrivs: i64(1), Seccomp: i64(2), CapEff: &caps}, ticks: wrkTicks, cgroup: cg},
	}}
	f.pods = fakeContainers{containerID: {PodUID: podUID, Namespace: "agent-exec", Observed: true, Running: true, ImageID: "us-docker.pkg.dev/p/agentarium/runtime@" + testImage}}
	f.commitExec("sup-exec", "", supHost, "/app/bin/agent-runtime", supExecRef)
	f.commitExec("wrk-exec", "sup-exec", wrkHost, workerBin, wrkExecRef)
	f.index.Namespace("sup-exec", pidNS)
	f.index.Namespace("wrk-exec", pidNS)
	r, err := New(Config{NodeUID: nodeUID, BootID: bootID, RuleHash: ruleHash, SensorGeneration: 3, WorkerBinaries: []string{workerBin},
		Health: mtls(t, f.health), Proc: f.proc, Containers: f.pods, Index: f.index, Ready: func(time.Time) bool { return f.ready }, Log: func(s string) { t.Log(s) }})
	if err != nil {
		t.Fatal(err)
	}
	f.r = r
	return f
}

func (f *fixture) commitExec(id, parent string, pid int64, binary, ref string) {
	var p any
	if parent != "" {
		p = parent
	}
	raw, _ := json.Marshal(map[string]any{"event_type": "process_exec", "source_event_id": ref, "process_exec_id": id, "parent_exec_id": p, "host_pid": pid,
		"container_id": containerID, "pod_uid": podUID, "node_uid": nodeUID, "boot_id": bootID, "rule_hash": ruleHash, "sensor_generation": 3,
		"safe_attributes": map[string]any{"binary": canonical.SHA256Hex([]byte(binary))}})
	f.index.Committed(raw)
}

func binding() map[string]any {
	return map[string]any{"cluster_uid": clusterUID, "pod_uid": podUID, "node_uid": nodeUID, "boot_id": bootID, "container_id": containerID,
		"restart_instance": 0, "cgroup_inode": cgInode, "image_manifest_digest": nil}
}

func workerChallenge(mutate func(map[string]any)) map[string]any {
	ch := map[string]any{"worker_binding_id": uuid.NewString(), "challenge_id": uuid.NewString(), "instance_binding": binding(),
		"supervisor_process_hint":  map[string]any{"local_pid": 1, "pid_ns_inode": pidNS, "start_ticks": supTicks},
		"worker_process_hint":      map[string]any{"local_pid": 7, "pid_ns_inode": pidNS, "start_ticks": wrkTicks},
		"isolation_profile_digest": strings.Repeat("d", 64), "expected_sensor_generation": 3, "rule_hash": ruleHash,
		"deadline": time.Now().Add(15 * time.Second).UTC()}
	if mutate != nil {
		mutate(ch)
	}
	return ch
}

func readinessChallenge(worker map[string]any, mutate func(map[string]any)) map[string]any {
	b := binding()
	b["image_manifest_digest"] = testImage
	ch := map[string]any{"check_id": uuid.NewString(), "challenge_id": uuid.NewString(), "instance_binding": b, "expected_sensor_generation": 3,
		"rule_hash": ruleHash, "worker_binding_id": worker["worker_binding_id"], "root_exec_id": "wrk-exec", "deadline": time.Now().Add(15 * time.Second).UTC()}
	if mutate != nil {
		mutate(ch)
	}
	return ch
}

func (f *fixture) step() {
	f.t.Helper()
	if err := f.r.Step(context.Background()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) posts() []posted {
	f.health.mu.Lock()
	defer f.health.mu.Unlock()
	return append([]posted{}, f.health.posts...)
}

func keys(m map[string]any) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return strings.Join(sortStrings(out), ",")
}

func sortStrings(s []string) []string {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	return s
}

func TestWorkerThenPodObservationWire(t *testing.T) {
	f := newFixture(t)
	wc := workerChallenge(nil)
	f.health.worker = []map[string]any{wc}
	f.step()
	p := f.posts()
	if len(p) != 1 || p[0].path != "/internal/control-health/worker-observation-results" {
		t.Fatalf("posts %+v", p)
	}
	w := p[0].body
	if keys(w) != "challenge_id,evidence_refs,exec_event_ref,instance_binding,observed_controls,reported_at,root_exec_id,sensor_generation,supervisor_identity,worker_alive,worker_binding_id,worker_identity" {
		t.Fatalf("worker keys %s", keys(w))
	}
	ib := w["instance_binding"].(map[string]any)
	if w["challenge_id"] != wc["challenge_id"] || w["worker_binding_id"] != wc["worker_binding_id"] || w["root_exec_id"] != "wrk-exec" || w["exec_event_ref"] != wrkExecRef ||
		w["worker_alive"] != true || w["sensor_generation"] != float64(3) || ib["image_manifest_digest"] != testImage || ib["container_id"] != containerID || ib["cgroup_inode"] != float64(cgInode) {
		t.Fatalf("worker body %s", p[0].raw)
	}
	sup, wrk := w["supervisor_identity"].(map[string]any), w["worker_identity"].(map[string]any)
	if sup["host_pid"] != float64(supHost) || sup["local_pid"] != float64(1) || sup["start_ticks"] != float64(supTicks) || wrk["host_pid"] != float64(wrkHost) || wrk["local_pid"] != float64(7) || wrk["pid_ns_inode"] != float64(pidNS) {
		t.Fatalf("identities %s", p[0].raw)
	}
	controls := w["observed_controls"].(map[string]any)
	if controls["no_new_privs"] != float64(1) || controls["seccomp_mode"] != float64(2) || controls["dumpable"] != "unknown" || controls["seccomp_filter"] != "unknown" {
		t.Fatalf("controls %v", controls)
	}
	reported, err := time.Parse(time.RFC3339Nano, w["reported_at"].(string))
	if err != nil || time.Since(reported) > 3*time.Second {
		t.Fatalf("reported_at %v", w["reported_at"])
	}
	if refs := w["evidence_refs"].([]any); len(refs) != 2 || refs[0] != "kernel_event:"+wrkExecRef || refs[1] != "kernel_event:"+supExecRef {
		t.Fatalf("refs %v", refs)
	}
	// Answered nonces are not re-posted.
	f.step()
	if len(f.posts()) != 1 {
		t.Fatal("answered challenge posted again")
	}

	rc := readinessChallenge(wc, nil)
	f.health.readiness = []map[string]any{rc}
	f.step()
	p = f.posts()
	if len(p) != 2 || p[1].path != "/internal/control-health/pod-observation-results" {
		t.Fatalf("posts %+v", p)
	}
	b := p[1].body
	if keys(b) != "challenge_id,check_id,evidence_refs,filter_included,instance_binding,reported_at,root_exec_id,rule_hash,sensor_generation,wal_fsync_ready,worker_alive,worker_binding_id,worker_evidence_refs" {
		t.Fatalf("pod keys %s", keys(b))
	}
	evidence := f.health.evidence[wc["challenge_id"].(string)]
	if b["check_id"] != rc["check_id"] || b["challenge_id"] != rc["challenge_id"] || b["rule_hash"] != ruleHash || b["filter_included"] != true || b["wal_fsync_ready"] != true ||
		b["worker_alive"] != true || b["root_exec_id"] != "wrk-exec" || b["worker_binding_id"] != wc["worker_binding_id"] {
		t.Fatalf("pod body %s", p[1].raw)
	}
	if refs := b["worker_evidence_refs"].([]any); len(refs) != 1 || refs[0] != "worker_evidence:"+evidence {
		t.Fatalf("worker evidence refs %v want %s", refs, evidence)
	}
}

func TestIgnoresOtherNodeBootSensorAndLateChallenges(t *testing.T) {
	f := newFixture(t)
	other := func(k, v string) func(map[string]any) {
		return func(ch map[string]any) { ch["instance_binding"].(map[string]any)[k] = v }
	}
	f.health.worker = []map[string]any{
		workerChallenge(other("node_uid", "30000000-0000-4000-8000-0000000000ff")),
		workerChallenge(other("boot_id", "boot-2")),
		workerChallenge(func(ch map[string]any) { ch["expected_sensor_generation"] = 4 }),
		workerChallenge(func(ch map[string]any) { ch["rule_hash"] = strings.Repeat("b", 64) }),
		workerChallenge(func(ch map[string]any) { ch["deadline"] = time.Now().Add(200 * time.Millisecond).UTC() }),
		workerChallenge(func(ch map[string]any) { ch["deadline"] = time.Now().Add(-time.Second).UTC() }),
	}
	f.step()
	f.step()
	if p := f.posts(); len(p) != 0 {
		t.Fatalf("reported a foreign or late challenge: %s", p[0].raw)
	}
}

func TestNoPositiveWorkerReportWithoutObservedProcess(t *testing.T) {
	cases := map[string]func(*fixture){
		"sensor unhealthy":   func(f *fixture) { f.ready = false },
		"worker not running": func(f *fixture) { delete(f.proc.procs, wrkHost) },
		"start ticks differ": func(f *fixture) { p := f.proc.procs[wrkHost]; p.ticks++; f.proc.procs[wrkHost] = p },
		"other container cgroup": func(f *fixture) {
			p := f.proc.procs[wrkHost]
			p.cgroup = "/kubepods.slice/cri-containerd-" + strings.Repeat("f", 64) + ".scope"
			f.proc.procs[wrkHost] = p
		},
		"ambiguous local pid": func(f *fixture) {
			p := f.proc.procs[wrkHost]
			p.status.NSpid = []int64{9100, 7}
			f.proc.procs[9100] = p
		},
		"parent is not supervisor": func(f *fixture) { p := f.proc.procs[wrkHost]; p.status.PPid = 1; f.proc.procs[wrkHost] = p },
		"exec not committed":       func(f *fixture) { f.index = NewIndex(nil); f.r.c.Index = f.index },
		"exec exited": func(f *fixture) {
			raw, _ := json.Marshal(map[string]any{"event_type": "process_exit", "process_exec_id": "wrk-exec"})
			f.index.Committed(raw)
		},
		"pid reused": func(f *fixture) {
			f.commitExec("wrk-exec-2", "sup-exec", wrkHost, workerBin, uuid.NewString())
		},
		"unapproved binary": func(f *fixture) {
			f.r.binaries = map[string]bool{"/usr/bin/other": true}
		},
		"pid namespace unknown":  func(f *fixture) { f.index.Namespace("wrk-exec", pidNS+1) },
		"container not running":  func(f *fixture) { c := f.pods[containerID]; c.Running = false; f.pods[containerID] = c },
		"image digest unknown":   func(f *fixture) { c := f.pods[containerID]; c.ImageID = "runtime:latest"; f.pods[containerID] = c },
		"cgroup inode differs":   func(f *fixture) { f.proc.inode[containerID] = cgInode + 1 },
		"container metadata gap": func(f *fixture) { delete(f.pods, containerID) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			mutate(f)
			f.health.worker = []map[string]any{workerChallenge(nil)}
			f.step()
			f.step()
			if p := f.posts(); len(p) != 0 {
				t.Fatalf("positive report without observation: %s", p[0].raw)
			}
		})
	}
}

func TestPodReportsObservedWorkerExit(t *testing.T) {
	f := newFixture(t)
	wc := workerChallenge(nil)
	f.health.worker = []map[string]any{wc}
	f.step()
	// The worker exits and its PID is reused by an unrelated process.
	p := f.proc.procs[wrkHost]
	p.ticks = wrkTicks + 50
	f.proc.procs[wrkHost] = p
	f.health.readiness = []map[string]any{readinessChallenge(wc, nil)}
	f.step()
	posts := f.posts()
	if len(posts) != 2 || posts[1].body["worker_alive"] != false {
		t.Fatalf("pod result must report the observed exit: %+v", posts)
	}
	// A worker this sensor never witnessed is not vouched for at all.
	f.health.readiness = []map[string]any{readinessChallenge(workerChallenge(nil), nil)}
	f.step()
	if len(f.posts()) != 2 {
		t.Fatal("reported an unwitnessed worker")
	}
}

func TestLostAcknowledgementIsReplayedIdentically(t *testing.T) {
	f := newFixture(t)
	wc := workerChallenge(nil)
	f.health.worker = []map[string]any{wc}
	f.health.drop = 1
	f.step()
	p := f.posts()
	if len(p) != 2 || !bytes.Equal(p[0].raw, p[1].raw) {
		t.Fatalf("lost ack must be replayed with the identical body: %d posts", len(p))
	}
	// Both in-step attempts lost: the nonce leaves the pending list and the
	// next poll replays a sent body to learn the stored evidence.
	f2 := newFixture(t)
	wc2 := workerChallenge(nil)
	f2.health.worker = []map[string]any{wc2}
	f2.health.drop = 2
	f2.step()
	f2.step()
	p = f2.posts()
	if len(p) != 3 || !bytes.Equal(p[0].raw, p[2].raw) {
		t.Fatalf("recovery replay: %d posts", len(p))
	}
	f2.health.readiness = []map[string]any{readinessChallenge(wc2, nil)}
	f2.step()
	p = f2.posts()
	if len(p) != 4 || p[3].body["worker_evidence_refs"].([]any)[0] != "worker_evidence:"+f2.health.evidence[wc2["challenge_id"].(string)] {
		t.Fatalf("pod after recovered ack: %+v", p)
	}
}

func TestNotCommittedYetIsRetriedWithFreshBody(t *testing.T) {
	f := newFixture(t)
	f.health.worker = []map[string]any{workerChallenge(nil)}
	f.health.busy = 1
	f.step()
	time.Sleep(5 * time.Millisecond)
	f.step()
	p := f.posts()
	if len(p) != 2 || p[0].body["reported_at"] == p[1].body["reported_at"] {
		t.Fatalf("503 must be retried with a fresh observation: %d posts", len(p))
	}
	f.step()
	if len(f.posts()) != 2 {
		t.Fatal("stored nonce retried")
	}
}

func TestDecidedRejectionIsFinal(t *testing.T) {
	f := newFixture(t)
	f.health.worker = []map[string]any{workerChallenge(nil)}
	h := &rejecting{inner: f.health, status: 409, code: "WORKER_BINDING_MISMATCH"}
	f.r.c.Health = h
	f.step()
	f.step()
	if h.posts != 1 {
		t.Fatalf("409 must not be retried: %d", h.posts)
	}
}

type rejecting struct {
	inner  *fakeHealth
	status int
	code   string
	posts  int
}

func (r *rejecting) Challenges(ctx context.Context, node string) (healthreport.Challenges, error) {
	var out healthreport.Challenges
	for _, ch := range r.inner.worker {
		raw, _ := json.Marshal(ch)
		var c healthreport.WorkerChallenge
		if err := json.Unmarshal(raw, &c); err != nil {
			return out, err
		}
		out.Worker = append(out.Worker, c)
	}
	return out, nil
}
func (r *rejecting) ReportWorker(context.Context, healthreport.WorkerResult) (healthreport.EvidenceAck, error) {
	r.posts++
	return healthreport.EvidenceAck{}, &healthreport.StatusError{Status: r.status, Codes: []string{r.code}}
}
func (r *rejecting) ReportPod(context.Context, healthreport.PodResult) (healthreport.EvidenceAck, error) {
	r.posts++
	return healthreport.EvidenceAck{}, errors.New("unexpected")
}

// More than eight unavailable responses must not evict the latest potentially
// committed body. Recover its lost ack before answering a Pod challenge.
func TestLostAcknowledgementAfterManyUnavailableResponses(t *testing.T) {
	f := newFixture(t)
	wc := workerChallenge(nil)
	f.health.worker = []map[string]any{wc}
	f.health.busy = maxSent + 2
	for i := 0; i < maxSent+2; i++ {
		f.step()
	}
	f.health.drop = 2
	f.step()
	committed := f.posts()[maxSent+2].raw
	f.step()
	posts := f.posts()
	if !bytes.Equal(posts[len(posts)-1].raw, committed) {
		t.Fatal("latest committed body was not recovered")
	}
	f.health.readiness = []map[string]any{readinessChallenge(wc, nil)}
	f.step()
	posts = f.posts()
	if posts[len(posts)-1].body["worker_evidence_refs"] == nil {
		t.Fatal("recovered worker was not available for Pod observation")
	}
}
