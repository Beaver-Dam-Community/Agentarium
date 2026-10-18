//go:build integration

package m31

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	kms "google.golang.org/api/cloudkms/v1"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/packages/workloadcert"
)

// Simulated node-side components (README "Simulated locally"). Each one
// authenticates with a real workload certificate that the identity harness
// issued for its SAN and talks to the real control-health and audit-writer
// APIs. Inputs that no service API accepts are written directly to the DB
// and are marked "direct DB" here and in the README.

const (
	controlHealthSAN = sanPrefix + "agent-observe/sa/control-health"
	auditWriterSAN   = sanPrefix + "agent-observe/sa/audit-writer"
	tetragonSAN      = sanPrefix + "agent-sensors/sa/tetragon"
	sensorGeneration = 1
)

// ruleHash is the simulated Tetragon policy digest the node-sensors lease
// reports as active_version and every node answer carries.
var ruleHash = func() string {
	h := sha256.Sum256([]byte("m31-local tetragon tracing policy v1"))
	return hex.EncodeToString(h[:])
}()

// runtimePod is one runtime container the simulated node witnesses.
type runtimePod struct {
	name, podUID, containerID string
	cgroupInode               int64
}

type nodeSim struct {
	t                        *testing.T
	e                        env
	top                      topology
	db                       *pgxpool.Pool
	healthURL, writerURL     string
	tetragon, recorder, nr   *http.Client // to control-health
	kernel                   *http.Client // tetragon -> audit-writer
	imageDigest              string
	epoch                    string
	mu                       sync.Mutex
	seq                      int64
	pods                     map[string]runtimePod // pod UID -> pod
	handled                  map[string]bool       // answered challenge IDs
	workerRefs               map[string]string     // worker binding -> worker evidence ref
	execRefs                 map[string]string     // worker binding -> kernel event ref
	leaseErr, challengeErr   string
	leasesOK, workerAnswers  int
	readinessAnswers         int
	lastLeaseErrLogged       time.Time
	lastChallengeErrLoggedAt time.Time
}

// certClient bootstraps a workload certificate for a simulated component
// through the identity harness and returns its mTLS client for peerSAN.
func certClient(t *testing.T, e env, top topology, identityURL, name, peerSAN string) (*workloadcert.Manager, *http.Client) {
	t.Helper()
	m := &workloadcert.Manager{URL: identityURL, TokenFile: top.tokenFile(e, name), CAFile: e.path("cfg", "ca.pem"), SAN: top.pods[name].san()}
	ctx, cancel := context.WithTimeout(bg(), 20*time.Second)
	defer cancel()
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("%s certificate: %v", name, err)
	}
	go m.Run(bg(), func() { info("%s certificate renewal failed", name) })
	return m, m.Client(peerSAN, true)
}

func newNodeSim(t *testing.T, e env, top topology, db *pgxpool.Pool, identityURL, healthURL, writerURL, imageDigest string) *nodeSim {
	t.Helper()
	s := &nodeSim{t: t, e: e, top: top, db: db, healthURL: healthURL, writerURL: writerURL, imageDigest: imageDigest,
		pods: map[string]runtimePod{}, handled: map[string]bool{}, workerRefs: map[string]string{}, execRefs: map[string]string{}}
	var tm *workloadcert.Manager
	tm, s.tetragon = certClient(t, e, top, identityURL, "tetragon", controlHealthSAN)
	s.kernel = tm.Client(auditWriterSAN, true)
	_, s.recorder = certClient(t, e, top, identityURL, "lifecycle-recorder", controlHealthSAN)
	_, s.nr = certClient(t, e, top, identityURL, "node-readiness", controlHealthSAN)
	// COMMON runtime kernel epoch: node UID (32 hex) + sha256(boot_id) (64 hex) + exporter instance (32 hex).
	bh := sha256.Sum256([]byte(top.BootID))
	s.epoch = strings.ReplaceAll(top.NodeUID, "-", "") + hex.EncodeToString(bh[:]) + strings.ReplaceAll(uuid.NewString(), "-", "")
	return s
}

func lease(source, component, scope, scopeID string, activeVersion *string, generation *int64) map[string]any {
	now := time.Now().UTC()
	l := map[string]any{"source_id": source, "component": component, "scope": scope, "scope_id": scopeID,
		"lease_until": now.Add(12 * time.Second).Format(time.RFC3339Nano), "observed_state": "healthy",
		"reported_at": now.Format(time.RFC3339Nano)}
	if activeVersion != nil {
		l["active_version"] = *activeVersion
	}
	if generation != nil {
		l["sensor_generation"] = *generation
	}
	return l
}

// renewLeases posts the three simulated leases (API): node-sensors and
// lifecycle-recorder for the node, node-readiness global.
func (s *nodeSim) renewLeases() error {
	gen := int64(sensorGeneration)
	rh := ruleHash
	for _, l := range []struct {
		c    *http.Client
		body map[string]any
	}{
		{s.tetragon, lease("tetragon-node/"+s.top.NodeUID, "node-sensors", "node", s.top.NodeUID, &rh, &gen)},
		{s.recorder, lease("lifecycle-recorder-node/"+s.top.NodeUID, "lifecycle-recorder", "node", s.top.NodeUID, nil, nil)},
		{s.nr, lease("node-readiness/m31-local", "node-readiness", "global", "*", nil, nil)},
	} {
		status, raw, err := call(l.c, "POST", s.healthURL+"/internal/control-health/leases", "", l.body, nil)
		if err != nil || status != 200 {
			return fmt.Errorf("%s lease: %d %v %s", l.body["component"], status, err, raw)
		}
	}
	return nil
}

// markNodeReady is the one direct-DB node input: the boot that the first
// node-sensors lease created as "preparing" is set to "ready". No reachable
// API makes a boot ready locally or in GKE (README: probe-runner gap).
func (s *nodeSim) markNodeReady(t *testing.T) {
	t.Helper()
	waitFor(t, "node boot row from the first node-sensors lease", 30*time.Second, func() error {
		var state string
		err := s.db.QueryRow(bg(), `SELECT state FROM health.node_boot_generation WHERE node_uid=$1 AND boot_id=$2`, s.top.NodeUID, s.top.BootID).Scan(&state)
		if err != nil {
			return err
		}
		info("node boot %s/%s created by the node-sensors lease, state=%s", s.top.NodeUID, s.top.BootID, state)
		return nil
	})
	exec1(t, s.db, `UPDATE health.node_boot_generation SET state='ready', updated_at=now() WHERE node_uid=$1 AND boot_id=$2 AND state<>'retired'`, s.top.NodeUID, s.top.BootID)
	info("[direct DB] health.node_boot_generation state=ready")
}

// run renews the leases every 3s and answers node challenges every 250ms
// until ctx ends.
func (s *nodeSim) run(ctx context.Context) {
	leases := time.NewTicker(3 * time.Second)
	defer leases.Stop()
	poll := time.NewTicker(250 * time.Millisecond)
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-leases.C:
			err := s.renewLeases()
			s.mu.Lock()
			if err != nil {
				s.leaseErr = err.Error()
				if time.Since(s.lastLeaseErrLogged) > 10*time.Second {
					info("simulated lease renewal failed: %v", err)
					s.lastLeaseErrLogged = time.Now()
				}
			} else {
				s.leasesOK++
			}
			s.mu.Unlock()
		case <-poll.C:
			if err := s.answerChallenges(); err != nil {
				s.mu.Lock()
				s.challengeErr = err.Error()
				if time.Since(s.lastChallengeErrLoggedAt) > 5*time.Second {
					info("node challenge answer: %v", err)
					s.lastChallengeErrLoggedAt = time.Now()
				}
				s.mu.Unlock()
			}
		}
	}
}

type workerChallenge struct {
	WorkerBindingID       string          `json:"worker_binding_id"`
	ChallengeID           string          `json:"challenge_id"`
	InstanceBinding       json.RawMessage `json:"instance_binding"`
	SupervisorProcessHint json.RawMessage `json:"supervisor_process_hint"`
	WorkerProcessHint     json.RawMessage `json:"worker_process_hint"`
}

type readinessChallenge struct {
	CheckID         string          `json:"check_id"`
	ChallengeID     string          `json:"challenge_id"`
	InstanceBinding json.RawMessage `json:"instance_binding"`
	WorkerBindingID string          `json:"worker_binding_id"`
	RootExecID      string          `json:"root_exec_id"`
}

type instanceBinding struct {
	ClusterUID          string  `json:"cluster_uid"`
	PodUID              string  `json:"pod_uid"`
	NodeUID             string  `json:"node_uid"`
	BootID              string  `json:"boot_id"`
	ContainerID         string  `json:"container_id"`
	RestartInstance     int64   `json:"restart_instance"`
	CgroupInode         int64   `json:"cgroup_inode"`
	ImageManifestDigest *string `json:"image_manifest_digest"`
}

// answerChallenges reads the node's pending nonces (node-scope GET with the
// tetragon certificate) and answers each once.
func (s *nodeSim) answerChallenges() error {
	var snap struct {
		Workers   []workerChallenge    `json:"pending_worker_observation_challenges"`
		Readiness []readinessChallenge `json:"pending_work_readiness_challenges"`
	}
	status, raw, err := call(s.tetragon, "GET", s.healthURL+"/internal/control-health?scope=node&scope_id="+s.top.NodeUID, "", nil, &snap)
	if err != nil || status != 200 {
		return fmt.Errorf("node snapshot: %d %v %s", status, err, raw)
	}
	for _, c := range snap.Workers {
		if s.done(c.ChallengeID) {
			continue
		}
		if err := s.answerWorker(c); err != nil {
			return err
		}
	}
	for _, c := range snap.Readiness {
		if s.done(c.ChallengeID) {
			continue
		}
		if err := s.answerReadiness(c); err != nil {
			return err
		}
	}
	return nil
}

func (s *nodeSim) done(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handled[id]
}

func (s *nodeSim) markDone(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handled[id] = true
}

// hostProcs returns the host PIDs of the container's supervisor (PID 1) and
// its worker child, read from the container runtime: the node witness.
func hostProcs(containerID string) (supervisor, worker int64, err error) {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Pid}}", containerID).Output()
	if err != nil {
		return 0, 0, fmt.Errorf("docker inspect: %w", err)
	}
	supervisor, err = strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil || supervisor <= 0 {
		return 0, 0, fmt.Errorf("container is not running")
	}
	out, err = exec.Command("docker", "top", containerID, "-eo", "pid,ppid").Output()
	if err != nil {
		return 0, 0, fmt.Errorf("docker top: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		pid, _ := strconv.ParseInt(f[0], 10, 64)
		ppid, _ := strconv.ParseInt(f[1], 10, 64)
		if ppid == supervisor && pid > 0 {
			worker = pid
		}
	}
	if worker == 0 {
		return supervisor, 0, fmt.Errorf("no worker process in %s", containerID[:12])
	}
	return supervisor, worker, nil
}

// answerWorker is the node-sensors witness of one session worker: the
// worker's process_exec kernel event goes through the real audit-writer
// kernel ingest (API), then the worker observation result goes to
// control-health (API).
func (s *nodeSim) answerWorker(c workerChallenge) error {
	var ib instanceBinding
	if err := json.Unmarshal(c.InstanceBinding, &ib); err != nil {
		return err
	}
	s.mu.Lock()
	pod, ok := s.pods[ib.PodUID]
	s.mu.Unlock()
	if !ok || pod.containerID != ib.ContainerID {
		return fmt.Errorf("worker challenge for unknown pod %s", ib.PodUID)
	}
	supPID, workerPID, err := hostProcs(pod.containerID)
	if err != nil {
		return err
	}
	rootExec := "m31exec:" + uuid.NewString()
	parentExec := "m31exec:supervisor:" + pod.podUID
	eventID, err := s.ingestExec(pod, workerPID, rootExec, parentExec)
	if err != nil {
		return err
	}
	var supHint, workerHint map[string]any
	if json.Unmarshal(c.SupervisorProcessHint, &supHint) != nil || json.Unmarshal(c.WorkerProcessHint, &workerHint) != nil {
		return fmt.Errorf("challenge hints unreadable")
	}
	supHint["host_pid"], workerHint["host_pid"] = supPID, workerPID
	ib.ImageManifestDigest = &s.imageDigest
	body := map[string]any{"worker_binding_id": c.WorkerBindingID, "challenge_id": c.ChallengeID, "instance_binding": ib,
		"supervisor_identity": supHint, "worker_identity": workerHint, "root_exec_id": rootExec, "exec_event_ref": eventID,
		"worker_alive": true, "observed_controls": map[string]any{"no_new_privs": true, "seccomp": "filter"},
		"sensor_generation": sensorGeneration, "evidence_refs": []string{"kernel_event:" + eventID}}
	var ack struct {
		EvidenceID string `json:"evidence_id"`
	}
	// The exec ACK is committed before the result; a 503 retries within the nonce.
	for i := 0; i < 8; i++ {
		body["reported_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		status, raw, err := call(s.tetragon, "POST", s.healthURL+"/internal/control-health/worker-observation-results", "", body, &ack)
		if err == nil && status/100 == 2 {
			s.mu.Lock()
			s.handled[c.ChallengeID] = true
			s.workerRefs[c.WorkerBindingID] = "worker_evidence:" + ack.EvidenceID
			s.execRefs[c.WorkerBindingID] = "kernel_event:" + eventID
			s.workerAnswers++
			s.mu.Unlock()
			info("[API] worker observation for binding %s: worker host_pid=%d exec %s -> %d", c.WorkerBindingID, workerPID, eventID, status)
			return nil
		}
		if status != 503 {
			s.markDone(c.ChallengeID)
			return fmt.Errorf("worker observation: %d %v %s", status, err, raw)
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("worker observation kept answering 503")
}

// answerReadiness is the node answer to a work-readiness nonce (API).
func (s *nodeSim) answerReadiness(c readinessChallenge) error {
	var ib instanceBinding
	if err := json.Unmarshal(c.InstanceBinding, &ib); err != nil {
		return err
	}
	s.mu.Lock()
	pod, ok := s.pods[ib.PodUID]
	workerRef, execRef := s.workerRefs[c.WorkerBindingID], s.execRefs[c.WorkerBindingID]
	s.mu.Unlock()
	if !ok || workerRef == "" {
		return fmt.Errorf("readiness challenge for unwitnessed binding %s", c.WorkerBindingID)
	}
	_, workerPID, err := hostProcs(pod.containerID)
	alive := err == nil && workerPID > 0
	body := map[string]any{"check_id": c.CheckID, "challenge_id": c.ChallengeID, "instance_binding": ib,
		"sensor_generation": sensorGeneration, "rule_hash": ruleHash, "filter_included": true, "wal_fsync_ready": true,
		"worker_binding_id": c.WorkerBindingID, "root_exec_id": c.RootExecID, "worker_alive": alive,
		"worker_evidence_refs": []string{workerRef}, "reported_at": time.Now().UTC().Format(time.RFC3339Nano),
		"evidence_refs": []string{execRef}}
	status, raw, err := call(s.tetragon, "POST", s.healthURL+"/internal/control-health/pod-observation-results", "", body, nil)
	s.markDone(c.ChallengeID)
	if err != nil || status/100 != 2 {
		return fmt.Errorf("pod observation: %d %v %s", status, err, raw)
	}
	s.mu.Lock()
	s.readinessAnswers++
	s.mu.Unlock()
	info("[API] pod observation for check %s (worker alive=%v) -> %d", c.CheckID, alive, status)
	return nil
}

// ingestExec sends one process_exec KernelEvent batch through the real
// audit-writer kernel route and returns its source_event_id.
func (s *nodeSim) ingestExec(pod runtimePod, hostPID int64, execID, parentExec string) (string, error) {
	s.mu.Lock()
	s.seq++
	seq := s.seq
	s.mu.Unlock()
	id, err := canonical.KernelEventID(tetragonSAN, s.epoch, seq)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	r := map[string]any{"source_event_id": id, "sensor_id": tetragonSAN, "source_epoch": s.epoch, "source_sequence": seq,
		"exporter_instance_id": "m31-tetragon-exporter", "sensor_generation": sensorGeneration, "node_uid": s.top.NodeUID,
		"boot_id": s.top.BootID, "source_time": now.Add(-200 * time.Millisecond).Format(time.RFC3339Nano), "spooled_at": now.Format(time.RFC3339Nano),
		"process_exec_id": execID, "parent_exec_id": parentExec, "process_start": now.Add(-time.Second).Format(time.RFC3339Nano),
		"host_pid": hostPID, "container_id": pod.containerID, "pod_uid": pod.podUID, "metadata_status": "resolved",
		"normalization_version": "n1", "event_type": "process_exec", "safe_attributes": map[string]any{"binary": "/app/bin/agent-worker"},
		"rule_hash": ruleHash, "coverage": "complete"}
	d, err := canonical.CanonicalDigest(r)
	if err != nil {
		return "", err
	}
	r["record_digest"] = d
	b := map[string]any{"batch_id": uuid.NewString(), "source_epoch": s.epoch, "records": []any{r}, "sequence_range_abandoned": []any{}}
	if b["batch_digest"], err = canonical.CanonicalDigest(b); err != nil {
		return "", err
	}
	var ack struct {
		Accepted []string `json:"accepted_ids"`
	}
	status, raw, err := call(s.kernel, "POST", s.writerURL+"/internal/kernel/events:batch", "", b, &ack)
	if err != nil || status != 200 || len(ack.Accepted) != 1 || ack.Accepted[0] != id {
		return "", fmt.Errorf("kernel ingest: %d %v %s", status, err, raw)
	}
	info("[API] kernel process_exec %s (container %s, host_pid %d) accepted by audit-writer", id, pod.containerID[:12], hostPID)
	return id, nil
}

// addLifecycle records the runtime container's open lifecycle interval
// (direct DB: correlation.lifecycle_intervals has no writer service).
func (s *nodeSim) addLifecycle(t *testing.T, name, containerID string) {
	t.Helper()
	p := s.top.pods[name]
	inode := int64(4026530000 + len(s.pods) + 1)
	exec1(t, s.db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,
 restart_instance,cgroup_inode,netns_inode,started_at,ended_at,end_quality,mapping_version,source_event_ids)
VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8,now(),NULL,'open',1,'{}')`, uuid.NewString(), s.top.ClusterUID, p.PodUID, s.top.NodeUID, s.top.BootID, containerID, inode, inode+1000)
	s.mu.Lock()
	s.pods[p.PodUID] = runtimePod{name: name, podUID: p.PodUID, containerID: containerID, cgroupInode: inode}
	s.mu.Unlock()
	info("[direct DB] correlation.lifecycle_intervals open interval for %s (container %s)", name, containerID[:12])
}

// closeLifecycle ends the container interval after the container exits.
func (s *nodeSim) closeLifecycle(t *testing.T, name, containerID string) {
	t.Helper()
	p := s.top.pods[name]
	exec1(t, s.db, `INSERT INTO correlation.lifecycle_intervals(interval_id,cluster_uid,pod_uid,node_uid,boot_id,container_id,
 restart_instance,cgroup_inode,netns_inode,started_at,ended_at,end_quality,mapping_version,source_event_ids)
SELECT $1,cluster_uid,pod_uid,node_uid,boot_id,container_id,restart_instance,cgroup_inode,netns_inode,started_at,now(),'observed',mapping_version+1,'{}'
FROM correlation.lifecycle_intervals WHERE container_id=$2 AND pod_uid=$3 ORDER BY mapping_version DESC LIMIT 1`, uuid.NewString(), containerID, p.PodUID)
}

// fakeKMS is the Cloud KMS asymmetricSign stand-in for the audit exporter's
// manifest signer (--kms-endpoint): one local P-256 key version.
type fakeKMS struct {
	keyVersion string
	key        *ecdsa.PrivateKey
	url        string
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func startFakeKMS(t *testing.T, e env) *fakeKMS {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeKMS{key: key, keyVersion: "projects/m31-local/locations/global/keyRings/audit/cryptoKeys/manifest/cryptoKeyVersions/1"}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.url = "http://" + l.Addr().String() + "/"
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req kms.AsymmetricSignRequest
			if r.Method != http.MethodPost || r.URL.Path != "/v1/"+f.keyVersion+":asymmetricSign" || json.NewDecoder(r.Body).Decode(&req) != nil || req.Digest == nil {
				http.Error(w, `{"error":{"code":400,"message":"invalid"}}`, http.StatusBadRequest)
				return
			}
			digest, err := base64.StdEncoding.DecodeString(req.Digest.Sha256)
			if err != nil || len(digest) != sha256.Size || req.DigestCrc32c != int64(crc32.Checksum(digest, castagnoli)) {
				http.Error(w, `{"error":{"code":400,"message":"invalid digest"}}`, http.StatusBadRequest)
				return
			}
			sig, err := ecdsa.SignASN1(rand.Reader, f.key, digest)
			if err != nil {
				http.Error(w, `{"error":{"code":500}}`, http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(kms.AsymmetricSignResponse{Name: f.keyVersion, Signature: base64.StdEncoding.EncodeToString(sig),
				SignatureCrc32c: int64(crc32.Checksum(sig, castagnoli)), VerifiedDigestCrc32c: true, ForceSendFields: []string{"VerifiedDigestCrc32c"}})
		}))
	}()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	writeJSON(t, e.path("cfg", "export-keys.json"), map[string]string{f.keyVersion: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))})
	return f
}
