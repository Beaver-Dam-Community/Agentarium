package recorder

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/services/lifecycle-recorder/internal/ctrdtest"
	eventtypes "github.com/containerd/containerd/api/events"
	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	clusterUID = "00000000-0000-4000-8000-000000000001"
	nodeUID    = "30000000-0000-4000-8000-000000000001"
	bootID     = "6f1d3d1c-1f5e-4a1b-9c7c-0c4f7d9e2a11"
	podA       = "11111111-1111-4111-8111-111111111111"
	podB       = "22222222-2222-4222-8222-222222222222"
)

var c1 = strings.Repeat("a", 64)
var s1 = strings.Repeat("b", 64)
var c2 = strings.Repeat("c", 64)

// collector enforces the TASK-07 3.3 runtime lifecycle batch contract.
type collector struct {
	mu         sync.Mutex
	records    []map[string]any
	ids        map[string]string
	acked      map[string]uint64
	violations []string
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.TLS == nil || r.TLS.PeerCertificates[0].URIs[0].String() != SourceSAN || r.URL.Path != "/internal/lifecycle/events:batch" {
		c.violations = append(c.violations, "caller/path")
		w.WriteHeader(403)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var env struct {
		BatchID   string            `json:"batch_id"`
		Epoch     string            `json:"source_epoch"`
		Records   []json.RawMessage `json:"records"`
		Abandoned []json.RawMessage `json:"sequence_range_abandoned"`
		Digest    string            `json:"batch_digest"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields() // a runtime batch has no scope or cursor
	if d.Decode(&env) != nil || uuid.Validate(env.BatchID) != nil || len(env.Epoch) != 128 {
		c.violations = append(c.violations, "envelope "+string(raw))
		w.WriteHeader(422)
		return
	}
	var body map[string]json.RawMessage
	json.Unmarshal(raw, &body)
	delete(body, "batch_digest")
	unsigned, _ := json.Marshal(body)
	jcs, _ := canonical.JCS(unsigned)
	if canonical.SHA256Hex(jcs) != env.Digest {
		c.violations = append(c.violations, "batch_digest")
	}
	accepted, dups := []string{}, []string{}
	last := c.acked[env.Epoch]
	for _, rec := range env.Records {
		var m map[string]any
		dd := json.NewDecoder(bytes.NewReader(rec))
		dd.UseNumber()
		dd.Decode(&m)
		seq, _ := m["source_sequence"].(json.Number).Int64()
		id, _ := canonical.LifecycleEventID(SourceSAN, env.Epoch, seq)
		digest, _ := canonical.DigestWithoutKeys(rec, "record_digest", "received_at")
		if m["lifecycle_event_id"] != id || m["record_digest"] != digest || m["source_id"] != SourceSAN || m["cluster_uid"] != clusterUID || m["node_uid"] != nodeUID || m["boot_id"] != bootID || m["mapping_version"] != json.Number("1") || m["missing_reason"] != MissingReason {
			c.violations = append(c.violations, fmt.Sprintf("record %v", m))
		}
		if prev, ok := c.ids[id]; ok {
			if prev != digest {
				c.violations = append(c.violations, "EVENT_ID_CONFLICT")
			}
			dups = append(dups, id)
		} else {
			c.ids[id] = digest
			c.records = append(c.records, m)
			accepted = append(accepted, id)
		}
		last = max(last, uint64(seq))
	}
	c.acked[env.Epoch] = last
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"batch_id": env.BatchID, "accepted_ids": accepted, "duplicate_ids": dups, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": env.Epoch, "acked_through": last}}})
}

type gapRecv struct {
	mu     sync.Mutex
	bodies []GapRequest
	bad    []string
}

// runtimeEpoch is node UUID hex + SHA-256(boot_id) hex + instance hex.
func runtimeEpoch(node, boot string, instance byte) string {
	return strings.ReplaceAll(node, "-", "") + canonical.SHA256Hex([]byte(boot)) + strings.Repeat(string(instance), 32)
}

// gapKeys is the exact recorder gap body (TASK-10 3.6 runtime recorder).
const gapKeys = "boot_id,count_quality,end_at,evidence_refs,gap_id,loss_count,node_uid,reason,recovery_state,source_epoch,stage,start_at"

func (g *gapRecv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	raw, _ := io.ReadAll(r.Body)
	var shape struct {
		Scope string                     `json:"scope"`
		Gap   map[string]json.RawMessage `json:"gap"`
	}
	var keys []string
	if json.Unmarshal(raw, &shape) == nil {
		for k := range shape.Gap {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var req GapRequest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if r.TLS == nil || r.TLS.PeerCertificates[0].URIs[0].String() != SourceSAN || d.Decode(&req) != nil || strings.Join(keys, ",") != gapKeys ||
		req.Scope != "node/"+nodeUID || req.Gap.Stage != "lifecycle_capture" || req.Gap.Reason != "RUNTIME_RECORD_MISSING" || req.Gap.NodeUID != nodeUID || req.Gap.BootID != bootID ||
		req.Gap.LossCount != nil || req.Gap.CountQuality != "unknown" || req.Gap.RecoveryState != "unrecoverable" ||
		!strings.HasPrefix(req.Gap.SourceEpoch, runtimeEpoch(req.Gap.NodeUID, req.Gap.BootID, '0')[:96]) || req.Gap.StartAt > req.Gap.EndAt {
		g.bad = append(g.bad, fmt.Sprintf("%+v", req))
		w.WriteHeader(422)
		return
	}
	g.bodies = append(g.bodies, req)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	fmt.Fprintf(w, `{"gap_id":%q,"recorded_at":%q,"result":"created"}`, req.Gap.GapID, time.Now().UTC().Format(time.RFC3339Nano))
}

func tlsPair(t *testing.T) (func(san string, h http.Handler) *httptest.Server, *tls.Config) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(san string, usage x509.ExtKeyUsage) tls.Certificate {
		u, _ := url.Parse(san)
		d, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), URIs: []*url.URL{u}, ExtKeyUsage: []x509.ExtKeyUsage{usage}}, ca, &key.PublicKey, key)
		return tls.Certificate{Certificate: [][]byte{d}, PrivateKey: key}
	}
	server := func(san string, h http.Handler) *httptest.Server {
		s := httptest.NewUnstartedServer(h)
		s.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf(san, x509.ExtKeyUsageServerAuth)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	return server, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{leaf(SourceSAN, x509.ExtKeyUsageClientAuth)}}
}

type rig struct {
	t       *testing.T
	fake    *ctrdtest.Fake
	coll    *collector
	gaps    *gapRecv
	dir     string
	cgroups string
	source  GRPCSource
	client  *batch.Client
	sink    *HTTPGapSink
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, dir: t.TempDir(), cgroups: t.TempDir()}
	r.fake = ctrdtest.New()
	r.fake.Containers[c1] = ctrdtest.PodContainer(c1, podA, "main", "kubepods-burstable-pod"+podA[:8]+".slice:cri-containerd:"+c1, false)
	r.fake.Containers[s1] = ctrdtest.PodContainer(s1, podA, "", "kubepods-burstable-pod"+podA[:8]+".slice:cri-containerd:"+s1, true)
	r.fake.Containers["nonpod"] = &containersapi.Container{ID: "nonpod", Spec: ctrdtest.OCISpec("/system.slice/x", nil)}
	r.fake.Order = []string{c1, s1, c2, "nonpod"}
	r.fake.Sandbox[s1] = true
	// The c1 cgroup directory exists under the read-only cgroup root.
	dir, err := CgroupDir(r.cgroups, "kubepods-burstable-pod"+podA[:8]+".slice:cri-containerd:"+c1)
	if err != nil || os.MkdirAll(dir, 0o755) != nil {
		t.Fatal(err)
	}
	sockDir, _ := os.MkdirTemp("", "ctrd")
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := r.fake.Serve(t, sockDir)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	r.source = GRPCSource{Conn: conn}
	server, tlsCfg := tlsPair(t)
	r.coll = &collector{ids: map[string]string{}, acked: map[string]uint64{}}
	collSrv := server("spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer", r.coll)
	r.gaps = &gapRecv{}
	gapSrv := server("spiffe://agentarium.internal/ns/agent-observe/sa/control-health", r.gaps)
	r.client, err = batch.NewClient(collSrv.URL, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	health, err := NewControlHealthClient(tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	r.sink = &HTTPGapSink{Directory: r.dir, Origin: gapSrv.URL, Client: health}
	return r
}

func (r *rig) start(instance byte) (context.CancelFunc, chan error, *Recorder) {
	epoch := runtimeEpoch(nodeUID, bootID, instance)
	rec, err := Open(Config{Directory: r.dir, ClusterUID: clusterUID, NodeUID: nodeUID, BootID: bootID, Epoch: epoch, Source: r.source, Collector: r.client, GapSink: r.sink.Report, CgroupRoot: r.cgroups})
	if err != nil {
		r.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx) }()
	return cancel, done, rec
}

func (r *rig) waitRecords(n int) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		r.coll.mu.Lock()
		got := len(r.coll.records)
		r.coll.mu.Unlock()
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			r.t.Fatalf("records %d < %d", got, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestRecorderMapsEventsReconcilesAndReportsGaps(t *testing.T) {
	r := newRig(t)
	cancel, done, rec := r.start('1')
	stream := <-r.fake.Streams
	// Reconcile: c1 and the sandbox s1 are present; the non-Pod container is not recorded.
	r.waitRecords(2)
	r.fake.Mu.Lock()
	r.fake.Containers[c2] = ctrdtest.PodContainer(c2, podB, "worker", "kubepods-pod"+podB[:8]+".slice:cri-containerd:"+c2, false)
	r.fake.Mu.Unlock()
	t0 := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskCreate{ContainerID: c2, Pid: 100}, "/tasks/create", t0)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskStart{ContainerID: c2, Pid: 100}, "/tasks/start", t0.Add(time.Second))
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskExit{ContainerID: c2, ID: "exec-1", Pid: 200}, "/tasks/exit", t0.Add(2*time.Second))
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskExit{ContainerID: c2, ID: c2, Pid: 100, ExitStatus: 0}, "/tasks/exit", t0.Add(3*time.Second))
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskDelete{ContainerID: c2, Pid: 100}, "/tasks/delete", t0.Add(4*time.Second))
	r.waitRecords(6)
	// Break the subscription: resubscribe, reconcile again, report the gap.
	close(stream)
	<-r.fake.Streams
	r.waitRecords(9)
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("run: %v", err)
	}
	if st := rec.Status(); st.Failed {
		t.Fatal("recorder failed")
	}
	rec.Close()
	// A restart with a new epoch bounds the gap by the saved last event.
	cancel2, done2, rec2 := r.start('2')
	<-r.fake.Streams
	r.waitRecords(12)
	cancel2()
	<-done2
	rec2.Close()

	r.coll.mu.Lock()
	defer r.coll.mu.Unlock()
	r.gaps.mu.Lock()
	defer r.gaps.mu.Unlock()
	if len(r.coll.violations) != 0 || len(r.gaps.bad) != 0 || len(r.fake.Violations) != 0 {
		t.Fatalf("contract: %v %v %v", r.coll.violations, r.gaps.bad, r.fake.Violations)
	}
	var seq []string
	for _, m := range r.coll.records {
		seq = append(seq, fmt.Sprintf("%s:%s", m["transition"], m["container_id"].(string)[:1]))
	}
	want := "container_present:a,container_present:b,container_created:c,container_started:c,container_exited:c,container_deleted:c,container_present:a,container_present:b,container_present:c,container_present:a,container_present:b,container_present:c"
	if strings.Join(seq, ",") != want {
		t.Fatalf("records %v", seq)
	}
	created := r.coll.records[2]
	if created["source_time"] != t0.Format(time.RFC3339Nano) || created["cgroups_path"] == nil || created["image_id"] == nil || created["restart_instance"] != json.Number("0") || created["container_name"] != "worker" {
		t.Fatalf("create record: %v", created)
	}
	present := r.coll.records[0]
	if _, ok := present["source_time"]; ok {
		t.Fatal("container_present must not claim a time")
	}
	var dirIno uint64
	if dir, _ := CgroupDir(r.cgroups, "kubepods-burstable-pod"+podA[:8]+".slice:cri-containerd:"+c1); dir != "" {
		fi, _ := os.Stat(dir)
		dirIno = fi.Sys().(*syscall.Stat_t).Ino
	}
	if present["cgroup_inode"] != json.Number(fmt.Sprint(dirIno)) || present["image_id"] == nil {
		t.Fatalf("c1 inode/image: %v", present)
	}
	sandbox := r.coll.records[1]
	if _, ok := sandbox["image_id"]; ok || sandbox["container_name"] != nil {
		t.Fatalf("sandbox must not get CRI image_id or name: %v", sandbox)
	}
	// Three gaps: first start, broken stream, restart; the later two start at
	// the last processed event.
	if len(r.gaps.bodies) != 3 {
		t.Fatalf("gaps %d", len(r.gaps.bodies))
	}
	if r.gaps.bodies[2].Gap.StartAt < r.gaps.bodies[1].Gap.StartAt || r.gaps.bodies[2].Gap.SourceEpoch == r.gaps.bodies[1].Gap.SourceEpoch {
		t.Fatalf("restart gap %+v", r.gaps.bodies[2].Gap)
	}
}

func TestCgroupDirExpandsSystemdSlices(t *testing.T) {
	got, err := CgroupDir("/sys/fs/cgroup", "kubepods-burstable-pod1234.slice:cri-containerd:abc")
	if err != nil || got != "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-abc.scope" {
		t.Fatalf("%q %v", got, err)
	}
	if got, _ := CgroupDir("/sys/fs/cgroup", "/kubepods/pod1/abc"); got != "/sys/fs/cgroup/kubepods/pod1/abc" {
		t.Fatalf("cgroupfs path %q", got)
	}
	for _, bad := range []string{"x:y", "a.slice:b", "../x.slice:a:b", "a--b.slice:p:i"} {
		if _, err := CgroupDir("/r", bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestPermanentGapRefusalStopsRecorder(t *testing.T) {
	r := newRig(t)
	r.gaps.mu.Lock()
	r.gaps.bad = nil
	r.gaps.mu.Unlock()
	// A sink pointing at a 422 answer: scope mismatch through a wrong node.
	_, done, rec := func() (context.CancelFunc, chan error, *Recorder) {
		epoch := strings.Repeat("3", 32) + strings.Repeat("b", 64) + strings.Repeat("9", 32)
		rec, err := Open(Config{Directory: r.dir, ClusterUID: clusterUID, NodeUID: "40000000-0000-4000-8000-000000000004", BootID: bootID, Epoch: epoch, Source: r.source, Collector: r.client, GapSink: r.sink.Report, CgroupRoot: r.cgroups})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		t.Cleanup(cancel)
		d := make(chan error, 1)
		go func() { d <- rec.Run(ctx) }()
		return cancel, d, rec
	}()
	err := <-done
	var p *PermanentGapError
	if !errors.As(err, &p) || !rec.Status().Failed {
		t.Fatalf("want permanent gap error, got %v", err)
	}
	rec.Close()
	if _, err := os.Stat(filepath.Join(r.dir, pendingGapFile)); err != nil {
		t.Fatal("refused gap must stay on disk")
	}
}

// A create event whose container record is already gone cannot be attributed
// to a Pod: it becomes a one-instant RUNTIME_RECORD_MISSING gap and the
// recorder keeps going (TASK-09 3.6).
func TestVanishedContainerBecomesInstantGap(t *testing.T) {
	r := newRig(t)
	cancel, done, rec := r.start('1')
	stream := <-r.fake.Streams
	r.waitRecords(2)
	t0 := time.Date(2026, 10, 18, 2, 0, 0, 0, time.UTC)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskCreate{ContainerID: "ghost"}, "/tasks/create", t0)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskStart{ContainerID: c1}, "/tasks/start", t0.Add(time.Second))
	r.waitRecords(3)
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("run: %v", err)
	}
	if rec.Status().Failed {
		t.Fatal("recorder stopped on a vanished container")
	}
	rec.Close()
	r.gaps.mu.Lock()
	defer r.gaps.mu.Unlock()
	if len(r.gaps.bad) != 0 || len(r.gaps.bodies) != 2 {
		t.Fatalf("gaps %+v bad %v", r.gaps.bodies, r.gaps.bad)
	}
	g := r.gaps.bodies[1].Gap
	if g.StartAt != t0.Format(time.RFC3339Nano) || g.EndAt != g.StartAt {
		t.Fatalf("instant gap %+v", g)
	}
}

// A gap fsynced before a reboot is not sent with the new boot's certificate;
// the new boot's gap replaces it and starts no later than it.
func TestPendingGapFromPreviousBootIsFolded(t *testing.T) {
	r := newRig(t)
	oldStart := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	write := func(node, boot string) {
		old := GapRequest{Scope: "node/" + node, Gap: gapBody{GapID: uuid.NewString(), Stage: "lifecycle_capture", Reason: "RUNTIME_RECORD_MISSING", SourceEpoch: runtimeEpoch(node, boot, '7'), NodeUID: node, BootID: boot,
			StartAt: oldStart.Format(time.RFC3339Nano), EndAt: oldStart.Add(time.Minute).Format(time.RFC3339Nano), CountQuality: "unknown", RecoveryState: "unrecoverable", EvidenceRefs: []json.RawMessage{}}}
		b, _ := canonical.CanonicalJSON(old)
		if err := os.WriteFile(filepath.Join(r.dir, pendingGapFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC)
	gap := Gap{Epoch: runtimeEpoch(nodeUID, bootID, '8'), NodeUID: nodeUID, BootID: bootID, Start: now.Add(-time.Minute), End: now}

	write(nodeUID, "previous-boot")
	if err := r.sink.Report(context.Background(), gap); err != nil {
		t.Fatal(err)
	}
	// Another node's leftover is dropped without extending the interval.
	write("40000000-0000-4000-8000-000000000004", "previous-boot")
	if err := r.sink.Report(context.Background(), gap); err != nil {
		t.Fatal(err)
	}
	r.gaps.mu.Lock()
	defer r.gaps.mu.Unlock()
	if len(r.gaps.bad) != 0 || len(r.gaps.bodies) != 2 {
		t.Fatalf("gaps %+v bad %v", r.gaps.bodies, r.gaps.bad)
	}
	if got := r.gaps.bodies[0].Gap; got.StartAt != oldStart.Format(time.RFC3339Nano) || got.BootID != bootID || got.SourceEpoch != gap.Epoch {
		t.Fatalf("folded gap %+v", got)
	}
	if got := r.gaps.bodies[1].Gap; got.StartAt != gap.Start.Format(time.RFC3339Nano) {
		t.Fatalf("other-node gap %+v", got)
	}
	if _, err := os.Stat(filepath.Join(r.dir, pendingGapFile)); !os.IsNotExist(err) {
		t.Fatal("pending gap must be removed after the ack")
	}
}

type trackedSource struct {
	Source
	contexts    chan context.Context
	lookupError error
}

func (s *trackedSource) Subscribe(ctx context.Context) (func() (*types.Envelope, error), error) {
	s.contexts <- ctx
	return s.Source.Subscribe(ctx)
}
func (s *trackedSource) Container(context.Context, string) (Container, error) {
	if s.lookupError != nil {
		return Container{}, s.lookupError
	}
	return Container{}, errors.New("temporary container lookup failure")
}

func TestLookupFailureCancelsPreviousSubscription(t *testing.T) {
	r := newRig(t)
	source := &trackedSource{Source: r.source, contexts: make(chan context.Context, 4)}
	rec, err := Open(Config{Directory: r.dir, ClusterUID: clusterUID, NodeUID: nodeUID, BootID: bootID, Epoch: runtimeEpoch(nodeUID, bootID, '1'), Source: source, Collector: r.client, GapSink: r.sink.Report, CgroupRoot: r.cgroups})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx) }()
	defer func() { cancel(); <-done; rec.Close() }()
	first := <-source.contexts
	stream := <-r.fake.Streams
	r.waitRecords(2)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskStart{ContainerID: c1, Pid: 100}, "/tasks/start", time.Now().UTC())
	select {
	case <-source.contexts:
	case <-ctx.Done():
		t.Fatal("recorder did not resubscribe")
	}
	if first.Err() != context.Canceled {
		t.Fatal("old subscription still alive at resubscribe")
	}
}

func TestGapRetryStopsStreamAndReconciles(t *testing.T) {
	r := newRig(t)
	source := &trackedSource{Source: r.source, contexts: make(chan context.Context, 4), lookupError: status.Error(codes.NotFound, "removed container")}
	var first context.Context
	var rec *Recorder
	attempts := 0
	acked := make(chan struct{}, 1)
	sink := func(context.Context, Gap) error {
		attempts++
		if attempts == 1 {
			first = <-source.contexts
			return nil
		}
		if attempts == 2 {
			return errors.New("control-health unavailable")
		}
		if attempts == 3 {
			if first.Err() != context.Canceled || rec.Status().Subscribed {
				return &PermanentGapError{Status: 0}
			}
			acked <- struct{}{}
		}
		return nil
	}
	var err error
	rec, err = Open(Config{Directory: r.dir, ClusterUID: clusterUID, NodeUID: nodeUID, BootID: bootID, Epoch: runtimeEpoch(nodeUID, bootID, '1'), Source: source, Collector: r.client, GapSink: sink, CgroupRoot: r.cgroups})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- rec.Run(ctx) }()
	defer func() { cancel(); <-done; rec.Close() }()
	stream := <-r.fake.Streams
	r.waitRecords(2)
	stream <- ctrdtest.Envelope(t, &eventtypes.TaskStart{ContainerID: c1, Pid: 100}, "/tasks/start", time.Now().UTC())
	select {
	case <-acked:
	case <-ctx.Done():
		t.Fatal("gap retry did not cancel stream and clear subscribed health")
	}
	select {
	case <-source.contexts:
	case <-ctx.Done():
		t.Fatal("gap ACK did not lead to a fresh subscription")
	}
}

func TestDifferentNodeStateStartsAtProcessStart(t *testing.T) {
	r := newRig(t)
	old := time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)
	now := old.Add(time.Hour)
	state, _ := json.Marshal(map[string]any{"node_uid": "40000000-0000-4000-8000-000000000004", "last_event_at": old})
	if err := os.WriteFile(filepath.Join(r.dir, stateFile), state, 0o600); err != nil {
		t.Fatal(err)
	}
	rec, err := Open(Config{Directory: r.dir, ClusterUID: clusterUID, NodeUID: nodeUID, BootID: bootID, Epoch: runtimeEpoch(nodeUID, bootID, '1'), Source: r.source, Collector: r.client, GapSink: r.sink.Report, CgroupRoot: r.cgroups, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()
	gap, err := rec.reconcile(context.Background())
	if err != nil || !gap.Start.Equal(now) {
		t.Fatalf("foreign node gap %+v %v", gap, err)
	}
	if err := rec.saveLastEvent(now); err != nil {
		t.Fatal(err)
	}
	saved, err := rec.loadLastEvent()
	if err != nil || !saved.Equal(now) {
		t.Fatalf("same node restart %v %v", saved, err)
	}
}
