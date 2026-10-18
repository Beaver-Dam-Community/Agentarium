package watcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
)

const clusterUID = "00000000-0000-4000-8000-000000000001"

// Explicit collector CAS fixture: real mTLS transport, no production audit DB.
type collector struct {
	mu                               sync.Mutex
	cp                               *batch.Checkpoint
	lastID, lastDigest               string
	watermark                        map[string]uint64
	records                          []json.RawMessage
	requests                         [][]byte
	staleRV                          string
	rejectPosts                      bool
	getFailures, getStatus, getCalls int
}

func (c *collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Method == http.MethodGet {
		c.getCalls++
		if c.getFailures > 0 {
			c.getFailures--
			http.Error(w, "checkpoint unavailable", c.getStatus)
			return
		}
		if r.URL.Query().Get("scope") != "namespace/agent-exec" {
			http.Error(w, "scope", 400)
			return
		}
		if c.cp == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(batch.CheckpointResult{Scope: c.cp.Scope, ResourceVersion: c.cp.ResourceVersion, Revision: c.cp.Revision, CommittedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		return
	}
	raw, _ := io.ReadAll(r.Body)
	c.requests = append(c.requests, raw)
	if c.rejectPosts {
		http.Error(w, "temporary collector outage", 503)
		return
	}
	var req struct {
		ID      string            `json:"batch_id"`
		Digest  string            `json:"batch_digest"`
		Epoch   string            `json:"source_epoch"`
		Records []json.RawMessage `json:"records"`
		Cursor  *batch.Cursor     `json:"cursor"`
	}
	if json.Unmarshal(raw, &req) != nil {
		http.Error(w, "body", 400)
		return
	}
	if c.watermark == nil {
		c.watermark = map[string]uint64{}
	}
	accepted, duplicate := []string{}, []string{}
	for _, record := range req.Records {
		var identity struct {
			ID       string `json:"lifecycle_event_id"`
			Sequence uint64 `json:"source_sequence"`
		}
		_ = json.Unmarshal(record, &identity)
		if identity.Sequence <= c.watermark[req.Epoch] {
			duplicate = append(duplicate, identity.ID)
		} else {
			accepted = append(accepted, identity.ID)
			c.watermark[req.Epoch] = identity.Sequence
			c.records = append(c.records, record)
		}
	}
	var cp *batch.Checkpoint
	if req.Cursor != nil {
		revision := uint64(0)
		if c.cp != nil {
			revision = c.cp.Revision
		}
		if req.Cursor.ResourceVersion == c.staleRV && c.staleRV != "" {
			c.cp = &batch.Checkpoint{Scope: req.Cursor.Scope, ResourceVersion: "server-current", Revision: revision + 1}
			c.staleRV = ""
		} else if req.ID == c.lastID && req.Digest == c.lastDigest {
			cp = c.cp
		} else if req.Cursor.ExpectedRevision == revision {
			c.cp = &batch.Checkpoint{Scope: req.Cursor.Scope, ResourceVersion: req.Cursor.ResourceVersion, Revision: revision + 1}
			c.lastID = req.ID
			c.lastDigest = req.Digest
			cp = c.cp
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"batch_id": req.ID, "accepted_ids": accepted, "duplicate_ids": duplicate, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": req.Epoch, "acked_through": c.watermark[req.Epoch]}}, "checkpoint": cp})
}
func (c *collector) checkpoint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cp == nil {
		return ""
	}
	return c.cp.ResourceVersion
}
func (c *collector) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.records) }
func testConfig(t *testing.T, handler http.Handler) (Config, *collector) {
	t.Helper()
	kube := httptest.NewServer(handler)
	t.Cleanup(kube.Close)
	core, err := coreclient.NewForConfig(&rest.Config{Host: kube.URL})
	if err != nil {
		t.Fatal(err)
	}
	sink := &collector{}
	server, tls := tlsFixture(t, sink)
	client, err := batch.NewClient(server.URL, tls)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// A test-only mapper, deliberately not a selected production transition enum.
	config := Config{Directory: dir, Namespace: "agent-exec", ClusterUID: clusterUID, Core: core, Collector: client, PageSize: 1,
		Normalize: func(_ context.Context, event PodEvent) ([]Facts, error) {
			return []Facts{{Transition: "fixture_metadata", MappingVersion: 1, EvidenceRefs: []json.RawMessage{}}}, nil
		},
		GapSink: func(_ context.Context, gap Gap) error {
			raw, e := json.Marshal(gap)
			if e != nil {
				return e
			}
			return writeAtomic(dir, "fixture-gap.json", raw)
		}}
	return config, sink
}
func openTestProducer(t *testing.T, c Config) *Producer {
	t.Helper()
	p, err := Open(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func pod(n int, rv string) corev1.Pod {
	return corev1.Pod{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"}, ObjectMeta: metav1.ObjectMeta{UID: types.UID(fmt.Sprintf("00000000-0000-4000-8000-%012d", n)), Name: fmt.Sprintf("pod-%d", n), Namespace: "agent-exec", ResourceVersion: rv}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "worker", Command: []string{"PRIVATE_ARGV"}, Env: []corev1.EnvVar{{Name: "KEY", Value: "PRIVATE_SECRET"}}}}}}
}
func list(w http.ResponseWriter, rv, next string, pods ...corev1.Pod) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: metav1.ListMeta{ResourceVersion: rv, Continue: next}, Items: pods})
}
func status(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonExpired, Code: int32(code)})
}
func event(w http.ResponseWriter, kind watch.EventType, object any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"type": kind, "object": object})
	w.(http.Flusher).Flush()
}
func expired() metav1.Status {
	return metav1.Status{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"}, Status: metav1.StatusFailure, Reason: metav1.StatusReasonExpired, Code: 410}
}
func TestLISTAllPagesBeforeCursorAndNoPodSecrets(t *testing.T) {
	var sink *collector
	var calls atomic.Int32
	cfg, c := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/namespaces/agent-exec/pods" || r.URL.Query().Get("limit") != "1" {
			t.Errorf("unexpected LIST %s", r.URL)
		}
		switch r.URL.Query().Get("continue") {
		case "":
			list(w, "snapshot-opaque", "next/<&>", pod(1, "item-a"))
		case "next/<&>":
			if sink.checkpoint() != "" || sink.count() != 1 {
				t.Error("cursor committed before final page")
			}
			list(w, "snapshot-opaque", "", pod(2, "item-b"))
		default:
			t.Error("continuation changed")
			http.Error(w, "bad", 400)
		}
	}))
	sink = c
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	rv, err := p.list(context.Background())
	if err != nil || rv != "snapshot-opaque" || sink.checkpoint() != rv || calls.Load() != 2 {
		t.Fatalf("LIST: %q %v calls=%d", rv, err, calls.Load())
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.records) != 2 {
		t.Fatal("wrong record count")
	}
	for _, raw := range sink.records {
		if bytes.Contains(raw, []byte("PRIVATE")) || bytes.Contains(raw, []byte("received_at")) {
			t.Fatal("Pod spec or server field leaked")
		}
		var record lifecycleRecord
		if err = json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		digest, e := canonical.DigestWithoutKeys(raw, "record_digest", "received_at")
		if e != nil || digest != record.Digest {
			t.Fatal("record digest mismatch")
		}
		id, e := canonical.LifecycleEventID(batch.PodWatcherSource, record.Epoch, int64(record.Sequence))
		if e != nil || id != record.ID {
			t.Fatal("record identity mismatch")
		}
	}
}
func TestLISTFailureOrSnapshotChangeNeverCommits(t *testing.T) {
	for _, mode := range []string{"page-error", "snapshot-change", "repeat-token"} {
		t.Run(mode, func(t *testing.T) {
			cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("continue") == "" {
					list(w, "snapshot", "next", pod(1, "item"))
					return
				}
				switch mode {
				case "page-error":
					http.Error(w, "permanent denial", http.StatusForbidden)
				case "snapshot-change":
					list(w, "changed", "", pod(2, "item-2"))
				case "repeat-token":
					list(w, "snapshot", "next")
				}
			}))
			p := openTestProducer(t, cfg)
			_, err := p.pump.ResumeCheckpoint(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = p.list(context.Background()); err == nil {
				t.Fatal("invalid pagination succeeded")
			}
			if sink.checkpoint() != "" || sink.count() != 1 {
				t.Fatalf("unsafe checkpoint: %s records=%d", sink.checkpoint(), sink.count())
			}
		})
	}
}
func TestEmptyLISTAndDurableRestartCounterScope(t *testing.T) {
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { list(w, "empty-snapshot", "") }))
	p := openTestProducer(t, cfg)
	first := p.identity.epoch
	if _, err := Open(cfg); err == nil {
		t.Fatal("concurrent producer reused identity")
	}
	if _, err := p.pump.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.list(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sink.count() != 0 || sink.checkpoint() != "empty-snapshot" {
		t.Fatal("empty LIST invented record or missed checkpoint")
	}
	_ = p.Close()
	p = openTestProducer(t, cfg)
	if !strings.HasSuffix(first, "_1") || p.identity.epoch != strings.TrimSuffix(first, "_1")+"_2" {
		t.Fatal("counter not durable", first, p.identity.epoch)
	}
	_ = p.Close()
	other := cfg
	other.Namespace = "other"
	if _, err := Open(other); err == nil {
		t.Fatal("scope changed")
	}
	if err := os.Remove(filepath.Join(cfg.Directory, "instance.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(cfg); err == nil {
		t.Fatal("missing identity silently reinitialized")
	}
}
func TestMandatoryAdaptersFailBeforeOpeningState(t *testing.T) {
	cfg, _ := testConfig(t, http.NotFoundHandler())
	cfg.Normalize = nil
	if _, err := Open(cfg); err == nil {
		t.Fatal("missing normalizer accepted")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "instance.json")); !os.IsNotExist(err) {
		t.Fatal("invalid adapter initialized state")
	}
	cfg.Normalize = func(context.Context, PodEvent) ([]Facts, error) { return nil, nil }
	cfg.GapSink = nil
	if _, err := Open(cfg); err == nil {
		t.Fatal("missing gap sink accepted")
	}
}
func TestWatchBookmarkAndStream410AreDurableBeforeRelist(t *testing.T) {
	var sink *collector
	cfg, c := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" || r.URL.Query().Get("resourceVersion") != "snapshot" || r.URL.Query().Get("allowWatchBookmarks") != "true" {
			t.Errorf("bad watch options %s", r.URL)
		}
		bookmark := pod(1, "bookmark/<&>")
		event(w, watch.Bookmark, &bookmark)
		event(w, watch.Modified, func() *corev1.Pod { p := pod(1, "modified-rv"); return &p }())
		event(w, watch.Error, expired())
	}))
	sink = c
	cfg.Normalize = func(_ context.Context, e PodEvent) ([]Facts, error) {
		if sink.checkpoint() != "bookmark/<&>" {
			t.Error("bookmark not committed before next fact")
		}
		return []Facts{{Transition: "fixture_metadata", MappingVersion: 1, EvidenceRefs: []json.RawMessage{}}}, nil
	}
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.commitCursor(context.Background(), "snapshot"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.watch(ctx, "snapshot"); !errors.Is(err, errRelist) {
		t.Fatal(err)
	}
	if sink.count() != 1 || sink.checkpoint() != "modified-rv" {
		t.Fatal("bookmark allocated record or cursor missing")
	}
	// The 410 is remembered; the gap is reported after the relist (#178).
	if _, err := os.Stat(filepath.Join(cfg.Directory, "fixture-gap.json")); !os.IsNotExist(err) {
		t.Fatal("gap must not be reported before the relist completes")
	}
	if p.expired == nil || p.expired.LastCommittedResourceVersion != "modified-rv" || p.expired.Reason != "WATCH_HISTORY_EXPIRED" {
		t.Fatalf("wrong pending gap: %+v", p.expired)
	}
}
func TestInitialHTTP410ReachesGapSinkWithoutRetryLoop(t *testing.T) {
	var calls atomic.Int32
	cfg, _ := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); status(w, 410) }))
	p := openTestProducer(t, cfg)
	p.committed = "old"
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := p.watch(ctx, "old"); !errors.Is(err, errRelist) {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("initial 410 retried", calls.Load())
	}
}
func TestFailedGapSinkPreventsAutomaticRelist(t *testing.T) {
	var lists atomic.Int32
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			event(w, watch.Error, expired())
			return
		}
		n := lists.Add(1)
		if n == 1 {
			list(w, "snapshot", "")
		} else {
			list(w, "snapshot-after-410", "")
		}
	}))
	denied := errors.New("durable gap sink unavailable")
	cfg.GapSink = func(context.Context, Gap) error { return denied }
	p := openTestProducer(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Run(ctx); !errors.Is(err, denied) {
		t.Fatal(err)
	}
	// LIST 1 is the initial snapshot; LIST 2 is read after the 410, but its
	// cursor is not committed and no WATCH resumes without a durable gap.
	if lists.Load() != 2 || sink.checkpoint() != "snapshot" {
		t.Fatal("relist cursor committed without durable gap", lists.Load(), sink.checkpoint())
	}
}
func TestStaleCursorRestartsFromServerCurrent(t *testing.T) {
	var watches atomic.Int32
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") != "true" {
			list(w, "snapshot", "")
			return
		}
		if watches.Add(1) == 1 {
			if r.URL.Query().Get("resourceVersion") != "snapshot" {
				t.Error("unexpected initial RV")
			}
			bookmark := pod(1, "stale-A")
			event(w, watch.Bookmark, &bookmark)
			<-r.Context().Done()
			return
		}
		if r.URL.Query().Get("resourceVersion") != "server-current" {
			t.Errorf("resumed old cursor: %s", r.URL)
		}
		event(w, watch.Error, metav1.Status{TypeMeta: metav1.TypeMeta{Kind: "Status", APIVersion: "v1"}, Reason: metav1.StatusReasonExpired, Code: 410})
	}))
	sink.staleRV = "stale-A"
	stop := errors.New("stop after second watch")
	cfg.GapSink = func(context.Context, Gap) error { return stop }
	p := openTestProducer(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Run(ctx); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	if watches.Load() != 2 || sink.checkpoint() != "server-current" {
		t.Fatalf("stale restart failed: %d %s", watches.Load(), sink.checkpoint())
	}
}
func TestPinnedRetryWatcherDoesNotForwardBookmarks(t *testing.T) {
	cfg, _ := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bookmark := pod(1, "bookmark")
		event(w, watch.Bookmark, &bookmark)
		event(w, watch.Error, expired())
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	lw := &cache.ListWatch{WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
		return cfg.Core.Pods(cfg.Namespace).Watch(ctx, o)
	}}
	retry, err := watchtools.NewRetryWatcherWithContext(ctx, "snapshot", lw)
	if err != nil {
		t.Fatal(err)
	}
	defer retry.Stop()
	count := 0
	for e := range retry.ResultChan() {
		count++
		if e.Type != watch.Error {
			t.Errorf("unexpected forwarded bookmark: %s", e.Type)
		}
	}
	if count != 1 {
		t.Fatal("expected only stream410", count)
	}
}

func TestEOFReconnectUsesCommittedResourceVersion(t *testing.T) {
	var calls atomic.Int32
	var sink *collector
	cfg, c := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			p := pod(1, "event-before-eof")
			event(w, watch.Modified, &p)
			return
		}
		if r.URL.Query().Get("resourceVersion") != "event-before-eof" || sink.checkpoint() != "event-before-eof" {
			t.Error("EOF resumed ahead of durable checkpoint")
		}
		p := pod(1, "bookmark-after-eof")
		event(w, watch.Bookmark, &p)
		event(w, watch.Error, expired())
	}))
	sink = c
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.commitCursor(context.Background(), "snapshot"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.watch(ctx, "snapshot"); !errors.Is(err, errRelist) {
		t.Fatal(err)
	}
	if calls.Load() != 2 || sink.checkpoint() != "bookmark-after-eof" || sink.count() != 1 {
		t.Fatalf("EOF recovery: calls=%d checkpoint=%s", calls.Load(), sink.checkpoint())
	}
}
func TestRunRelistsOnlyAfterDurableGap(t *testing.T) {
	for _, mode := range []string{"stream-410", "http-410"} {
		t.Run(mode, func(t *testing.T) {
			var lists, watches atomic.Int32
			cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("watch") != "true" {
					n := lists.Add(1)
					list(w, fmt.Sprintf("snapshot-%d", n), "")
					return
				}
				if watches.Add(1) == 1 {
					if mode == "http-410" {
						status(w, 410)
					} else {
						event(w, watch.Error, expired())
					}
					return
				}
				if r.URL.Query().Get("resourceVersion") != "snapshot-2" {
					t.Error("did not watch new LIST snapshot")
				}
				p := pod(1, "stop-event")
				event(w, watch.Modified, &p)
				<-r.Context().Done()
			}))
			// The gap is reported after LIST 2 is read and before its cursor
			// is committed; its end is not earlier than the relist.
			fixture := cfg.GapSink
			cfg.GapSink = func(ctx context.Context, g Gap) error {
				if lists.Load() != 2 || sink.checkpoint() == "snapshot-2" || g.DetectedAt.Before(g.LastCommittedAt) {
					t.Errorf("gap order: lists=%d cursor=%s gap=%+v", lists.Load(), sink.checkpoint(), g)
				}
				return fixture(ctx, g)
			}
			stop := errors.New("test stops after proven relist")
			cfg.Normalize = func(_ context.Context, e PodEvent) ([]Facts, error) {
				if !e.Snapshot {
					return nil, stop
				}
				return []Facts{{Transition: "fixture_metadata", MappingVersion: 1, EvidenceRefs: []json.RawMessage{}}}, nil
			}
			p := openTestProducer(t, cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := p.Run(ctx); !errors.Is(err, stop) {
				t.Fatal(err)
			}
			if lists.Load() != 2 || watches.Load() != 2 || sink.checkpoint() != "snapshot-2" {
				t.Fatalf("relist path: lists=%d watches=%d cursor=%s", lists.Load(), watches.Load(), sink.checkpoint())
			}
			if _, err := os.Stat(filepath.Join(cfg.Directory, "fixture-gap.json")); err != nil {
				t.Fatal("gap not recorded", err)
			}
		})
	}
}

func TestRestartDrainsOldWALBeforeNewLIST(t *testing.T) {
	var lists atomic.Int32
	var sink *collector
	cfg, c := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			p := pod(2, "stop")
			event(w, watch.Modified, &p)
			<-r.Context().Done()
			return
		}
		if lists.Add(1) == 1 {
			list(w, "snapshot-1", "", pod(1, "original-pod-rv"))
			return
		}
		if sink.count() != 1 {
			t.Error("new LIST began before historical WAL drained")
		}
		list(w, "snapshot-2", "")
	}))
	sink = c
	sink.mu.Lock()
	sink.rejectPosts = true
	sink.mu.Unlock()
	p := openTestProducer(t, cfg)
	firstEpoch := p.identity.epoch
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	err := p.Run(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	pending, err := p.journal.Pending()
	if err != nil || len(pending) != 1 || pending[0].Epoch != firstEpoch {
		t.Fatalf("missing durable unacked record: %+v %v", pending, err)
	}
	original := append([]byte(nil), pending[0].Payload...)
	_ = p.Close()
	sink.mu.Lock()
	sink.rejectPosts = false
	sink.mu.Unlock()
	stop := errors.New("test stops after restart")
	cfg.Normalize = func(context.Context, PodEvent) ([]Facts, error) { return nil, stop }
	p = openTestProducer(t, cfg)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = p.Run(ctx); !errors.Is(err, stop) {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.records) != 1 || !bytes.Equal(original, sink.records[0]) {
		t.Fatal("historical record was rewritten")
	}
}
func TestEpochCounterCorruptionAndOverflowFailClosed(t *testing.T) {
	for _, mode := range []string{"overflow", "duplicate", "corrupt", "valid-json-bitflip"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := testConfig(t, http.NotFoundHandler())
			p := openTestProducer(t, cfg)
			_ = p.Close()
			path := filepath.Join(cfg.Directory, "instance.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "overflow":
				raw = bytes.Replace(raw, []byte(`"counter":1`), []byte(`"counter":9007199254740991`), 1)
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"counter":1`), []byte(`"counter":1,"counter":2`), 1)
			case "corrupt":
				raw = []byte(`{"version":1`)
			case "valid-json-bitflip":
				raw = bytes.Replace(raw, []byte(`"counter":1`), []byte(`"counter":2`), 1)
			}
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = Open(cfg); err == nil {
				t.Fatal("unsafe epoch state accepted")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) {
				t.Fatal("failed recovery overwrote evidence")
			}
		})
	}
}

func TestForeignNamespaceNeverReachesNormalizerOrCursor(t *testing.T) {
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreign := pod(1, "rv")
		foreign.Namespace = "other"
		list(w, "snapshot", "", foreign)
	}))
	var called atomic.Bool
	cfg.Normalize = func(context.Context, PodEvent) ([]Facts, error) { called.Store(true); return nil, nil }
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.list(context.Background()); err == nil {
		t.Fatal("foreign namespace accepted")
	}
	if called.Load() || sink.count() != 0 || sink.checkpoint() != "" {
		t.Fatal("foreign namespace crossed producer boundary")
	}
}

func TestIdentityRejectsAnotherClusterWithoutChangingState(t *testing.T) {
	cfg, _ := testConfig(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	p, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Directory, "instance.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ClusterUID = "11111111-2222-4333-8444-555555555555"
	if _, err = Open(cfg); err == nil {
		t.Fatal("cross-cluster spool reuse accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected cluster changed identity")
	}
}

func TestFactsValidateOriginalUTF8AndPreserveInt32MappingVersion(t *testing.T) {
	item := pod(1, "rv")
	facts := Facts{Transition: string([]byte{0xff}), EvidenceRefs: []json.RawMessage{}}
	if _, err := prepareRecord(facts, clusterUID, batch.PodWatcherSource, &item); err == nil {
		t.Fatal("invalid UTF-8 normalized before validation")
	}
	// Mapping-version meaning is deliberately delegated; COMMON defines int32,
	// not a positive counter. This driver must not invent a stricter contract.
	for _, version := range []int32{0, -1, 2147483647} {
		facts.Transition = "fixture_metadata"
		facts.MappingVersion = version
		build, err := prepareRecord(facts, clusterUID, batch.PodWatcherSource, &item)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := build("11111111222243338444555555555555_1", 1)
		if err != nil {
			t.Fatal(err)
		}
		var record lifecycleRecord
		if err = json.Unmarshal(raw, &record); err != nil || record.MappingVersion != version {
			t.Fatalf("version changed: %s (%v)", raw, err)
		}
	}
}
