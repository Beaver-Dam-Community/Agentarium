package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/packages/canonical"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
)

// This server is an explicit CAS wire fixture, not evidence for the audit DB
// implementation. All producer retries/restarts below use real persisted files.
type checkpointReceiver struct {
	mu                 sync.Mutex
	cp                 *batch.Checkpoint
	lastID, lastDigest string
	loseNext           bool
	requests           [][]byte
	watermarks         map[string]uint64
}

func (s *checkpointReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet {
		if r.URL.Path != "/internal/lifecycle/checkpoints" || r.URL.Query().Get("scope") != "namespace/agent-exec" {
			http.Error(w, "bad scope", 400)
			return
		}
		if s.cp == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(batch.CheckpointResult{Scope: s.cp.Scope, ResourceVersion: s.cp.ResourceVersion, Revision: s.cp.Revision, CommittedAt: time.Now().UTC().Format(time.RFC3339Nano)})
		return
	}
	raw, _ := io.ReadAll(r.Body)
	s.requests = append(s.requests, append([]byte(nil), raw...))
	var req struct {
		BatchID string            `json:"batch_id"`
		Digest  string            `json:"batch_digest"`
		Epoch   string            `json:"source_epoch"`
		Scope   string            `json:"scope"`
		Records []json.RawMessage `json:"records"`
		Cursor  *batch.Cursor     `json:"cursor"`
	}
	if json.Unmarshal(raw, &req) != nil || req.Scope != "namespace/agent-exec" {
		http.Error(w, "bad request", 400)
		return
	}
	if s.watermarks == nil {
		s.watermarks = map[string]uint64{}
	}
	accepted, duplicate := []string{}, []string{}
	for _, raw := range req.Records {
		var rec struct {
			ID  string `json:"lifecycle_event_id"`
			Seq uint64 `json:"source_sequence"`
		}
		_ = json.Unmarshal(raw, &rec)
		if rec.Seq <= s.watermarks[req.Epoch] {
			duplicate = append(duplicate, rec.ID)
		} else {
			accepted = append(accepted, rec.ID)
			s.watermarks[req.Epoch] = rec.Seq
		}
	}
	var cp *batch.Checkpoint
	if req.Cursor != nil {
		revision := uint64(0)
		if s.cp != nil {
			revision = s.cp.Revision
		}
		if req.BatchID == s.lastID && req.Digest == s.lastDigest {
			cp = s.cp
		} else if req.Cursor.ExpectedRevision == revision {
			s.cp = &batch.Checkpoint{Scope: req.Cursor.Scope, ResourceVersion: req.Cursor.ResourceVersion, Revision: revision + 1}
			s.lastID = req.BatchID
			s.lastDigest = req.Digest
			cp = s.cp
		}
	}
	if s.loseNext {
		s.loseNext = false
		http.Error(w, "committed but ack unavailable", 503)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"batch_id": req.BatchID, "accepted_ids": accepted, "duplicate_ids": duplicate, "rejected": []any{}, "watermarks": []any{map[string]any{"source_epoch": req.Epoch, "acked_through": s.watermarks[req.Epoch]}}, "checkpoint": cp})
}
func watcherPump(t *testing.T, dir, epoch string, c *batch.Client) (*Pump, *wal.Journal) {
	t.Helper()
	j, err := wal.Open(dir, epoch, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	p, err := New(Config{Journal: j, Client: c, SourceID: batch.PodWatcherSource, Stream: batch.Lifecycle, WatchScope: "namespace/agent-exec", RecoveryReason: "wal_segment_corrupt"})
	if err != nil {
		t.Fatal(err)
	}
	return p, j
}
func watcherClient(t *testing.T, h http.Handler) *batch.Client {
	t.Helper()
	s, cfg := tlsFixture(t, h)
	c, err := batch.NewClient(s.URL, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
func snapshotEmptySpool(t *testing.T, src string) string {
	t.Helper()
	dst := privateDir(t)
	for _, file := range []string{"state.json", "initialized"} {
		raw, err := os.ReadFile(filepath.Join(src, file))
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dst, file), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}
func TestDurableBookmarkACKLossAndDelayedHistoricalRetry(t *testing.T) {
	ctx := context.Background()
	server := &checkpointReceiver{}
	c := watcherClient(t, server)
	dir := privateDir(t)
	p, j := watcherPump(t, dir, "watcher_a", c)
	if err := p.QueueCursor("old"); !errors.Is(err, ErrCheckpointRefresh) {
		t.Fatalf("initial GET not required: %v", err)
	}
	if cp, err := p.ResumeCheckpoint(ctx); err != nil || cp != nil {
		t.Fatalf("initial GET: %v %v", cp, err)
	}
	if err := p.QueueCursor("opaque-<&>"); err != nil {
		t.Fatal(err)
	}
	saved, err := j.Delivery()
	if err != nil || saved == nil {
		t.Fatalf("not durable before send: %v", err)
	}
	archive := snapshotEmptySpool(t, dir)
	server.mu.Lock()
	server.loseNext = true
	server.mu.Unlock()
	if _, err = p.Flush(ctx); err == nil {
		t.Fatal("expected lost ACK")
	}
	_ = j.Close()
	p, j = watcherPump(t, dir, "watcher_restart", c)
	recovered, _ := j.Delivery()
	if !bytes.Equal(saved.Body, recovered.Body) {
		t.Fatal("restart changed immutable request")
	}
	if _, err = p.ResumeCheckpoint(ctx); err == nil {
		t.Fatal("GET allowed to replace pending revision")
	}
	if _, err = p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	state, _ := j.Watch()
	if state.Checkpoint == nil || state.Checkpoint.Revision != 1 || state.RefreshRequired {
		t.Fatalf("same-current retry: %+v", state)
	}
	server.mu.Lock()
	if len(server.requests) != 2 || !bytes.Equal(server.requests[0], server.requests[1]) {
		t.Error("retry bytes changed")
	}
	server.mu.Unlock()
	if records, err := j.Pending(); err != nil || len(records) != 0 {
		t.Fatal("empty bookmark manufactured record", err)
	}
	if err = p.QueueCursor("opaque-B"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	// An earlier durable request arrives after B: server fixture commits records
	// but returns checkpoint=null. The producer must persist recovery-required.
	old, oldJournal := watcherPump(t, archive, "watcher_delayed", c)
	if _, err = old.Flush(ctx); !errors.Is(err, ErrCheckpointRefresh) {
		t.Fatal(err)
	}
	if err = old.QueueCursor("opaque-A"); !errors.Is(err, ErrCheckpointRefresh) {
		t.Fatalf("stale cursor reused: %v", err)
	}
	_ = oldJournal.Close()
	old, oldJournal = watcherPump(t, archive, "watcher_delayed_restart", c)
	state, _ = oldJournal.Watch()
	if !state.RefreshRequired {
		t.Fatal("stale recovery state lost on restart")
	}
	cp, err := old.ResumeCheckpoint(ctx)
	if err != nil || cp.ResourceVersion != "opaque-B" || cp.Revision != 2 {
		t.Fatalf("resume current: %+v %v", cp, err)
	}
	// Represents a newly observed cursor after restarting WATCH from B.
	if err = old.QueueCursor("opaque-C"); err != nil {
		t.Fatal(err)
	}
	pending, _ := oldJournal.Delivery()
	var request map[string]json.RawMessage
	_ = json.Unmarshal(pending.Body, &request)
	var cursor batch.Cursor
	_ = json.Unmarshal(request["cursor"], &cursor)
	if cursor.ExpectedRevision != 2 || cursor.ResourceVersion != "opaque-C" {
		t.Fatalf("wrong new cursor: %+v", cursor)
	}
	if _, err = old.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.cp.Revision != 3 || server.cp.ResourceVersion != "opaque-C" {
		t.Fatalf("current regressed: %+v", server.cp)
	}
}
func TestWatcherDrainsRecordsBeforeCursorAndReplaysOriginalRecords(t *testing.T) {
	ctx := context.Background()
	server := &checkpointReceiver{}
	c := watcherClient(t, server)
	dir := privateDir(t)
	p, j := watcherPump(t, dir, "records", c)
	if _, err := p.ResumeCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	_, err := j.Append(func(epoch string, seq uint64) ([]byte, error) {
		id, e := canonical.LifecycleEventID(batch.PodWatcherSource, epoch, int64(seq))
		if e != nil {
			return nil, e
		}
		return json.Marshal(map[string]any{"lifecycle_event_id": id, "source_id": batch.PodWatcherSource, "source_epoch": epoch, "source_sequence": seq, "namespace": "agent-exec"})
	}, wal.Checkpoint{})
	if err != nil {
		t.Fatal(err)
	}
	if err = p.QueueCursor("rv"); err == nil {
		t.Fatal("cursor crossed unacked record")
	}
	server.mu.Lock()
	server.loseNext = true
	server.mu.Unlock()
	if _, err = p.Flush(ctx); err == nil {
		t.Fatal("expected ACK loss")
	}
	pending, _ := j.Delivery()
	if pending != nil {
		t.Fatal("record-only envelope must not reserve spool capacity")
	}
	_ = j.Close()
	p, j = watcherPump(t, dir, "new_epoch", c)
	if result, err := p.Flush(ctx); err != nil || result.Acked != 1 {
		t.Fatalf("replay: %+v %v", result, err)
	}
	server.mu.Lock()
	var first, last struct {
		Records []json.RawMessage `json:"records"`
	}
	_ = json.Unmarshal(server.requests[0], &first)
	_ = json.Unmarshal(server.requests[1], &last)
	if len(first.Records) != 1 || len(last.Records) != 1 || !bytes.Equal(first.Records[0], last.Records[0]) {
		t.Error("record identity changed after restart")
	}
	server.mu.Unlock()
	if err = p.QueueCursor("rv"); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = New(Config{Journal: j, Client: c, SourceID: batch.PodWatcherSource, Stream: batch.Lifecycle, WatchScope: "namespace/other", RecoveryReason: "gap"}); err == nil {
		t.Fatal("scope silently changed")
	}
}
func TestPendingBatchDigestCorruptionFailsClosed(t *testing.T) {
	server := &checkpointReceiver{}
	c := watcherClient(t, server)
	dir := privateDir(t)
	p, j := watcherPump(t, dir, "epoch", c)
	if _, err := p.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.QueueCursor("original"); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	path := filepath.Join(dir, "state.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]json.RawMessage
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	var pending wal.PendingDelivery
	if err = json.Unmarshal(state["delivery"], &pending); err != nil {
		t.Fatal(err)
	}
	pending.Body = bytes.Replace(pending.Body, []byte(`"original"`), []byte(`"tampered"`), 1)
	state["delivery"], _ = json.Marshal(pending)
	raw, _ = json.Marshal(state)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	j, err = wal.Open(dir, "restart", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	_, err = New(Config{Journal: j, Client: c, SourceID: batch.PodWatcherSource, Stream: batch.Lifecycle, WatchScope: "namespace/agent-exec", RecoveryReason: "gap"})
	if err == nil {
		t.Fatal("corrupt request rehashed and sent")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 0 {
		t.Fatal("corrupt pending request sent")
	}
}
func TestCheckpointGETRejectsInvalidBodies(t *testing.T) {
	for name, body := range map[string]string{
		"missing revision": `{"scope":"namespace/agent-exec","resource_version":"rv","committed_at":"2026-10-17T00:00:00Z"}`,
		"wrong scope":      `{"scope":"namespace/other","resource_version":"rv","committed_at":"2026-10-17T00:00:00Z","checkpoint_revision":1}`,
		"overflow":         `{"scope":"namespace/agent-exec","resource_version":"rv","committed_at":"2026-10-17T00:00:00Z","checkpoint_revision":9007199254740992}`,
		"null RV":          `{"scope":"namespace/agent-exec","resource_version":null,"committed_at":"2026-10-17T00:00:00Z","checkpoint_revision":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			c := watcherClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			if _, err := c.GetCheckpoint(context.Background(), "namespace/agent-exec"); err == nil {
				t.Fatal("invalid GET accepted")
			}
		})
	}
}

func TestPendingPersistFailureNeverSends(t *testing.T) {
	server := &checkpointReceiver{}
	c := watcherClient(t, server)
	dir := privateDir(t)
	p, j := watcherPump(t, dir, "epoch", c)
	if _, err := p.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	} // fail the atomic publish
	if err := p.QueueCursor("rv"); err == nil {
		t.Fatal("persist failure ignored")
	}
	if _, err := p.Flush(context.Background()); err == nil {
		t.Fatal("failed spool remained usable")
	}
	if _, err := j.HealthSnapshot(); err == nil {
		t.Fatal("failed spool reports healthy snapshot")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 0 {
		t.Fatal("sent without durable request")
	}
}
func TestPendingBytesCapacityAndHealthSurviveRestart(t *testing.T) {
	server := &checkpointReceiver{}
	c := watcherClient(t, server)
	dir := privateDir(t)
	p, j := watcherPump(t, dir, "epoch", c)
	if _, err := p.ResumeCheckpoint(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := p.QueueCursor("rv"); err != nil {
		t.Fatal(err)
	}
	before, err := j.HealthSnapshot()
	if err != nil || !before.Pending || before.Used == 0 || before.AckProgress != 0 {
		t.Fatalf("pending snapshot: %+v %v", before, err)
	}
	_ = j.Close()
	p, j = watcherPump(t, dir, "new_epoch", c)
	after, err := j.HealthSnapshot()
	if err != nil || after.Used != before.Used || !after.Pending || after.AckProgress != 0 {
		t.Fatalf("recovered snapshot: %+v %v", after, err)
	}
	if _, err = p.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err = j.HealthSnapshot()
	if err != nil || after.Used != 0 || after.Pending || after.AckProgress != 0 {
		t.Fatalf("bookmark manufactured record ack progress: %+v %v", after, err)
	}
}

func TestFullWALDrainsWithoutEnvelopeReservation(t *testing.T) {
	dir := privateDir(t)
	j, err := wal.Open(dir, "full", 1800)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	n := 0
	for {
		_, err = j.Append(normalized, wal.Checkpoint{})
		if errors.Is(err, wal.ErrFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("fixture has no records")
	}
	calls := 0
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		response(t, w, raw, false)
	}))
	result, err := p.Flush(context.Background())
	if err != nil || result.Acked != uint64(n) || calls != 1 {
		t.Fatalf("full WAL did not drain: %+v %v calls=%d", result, err, calls)
	}
	result, err = p.Flush(context.Background())
	if err != nil || !result.Idle {
		t.Fatalf("not drained: %+v %v", result, err)
	}
}
func TestQuarantineCrashReplaysRangeInsteadOfRejectedRecord(t *testing.T) {
	dir := privateDir(t)
	j := journal(t, dir, "rejected", 1)
	p := pump(t, j, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "ack lost", 503) }))
	if _, err := p.Flush(context.Background()); err == nil {
		t.Fatal("expected transient error")
	}
	// Crash boundary after the validated SCHEMA_INVALID response's quarantine
	// fsync and before clearing the in-memory envelope / constructing its range.
	if err := j.QuarantineSchemaRejected("rejected", 1); err != nil {
		t.Fatal(err)
	}
	_ = j.Close()
	next, err := wal.Open(dir, "restart", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	calls := 0
	p = pump(t, next, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		raw, _ := io.ReadAll(r.Body)
		in := response(t, w, raw, false)
		if len(in.Records) != 0 || len(in.Ranges) != 1 || in.Ranges[0].Reason != "record_rejected" {
			t.Errorf("rejected record was resent: %+v", in)
		}
	}))
	result, err := p.Flush(context.Background())
	if err != nil || result.Acked != 1 || calls != 1 {
		t.Fatalf("range replay: %+v %v calls=%d", result, err, calls)
	}
}
