package watcher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/wal"
	corev1 "k8s.io/api/core/v1"
)

func TestLISTBatchesPageBeforeNextPage(t *testing.T) {
	// Every record fsyncs. Allow parallel race suites to contend for local disk;
	// cancellation behavior is verified separately with short deadlines.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var calls atomic.Int32
	var sink *collector
	cfg, c := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			pods := make([]corev1.Pod, batch.MaxRecords+3)
			for i := range pods {
				pods[i] = pod(i+1, fmt.Sprintf("item-%d", i))
			}
			list(w, "snapshot", "page-2", pods...)
			return
		}
		if sink.count() != batch.MaxRecords+3 || sink.checkpoint() != "" {
			t.Error("next page requested before prior records ACK, or partial cursor committed")
		}
		if r.URL.Query().Get("continue") != "page-2" {
			t.Error("wrong continuation")
		}
		list(w, "snapshot", "", pod(200, "last-item"))
	}))
	sink = c
	cfg.PageSize = batch.MaxRecords + 3
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if rv, err := p.list(ctx); err != nil || rv != "snapshot" {
		t.Fatalf("LIST: rv=%q err=%v", rv, err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	// Two batches for page 1, one for page 2, one final cursor-only request.
	if len(sink.requests) != 4 || len(sink.records) != batch.MaxRecords+4 {
		t.Fatalf("requests=%d records=%d", len(sink.requests), len(sink.records))
	}
	for i, raw := range sink.requests {
		var req struct {
			Records []json.RawMessage `json:"records"`
			Cursor  *batch.Cursor     `json:"cursor"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		if len(raw) > batch.MaxBytes || len(req.Records) > batch.MaxRecords || (i < 3 && req.Cursor != nil) || (i == 3 && (req.Cursor == nil || len(req.Records) != 0)) {
			t.Fatalf("batch %d crossed delivery bounds or cursor barrier", i)
		}
	}
}

func TestLISTSmallWALFlushesBetweenFacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		list(w, "snapshot", "", pod(1, "one"), pod(2, "two"), pod(3, "three"))
	}))
	cfg.Capacity = 2300
	// One Pod can itself produce more records than the spool can hold.
	cfg.Normalize = func(context.Context, PodEvent) ([]Facts, error) {
		facts := make([]Facts, 5)
		for i := range facts {
			facts[i] = Facts{Transition: "fixture_metadata", MappingVersion: 1, EvidenceRefs: []json.RawMessage{}}
		}
		return facts, nil
	}
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.list(ctx); err != nil || sink.checkpoint() != "snapshot" || sink.count() != 15 {
		t.Fatalf("LIST err=%v checkpoint=%q records=%d", err, sink.checkpoint(), sink.count())
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.requests) >= 16 {
		t.Fatalf("small WAL fell back to per-fact requests: %d", len(sink.requests))
	}
	for i, raw := range sink.records {
		var rec struct {
			Sequence uint64 `json:"source_sequence"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil || rec.Sequence != uint64(i+1) {
			t.Fatalf("capacity refusal reserved a sequence: i=%d sequence=%d err=%v", i, rec.Sequence, err)
		}
	}
}

func TestLISTOversizedFactStopsWithoutCursor(t *testing.T) {
	for _, prior := range []bool{false, true} {
		t.Run(fmt.Sprintf("prior-record-%v", prior), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pods := []corev1.Pod{pod(2, "oversized")}
				if prior {
					pods = append([]corev1.Pod{pod(1, "small")}, pods...)
				}
				list(w, "snapshot", "", pods...)
			}))
			cfg.Capacity = 2300
			cfg.Normalize = func(_ context.Context, event PodEvent) ([]Facts, error) {
				f := Facts{Transition: "fixture_metadata", MappingVersion: 1, EvidenceRefs: []json.RawMessage{}}
				if event.Pod.ResourceVersion == "oversized" {
					large := strings.Repeat("x", 3000)
					f.MissingReason = &large
				}
				return []Facts{f}, nil
			}
			p := openTestProducer(t, cfg)
			if _, err := p.pump.ResumeCheckpoint(ctx); err != nil {
				t.Fatal(err)
			}
			_, err := p.list(ctx)
			if !errors.Is(err, wal.ErrFull) || ctx.Err() != nil || sink.checkpoint() != "" {
				t.Fatalf("oversized fact retried or committed cursor: %v", err)
			}
			want := 0
			if prior {
				want = 1
			}
			if sink.count() != want {
				t.Fatalf("records=%d want=%d", sink.count(), want)
			}
			window, err := p.journal.Next(batch.MaxRecords, batch.MaxBytes)
			if err != nil || window.Epoch != "" {
				t.Fatalf("oversized fact reserved a sequence: %+v %v", window, err)
			}
		})
	}
}

func TestLISTPageFailurePreservesUnackedWAL(t *testing.T) {
	for _, collectorOutage := range []bool{false, true} {
		t.Run(fmt.Sprintf("collector-outage-%v", collectorOutage), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				list(w, "snapshot", "", pod(1, "one"), pod(2, "two"), pod(3, "three"), pod(4, "four"))
			}))
			cfg.Capacity = 2300
			sink.rejectPosts = collectorOutage
			normalize := cfg.Normalize
			invalid := errors.New("invalid fixture facts")
			cfg.Normalize = func(ctx context.Context, event PodEvent) ([]Facts, error) {
				if !collectorOutage && event.Pod.ResourceVersion == "two" {
					return nil, invalid
				}
				return normalize(ctx, event)
			}
			p := openTestProducer(t, cfg)
			if _, err := p.pump.ResumeCheckpoint(ctx); err != nil {
				t.Fatal(err)
			}
			_, err := p.list(ctx)
			wantErr := invalid
			if collectorOutage {
				wantErr = context.DeadlineExceeded
			}
			if !errors.Is(err, wantErr) || sink.count() != 0 || sink.checkpoint() != "" {
				t.Fatalf("unacked failure: %v records=%d checkpoint=%q", err, sink.count(), sink.checkpoint())
			}
			window, err := p.journal.Next(batch.MaxRecords, batch.MaxBytes)
			if err != nil || len(window.Records) == 0 || window.Acked != 0 {
				t.Fatalf("unacked records disappeared: %+v %v", window, err)
			}
		})
	}
}
