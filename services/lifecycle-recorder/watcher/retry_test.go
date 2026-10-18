package watcher

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Beaver-Dam-Community/Agentarium/sensors/exporter/batch"
)

func TestCheckpointTransientRetryAndPermanentDenial(t *testing.T) {
	for _, code := range []int{503, 403} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var calls atomic.Int32
			cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Query().Get("watch") == "true" {
					cancel()
					return
				}
				list(w, "ready-rv", "")
			}))
			sink.getFailures = 1
			sink.getStatus = code
			p := openTestProducer(t, cfg)
			err := p.Run(ctx)
			sink.mu.Lock()
			gets := sink.getCalls
			sink.mu.Unlock()
			if code == 503 {
				if !errors.Is(err, context.Canceled) || gets != 2 || calls.Load() != 2 || sink.checkpoint() != "ready-rv" {
					t.Fatalf("err=%v gets=%d kube=%d checkpoint=%q", err, gets, calls.Load(), sink.checkpoint())
				}
			} else if err == nil || gets != 1 || calls.Load() != 0 {
				t.Fatalf("permanent denial retried: err=%v gets=%d kube=%d", err, gets, calls.Load())
			}
		})
	}
}

func TestLISTRetriesPageAndRestartsExpiredContinue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var calls atomic.Int32
	var sink *collector
	cfg, c := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if sink.checkpoint() != "" {
			t.Error("incomplete LIST committed a cursor")
		}
		switch n {
		case 1:
			list(w, "old-snapshot", "expired-token", pod(1, "old-item"))
		case 2:
			if r.URL.Query().Get("continue") != "expired-token" {
				t.Error("continuation changed")
			}
			status(w, 410)
		case 3:
			if r.URL.Query().Get("continue") != "" {
				t.Error("expired continuation reused")
			}
			http.Error(w, "temporary API outage", 503)
		case 4:
			if r.URL.Query().Get("continue") != "" {
				t.Error("retry changed page")
			}
			list(w, "fresh-snapshot", "", pod(1, "fresh-item"), pod(2, "fresh-item-2"))
		default:
			t.Errorf("unexpected LIST request %d", n)
			http.Error(w, "unexpected", 403)
		}
	}))
	sink = c
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	rv, err := p.list(ctx)
	if err != nil || rv != "fresh-snapshot" || sink.checkpoint() != rv || calls.Load() != 4 || sink.count() != 3 {
		t.Fatalf("rv=%q err=%v calls=%d records=%d", rv, err, calls.Load(), sink.count())
	}
}

func TestCheckpointRetryCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("Kubernetes called before checkpoint recovery") }))
	sink.getFailures = 100
	sink.getStatus = 503
	p := openTestProducer(t, cfg)
	started := time.Now()
	err := p.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
		t.Fatalf("retry ignored cancellation: %v", err)
	}
}

func TestLISTRetryCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "API unavailable", 503) }))
	p := openTestProducer(t, cfg)
	if _, err := p.pump.ResumeCheckpoint(ctx); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err := p.list(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second || sink.checkpoint() != "" {
		t.Fatalf("LIST retry cancellation: %v checkpoint=%q", err, sink.checkpoint())
	}
}

func TestRelistSurvivesCheckpointOutageWithoutRepeatingGap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var lists, gaps atomic.Int32
	cfg, sink := testConfig(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("watch") == "true" {
			if r.URL.Query().Get("resourceVersion") == "old-rv" {
				status(w, 410)
			} else {
				cancel()
			}
			return
		}
		lists.Add(1)
		list(w, "new-rv", "")
	}))
	sink.cp = &batch.Checkpoint{Scope: "namespace/agent-exec", ResourceVersion: "old-rv", Revision: 1}
	cfg.GapSink = func(_ context.Context, gap Gap) error {
		gaps.Add(1)
		if gap.LastCommittedResourceVersion != "old-rv" {
			t.Error("wrong expired RV")
		}
		sink.mu.Lock()
		sink.getFailures = 1
		sink.getStatus = 503
		sink.mu.Unlock()
		return nil
	}
	p := openTestProducer(t, cfg)
	err := p.Run(ctx)
	if !errors.Is(err, context.Canceled) || gaps.Load() != 1 || lists.Load() != 1 || sink.checkpoint() != "new-rv" {
		t.Fatalf("err=%v gaps=%d lists=%d cp=%q", err, gaps.Load(), lists.Load(), sink.checkpoint())
	}
}
