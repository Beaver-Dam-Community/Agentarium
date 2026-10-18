package healthreport

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

func metricFixture(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/tetragon-1.7.1.prom")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestPinnedExpositionAndActualPrometheusEncoder(t *testing.T) {
	b := metricFixture(t)
	got, e := ParseTetragon171(bytes.NewReader(b))
	if e != nil || !got.complete() || got.Values != [4]uint64{7, 11, 13, 17} {
		t.Fatalf("%+v %v", got, e)
	}
	// Use the same Prometheus Counter API as upstream 1.7.1 registrations;
	// this catches a handcrafted fixture that differs from real exposition.
	reg := prometheus.NewRegistry()
	for i, name := range lossMetricNames {
		c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "synthetic counter"})
		c.Add(float64(got.Values[i]))
		reg.MustRegister(c)
	}
	families, e := reg.Gather()
	if e != nil {
		t.Fatal(e)
	}
	var wire bytes.Buffer
	enc := expfmt.NewEncoder(&wire, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, family := range families {
		if e := enc.Encode(family); e != nil {
			t.Fatal(e)
		}
	}
	actual, e := ParseTetragon171(&wire)
	if e != nil || actual != got {
		t.Fatalf("actual registry: %+v %v", actual, e)
	}
}
func TestPinnedMetricsRejectInvalidWithoutInventingZero(t *testing.T) {
	name := lossMetricNames[0]
	for _, row := range []string{name + " -1", name + " NaN", name + " +Inf", name + " 1.5", name + " 9007199254740992", name + "{hook=\"process\"} 0", name + " 0 123", name + " 0\n" + name + " 1"} {
		t.Run(row, func(t *testing.T) {
			got, e := ParseTetragon171(strings.NewReader("# TYPE " + name + " counter\n" + row + "\n"))
			if e == nil || got.Known[0] {
				t.Fatalf("%+v %v", got, e)
			}
		})
	}
	for _, kind := range []string{"gauge", "untyped"} {
		got, e := ParseTetragon171(strings.NewReader("# TYPE " + name + " " + kind + "\n" + name + " 0\n"))
		if e == nil || got.complete() {
			t.Fatal(got, e)
		}
	}
	got, e := ParseTetragon171(strings.NewReader("# TYPE " + name + " counter\n" + name + " 0\n"))
	if e != nil || !got.Known[0] || got.complete() {
		t.Fatal(got, e)
	}
	if _, e := ParseTetragon171(strings.NewReader(strings.Repeat(" ", MetricsMaxBytes+1))); e == nil {
		t.Fatal("unbounded body")
	}
	if _, e := ParseTetragon171(strings.NewReader("malformed{\n")); e == nil {
		t.Fatal("malformed accepted")
	}
}
func TestMetricsScraperBoundsAndEndpoint(t *testing.T) {
	fixture := metricFixture(t)
	for _, mode := range []string{"ok", "redirect", "status", "slow", "large"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, "http://127.0.0.1:1/metrics", 302)
				case "status":
					w.WriteHeader(503)
				case "slow":
					<-r.Context().Done()
				case "large":
					io.WriteString(w, strings.Repeat(" ", MetricsMaxBytes+1))
				default:
					w.Write(fixture)
				}
			}))
			defer server.Close()
			s, e := NewMetricsScraper(server.URL+"/metrics", "1.7.1")
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			got, e := s.Scrape(ctx)
			if (e == nil) != (mode == "ok") || (mode == "ok" && !got.complete()) {
				t.Fatalf("%+v %v", got, e)
			}
		})
	}
	for _, endpoint := range []string{"http://localhost:123/metrics", "http://169.254.169.254:80/metrics", "http://127.0.0.1/metrics", "http://a:b@127.0.0.1:123/metrics", "http://127.0.0.1:123/metrics?x=y", "http://127.0.0.1:123/other"} {
		if _, e := NewMetricsScraper(endpoint, "1.7.1"); e == nil {
			t.Fatal(endpoint)
		}
	}
	if _, e := NewMetricsScraper("http://127.0.0.1:123/metrics", "1.8.0"); e == nil {
		t.Fatal("version not pinned")
	}
}
func TestGlobalLossPartialMissingResetAndReporter(t *testing.T) {
	for i := range 4 {
		m, s, now := NewMonitor(), goodSample(), time.Now()
		s.GlobalMetrics = true
		s.GlobalLoss = GlobalLoss{Known: [4]bool{true, true, true, true}, Values: [4]uint64{7, 11, 13, 17}}
		if e := m.Observe(now, s); e != nil {
			t.Fatal(e)
		}
		s.GlobalLoss.Known[(i+1)%4] = false
		s.GlobalLoss.Values[i]++
		if e := m.Observe(now.Add(time.Second), s); e != nil {
			t.Fatal(e)
		}
		sink := &fakeSink{}
		r := reporter(t, m, sink)
		if e := r.Report(context.Background(), now.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		if len(sink.holds) != 1 || sink.leases[0].ObservedState != "unhealthy" {
			t.Fatalf("loss %d hidden by missing stage", i)
		}
	}
	m, s, now := NewMonitor(), goodSample(), time.Now()
	s.GlobalMetrics = true
	s.GlobalLoss = GlobalLoss{Known: [4]bool{true, true, true, true}, Values: [4]uint64{10, 0, 0, 0}}
	_ = m.Observe(now, s)
	s.GlobalLoss.Known[0] = false
	_ = m.Observe(now.Add(time.Second), s)
	s.GlobalLoss.Known[0] = true
	s.GlobalLoss.Values[0] = 11
	_ = m.Observe(now.Add(2*time.Second), s)
	if !m.State(now.Add(2 * time.Second)).NeedsHold {
		t.Fatal("missing erased baseline")
	}
	m = NewMonitor()
	s.GlobalLoss.Values[0] = 10
	_ = m.Observe(now, s)
	s.GlobalLoss.Values[0] = 0
	_ = m.Observe(now.Add(time.Second), s)
	if state := m.State(now.Add(time.Second)); state.Healthy || state.NeedsHold {
		t.Fatal("reset fabricated loss or health", state)
	}
	for i := 2; i <= 61; i++ {
		if e := m.Observe(now.Add(time.Duration(i)*time.Second), s); e != nil {
			t.Fatal(e)
		}
	}
	if !m.State(now.Add(61 * time.Second)).Healthy {
		t.Fatal("unknown window failed to expire")
	}
}
