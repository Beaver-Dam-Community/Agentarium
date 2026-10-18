package healthreport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

const MetricsMaxBytes = 4 << 20

// GlobalLoss keeps the pinned Tetragon v1.7.1 counters global. These counters
// have no hook labels; copying them into per-hook counters invents attribution.
// Order: perf ring buffer, userspace queue, listener overflow, export rate limit.
// Missing series remain unknown independently, so a known loss still triggers
// a hold when another stage is missing. No counters are summed across stages.
type GlobalLoss struct {
	Values [4]uint64
	Known  [4]bool
}

var lossMetricNames = [4]string{
	"tetragon_observer_ringbuf_events_lost_total",
	"tetragon_observer_ringbuf_queue_events_lost_total",
	"tetragon_notify_overflowed_events_total",
	"tetragon_export_ratelimit_events_dropped_total",
}

func (s GlobalLoss) complete() bool { return s.Known == [4]bool{true, true, true, true} }

// ParseTetragon171 accepts Prometheus text exposition from the pinned daemon,
// not a Prometheus federation endpoint with added labels. Presence and shape
// are checked independently of value. HELP text is not used as an authority.
func ParseTetragon171(r io.Reader) (GlobalLoss, error) {
	var result GlobalLoss
	body, err := io.ReadAll(io.LimitReader(r, MetricsMaxBytes+1))
	if err != nil || len(body) > MetricsMaxBytes {
		return result, errors.New("metrics read failed or exceeded limit")
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		return result, errors.New("invalid Prometheus exposition")
	}
	var invalid bool
	for i, name := range lossMetricNames {
		f := families[name]
		if f == nil {
			continue
		}
		if f.GetType() != dto.MetricType_COUNTER || len(f.Metric) != 1 {
			invalid = true
			continue
		}
		m := f.Metric[0]
		if m.Counter == nil || m.Counter.Value == nil || len(m.Label) != 0 || m.TimestampMs != nil {
			invalid = true
			continue
		}
		v := m.Counter.GetValue()
		// Above the exact integer range float64 may erase a one-event increase.
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 9007199254740991 || math.Trunc(v) != v {
			invalid = true
			continue
		}
		result.Values[i], result.Known[i] = uint64(v), true
	}
	if invalid {
		return result, errors.New("invalid pinned loss counter")
	}
	return result, nil
}

// MetricsScraper only reads a directly addressed loopback daemon endpoint.
// It neither follows redirects nor uses ambient proxies. ExpectedVersion is
// enforced by construction (only the deployed 1.7.1 mapping is implemented);
// deployment still must verify the image digest and capture configuration.
type MetricsScraper struct {
	endpoint string
	client   *http.Client
}

func NewMetricsScraper(endpoint, expectedVersion string) (*MetricsScraper, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/metrics" || expectedVersion != "1.7.1" {
		return nil, errors.New("invalid pinned metrics endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() || u.Port() == "" {
		return nil, errors.New("metrics must use an explicit loopback IP and port")
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 16 << 10}
	return &MetricsScraper{endpoint: endpoint, client: &http.Client{Transport: tr, Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (s *MetricsScraper) Scrape(ctx context.Context) (GlobalLoss, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return GlobalLoss{}, errors.New("invalid metrics request")
	}
	req.Header.Set("Accept", "text/plain; version=0.0.4")
	resp, err := s.client.Do(req)
	if err != nil {
		return GlobalLoss{}, errors.New("metrics request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return GlobalLoss{}, errors.New("metrics endpoint did not return success")
	}
	return ParseTetragon171(resp.Body)
}
