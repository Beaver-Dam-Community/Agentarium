# Pinned metrics fixture

`tetragon-1.7.1.prom` uses **synthetic counter values**, not a deployed scrape.
Metric names, counter types and lack of labels follow the pinned release:

- [observer registration](https://github.com/cilium/tetragon/blob/v1.7.1/pkg/observer/metrics.go): ring buffer loss and userspace queue loss.
- [eventmetrics registration](https://github.com/cilium/tetragon/blob/v1.7.1/pkg/metrics/eventmetrics/eventmetrics.go): listener overflow.
- [exporter registration](https://github.com/cilium/tetragon/blob/v1.7.1/pkg/exporter/metrics.go): export rate-limit loss.

The deployment seed pins chart/image v1.7.1 in `deploy/gcp/sensors/tetragon-values.yaml`.
`TestPinnedExpositionAndActualPrometheusEncoder` also registers these counters
using the Prometheus Counter API used by upstream, serializes the actual text
exposition, and verifies the parser against that output. Additional labels,
multiple series, client timestamps, wrong types and non-exact integer values
are rejected for these four series. Unrelated metric families are ignored.

These are global counters. They do not establish per-hook losses, loaded hooks,
expected rule digests, probe outcomes, or complete observation coverage. A real
node scrape and capture-verifier integration remain runtime validation work.
