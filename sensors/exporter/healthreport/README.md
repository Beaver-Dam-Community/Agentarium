# Sensor failure reporting

This package implements the detection and reporting boundary of TASK-09 3.5.
It is not a running sensor or proof that hooks, collection, or a server hold work.

`MetricsScraper` reads bounded Prometheus text from an explicit loopback IP
endpoint (no proxy, redirects or compression; one-second deadline, 4 MiB cap).
`ParseTetragon171` maps the pinned v1.7.1 global ring-buffer, queue, listener and
export-rate-limit loss counters. It does not copy global counts into fabricated
per-hook values. Each stage has its own availability bit; a known increase still
requests a hold if another stage is unavailable. Missing, malformed, fractional,
negative, timestamped, duplicate, labeled or non-exact large values remain unknown.
See [fixture provenance](testdata/README.md) for upstream definitions and limits.

`Sampler` reads `Journal.HealthSnapshot` once per sample, combining it with the
metrics and an explicitly supplied `CaptureVerifier`. Nil or failed verification
cannot report healthy. The verifier must check loaded hooks, rule hash, filtering,
rate/aggregation settings and current probe evidence for this node/generation.
There is no production verifier yet: metrics are insufficient to implement one.
Unknown/failed probes must not become pass; TASK-10 owns `probe_failed` and
`sensor_tampering` classification. No new probe API or wire fields are added.

`Supervisor` constructs acquisition and delivery against the same journal and
runs them alongside one-second sampling and the independent reporter. Worker
failure immediately latches unhealthy; actual rotation loss and WAL-full/durable
failure also latch a hold. A metrics deadline cannot block the reporter. On a
worker failure the supervisor keeps reporting and retrying hold requests until
its context is canceled; it does not restart failed workers or delete WAL data.
All caller-supplied adapters must honor context cancellation. The supervisor
joins its workers on shutdown; close the journal only after `Run` returns.

Samples use `time.Now()` before I/O, so a slow response cannot make old evidence
fresh. The legacy `Monitor.Observe` per-hook input remains available to a future
verified per-hook mapping; the pinned Tetragon adapter selects global mode.

`Used` includes retained WAL and quarantine bytes. `Pending` includes outstanding
records and abandoned ranges from all epochs. `AckProgress` is a process-local
monotonic total of durable contiguous watermark advancement across epochs. A
successful HTTP send, individually accepted ID, or duplicate response does not
advance it. The sampler uses the atomic WAL snapshot for consistency. Filtering via
`acquire.Collector` advances only the input checkpoint; it neither creates a WAL
sequence nor counts as ACK progress or capture/probe evidence. Pending replay
from an old epoch remains visible after a new epoch advances. Diagnostics such
as `filtered_by_policy` are not inserted into COMMON's lease payload.

- Spool usage at 80%, any observed required drop increase, a 30-second pending
  backlog without durable ACK progress, `DurabilityFailed`, or `RotationLost`
  latch an unhealthy state and a node `sensor_degraded` hold request.
- Counter reset, missing metrics, or a sampling gap leave a 60-second unknown
  window. They do not claim a quantified loss. No sample or a sample older than
  five seconds is unhealthy. An empty idle spool is not ACK stagnation.
- Call failure methods before the affected worker exits. `WorkerStopped` also
  prevents healthy reports for permanent parsing, authorization, or protocol
  failures without misclassifying those errors as fsync failure.
- `Reporter.Run` sends leases every five seconds with a 15-second TTL. Explicit
  failures wake the loop; a one-second timer checks ACK stagnation independently
  of the delivery loop. Lease and hold requests run independently with four-second
  timeouts. Sinks must honor context cancellation. Pending calls can delay the
  next report by up to four seconds. Failed hold requests retry; only a validated
  `created`/`existing` acknowledgement stops repeated requests in this process.
- HTTPS uses the trusted CA chain, serverAuth EKU, certificate validity, and the
  exact control-health URI SAN. Each request starts a new TLS connection and uses
  the supplied in-memory client certificate callback. No environment proxy or
  redirect is used. Responses are bounded and reject duplicate JSON keys.

No release endpoint is called. Holds stay latched in this monitor and on the
server until the owner's release workflow is implemented. A heartbeat or restart
cannot release a server hold. The 120-second no-drop plus two probe-pass release
flow depends on the separately pending release request contract; this package
must not be used as an automatic recovery implementation. Loaded hook/rule hash
mismatches are reported as unhealthy input; TASK-10 decides `sensor_tampering`.

Tests use pinned-format synthetic metrics, actual Prometheus registry output,
local HTTP/TLS servers and real temporary WAL files. They cover partial/missing
loss stages, reset/stall behavior, malformed and oversized scrapes, replay/ACK
across epochs, policy exclusions, capture failure, worker-loss reporting while
metrics are blocked, independent lease/hold delivery, cancellation and races.
`go test -race ./sensors/exporter/...` and `go vet ./sensors/exporter/...` exercise
these local paths. The WAL tests do actual fsync, restart and recovery.

This remains library integration, not a deployable sensor binary. The WAL and reporter prerequisites are now on main. Kernel normalization is
covered separately by [PR #89](https://github.com/Beaver-Dam-Community/Agentarium/pull/89),
which depends on shared wire spec #87; neither is part of this adapter change.
Production capture/probe verification, authenticated client identity loading/registration,
deployed Tetragon scraping, the hold API transaction and GKE enforcement have not
been exercised. No automatic release, real probe execution, new API fields,
functional-completion metadata or deployment changes are included.
