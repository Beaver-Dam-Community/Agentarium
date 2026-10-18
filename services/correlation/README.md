# Correlation join checkpoint (TASK-10 3.1)

`internal/join.Match` calculates socket candidates from a verified historical
snapshot. It is a pure Go function, with no DB, HTTP, message queue, Kubernetes
client, clock reads or durable writes. This checkpoint does not complete M2-4
or the M3 observation flow.

The engine indexes lifecycle intervals by node/boot/full container ID, adapter
observations by netns/local tuple/Pod, and established state events by
node/boot/sock_ptr/full tuple. It compares connect source time with the adapter's
inclusive `[connect_started_at - 2s, send_started_at + 2s]` window. ESTABLISHED
must be inside `[connect.source_time, send_started_at + 2s]`. The lifecycle
interval must identify the same Pod at that source time and the same node/boot.
Neither PID, Pod name, current Pod IP nor an injected request ID is an input.
State events deliberately have no process/Pod/container fields: softirq metadata
cannot establish attribution. sock_ptr is never compared with userspace cookies.

A pair becomes `confirmed` only if every condition succeeds and the eligible
pair is unique in both directions. The kernel process exec ID is required for
confirmed attribution. Multiple observations for one connect and multiple
connects for one observation both retain only a verified workload relation.
Without a unique historical workload mapping the result is `unlinked`.
Candidate count means pairs satisfying all socket conditions, including state;
when the other socket conditions match but state is missing, candidate count is
zero and the diagnostic is `state_event_missing`.

Only confirmed results contain attempt/action/process attribution. There is no
session field: COMMON Correlation does not define one, and worker-session
attribution is a separate mechanism. An `agent-exec` workload never receives
confirmed attribution, even if a caller erroneously supplies a matching adapter
observation. The MVP gateway does not record the required socket observation.

Normalization requires the selected algorithm version and a measured Q0 run ID.
An identical destination address without a measured rule is insufficient.
Rules support the schema's VIP/endpoint directions; overlapping rules producing
multiple canonical destinations are ambiguous. When both sides report endpoint
addresses, different concrete endpoints are not equated merely because they fall
inside the same rule CIDR. Results and evidence lists are sorted, input slices
are never changed, and duplicate kernel/attempt/interval identities fail closed.
Recomputing after late data produces a new result without modifying prior results.

## Verified-input adapter boundary

The structs are internal calculation types, not new wire contracts. Before
calling this engine, an adapter must authenticate the source, validate wire IDs
and digests, select authoritative lifecycle revisions, derive historical
namespace/KSA workload mappings and load real TASK-03 observation/action
relations. `Snapshot` must include all possibly matching connects and
observations across the complete overlapping windows. Passing a preselected
singleton cannot prove uniqueness. This function cannot prove that a future
storage adapter supplied complete data or genuine Q0 evidence.

The [lifecycle package](internal/lifecycle/README.md) derives and stores classified
intervals. The [results package](internal/results/README.md) persists trusted
correlation calculations, allocates revision IDs and atomically appends the real
`kernel_correlation_checked` event. Source-consumer integration, authoritative
history selection and COMMON method/evidence translation from this engine
remain unimplemented. Internal diagnostics are
not added to a public enum. No source event is rewritten or given a session ID.

The following details remain explicit review questions rather than new shared
contracts:

- TASK-10 does not specify lifecycle end-boundary inclusivity. The current
  calculation excludes the exact end instant and unknown-ended intervals;
  known open intervals and known closed interiors can match. The lifecycle
  adapter contract must settle endpoint semantics before runtime wiring.
- The normalization table defines service VIP/endpoint rules but no explicit
  representation for measured direct/external destinations. Such destinations
  stay below confirmed until their measured rule representation is agreed.
- The results store allocates IDs/revisions with optimistic concurrency. The
  trusted calculation adapter must still supply method/evidence wire encoding
  and complete source history; storage does not prove input authenticity.

## Verification

```sh
go test -race ./services/correlation/...
go vet ./services/correlation/...
```

Table tests cover every matching dimension, both ambiguity directions, missing
state, old-boot/container reuse, observed/unknown/open intervals, exact time
bounds, unmeasured/overlapping normalization, both endpoint directions,
exec-workload confidence limits, late ambiguity, deterministic ordering and
concurrent calls without input mutation. These are local engine tests, not
actual PostgreSQL, CAS, Tetragon, adapter transport, GKE or end-to-end evidence.

## Durable evaluation queue

`correlation.pending_inputs` contains only unacknowledged kernel/netpol input IDs.
INSERT triggers enqueue them in the source transaction. Successful worker,
netpol and risk evaluation removes the exact input IDs; failed windows remain
pending. A transaction that commits after a scan is visible on the next scan,
even when its source time or received_at is old. Completed history and receipt
anti-joins are absent from the scheduling query.

Run migrations through `20261018102002` before starting this version. The
trigger-installation DDL and the one-time retained-evidence backfill are separate
migrations, so the backfill does not retain trigger-installation locks. The
backfill still scans all retained raw evidence and needs a measured maintenance
budget on the target database. Do not start the queue consumer until backfill
commits. Reinstalling the queue re-evaluates retained inputs using idempotent
result stores.

Pending uses at most 64 nodes and 128 inputs per node per tick. Short pages wrap
without wasting an empty tick; failed nodes remain eligible on later passes.
Sustained input above this bounded drain rate can still grow backlog. The recent
source-time tail also runs to reconsider late join evidence. Neither mechanism
claims unlimited throughput or actual GKE verification.

`CORRELATION_QUEUE_LOAD_ROWS=3000000 CORRELATION_POSTGRES_IMAGE=postgres:16 bash tests/correlation/run-netpol-local.sh -v`
adds a disposable PostgreSQL load fixture with three million completed records,
40 nodes and five delayed pending inputs. The fixture omits queue entries for
completed history; it measures pending selection, not full correlation throughput.
