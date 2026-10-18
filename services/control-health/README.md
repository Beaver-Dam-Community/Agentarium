# Control health

This checkpoint implements lease reception, scope health queries and durable
lease-expiry holds, and registered component hold requests. It is not the full
TASK-10 correlation/readiness service.
The existing node-readiness client response keys are preserved, including empty
arrays and null `startup_capture` when no current node/boot has been established.
A heartbeat does not prove hooks loaded, probe success or worker readiness.

State-change events call TASK-07 `audit.audit_append()` in the same PostgreSQL
transaction. A missing audit grant/function prevents that state transition from committing.

The migration supports PostgreSQL 16+ non-superuser CREATEROLE installation,
with database CREATE and ADMIN on pre-existing health roles. Temporary owner
SET/INHERIT privileges are removed at transaction end. It creates the COMMON
`coordinator_reader` and `gateway_reader` group roles when absent, with only
their specified health SELECT grants. Service login membership is installed by
the consuming Task. `loaded_artifact_digest` has its own nullable column.

Prerequisites are the health migrations, the TASK-07 audit migration (#56),
TASK-03 registered workloads/certificates and install-time principal/source
registrations. `control_health_writer` gets no DDL, principal-table writes or
hold-release privilege. The installer must grant it `audit_producer` membership,
register the actual login/source, grant the three business event types
`execution_held`, `hold_requested`, and `source_health_changed` for tenant `*`, and grant the
specified TASK-03 identity read columns. The service never creates identities,
principals, schema or grants at startup.

Run the binary with `DATABASE_URL`, `--identity-url`, `--bootstrap-token`,
`--tls-ca`, `--epoch-dir`, and `--profile`. Bootstrap/renewal uses in-memory keys
and exact service SAN verification. Existing file certificate mode remains for
tests. The epoch directory must be on a retained persistent volume: an exclusive
OS lock and fsynced counter ensure increasing epochs across process restarts,
without depending on wall-clock time. Corrupt or missing initialized counters
fail closed. Losing the entire volume requires a newly registered source ID; do
not recreate it empty under an existing source. Use a single replica with Recreate
for this producer source. Example profile structure (replace installation values):

```json
{
  "sources": [],
  "readers": ["spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway"],
  "guarded_profile": false,
  "audit_source_id": "example-control-health",
  "version": "installed-image-version"
}
```

New global/node/workload replicas need no per-Pod profile entry. Global scope
is `*`, node scope must match the live certificate node UID, and workload scope
is the certificate namespace/KSA. Target sources retain explicit installation
bindings because certificates do not carry target identities. Existing source
rows remain bound to their original principal SAN. The server checks live principal component
and allowed scopes, enabled workload registration and an unexpired/unrevoked
certificate by its hex serial. Node leases require its certified node/current
boot; node-sensors additionally require the current sensor generation. Even if
listed among readers, node-sensors can read only their own current node/boot.
Node lease `source_id` is per node, `<component>-node/<node_uid>`, with the
node part equal to the lease scope (the certified node). Shared or other-node
source IDs are 403, each node keeps one row per component, and another row on
the same node never covers an expired node lease. The component token is
checked as a lowercase label until COMMON fixes the per-component strings.
Until then the label is not bound to the component: one node principal could
report under two labels for its own node (`sensors-node/X`, `foo-node/X`); it
still cannot report or cover another node. Both `Put` and `Expire` ignore other
rows when deciding whether an expired node lease is covered.
Timestamp checks reject old/future reports and TTL extension. Replay is rejected.

Queries use a single repeatable-read snapshot. Lease ingestion, Health queries
and expiry processing reject multiple non-retired boots for the same node; a
newer `updated_at` never selects an authoritative boot. Such inconsistencies
return an error and roll back state/audit writes until the stale boot is explicitly
retired. Zero-row bootstrap/absent-state behavior remains unchanged. Optional netpol-collector leases
are returned but never contribute to missing components or health state.
Unsupported profiles do not require runtime-guard/start-coordinator. Expiry
writes a durable hold and audit event atomically; a renewed heartbeat alone
cannot release a hold. Probe rows are summarized only within the current boot
and consecutive runs with no gap over 62 seconds.

## Component hold requests

`POST /internal/holds` accepts only `scope`, `scope_id`, `reason`, and
`evidence_refs` for registered components. It checks the live principal's reason
and scope grants and the enabled, unexpired, unrevoked certificate. Local node
components must target their own certified current node/boot. Netpol collectors
and probe runners cannot request holds. The reason's owner is server-selected;
the request cannot supply its own owner, requester, source, or security detail.

Creation uses the existing unique open-hold constraint. Concurrent retries return
one hold ID without rewriting its owner. A new hold, `hold_requested`,
`execution_held`, and current node state `held` commit together. An existing hold
still requires a fresh authorization check and a committed `hold_requested`.
Request evidence is preserved, and requester comes from verified mTLS identity.
The server answers only after COMMIT. Any audit failure rolls the transaction
back. Node updates use the existing TASK-10 writer privileges from M1 #55;
this change adds no hold release or certificate/principal mutation privileges.

Node-scoped requests take the existing bootstrap advisory lock, inspect all current
boots, write the hold and only then update the node row. This keeps hold writes
before node row locks and serializes boot retirement. Zero or multiple current
boots return retryable 503; a real certificate node/boot mismatch remains 403.
Database lock waits are bounded to two seconds. A hold released between a losing
INSERT and the following existing-hold lookup can yield retryable 503; no success
ACK or request audit is committed for that failed transaction.

This depends on shared spec #74, which must merge first. M1 #55/#56 are merged.
Shared spec #129 resolves #118 with `HOLD_REQUEST_DENIED` and controller-owned probe holds; #129 must merge before this implementation. `operator_stop`
needs the separate BFF identity/role check and durable session-revocation flow;
`risk_event` needs a correlation decision with reason_detail. The generic endpoint
rejects both until those flows are connected. Hold release and automatic recovery
are also separate remaining work. No heartbeat clears a persisted hold.

`tests/correlation/run-health-local.sh` runs actual PostgreSQL tests. The runner
finds the merged audit migration by default; `HEALTH_TEST_AUDIT_MIGRATION` can
select an explicit fixture migration. The tests use
that actual audit function and the merged TASK-03 schema migration, but not a
deployed identity service. The test also sends real mTLS requests through the
production handler to PostgreSQL: lease commit, full snapshot response keys,
replay rejection and certificate revocation on an existing connection are
checked. A local CA supplies test certificates; this does not verify CAS issuance.
Hold tests use the actual audit migration and non-owner writer login: 12
concurrent requests produce one hold, 12 request events and one execution event
with matching outbox rows. An additional 24 simultaneous global requests, with no
node row serialization, converge on one hold and 25 event/outbox rows. Missing
grants roll back state/events; old/revoked
certificates, another node and disabled registrations are rejected. Real mTLS
requests verify create/existing responses, committed snapshot state, failed audit
503 and revoked-certificate 403. The HTTP fixture is the production handler and
PostgreSQL, with a local CA instead of CAS.
`go test ./...` skips PostgreSQL tests without the explicit
admin DSN. The shared Go-service Dockerfile builds `./services/control-health/cmd/control-health`.

Remaining M2/integration work: bundle acknowledgement via desired_bundle and
Deployment replicas, production node-facts wiring,
netpol-collector gap transitions, worker/readiness challenges, node-bridge and
runtime relay paths, correlation, GKE/Cloud SQL deployment and live admission/
network validation. `bundle_ack` stays null and challenge arrays stay empty;
these do not assert successful verification. Authenticated hold authorization
failures return 403/rejected with `HOLD_REQUEST_DENIED` under shared spec #129.
Other endpoints retain their existing error behavior. Direct probe-runner hold
calls stay prohibited even with an accidental grant. Only `control-health` and
`destination-evidence` may request/own `probe_failed`; the probe-results validation
and release pipeline remains separate unfinished work in #99.

## Probe results and hold recovery (M2-4)

Both APIs follow the #99 owner decision and the contract in #159.
`POST /internal/control-health/probe-results` takes the COMMON wire and returns
201 `{probe_result_id}`. Each kind has one scope and one reporting component:
`process`/`tcp`/`file` are node probes from `probe-runner` only, `export` is
global or node-scoped from `audit-export` only (node scope without `boot_id`),
and `receipt` is target-scoped from `destination-evidence` (installation target
binding). Node reports require a certificate bound to that node and current
boot; node answer probes store the runner's certified namespace
(`agent-exec`/`agent-adapters`). `outcome` is stored as `result`, `judged_at`
is DB time, `stimulus_at` is stored for answer probe passes only (#179) and
`missing_events` stays empty. A pass needs evidence references. The migration's
`probe_results_kind_fields` CHECK enforces the same combinations. A failed node
answer probe creates a control-health-owned `probe_failed` node hold with
`execution_held` in the same transaction; reports never request or release
holds themselves.

Two consecutive passes count only when they are 58 to 62 seconds apart (60s
interval within 2s skew; receipt 3 to 7 seconds) and judged after the hold was
created. Answer probe spacing is the `stimulus_at` difference; export and
receipt spacing is the `judged_at` difference. Reports closer
together are one stimulus window, so a burst cannot satisfy recovery; any
`fail`/`unknown` ends the run. Node holds need all three answer kinds plus live
required node leases (node-sensors at the current generation); global holds
need `export` passes and a live owner lease; target holds need `receipt`
passes and a live owner lease. A heartbeat alone never releases a hold.

Control-health releases its own `probe_failed`/`lease_expired` node holds in
the passing probe's transaction and in a periodic sweep
(`auto:control-health:<probe_result_id>`). Other owners call
`POST /internal/holds/{hold_id}/release` with `{justification, evidence_refs,
probe_result_ids}`. The caller must be the hold owner with the reason
releasable, bound to the held node/boot or target, and cite exactly the two
latest counted passes of each kind. Security reasons are released only by the
console BFF SAN with `operator` role and a matching actor header
(`operator:<actor>:<console_request_id>`); operator approval cannot release
transient reasons. The response is `{hold_id, released_at, release_ref}` after
`hold_released` commits in the same transaction. Workload/session holds and
global `lease_expired` have no automatic release; `start_unknown`,
`policy_activation` and `db_unavailable` use the owner-attested path below.

Lease writes, expiry, probe reports, releases and the sweep take the node
advisory lock before hold rows, then node rows. The `ready` transition is a
conditional UPDATE that refuses while any node hold is open. Migration
`20261017172318_health_probe_recovery` adds the probe scope columns and CHECK,
grants `control_health_writer` INSERT on `probe_results`, and UPDATE only on
`holds(released_at, release_ref)`. The installer must grant the `hold_released`
event type for tenant `*`.

Export probes (#163) come only from `audit-export`, for global or node scope
with `node_uid` and never `boot_id`. `export_lag` releases
after one export pass: the cited ID must be the newest export result for that
scope since the hold was created (a newer fail blocks), with a live owner
lease at global scope. An unknown hold returns 404 `RESOURCE_NOT_FOUND`; an
already released hold 409. `audit_integrity` is a security reason (operator
approval only). Migration `20261017172319_health_audit_integrity` adds it to
the holds CHECK and registers `audit-exporter` (`audit-export`, scopes
global/node, request and release `export_lag`) and `audit-verifier` (global,
request `audit_integrity`), refusing a pre-seeded row with other grants.

Answer probe passes (#179) carry `stimulus_at`. control-health finds the
evidence itself: the runner certificate's `pod_uid` gives its containers on
that node/boot (`correlation.lifecycle_intervals`), and the TASK-07 definer
function `audit.probe_evidence_events` (migration
`20261017172320_audit_probe_evidence`, EXECUTE only, no table SELECT) returns
`[stimulus_at-2s, stimulus_at+10s]` of those containers plus tuple-matching
`tcp_state` rows. The full 3.2 table is required (process exec+exit; tcp
connect with ESTABLISHED and CLOSE; file_open 0, openat ≥ 0 and openat
EACCES; an openat without a return value never counts), else 409 and nothing
is stored. `stimulus_at` must be within 40s of server time. Found rows are
stored as `kernel_event:` refs and recorded in `health.probe_evidence_uses`,
so each kernel event backs one pass. Order, consecutiveness and recency use
the server `judged_at`. Spacing uses `stimulus_at`: a runner waiting for kernel
ingest retries with the same `stimulus_at`, so `judged_at` drifts, while
`stimulus_at` is bounded to server time and backed by consumed kernel events.

Release (#159 after review): for every required kind, the newest cited pass of
that kind must be within the kind's interval of now (answer/export 62s,
receipt 7s); a fresh pass of one kind never stands in for an old pass of
another, and the `ready` transition applies the same rule. Passes older than
that interval never release; a pass recorded within the interval while a
lease was expired can release once the lease is renewed. Receipt spacing is 3–7s.
`policy_activation` (releaser), `start_unknown` (start-coordinator) and
`db_unavailable` (audit-db) use the owner-attested path: owner SAN, evidence
refs only, `attested:<component>:<ref>`. Operator approval follows the
operator_stop rules, `approved_at` must be within the last 300s, and one
`(actor, console_request_id)` releases one hold. A repeated request that maps
to the stored `release_ref` returns the stored response; `hold_released`
records the justification. `Recover` commits each node separately.

Probe runner reporters (TASK-10 3.2 "relayed reporter identity"). Runner
certificates are Pod-bound (`.../ns/<ns>/sa/probe-runner/pod/<uid>`); the
`component_principals` row is keyed by the KSA service SAN
(`.../ns/<ns>/sa/probe-runner`, component `probe-runner`, scopes `{node}`), and
the issued record must name the same Pod. The agent-adapters runner connects
directly with its Pod SAN, which is accepted on `probe-results` only (401 on
every other route). The agent-exec runner reports through the gateway relay:
on a connection whose certificate is the registered `gateway` principal,
`X-Agentarium-Peer-Identity` and `X-Agentarium-Peer-Certificate-Serial` must
both be present once (else 403) and name an agent-exec probe runner Pod
certificate that is issued, unrevoked, unexpired and of an enabled workload.
On any other connection the two headers are ignored.

Not verified here: `sensor_degraded` drop-counter history and any live
cluster run (the relay is covered against PostgreSQL 16 with a local CA).
`tests/correlation/live-health-recovery.sh` is the cluster drill; it has not run.

Contract/integration questions retained from #55 review:
- Coordinator `FOR SHARE` uses the restricted functions merged in #79/#80,
  without reader UPDATE grants. Consumer wiring is #116; the remaining lease
  generation question is tracked in #39.
- First sensor leases create the current node/boot through `KubeNodeFacts`
  (#104/#189) when `--startup-capture` points to the mounted
  `control-health-startup-capture` file; without the file a nil source keeps
  rejecting new boots. See "NodeFacts operation" below.
- Workload lease scope uses certified namespace/KSA; gateway maps adapter_id via
  registered_workloads. COMMON loaded_artifact_digest is authoritative over the
  older TASK-10 active_version bundle wording; schema preserves both columns.

## NodeFacts operation

- The startup_capture file is read once at process start. After the installer
  re-renders the `control-health-startup-capture` ConfigMap (new Q0 run, a row
  rewritten to `not_measured`, or the first installation of the key), restart
  the control-health Deployment; a running Pod keeps the old rows.
- The ConfigMap volume is `optional`. If it is absent or the key name is wrong
  at start, the process logs `startup_capture not installed` and keeps new boot
  registration disabled. Check that log line after every install or restart.
  A present but invalid file fails startup.
- Each first report LISTs all Nodes (no UID field selector) within the 2-second
  bootstrap budget. The client uses QPS 20 / burst 40 instead of client-go's
  default 5 / 10; during a large pool upgrade some first reports can still time
  out and are rejected until the sensor retries.

## Node bootstrap draft

When a trusted `Store.NodeFacts` implementation is installed, the first valid
`node-sensors` lease for a new boot creates a `preparing` row with the schema's
initial sensor/guard generation of 1. The facts source must freshly resolve the
certified node UID to its current Kubernetes boot and that node pool's measured
Q0 `startup_capture`. Empty or unknown Q0 results are refused; they are never
converted to `unsupported`. Only a live authorized node-sensors certificate
and initial generation 1 can establish the row.

Bootstrap is serialized by a transaction-scoped advisory lock on the node UID,
including the no-existing-row case. The transaction sets PostgreSQL lock_timeout
to 2 seconds before taking that lock; a timeout aborts and rolls back the lease.
Old boot rows are retired without deleting
history, and a retired boot is never resurrected. Node changes and the accepted
lease commit in the same transaction. Failed TTL validation or other storage
errors roll both back. A heartbeat never marks a node ready or releases a hold;
probe evaluation and recovery remain separate work. Existing preprovisioned
boots retain the M1 path, and no Kubernetes or lock adapter is enabled by the
binary yet. This draft therefore does not remove live deployment prerequisites.

The PostgreSQL 17 integration tests use the real non-owner writer login, actual
migrations and lease transactions. Injected node/Q0 fixtures cover 12 concurrent
first reporters, new-boot retirement, rollback after an invalid first lease,
missing Q0, mismatched node/current boot, a non-sensor caller, generation mismatch,
old certificates, refused historical-boot resurrection, and a held advisory lock
that fails with PostgreSQL 55P03 after 2 seconds and leaves no boot/lease row. Those fixtures do
not verify Kubernetes currentness, Q0 measurement, or GKE lifecycle behavior.
## Restricted coordinator row locks (shared spec PR #79)

The follow-up migration adds `health.lock_dispatch_holds` and
`health.lock_dispatch_node`. Only `coordinator_reader` receives EXECUTE;
SELECT permissions remain unchanged and no reader UPDATE is added. The functions
run as `health_owner`, use fixed search paths and qualified table names, and
hold matching rows with `FOR SHARE` until the caller transaction finishes.

The coordinator must call both functions in its existing transaction and lock
order, set its two-second lock timeout, and validate hold reasons, boot and lease
generations. Node lookup returns every non-retired row; zero or multiple rows
must fail readiness instead of picking a row. New hold inserts are not prevented
by existing-row locks, so the permit check must repeat the lookup. These functions
do not implement the coordinator adapter or bootstrap a current node.

The migration implements merged shared spec #79 on the Health schema from #55.
Disposable PostgreSQL 16
and 17 tests cover non-superuser migration up/down/up, owner membership cleanup,
matching scopes, reader mutation denial, writer EXECUTE denial, temp-object
shadowing, and competing updates blocked until the calling transaction commits.
This is local DB evidence, not a deployed coordinator reservation test.

## Work readiness and session workers (TASK-10 3.5a/3.5b, M3-1)

Migrations `20261017210000_audit_worker_exec_evidence` (TASK-07 lookup function and FK privilege) and `20261017210001_health_work_readiness` (`health.session_process_bindings`, `health.work_readiness_checks`, `health.worker_challenges`, `health.worker_evidence`).

| Route | Caller | Result |
| --- | --- | --- |
| `POST /internal/control-health/session-workers` | gateway principal, `X-Agentarium-Peer-Identity` = runtime Pod SAN | 202 pending binding, idempotent per `worker_instance_id`/registration digest, 409 `WORKER_REGISTRATION_CONFLICT` |
| `GET /internal/control-health/session-workers/{id}`, `POST .../{id}:close` | same | own binding only (403 `WORKER_BINDING_MISMATCH`); close is idempotent |
| `POST /internal/control-health/worker-observation-results` | node-sensors of the challenge's node and current boot | 201; binding `observed` only when the witness matches the registered hints and one committed `process_exec` row (`audit.worker_exec_evidence`) |
| `POST /internal/control-health/work-readiness/checks` | gateway, forwarded runtime SAN | 202 pending check with a 15 s node nonce |
| `POST /internal/control-health/pod-observation-results` | node-sensors of the node/boot | 201; final transaction sets `ready` (at most 3 s) or `blocked` |
| `GET /internal/control-health/work-readiness/checks/{id}` | gateway, forwarded runtime SAN | own check and `remaining_valid_ms`; 404 unknown, 403 `WORK_READINESS_BINDING_MISMATCH` |

`X-Agentarium-Peer-Identity` is accepted only on a connection whose certificate is a `component_principals` row with component `gateway`; any other caller sending it is 403. Node nonces are listed in `pending_worker_observation_challenges` and `pending_work_readiness_challenges` of the node-scope `GET /internal/control-health` for that node's own node-sensors only. The profile needs `"environment"` (the `release.active_policy` scope_id); without it every check is 503.
