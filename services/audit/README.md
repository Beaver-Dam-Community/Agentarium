# Audit writer and export components

The business-event writer and the lifecycle batch receive path are implemented,
with local PostgreSQL and mTLS verification. M2 export components cover sequenced
business/kernel/lifecycle batches, signed manifests, source-range verification
and measured backlog Health reporting; see
[export scope and verification](internal/export/README.md). These components are
not a completed TASK-07 deployment or external export proof.

The writer requires a PostgreSQL login in `audit_writer`, the TASK-03
`identity.registered_workloads` table, and mTLS material issued by identity.
Migrations create no login passwords or source grants. The installer must:

1. Apply the audit migration with a migration identity with CREATEROLE and CREATE on the database. The migration temporarily
   grants the `audit_owner` NOLOGIN role for schema creation, then revokes that
   membership before commit. Existing full owner membership is preserved. Never run the writer as that owner.
2. Register each actual login in `audit.db_role_sources`. Only an `audit_writer`
   member may have `proxy=true`. Direct producers get their own source binding.
3. Register exact `(source_id,event_type,tenant)` grants. `*` is a literal
   tenant, not a wildcard over business tenants.
4. Grant the writer read access to TASK-03 registered workload columns after
   identity is installed. Install cross-task view/FK grants from TASK-07 3.1
   when those reader roles exist. The required `gateway_app` NOLOGIN group is
   created if absent; only that group gets `audit.enqueue_decision_input` EXECUTE
   and schema USAGE, with no base-table access. Other cross-task role grants
   remain installation inputs pending ownership assignment.
5. Supply a JSON array of trusted source bindings in `--sources`:
   `[{"source_id":"example-source","namespace":"agent-control","ksa":"coordinator","principal":"example-principal"}]`.
   The principal is checked against the live, enabled registered workload on
   every request. Sharing a KSA certificate also shares its security principal;
   the PKI contract cannot distinguish replicas carrying the same service SAN.

Run with `DATABASE_URL`, `--identity-url`, `--bootstrap-token`, `--tls-ca`, `--sources`,
`--health-url`, `--health-source-id`, and `--version`. The audit-db reporter
checks a real database transaction and writer privileges every five seconds
and sends a 15-second lease; it does not claim that export is healthy.
The identity bootstrap uses the TASK-03 CSR/token wire contract merged in PR #53. Keys are generated and retained
in memory, certificates are verified for exact SAN/chain/EKU and renewed halfway
through their lifetime. Failed renewal retains the prior valid certificate; expiry
fails closed. The `--tls-cert`/`--tls-key` file mode remains available for tests.
The default listener is `:8443`; HTTP is not exposed. Credentials and event
bodies are not logged. Certificates and trust roots reload each TLS handshake.
The image uses the existing `build/docker/go-service.Dockerfile` with
`CMD=./services/audit/cmd/writer`.

The `audit.audit_event_ack(uuid,text,text)` contract and safe-integer bound were
merged in PR #52. The helper returns only the original timestamp and only to a registered writer
proxy; it does not give producers table SELECT. JSON integers follow COMMON's
safe integer bound, including sequence. TASK-07's conflicting 64-bit wire bound
was corrected by that contract. Direct jsonb callers must validate raw
JSON before casting: PostgreSQL jsonb has already discarded duplicate names
and exponent spelling, which the function cannot recover.

The HTTP handler enforces the COMMON size, strict JSON, identity and digest
contract. PostgreSQL repeats shape, canonical digest, registry, source and
exact tenant grants, then writes event/outbox atomically. Same ID/digest returns
the original timestamp; a different digest rolls back and writes a separate
conflict incident. A different ID reusing an epoch/sequence is schema-invalid.
Authorization denials return 403 with an empty `reason_codes` array because
COMMON defines no TASK-07-specific authorization code; no new enum is invented.
`schema_version` is numeric `1` per TASK-07. The discovery producer's schema
version and text epoch were aligned in merged PR #54.
This receiver follows that shared integer schema version and text epoch contract.

Validate with `tests/audit/run-local.sh`; it creates and removes a disposable
loopback-only PostgreSQL container. Unit tests cover strict input, HTTP status
mapping and a real mutual-TLS handshake. PostgreSQL tests cover atomic rollback,
16 concurrent retries, durable conflict records, source/tenant boundaries,
role privileges, registry/shape validation, SQL/Go canonicalization and down/up.
The migration and down/up run as a real non-superuser CREATEROLE login, checking
that temporary owner access is removed. Use `AUDIT_POSTGRES_IMAGE=postgres:17-alpine`
for PostgreSQL 17. The gateway enqueue function is checked for atomic rollback,
idempotent retries, invalid input and caller/base-table permission boundaries.
An escaped NUL rejected by PostgreSQL jsonb maps to HTTP 422, not a retryable 503.
The same disposable DB test connects the real mTLS handler, live registered
workload authorizer and writer login to PostgreSQL: 201 commit, duplicate receipt,
409 conflict, wrong SAN/source and disabled registration are checked against
actual event/outbox rows. Its CA is local and does not verify identity/CAS issuance.
Set `AUDIT_TEST_ADMIN_DSN` only for an explicitly disposable test cluster if
running integration tests directly. Ordinary `go test ./...` skips that DB test
when the variable is absent.

`cmd/verify/recovery_integration_test.go` is the local stand-in for the M2-2
"records remain queryable after Pod deletion" check. It applies every merged
migration as the DSN superuser (the non-superuser installer path is covered by
#156's tests) and then performs the source/grant registration steps above, runs the built writer binary, kills it
with SIGKILL, and confirms that a new writer process returns the original
receipt for a retry. It then exports through the outbox worker and publisher as
`audit_exporter` under the PostgreSQL manifest lease and runs the built
verifier binary as `audit_verifier` in a separate process
against a local GCS/KMS contract fixture (create-only uploads, CRC32C, pinned
reads, 403 `retentionPolicyNotMet` on delete/replace). ACK drift and a batch
object removed outside retention must fail verification, store an
`export_verification_failed` event through a running writer and raise an
`audit_integrity` hold. It is not a GKE Pod,
Cloud SQL, or real GCS/KMS run.

Not yet complete in this branch: Cloud SQL/GKE deployment and runtime work-event relay. `cmd/exporter` and the verifier incident
path are described in the export component README. Daily anchors are out of MVP scope (#98). The
coverage, lease, verifier role and retention job are described in the export
component README; actual GCS/KMS and GKE Pod-deletion recovery remain unverified.


## Kernel batch ingest (TASK-07 §3.3, COMMON "Kernel source authentication and epoch")

`POST /internal/kernel/events:batch` is enabled with `--kernel` and
`--kernel-node-cidrs`. It shares the durable receiver epoch directory
(`--lifecycle-epoch-dir`) with the lifecycle path. Only the TASK-09 exporter's
exact SAN `spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon` from a node
CIDR is accepted; the handler passes only the verified leaf serial/SAN to
migration `20261018074000`'s six-argument `audit.ingest_kernel_batch`. Installer
steps: a `SourceBinding` for that SAN (`agent-sensors`/`tetragon`), the grant
`(tetragon SAN,'kernel_event_observed','*')`, the receiver's two `*` grants
already used by lifecycle, and the issued certificate/current boot rows that
identity and health maintain.

The SQL function repeats the source, certificate, current-boot and runtime
epoch checks; binds a new epoch to the cert node and the current or retained
historical boot; validates each KernelEvent (fields, types, event-type rules,
socket tuple, canonical ID and digest, node/boot equal to the binding); stores
records and outboxes; writes abandoned ranges as gap + two receiver audit events
+ outboxes; and advances the contiguous watermark in one transaction. Rejected
inputs never raise `max_seen`. A different digest for an existing record is an
`EVENT_ID_CONFLICT` with an atomic `event_conflicts` row. Concurrent requests for
one epoch fail fast with SQLSTATE 55P03 (503) and are retried by the producer.

`internal/store/kernel_ingest_integration_test.go` runs these rules on
PostgreSQL 16 with every merged migration and a restricted writer login,
including rollback when the second receiver audit fails, same-range retry,
different-body/overlap conflicts, historical replay evidence, Go/SQL validation
parity and eight concurrent identical requests. It also drives the real handler
over mTLS with the TASK-09 `wal`, `delivery` and `batch` packages: WAL ack after
commit, a receiver rejection quarantined and declared as an abandoned range, and
refusal of another SAN. It does not run Tetragon, Kubernetes or Cloud SQL.
## Kernel wire and storage alignment (TASK-07 §3.3)

`internal/ingest.DecodeKernelRecord` and `DecodeKernelEnvelope` validate the
approved producer wire: deterministic UUID/digest, exact fields and JSON limits,
source/epoch consistency, nullable `process_exec_id` only for `tcp_state`,
`tcp_new_state`, 16-character lowercase hexadecimal `sock_ptr`, optional socket
metadata and abandoned-range digest. Normalizer/batch integration tests use the
actual tracked Q0 event fixtures; metadata resolution in those tests is a fixture.

Migration `20261017103710` aligns the existing kernel table with those approved
fields. `process_exec_id` becomes nullable only for `tcp_state`, and `sock_ptr`
is nullable text constrained to exactly 16 lowercase hex digits. Existing IDs,
digests, timestamps, indexes, ownership and runtime privileges are preserved.
There is no new SELECT/INSERT permission for runtime writers.

The migration takes an exclusive table lock with a two-second acquisition
limit. A non-null legacy numeric pointer causes SQLSTATE 55000 and full rollback:
converting its bits to hex would change the JSON type covered by the original
record digest. Do not delete such evidence or recalculate its digest merely to
make installation pass; an installation with legacy values needs a separate
preservation plan. Existing rows with null pointers survive unchanged. This is
an offline schema migration, not a zero-downtime claim for large tables. Restart
consumers after applying it so cached bigint parameter metadata is not reused. The down
migration explicitly refuses to invalidate new null process identities or change
retained pointer representations; production rollback needs a forward migration.

Migration `20261017113838` adds the TASK-07 `tcp_state` / `tcp_new_state`
CHECK omitted from the initial schema. A stored `tcp_state` with no state causes
SQLSTATE 55000 and full rollback, preserving its original evidence and digest;
there is no automatic backfill. Installation uses the same two-second lock
acquisition limit. The down migration removes only this CHECK. The decoder also
rejects a present empty `process_exec_id` while continuing to accept null for
`tcp_state`. The existing text plus exact lowercase-hex CHECK for `sock_ptr`
already enforces the required 16-character value, so no type conversion is needed.

The local audit runner verifies actual PostgreSQL migration behavior with a
non-superuser installer and a separate runtime login, including legacy refusal,
new high-bit pointer text, null process state records and denied runtime writes.
This does not implement or enable `ingest_kernel_batch`, the HTTP kernel route,
certificate/epoch binding or receiver gap/ACK handling. No Cloud SQL migration
or GKE receiver deployment has been performed for this change.

## Lifecycle ingest and checkpoints

The opt-in writer routes `POST /internal/lifecycle/events:batch` and
`GET /internal/lifecycle/checkpoints?scope=` through current mTLS identity and
trusted source configuration. Source IDs are exact service SANs from shared spec
[PR #93](https://github.com/Beaver-Dam-Community/Agentarium/pull/93):
`agent-sensors/lifecycle-recorder` and `agent-observe/pod-watcher`.
The writer validates the live registered principal, invokes the restricted
`identity.audit_source_certificate` function, and checks
`health.audit_source_current_boot` for the recorder only. Certificate serial and
SAN come from the verified TLS leaf, never HTTP body/header values. The six-argument
ingest function repeats certificate/source/runtime-boot checks in its transaction.

Enable with `--lifecycle --lifecycle-epoch-dir=/persistent/receiver-epoch` and
`--lifecycle-node-cidrs=<node CIDRs>` when the recorder is registered. Each writer
replica needs its own persistent directory. The local epoch allocator holds an
exclusive OS lock, persists a replica UUID and increasing restart counter, and
fsyncs before returning an epoch. Missing/corrupt initialized metadata or counter
exhaustion fails startup. Do not use ephemeral storage or clone an initialized
replica directory. This repository change does not provision the persistent volume.

Add the exact lifecycle SAN to `--sources`, with its registered namespace, KSA,
and principal. A watcher binding also requires a nonempty `scopes` allowlist,
for example `"scopes":["namespace/agent-exec"]`. Every watcher batch must include
its allowed top-level `scope`; runtime batches cannot include scope or cursor.
Only the hostNetwork recorder is restricted to the direct peer node CIDR.
Ordinary watcher ingress still requires TASK-06 namespace/label NetworkPolicy;
forwarding headers never determine identity or peer IP. Local tests do not verify
that deployed policy.

Install the production ingest/checkpoint migrations and the identity/health
source helpers before enabling the routes. The writer gets function EXECUTE,
not SELECT on issued certificates, checkpoints or health boot tables. Existing
registered-workload principal checks retain the business writer's installed
read permission. Registry/source grants and the receiver's two exact operational
event grants remain installer inputs.

The strict envelope uses the approved original-byte digest rules. Caller
`received_at`, including null, is rejected by record validation. Source kind
comes from registered KSA. Individual record rejection and historical epoch
binding remain inside SQL; other accepted records and their outbox rows can
commit. The sqlc adapter validates the ACK before COMMIT and returns it only
after COMMIT succeeds. PostgreSQL storage failures do not become a successful ACK.

Checkpoint cursor fields include `expected_checkpoint_revision`; ACKs return
`checkpoint_revision`. A stale cursor can return `checkpoint=null` while records
commit. GET checks current watcher identity and the local scope allowlist before
calling only `audit.lifecycle_checkpoint`. Missing/out-of-scope checkpoints return
404. The wire and source gates depend on [#93](https://github.com/Beaver-Dam-Community/Agentarium/pull/93),
[#94](https://github.com/Beaver-Dam-Community/Agentarium/pull/94), and the receiver
gap audit rules in [#95](https://github.com/Beaver-Dam-Community/Agentarium/pull/95);
PRs #93/#94/#95/#106/#108/#132 are merged. The shared-spec merge prerequisites are satisfied.
The bounded decision in [#110](https://github.com/Beaver-Dam-Community/Agentarium/issues/110) is implemented here under merged shared-spec [#132](https://github.com/Beaver-Dam-Community/Agentarium/pull/132). Same-source, existing-record digest conflicts call `audit_record_conflict()` inside the ingest transaction; incident failure rolls back accepted records/outbox/watermark and returns no success ACK. Range overlaps without an existing record remain individual rejections. Only accepted/duplicate record sequences and range endpoints increase `max_seen`; partial rejection still prevents checkpoint advancement. Real PostgreSQL and mTLS HTTP regressions cover atomic commit, injected incident failure, range rejection and subsequent cursor-only revision CAS. Kernel ingestion remains disabled until #92 defines its authentication and trusted receiver metadata; deployed acceptance remains outside this implementation.

`TestLifecycleMutualTLS` uses real URI-only TLS with explicit identity/storage
fixtures. It tests watcher success outside node CIDRs, recorder denial and allowed
recorder success, trusted certificate arguments, and checkpoint scope/method
handling. `TestLifecycleTransactionFixturePostgres` runs a deliberately minimal
SQL fixture on PostgreSQL to test six-argument propagation, deferred COMMIT failure,
SQL/storage constraint failures, malformed ACK rollback, restricted helper calls,
NULL-node watcher authorization, disabled registration, and checkpoint reads.
Those fixtures are **not** production watermark/gap/CAS proof. The separate
`TestLifecycleSQLPostgres` integration test installs the real migrations and source
helpers; the local runner configures the disposable DB and merged helper paths automatically. Neither test
proves GKE/Cloud SQL deployment, CA issuance, external export or retention.


To run the real lifecycle migration and HTTP integration tests with the merged
identity and health helper migrations:

```sh
tests/audit/run-local.sh
```

`TestLifecycleSQLPostgres` installs the actual migrations as a non-superuser,
connects the production handler/authorizer/sqlc store through real mutual TLS,
and checks watcher/runtime writes, duplicate ACK, checkpoint GET/CAS, scope
isolation, revoked certificates, and a deferred COMMIT failure with HTTP 503 and
no durable record/watermark. Its certificate serials include a leading zero byte
nibble (`0a`/`0d`) to match the identity issuer's `hex.EncodeToString` format.
The lifecycle migration installs the #95 target schema: both abandoned-range
audit links are NOT NULL, and the sequence_range_abandoned registry records
TASK-07 with required source_id and stream. Any existing range without both
verified links, including a kernel range, stops installation without backfill.
Down disables the lifecycle functions but retains these constraints, registry
requirements and all evidence. DDL lock acquisition is bounded to two seconds;
this is an offline installation, not a zero-downtime claim for large tables.

The SQL checks also cover partial rejection, historical boot replay, large range
advancement, gap/audit/outbox rollback, privileges, and data-preserving down/up.
This uses local PostgreSQL 16 and a local test CA, not Cloud SQL or CAS.

## Runtime work events (TASK-07 work readiness check and multi-session audit)

`--work-events-gateway-san=spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway` enables
`POST /internal/audit/work-events`. Only that exact gateway SAN may call it; the gateway relays the
runtime's `POST /v1/runtime/work-events` with the verified runtime SAN in `X-Agentarium-Peer-Identity`
and a body `{context, check, event}`: the authenticated session (`session_id`, `tenant`, `workload_id`,
`authenticated_actor`), the TASK-10 WorkReadinessCheck it read for that caller, and the runtime's
`event {event_id, event_type, source_version, source_time, safe_payload}`. The writer accepts only
`agent_work_*`, requires the event's IDs to equal the check's and the check to be determined (pending is
503 `WORK_READINESS_EXPIRED`), builds the AuditEvent itself (source_id = runtime service SAN without the
Pod segment, source_epoch = `runtime_process_epoch`, evidence_refs = `[check.audit_event_ref]`) and answers
the TASK-07 ack `{event_id, result, received_at}` (201/200/409). Install
`producer_event_grants(<runtime service SAN>, agent_work_*, <tenant>)`; no migration is needed.
