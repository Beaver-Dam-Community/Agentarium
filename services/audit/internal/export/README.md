# Export format and verification (TASK-07 section 3.2)

This package implements canonical NDJSON, batch object keys, signed manifest
encoding, exact manifest source-range checks, a create-only GCS adapter, a pinned-key KMS signer, and verification.
It also provides the SQL outbox claim/retry/ack boundary, a single-iteration
worker, and a GCS/KMS-backed manifest publisher with durable intent recovery.
The publisher requires a leader lease; `PGLease` implements the PostgreSQL
lease and fencing token of TASK-07 3.2.1 (see below).

`cmd/verify` checks an explicitly bounded manifest range. It verifies strict
JSON, exact sequence/predecessor digest, a P-256 signature under a configured
KMS key version, the pinned GCS object generation and digest, canonical NDJSON
framing and class, and all fixed batch members' committed outbox acknowledgements.
A missing or partly acknowledged batch fails. Public keys are supplied by trusted
configuration; the manifest cannot choose an untrusted key or download one.

Required inputs are `DATABASE_URL`, `--bucket`, `--chain`, `--keys` and
`--through`. The keys file maps exact KMS version resource names to PEM public
keys. `--from` defaults to 1. A range starting later requires an independently
predecessor, read from the committed `export_manifests` row (an optional
`--previous-digest` must match it). Daily anchors are out of MVP scope, so
verification is supported within the 30-day retention only. It prints a
successful range/digest summary or exits nonzero at the first incident. A
definite failure (see the failure codes in `manifest.go`) is reported as an
`export_verification_failed` AuditEvent through the audit writer and an
`audit_integrity` hold; network, permission and DB errors only mark the run
incomplete and raise no security hold. Incident delivery inputs are required.

The GCS adapter uses a create-only generation precondition and, on HTTP 412,
reads that exact existing generation and compares bytes before accepting a
retry. It does not trust mutable object metadata as content evidence. For a
manifest, retain its signed envelope on retry or reconcile the already stored
valid signature: ECDSA signing the same body again can produce different bytes.
The KMS adapter sends and checks CRC32C, verifies the returned key-version name,
and verifies the signature with a pinned P-256 public key. These behaviors follow
[Cloud Storage preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions)
and [Cloud KMS signing integrity](https://docs.cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/asymmetricSign).

Validation:

- `go test -race ./services/audit/internal/export -count=1` exercises signature,
  chain, digest/generation, class/framing, source-range and missing-evidence
  failures. Local HTTP servers exercise the actual GCS/KMS client request path,
  including create-only writes, matching/conflicting 412 retries, and response
  integrity. These are not calls to real GCS or KMS.
- `tests/audit/run-local.sh` runs actual PostgreSQL migrations and checks whole
  batch acknowledgement, wrong generation/count/chain, missing batch, and a
  partially acknowledged batch using the `audit_exporter` database role.

Remaining here: deployment and real GCS/KMS/IAM/TASK-10 verification. Daily
anchors are an explicit follow-up outside MVP scope.


## Durable outbox boundary

`Outbox.Claim` commits a batch of at most 100 records and a 30-second lease
before external I/O. Existing batches are retried with the same ID, object key,
and ordinal members. If another transaction locks one member, the entire batch
is skipped and any partially acquired locks are rolled back. New rows can still
form other batches. Every claim increments each member's `attempts`; Ack/Retry
require that exact value and a live lease, preventing an old worker from changing
a reclaimed batch. Retry intervals are 1, 2, 4, 8, 16, then 30 seconds.

`Outbox.Ack` requires a matching committed manifest intent/manifest row for the
batch, destination, object generation and both digests. It updates every member
in one transaction; a failure leaves all rows unchanged. It does not itself
verify a signature or upload an object. Those are the publisher's responsibility;
DB administrators remain a stated trust boundary.

`Worker.Once` handles sequenced business, kernel, lifecycle and DecisionInput records. Its
`SourceClass` selects one class (empty defaults to business), and every batch
retains one class and fixed ordinal order. Observation records are exported from
their immutable stored rows with the registered kernel/lifecycle wrapper type. It uses
fixed member order, reads immutable records, produces NDJSON and source ranges,
then calls `Publisher.Publish` outside the SQL transaction. The publisher must
create/reconcile the immutable object, serialize/persist its signed manifest,
and return its receipt. Without a publisher the worker refuses to claim rows.
There is deliberately no permissive/default publisher. The basic worker boundary test uses a publisher test double. Additional tests
use ManifestPublisher, actual PostgreSQL, and actual GCS/KMS SDKs against local
HTTP fixtures; they do not execute Google APIs or real leader election.

DecisionInput publication reads the five stored fields, including the exact
`tenant`, from `decisions.decision_inputs` using the existing `audit_exporter`
SELECT grant. The worker selects `gcs_decision_inputs`; its publisher must be
configured with `Chain: "gcs_decision_inputs"` and the dedicated
`decision-input-exports` bucket adapter. A different chain is rejected before
claiming rows. The default publisher chain remains `gcs`. Each chain uses its
own manifest sequence and advisory lock, with the same configured KMS key.

DecisionInput rows have no source ID, epoch or sequence. Their manifest uses
`sources: []`, and verification rejects fabricated source ranges. This preserves
the decided five-field format; it does not resolve #98's separate question about
business events that have source identity but a null sequence. Fixed batch
metadata is read back before publication, so altered destination/class/key/time
cannot redirect an existing batch. A missing source row fails without uploading
or acknowledging the batch. Retry reconciles the same GCS objects and manifest.

The actual PostgreSQL test uses restricted gateway/exporter logins and merged
producer migrations. It checks producer rollback, tenant preservation, separate
bucket/chain publication, a crash after manifest upload followed by retry without
re-signing, signed verification against committed ACKs, false claims, missing
rows and source mutation denial. Actual GCS/KMS SDKs call local HTTP fixtures;
leader authorization is injected, and no cloud deployment is implied.

Unsequenced business events are exported without inventing a sequence: they
contribute no `sources[]` entry and are covered by `outbox_range`, record count
and batch digest. The HealthReporter below measures backlog; production runtime
wiring and probe-based release remain required.

Actual PostgreSQL 16 tests use `audit_exporter` privileges and cover concurrent
150-row claims, the 100-row cap, partial-lock skips, stable replay after expiry,
stale claims, wrong/missing manifest receipts, atomic rollback after an injected
second-row ack failure, retry timing, and original-data mutation/DELETE denial.
The test runner serializes packages because PostgreSQL group roles are
cluster-wide; the non-superuser migration fixture gets ADMIN-only permission
when a prior fixture already created a role, with SET/INHERIT still disabled.

The export wrapper no longer consumes the record's depth budget: strict JSON
limits apply to `record`, while the NDJSON wrapper is checked for JCS validity.
An accepted depth-16 record survives export and verification; depth-17 fails.


## Manifest publication and recovery

`ManifestPublisher` composes the existing `GCS` and `KMS` adapters. Its required
`LeaderLease.Check` returns the fencing token of a lease the caller still owns.
Missing/expired lease authorization fails closed, and one token is used for a
whole publication.

The publisher adds a PostgreSQL session advisory lock per chain as a second
serialization guard, not as a replacement leader lease. It reserves and commits
`manifest_intents` before signing, refuses to skip an unfinished predecessor,
and uses the intent's fixed `created_at`. GCS upload and KMS signing run outside
DB transactions. The complete publication attempt is bounded to 25 seconds;
lease ownership is checked again before durable steps and the manifest commit.
If advisory unlock cannot be confirmed, the dedicated connection is discarded
so a pooled connection cannot retain a chain lock.

On restart after manifest upload but before DB commit, the publisher reads that
manifest's pinned generation, checks its exact body against the fixed intent,
and verifies its signature under configured trusted key versions. It then
persists the existing signature, rather than creating new ECDSA bytes. A
matching data-object 412 is reconciled by the existing byte comparison adapter.
A committed manifest that has disappeared is missing evidence, never silently
re-signed. A rotated key's old version must remain in the trusted key map for
recovery; an absent old trusted key fails closed.

The actual-PG + local HTTP SDK tests cover publication through `Worker.Once`,
chain extension, upload-before-commit crash recovery without a second signing
call, unfinished predecessor blocking, competing chain locks, missing/expired
leader authorization, signature tampering, and deleted committed manifests.
GCP KMS/GCS/IAM and incident delivery are not validated by these fixtures. The kernel wire/schema
alignment is merged, while kernel/lifecycle receiver acceptance remains separate; testing stored export rows
is not proof of production sensor ingestion.

The verifier recomputes each source/epoch first/last sequence from the actual
NDJSON records and rejects a signed manifest whose ranges differ. It does not
infer contiguous delivery from a range containing gaps. Tests cover an
authentically signed but incorrect source, epoch, first/last sequence or omitted
range, and actual PostgreSQL observation batches published through the GCS/KMS
SDK HTTP fixtures and verified against committed outbox acknowledgements.

## Export health reporting

`HealthReporter` reads actual non-acked outbox rows in a single DB snapshot. It
applies TASK-07's initial lag/count/byte thresholds, grouping kernel/lifecycle
backlog by the immutable record's node. Business holds use global scope;
observation holds use that node; decision-input delay never creates a hold.
It reports the required global `audit-export` lease every five seconds with a
15-second TTL and requests `export_lag` holds through the existing HTTP API.
A missing node at a hold threshold is unavailable evidence, not the exporter's
own node. DB failure, unknown class and a rejected/invalid hold ACK lead to an
unhealthy lease rather than reporting success. Duplicate node hold requests
across classes are combined within one report.

The reporter never releases a persisted hold just because backlog drops. Actual
export probe ingestion/recovery depends on #99 and must be connected before M2
completion. The PostgreSQL/HTTP fixture tests exercise real backlog aggregation,
strict threshold boundaries, committed ACK exclusion, lease TTL, global hold
requests and failed-hold unhealthy reporting. They do not prove deployed mTLS,
control-health owner grants, production scheduling or probe-based recovery.


## Coverage, lease, verifier role and retention (TASK-07 3.2.1)

These follow the #98/#99 owner decisions and migration
`20261018091800_audit_export_coverage_lease`.

- **Coverage:** `audit_outbox.outbox_id` is a storage-order identity, never a
  source sequence. Every manifest signs `outbox_range {first_outbox_id,
  last_outbox_id}`, the exact min/max of the fixed members. The verifier reads
  the members (`PGAcks.Members`) and requires the same count, the same min/max
  and the same `(record_kind, record_id)` per NDJSON line, then checks ACKs.
  A range does not claim that every intermediate ID belongs to the batch.
- **Lease holder:** must be unique per process (replicas sharing a holder
  would share a token); `cmd/exporter` appends a UUID. `Run` rejects renewal
  intervals at or above TTL minus the 5-second margin.
- **Lease:** `audit.acquire_manifest_lease` renews a live lease for the same
  holder with the same token, takes over an empty or expired lease with
  token + 1, and returns no row while another holder is live (30-second TTL).
  A BEFORE INSERT trigger on `manifest_intents` and `export_manifests` requires
  the current token of a live lease and keeps the lease row share-locked until
  that transaction ends, so a takeover waits for the commit and a stale holder's
  later INSERT is rejected (SQLSTATE `AU401`, surfaced as `ErrLeaseLost`).
  `PGLease` keeps a local deadline measured from before each acquire and stops
  new durable steps five seconds before it. No Kubernetes API or RBAC is used.
- **Verifier role:** `audit_verifier` has schema USAGE, SELECT on the batch,
  member, intent and manifest tables, and column SELECT on
  `audit_outbox(record_kind, record_id, destination, state, ack_ref, outbox_id)`.
- **Retention:** `audit_retention` can only execute
  `audit.purge_expired_records(batch_limit)`. It removes members, outbox rows
  and stored records of fully acknowledged batches whose outbox rows and
  records are all older than 30 days and whose manifest commit
  (`export_manifests.created_at`) is older than 31 days. The verification window
  is the last 30 days of manifest commits, so a batch exported days late keeps
  its rows while its manifest can be verified. A batch with a record still
  referenced by another table is skipped as a whole. Batch and manifest
  metadata stay; `decisions.decision_inputs` is TASK-04 data and is untouched.

`TestCoverageLeaseRetentionPostgres` installs every merged migration on
PostgreSQL 16 and uses restricted logins. It checks renewal, busy rejection,
missing/stale tokens, a takeover waiting for a fenced transaction, a stale
holder whose local lease still looks valid being stopped by the DB fence, mixed
sequenced/unsequenced coverage verified as `audit_verifier`, a swapped member
reported as `COVERAGE_MISMATCH`, verifier privilege denials, and purge
selection including the FK-referenced and unacknowledged cases.


## Exporter command, probe/release and incidents

`cmd/exporter` composes everything above: `PGLease` renewal for both chains,
one worker per class (business, kernel, lifecycle on the evidence bucket,
decision_input on `decision-input-exports`), the audit-export health lease and
`export_lag` holds, and probe-based release. A replica without the lease does
not claim rows; several replicas are safe. SIGTERM releases held leases.

`HealthReporter` remembers the export_lag holds it obtained. When a held scope
falls below the degraded limit, `ExportProber` writes
`probes/<yyyy-mm-dd>/<probe_id>.json` create-only, reads the same generation
back and compares bytes. The result is reported in the COMMON probe-results
wire (`probe_kind=export`, the hold's scope, `node_uid` only for node scope, no
`boot_id`, evidence `gs://<bucket>/<key>#<generation>`). Only a passing probe
leads to `POST /internal/holds/{hold_id}/release` in the TASK-10 §3.2 form; the
response must carry `release_ref = auto:audit-export:<probe_result_id>`. A 404
(unknown hold) makes the exporter forget it and re-read its owned holds. A 409
(#159: released by another request, or insufficient evidence; the wire does not
say which) is classified with the owned-hold listing: a hold no longer listed
was released and is forgotten with a log line; a still open hold keeps the 409
as an error and is retried next round. An identical repeated request gets the
stored 200. One probe runs per release round and its
result is reported for every recovered scope; each probe is bounded (2s by
default). The release loop has its own deadline and never changes the
audit-export lease state. Hold requests carry `audit_outbox_backlog:` evidence
refs. Hold IDs are not lost on restart: `RecoverLoop` replaces the remembered
holds with the open export_lag holds owned by `audit-export` from
`GET /internal/holds?owner_component=audit-export` (#177) at start, on each new
gcs lease token and after a 404/409 release answer, retrying a failed listing
with exponential backoff (1s doubling to 30s by default). Recovery itself never
releases; the probe path above still decides.

`internal/testfixture` holds the local stand-ins used by the process tests: a
GCS/KMS contract fixture and a TASK-10 control-health contract fake. The fake
enforces caller/component binding, the hold request rules, the probe-results
field rules and automatic-release evidence; it is not the TASK-10 service.
`TestExporterProcesses` runs two exporter binaries, injects a storage outage,
checks the hold, the absence of probes and release during the outage, the
probe-backed release after recovery, a SIGKILL failover with a higher fencing
token on one continuous chain verified as `audit_verifier`, and a clean SIGTERM.


## Verification window and manifest times (security fixes)

- `manifest_intents.created_at` and `export_manifests.created_at` are
  DB-assigned (`clock_timestamp()` in a BEFORE INSERT trigger) and immutable
  (BEFORE UPDATE rejects changes); the exporter has column INSERT grants that
  exclude them (migration `20261018091801`). The intent time is the signed
  manifest `created_at`.
- `cmd/verify` compares the signed `created_at` with the DB intent time and the
  committed DB manifest digest with the stored manifest; a mismatch is a
  `MANIFEST_INVALID` incident. The window is the last 30 days of intent time.
  Outside it the verifier still checks signature, chain, pinned object and
  records (`VerifyDetached`, no DB coverage) and reports
  `verified_outside_window`; if the manifest or batch object has expired it
  records `skipped_outside_window`, continues the chain with the committed DB
  digest and exits 2. Exit 1 remains failure, 0 complete success.
- The health reporter publishes each backlog measurement with a generation
  before requesting holds. A release round uses only holds requested before
  its measurement and, right before each probe report and release call,
  rechecks under the lock that the latest measurement still shows the scope
  below the limit and that the hold was not requested again. Unrelated newer
  measurements do not abort the round, so frequent reports cannot starve it.
