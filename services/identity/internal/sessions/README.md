# Transactional audit adapter

`NewPGAuditor(AuditConfig{SourceID, Version, Epoch})` implements the existing
`Auditor` interface for sessions and approvals. Inject it into their `Service.Audit`
fields alongside the existing pool. It calls `audit.audit_append` on the caller's
business transaction, so session state, counters, AuditEvent and export outbox
commit or roll back together. An unknown append result fails closed.

Configuration must come from the trusted installation/process state. `Epoch` must
be the producer's durable restart epoch; this adapter does not allocate or persist
that epoch. The database login needs `identity_app` (and its existing
`audit_producer` membership), `audit.db_role_sources` registration and exact
source/event/tenant grants. No base audit-table privileges are needed.

Tenant is internal event context taken from the validated Actor/request or the
locked session row. Known action/workload/session references are explicit internal
fields populated from validated calls or stored rows; payload keys are not
automatically promoted into top-level audit context. Source time is the database transaction timestamp. The adapter
uses COMMON's optional `source_sequence: null`, an empty `evidence_refs` list and
the existing canonical payload digest. It allocates a UUID for each append. It does
not add HTTP request idempotency: the existing service-session retry after a
serialization rollback makes a new event in the new transaction. A successful HTTP
request repeated by a caller is still governed by the existing service behavior.

An event ID conflict causes `InTx` to confirm business rollback, then call the
existing `audit_record_conflict` function in a separate transaction. Successful
incident persistence returns `409 EVENT_ID_CONFLICT`; incident persistence failure
fails the request. This cleanup has its own bounded context so request cancellation
does not silently discard the incident.

`cmd/identity --session-apis` wires this adapter with `--audit-source-id`,
`--audit-source-version` and a durable producer epoch from `--epoch-dir`
(`internal/epoch`, the control-health counter). The source registration and
event/tenant grants remain install steps.

## Verification

On an explicitly disposable PostgreSQL 16 cluster:

```sh
IDENTITY_AUDIT_TEST_ADMIN_DSN='postgres://.../postgres?sslmode=disable' \
  go test -race -tags integration -run TestPGAuditor -count=1 -v \
  ./services/identity/internal/sessions
```

The fixture creates a fresh database using a non-superuser installer, then uses a
restricted `identity_app` login and actual mTLS HTTP service-session requests. It
checks the activation budget, counter and audit/outbox together, grant rejection,
append/commit rollback, conflict incident failure, same-transaction duplicate
handling and base-table/owner privilege denial. It does not exercise Cloud SQL IAM,
production deployment, a restart epoch allocator or exporter delivery.

# Policy snapshot adapter

`SnapshotPolicy` implements the existing `PolicySource` used by session creation
and approval rendering. TASK-03 requires identity to read `data.standing_rules`
and the catalog through the shared signature-verifying `packages/policyloader`.

The adapter captures one immutable snapshot and reads the environment's COMMON
`active_policy` row once through a trusted `ActivePolicyReader`. That single read
returns `scope_id`, `bundle_id`, `artifact_digest`, `expected_opa_revision` and
`epoch`; the first four must match the snapshot and the epoch is returned with
the policy. No loaded snapshot, no active row, a read error or a missing epoch is
`POLICY_UNAVAILABLE`. A loaded bundle that is not the active revision (preloaded
before the epoch CAS) is COMMON 503 `POLICY_VERSION_MISMATCH`. The adapter neither
creates an epoch nor activates a policy and never substitutes `desired_bundle`.

Reader contract (installer-supplied implementation):

- `ActivePolicy(ctx, q, environment)` runs exactly one plain `SELECT` on `q`.
  It must not use `FOR SHARE`/`FOR UPDATE`: `identity_app` has SELECT only, so a
  locking read fails with 42501.
- Transactional callers pass their own `pgx.Tx` through `PolicyIn(ctx, tx)`.
  Approval rendering does this, so it never takes a second pool connection while
  its transaction holds one. `Policy(ctx)` uses `SnapshotPolicy.DB` and is only
  for callers without a transaction (session creation before its write).
- Approval stores `policy_epoch` only if the epoch of the rendered snapshot equals
  `EpochSource.ActiveEpoch(tx)` in the same transaction; otherwise it returns
  503 `POLICY_VERSION_MISMATCH` and writes nothing. Under READ COMMITTED two reads
  can see different commits, so the equality check is what prevents an approval
  rendered from bundle A from being recorded under bundle B's epoch.

From a `desired_bundle` change until TASK-14's epoch CAS commits, gateway and
adapters have loaded the new bundle but it is not yet active. During that window
session creation and contract rendering return 503 `POLICY_VERSION_MISMATCH`. The
window is at most the 120-second lease ack timeout plus one 2-second
`desired_bundle` poll; the gateway behaves the same way.

The exact standing-rule fields identity consumes are decoded into independent
copies. Missing/malformed rules or budgets return `ErrPolicyUnavailable`; no
default rule or budget is supplied. A failed signature reload retains the
loader's previous verified snapshot, usable only while it matches the active row.
New sessions use the matched snapshot's budgets; existing session budget rows are
not rewritten on reload.

`cmd/identity --session-apis` wires `PGActivePolicy` (one plain SELECT on
`release.active_policy`, migration `20261018092000_release_active_policy`), the
loader (`--bundle-key-id`, `--bundle-key-file`, GCS) and `SnapshotPolicy.DB` = the
pool. This package creates no epoch: the first `active_policy` row is an install
step.

Tests use real ES256 signed OPA bundles and the production loader with local
storage transport and a fixture active-policy reader: preload versus activation,
environment/bundle/digest/revision mismatch (`POLICY_VERSION_MISMATCH`), missing
row/epoch and read failure (`POLICY_UNAVAILABLE`), `PolicyIn` using the caller's
querier, unsigned rejection, malformed rules, copy isolation and concurrent
catalog/budget consistency. PostgreSQL integration tests verify session budgets
before/after activation, and that approval reads the policy inside its
transaction and rejects an epoch mismatch without writing an approval or event.
No GCS, KMS, Cloud SQL, deployed active-policy reader or M3-1 flow is claimed.
