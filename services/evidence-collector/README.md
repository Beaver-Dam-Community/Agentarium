# Evidence collector

`internal/receipt.Client.Check` implements the existing TASK-08 §4 receipt API
and the receiver comparison rules, including the TASK-08 owner's pending
R1 clarification in PR #143 (merge remains gated on that shared spec). It connects only to a trusted HTTPS
origin and authenticates the exact receiver URI SAN with chain, validity and
server-EKU verification. Its own certificate must identify `evidence-collector`.
Client certificates and trust roots reload for each connection; redirects are
rejected. Receipt target/route values never select the network destination.

The caller supplies verified action ID, target ID, route ID and the preflight
`wire_body_digest`. The client strictly decodes the existing receipt schema,
checks action-key binding and count consistency, and hashes the received JSON
with JCS. Optional-field presence is preserved in the digest. It returns all
receipt effects/attempts without collapsing multiple digests or byte counts.

R1 verifies one matching effect with no mismatching receiver attempt. R2 detects
effect/attempt digest mismatch, target/route mismatch with observed evidence, or
multiple effects. R3 detects zero-effect key/body rejection. R5 returns unknown
for an empty receipt. R6 is supported only when the caller explicitly supplies
verified `attempt_failed` context and the receipt has no receive attempts. The
separate no-attempt case is not inferred from missing data or a default value.
Independent effects take precedence over `attempt_failed`. R4 provider evidence
is outside this receiver client.

Transport, authentication, non-200 HTTP responses (including 404), and malformed
receipts return errors with no evidence classification. In particular, they
cannot prove `none`. The 4-second timeout and canonical package JSON size/depth/
collection limits are local bounded-input safeguards, not a new shared receipt
wire contract. Oversized history fails the read instead of truncating evidence.

## Collector command (M3-1 PR-F)

`cmd/evidence-collector` runs the loop in `internal/collector`. It has no
listener. Every flag is required: `--database-url`, `--tenant`,
`--receiver-url`, `--target-id`, `--tls-ca`, `--tls-cert`, `--tls-key`,
`--health-url`, `--health-source-id`, `--version`, `--audit-source-id`,
`--audit-source-version`, `--epoch-dir`, `--probe-action-key`
(`--feed-settle` 5s and `--late-window` 10m have defaults).

- Every second it reads `audit.collector_feed` after the durable cursor
  (`evidence.collector_cursors`) and advances the cursor in the same
  transaction. The cursor stays `--feed-settle` behind DB time because
  `received_at` is not commit order; reprocessing is idempotent.
- `receiver.submit` `response_received`/`attempt_uncertain`/`attempt_failed`
  schedule `evidence.receipt_polls` (now, 1, 2, 4, 8s; deadline 30s). Other
  operations' `response_received` is R4 at once.
- A poll builds the trusted context from the two views only (latest
  `preflight_passed` `wire_body_digest`, `canonical_target`
  `target_id`/`route_id`, `attempt_failed` seen) and classifies with
  `receipt.Client.Check`. R1/R2/R3/R6 end the schedule; at the deadline the
  result is R5 (`NO_RECEIVER_ATTEMPT` or `RECEIPT_UNAVAILABLE`). Polling goes on
  every 8s inside `--late-window` so a late receipt adds a revision.
- A revision is added only when `(rule_id, evidence_level)` changes. The
  `evidence.destination_observations` row and its `destination_observed`
  event (`audit.audit_append`, TASK-08 3.2 payload, durable `--epoch-dir`
  source_epoch) commit in one transaction; any failure rolls both back.
- `internal/probe` reads the receipt of `--probe-action-key` every 5s and
  reports `receipt` probe results (scope `target/<target_id>`). After 3
  consecutive failures it requests a `probe_failed` target hold; 2 consecutive
  reported passes release it. The owned hold is found again after a restart.
- The `destination-evidence` lease (`packages/healthlease`, scope
  `target/<target_id>`, `active_version` = `--version`) is `unhealthy` after 3
  probe failures or when no collection pass succeeded for 15s.

Install inputs: DB login as an `evidence_collector` member,
`audit.db_role_sources` (login → `--audit-source-id`),
`audit.producer_event_grants` (`destination_observed`, tenant), control-health
`component_principals` for `destination-evidence` target scope, persistent
`--epoch-dir`. Certificates are file mode; identity bootstrap comes with
`packages/workloadcert` (#218).

## Verification

`tests/evidence/run-local.sh` runs every PostgreSQL 16 test below in disposable
Docker clusters.

```sh
go test -race ./services/evidence-collector/...
EVIDENCE_TEST_ADMIN_DSN='postgres://.../postgres?sslmode=disable' \
  go test -race -tags integration -count=1 ./services/evidence-collector/...
```

Use an explicitly disposable PostgreSQL 16 cluster. The integration test builds
and runs the existing receiver command, installs its real migration, connects
its runtime using a non-superuser login with only receiver writer/reader roles,
and sends actual mTLS submissions and receipt reads. It compares database effect
and attempt counts with the client in both receiver modes. No GCP or deployed
collector execution is claimed.
