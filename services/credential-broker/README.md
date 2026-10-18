# Credential broker (TASK-06 API section)

The mTLS `POST /internal/credentials:resolve` endpoint returns a fixed Secret
Manager version only after matching the peer's registered adapter identity,
request adapter ID, enabled binding, and planned attempt's operation ID. It
checks authorization again after a potentially slow secret fetch. A cache hit
never bypasses the database check. Requests cannot supply a secret resource.

Secrets are fetched from the binding's fixed numeric version, checked with
CRC32C, and kept in an in-memory cache for at most 60 seconds. Disabled bindings,
changed versions, claimed attempts, expired cache, failed refresh and provider
errors fail closed. Provider error text and secret values are not logged or
returned in errors. Success logging contains only resource/version identifiers.
Failure logging contains only fixed categories for database/binding lookup,
Secret Manager access, revalidation, and invalid secret headers. A database/binding
category includes authorization denial because the repository deliberately exposes
only an opaque unavailable error. No upstream error text or request fields enter
these observations. HTTP responses use `Cache-Control: no-store`. Invalid header characters, invalid
UTF-8 and the COMMON 2 KiB total-header boundary are enforced. Expired cached
byte slices are cleared periodically; Go cannot guarantee erasure of all prior
heap copies or immutable response strings.

Apply `*_broker_credential_bindings.up.sql` as the migration operator. The
`broker_reader` runtime role has SELECT only on the allowlist. The TASK-03 follow-up
migration supplies USAGE on the coordinator schema and SELECT on its restricted
view after the broker role migration.
The runtime role has no identity schema or registered-workload table access;
the view owner performs the live enabled-adapter join.
The broker does not create or modify another Task's tables/views. Populate
bindings through the operator with the exact canonical Secret Manager resource
name (prefer project number) and version; the provider response name must match.
Use the canonical resource name to avoid a project-ID/project-number alias
mismatch. Version aliases such as `latest` are refused.

Run `cmd/broker` with `DATABASE_URL`, `--identity-url`, `--bootstrap-token`,
`--tls-ca`, and optionally `--listen`. It uses the existing TASK-03 CSR/token
wire adapter isolated in its own path, follows the merged COMMON contract in
PR #53, generates keys in memory, verifies chain/SAN/EKU and renews at half-life.
The existing shared Dockerfile uses `CMD=./services/credential-broker/cmd/broker`.
Direct KSA ADC accesses only the individually allowed secrets. The Deployment,
Service and DB Proxy sidecar are in `deploy/gcp/base/credential-broker/`.

## Cross-task prerequisite

The merged [shared spec PR #75](https://github.com/Beaver-Dam-Community/Agentarium/pull/75) extends
`coordinator.attempt_credential_scope` with `adapter_namespace` and `adapter_ksa`
after the existing `attempt_id, adapter_id, operation_id, state` columns. It
joins only currently enabled adapter registrations matching the attempt's
adapter ID. The broker filters the view by its verified peer SAN's namespace
and KSA, so another active KSA cannot bypass revocation of this caller.

The shared contract prerequisite is merged, and TASK-03 implemented the view
and its grants in `migrations/*_coordinator_credential_scope.up.sql` (#44).
`services/coordinator/internal/dispatch/credential_scope_integration_test.go`
runs the broker's sqlc queries against that view as a `broker_reader` login. The
broker must not receive SELECT on `identity.registered_workloads` or the source
attempt/reservation/action tables. Startup checks broker/coordinator schema
USAGE and every required view column privilege; missing scope columns, view or
grants fail closed. No fallback to base tables is provided. The startup check
does not claim that a real secret or planned attempt has been resolved.

## Evidence and remaining work

`go test -race ./services/credential-broker/...`, `go vet
./services/credential-broker/...`, and `tests/egress/run-broker-local.sh` cover
cache expiry/rotation, authorization on cache hits, revocation during fetch,
header injection, strict JSON and forged identity headers, real local TLS
certificate bootstrap, and a local HTTP Secret Manager adapter with CRC and
version checks. The DB runner uses PostgreSQL 17 and applies the broker
up/down/up migrations through a non-superuser CREATEROLE login. It verifies
that temporary owner INHERIT/SET access is revoked, existing full memberships
are preserved, and broker objects retain broker_owner ownership. The runner applies the actual merged identity migration and
broker migration, then uses an explicitly marked coordinator-view contract
fixture. It checks a real non-owner database login without identity schema
access, adapter/operation/state boundaries, live registration revocation and
role/adapter changes, multiple KSAs, missing schema/view privileges and scope
columns, and denied UPDATE/DELETE/base-table SELECT. These fixture results do
not replace the coordinator test against the actual view migration.

No actual Secret Manager access, adapter integration, GKE deployment,
IAM or network enforcement has been verified here. These are required before
M2-1 is complete. Operational resource/version logging is not a new AuditEvent
registry type; durable credential-specific audit publishing requires an agreed
registry contract if it is required beyond these metadata logs.

The provider integrity check follows [Secret Manager data integrity](https://docs.cloud.google.com/secret-manager/docs/data-integrity).
