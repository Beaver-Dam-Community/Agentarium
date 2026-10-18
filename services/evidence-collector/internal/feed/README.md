# Collector feed reads

`New(pool, tenant)` fixes trusted installation tenant context for queries of the
existing `audit.collector_feed` and `decisions.actions_target_view`. `Page` applies
the tenant predicate before a bounded LIMIT and follows the specified strict
`(received_at,event_id)` cursor order. `Target` includes both tenant and action ID
in SQL; a different tenant's action returns the same `pgx.ErrNoRows` as an unknown
ID. Nullable action/attempt IDs remain nullable. The reader never falls back to
base tables or adapter APIs.

The migration creates the existing specified NOLOGIN `evidence_collector` role
if absent, then grants schema USAGE and SELECT on exactly these two views. It
must follow the audit and gateway migrations. The installer needs ADMIN on
`audit_owner` and ownership/grant options for the decisions schema/view. A
transaction temporarily permits SET audit_owner only when needed, then restores
its own prior membership state; failure rolls back all grants. Runtime IAM login
membership is an installation input, not created here. Down revokes these reads
and schema usage while retaining the role and all source history.

Tenant isolation here is the trusted reader's SQL predicate, **not** a new
per-login database/RLS boundary. The existing views expose their tenant column;
the role itself can query rows of another tenant if misused directly. This PR
adds no tenant mapping, RLS, new view, audit producer privilege or public API.

## Cursor limitation and remaining work

`received_at` is not a commit-order watermark. A transaction can commit later
with a timestamp preceding the reader's cursor. These methods do not claim
lossless streaming, advance a durable cursor, or implement restart/replay
recovery. A complete collector must account for that behavior when connecting
feed polling to its durable scheduling/observation work.

No collector command, poll scheduler, durable observation/revision transaction,
receipt client connection, destination_observed emission or lease/hold handling
is included. The missing/plural receiver-facts audit payload is a separate shared
contract question. The local maximum page size of 100 is an operational query
bound, not a new wire contract. No M2-8/M3-1 completion or deployment is claimed.

## Generation and validation

```sh
go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0 generate \
  -f services/evidence-collector/internal/feed/sqlc.yaml
EVIDENCE_FEED_TEST_ADMIN_DSN='postgres://.../postgres?sslmode=disable' \
  go test -race -tags integration -count=1 ./services/evidence-collector/internal/feed/...
```

`sql/schema.sql` is only a sqlc projection of the two merged view definitions;
it is never installed. The actual PostgreSQL 16 test installs the real migrations
with a non-superuser installer, then queries through a restricted runtime login.
It checks tenant filtering before pagination, timestamp ties, nullable IDs,
cross-tenant target refusal, grants/owner restoration on success and failure,
base-table/write denial, and down/up without deleting audit/action evidence.
