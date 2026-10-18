# Durable correlation results (TASK-10 3.1 and 3.6)

`Store.Append` writes the documented `correlation.correlations` columns and the
real `audit.audit_append()` event/outbox in one PostgreSQL transaction. It uses
sqlc v1.29.0 queries and the existing audit source/event/tenant grant checks.
A correlation ID identifies one immutable revision. Each kernel event's revisions
start at 1; each changed calculation appends a new ID/revision. Old evidence and
confidence remain queryable, including when late evidence lowers confidence.

The caller supplies the latest revision on which it based its calculation.
A per-kernel advisory transaction lock with a two-second lock timeout serializes
allocation, including the first INSERT. An identical current result returns the
stored ID/time/revision without another event or outbox row. A different result
with an outdated expected revision returns `ErrStaleRevision`; its caller must
reload the current result and recompute using complete history. This local Go
parameter adds no public API field. Revisions cannot exceed signed int32 storage.

Evidence references and limitations are normalized as sorted sets without
changing caller-owned slices. Validation prevents inferred/unlinked results from
assigning action/attempt identity and requires a unique attempt/action/workload
for confirmed results. These shape checks do not prove confidence: an upstream
adapter must authenticate and validate the complete underlying observations.

The installer owns the new table; `correlation_writer` receives SELECT/INSERT
and membership in `audit_producer`. The audit function still requires a matching
login registration in `db_role_sources` and event/tenant grant. This migration
creates neither registration nor grant. Runtime has no UPDATE/DELETE/TRUNCATE or
schema DDL permission. As with lifecycle storage, `timeline_reader` base access
is withheld because COMMON requires a tenant-filtered view not defined here.
The down migration explicitly refuses to delete history referenced by committed
audit events; rollback of persisted revisions requires a forward migration.

## Integration boundary

This package stores trusted internal calculations, not external submissions.
It does not query kernel records, build complete matching windows, translate
`join.Result` diagnostics into wire fields, resolve historical workload identity,
select Q0 normalization rules or run a consumer service. Its `Result` type maps
existing documented columns and does not add a process/session field. Tenant,
source, version and durable producer epoch are trusted installation inputs.

`Latest` restores a result after process restart. There is no claim that the
source consumer, lifecycle-to-join adapter, risk hold controller, real Cloud SQL
installation or M2-4 deployment is complete.

## Verification

```sh
go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0 generate -f services/correlation/internal/results/sqlc.yaml
bash tests/correlation/run-results-local.sh
go test -race ./services/correlation/...
go vet ./services/correlation/...
```

The local runner starts a fresh disposable PostgreSQL 16 cluster and uses real
merged audit/health/lifecycle migrations plus this migration. Tests use a separate
non-superuser installer and runtime login. They cover concurrent duplicate and
conflicting computations, retained revisions, retry/reload, source/grant denial,
audit insert and deferred commit failure, bounded lock waits, forbidden runtime
writes and refusal to destroy history through a down migration. Synthetic
calculation inputs do not prove a deployed sensor or full join consumer.
