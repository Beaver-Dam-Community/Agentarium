# Durable lifecycle interval derivation (TASK-10 3.3)

`Derive` accepts verified, classified source facts for one full identity
`cluster/Pod/node/boot/container/restart`. Runtime start and exit provide source
time boundaries. Create, task deletion and Pod deletion do not substitute for
process start or exit. Missing end facts remain `unknown`; `open` additionally
requires an explicit runtime coverage assertion. Watch history loss does not
invalidate an independently continuous runtime source. An observed exit remains
observed even when the capture history has a gap.

Duplicate event IDs with identical facts coalesce; contradictory bodies, cgroup
metadata, repeated boundary times, or mixed identities fail closed. Unknown
identities return an error because the documented interval DDL cannot represent
them. Input source timestamps must fit PostgreSQL microsecond precision; the
adapter must not silently round correlation boundaries. Results are deterministic
for input order and do not alias caller input.

`Store.Append` persists the exact TASK-10 interval columns using SELECT/INSERT.
sqlc v1.29.0 generates the explicit queries in `sql/` (`sqlc.yaml`).
A transaction advisory lock with a 2-second lock timeout serializes version allocation for a full container ID
across boots, matching the documented `UNIQUE(container_id,mapping_version)`.
Versions are derived storage revisions, independently allocated from raw source
record versions. Duplicate snapshots reuse their stored ID/version. A later
snapshot must include all previous source IDs for the same instance, and cannot
retract an observed boundary or replace known inode metadata. A late exit appends
a new version; `Latest` returns each historical boot/Pod/restart instance's latest
revision after restart. Older revisions remain queryable in PostgreSQL.

The installer owns the relation. `correlation_writer` receives SELECT/INSERT and
membership in the existing spec role `correlation_reader`; it has no schema DDL,
UPDATE, DELETE or TRUNCATE. `control_health_writer` is an installation prerequisite
and receives the spec's read-only grant. Source-table grants belong to the source
owner's migrations. The down migration deliberately deletes derived history and
is for disposable development databases; production rollback needs a forward
migration and preservation of retained evidence.

## Scope and unresolved integration boundaries

- These are internal typed inputs, not newly standardized LifecycleRecord
  transition strings. A source adapter must authenticate/classify immutable
  `audit.lifecycle_events`, supply complete retained history, resolve full
  identity, and establish runtime coverage. There is no SQL source consumer,
  checkpoint, Kafka worker or deployed service in this change.
- The store does not authenticate source event IDs against `audit` or create
  cross-schema grants. PostgreSQL tests use classified synthetic source facts.
- `inferred_from_other_source` is accepted by the specified DDL but is never
  synthesized here. Neither deletion nor a watch timestamp is a process exit.
- `netns_inode` stays null until an adapter supplies the same-container first
  `process_exec` evidence. Kernel evidence provenance is not invented in the
  lifecycle-only `source_event_ids` array.
- Capture gaps are inputs that prevent an open interval; writing ObservationGap
  rows, tombstone raw attributes/resourceVersion, 30-day retention scheduling,
  and the 10-minute re-evaluation worker remain separate work. Original facts
  stay owned by audit; this table is not a replacement for their retention.
- No matcher boundary policy is added: workload identity and mapping to `join`
  still require an adapter. This PR does not settle #83's exact end inclusivity
  or direct-destination normalization questions.
- TASK-10 grants `timeline_reader` base-table SELECT, but COMMON requires
  tenant-filtered views. That cross-task grant is withheld pending resolution;
  no tenant column, view or broad read permission is invented.

## Verification

```sh
go test -race -count=3 ./services/correlation/...
go vet ./services/correlation/...
# Dedicated disposable PostgreSQL cluster; test creates a unique DB and login.
LIFECYCLE_TEST_DATABASE_URL='postgres://postgres@127.0.0.1:PORT/postgres?sslmode=disable' \
  go test -race -tags integration -count=1 ./services/correlation/internal/lifecycle
```

Integration tests exercise a real non-superuser writer login, twelve concurrent
duplicate appends, unknown tombstone → late observed exit, retained old versions,
cross-boot version allocation, fresh-pool reload, stale snapshot and fact
replacement rejection, write/DDL privilege denial, reader grants, 55P03 lock-timeout rollback, and down/up.
The migration installation itself uses the fixture administrator; Cloud SQL
installer permissions and live runtime consumers are not verified here.
