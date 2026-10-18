# M3-1 install data

#156 (migration installer Job) is not merged yet, so the M3-1 install data is
documented SQL here instead of a rendered Job. Run the files with the
migration installer login (#156 `db-installer`, a `cloudsqlsuperuser` member)
after every migration of the M3-1 code PRs is applied. No file contains a
secret value. Steps and expected output: `docs/runbooks/m3-1-gke-bringup.md`
(steps 6 and 8).

| File | When | What |
| --- | --- | --- |
| `m3-1-action-path.sql` | after migrations, before the action path Pods start | login role memberships, `audit.db_role_sources`, `audit.producer_event_grants` (incl. the four `agent_work_*` rows for the agent-runtime SAN), `decisions.adapter_db_roles`, `identity.registered_workloads`, `health.component_principals`, broker binding `receiver-api-key` |
| `m3-1-probe-runner.sql` | after `m3-1-action-path.sql`, before `probe-runner/` is applied | `identity.registered_workloads` for both `probe-runner` KSAs and `agent-targets/probe-sink`, `health.component_principals` for the two probe runner service SANs (component `probe-runner`, scope `node`) |
| `m3-1-observe.sql` | after `m3-1-action-path.sql`, before the contact services, `audit-exporter/`, `correlation/` and `deploy/gcp/sensors` are applied | memberships `audit_writer`, `audit_exporter`, `broker_reader`, `correlation_writer` + `correlation_reader`; the writer's registered-workload column read; `audit.db_role_sources` for the writer (proxy) and correlation; `*`-tenant event grants (tetragon `kernel_event_observed`, writer gap events, control-health `execution_held`/`hold_requested`/`source_health_changed`, the five correlation events); `identity.registered_workloads` for workload-identity, credential-broker, control-health, audit-writer, audit-exporter, correlation, lifecycle-recorder, netpol-collector; `health.component_principals` for audit-db, lifecycle-recorder, netpol-collector, correlation (`risk_event`), and a check of the migration-seeded audit-export row. Variables: `writer_login`, `exporter_login`, `correlation_login`, `broker_login`, `health_audit_source_id`, `correlation_audit_source_id`. Covers everything `tests/m3-1/local-install.sql` grants the local E2E run |
| `m3-1-first-active-policy.sql` | after `tools/first-bundle -publish` and the bundle lease ack | first `release.active_policy` row (epoch 1) |

All are idempotent and never overwrite: an existing row with other values
makes a final check divide by zero and the whole transaction rolls back.
Checked locally against PostgreSQL 16 with the union of the M3-1 branch
migrations (superuser, not Cloud SQL or IAM logins): first run, no-op rerun,
and rollback on a conflicting value.

Open questions recorded in the files: the `control_health_writer` SELECT on
`identity.issued_certificates`/`registered_workloads` that control-health's
caller check needs but COMMON's cross-task read table does not list, and the
first-epoch procedure that TASK-14 does not define.
