-- Local install inputs that no repository install file provides yet
-- (tests/m3-1/run-local.sh). They are TASK-16 installer inputs of
-- components outside deploy/gcp/base/installer/m3-1-action-path.sql: the
-- broker, audit-writer, audit exporter and control-health (M1 contact
-- services) and the node-side components the local run simulates. Values
-- follow the service READMEs and their integration-test fixtures; every row
-- is listed in tests/m3-1/README.md ("Install inputs not in the repository").
--
-- Run as the migration installer after m3-1-action-path.sql:
--   psql -v broker_login=... -v writer_login=... -v exporter_login=... \
--        -v health_audit_source_id=control-health -f tests/m3-1/local-install.sql

\set ON_ERROR_STOP on
BEGIN;

-- Login memberships (services/credential-broker, services/audit README).
GRANT broker_reader  TO :"broker_login";
GRANT audit_writer   TO :"writer_login";
GRANT audit_exporter TO :"exporter_login";

-- audit-writer: proxy source row (TASK-07 3.2) and its registered-producer
-- read (services/audit/cmd/verify/recovery_integration_test.go).
INSERT INTO audit.db_role_sources (db_role, source_id, proxy) VALUES (:'writer_login', 'audit-writer', true)
ON CONFLICT (db_role) DO NOTHING;
GRANT SELECT (namespace, ksa, role, service_principal, enabled) ON identity.registered_workloads TO audit_writer;

-- Kernel ingest (services/audit README, kernel_ingest_integration_test.go):
-- the node sensor SAN may send kernel_event_observed; the writer (receiver
-- source) may record abandoned ranges and gaps.
INSERT INTO audit.producer_event_grants (source_id, event_type, tenant) VALUES
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon', 'kernel_event_observed', '*'),
  ('audit-writer', 'sequence_range_abandoned', '*'),
  ('audit-writer', 'observation_gap_recorded', '*')
ON CONFLICT DO NOTHING;

-- control-health's own business events (services/control-health README).
INSERT INTO audit.producer_event_grants (source_id, event_type, tenant)
SELECT :'health_audit_source_id', e, '*' FROM unnest(ARRAY['execution_held', 'hold_requested', 'source_health_changed']) AS e
ON CONFLICT DO NOTHING;

-- Workload certificate principals of the contact services and the
-- simulated node-side components.
-- workload-identity records its own server certificate (servercert) in
-- identity.issued_certificates, whose (namespace, ksa) references this table.
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal, enabled) VALUES
  ('agent-control', 'workload-identity',  'service', NULL, 'workload-identity',  true),
  ('agent-control', 'credential-broker',  'service', NULL, 'credential-broker',  true),
  ('agent-observe', 'control-health',     'service', NULL, 'control-health',     true),
  ('agent-observe', 'audit-writer',       'service', NULL, 'audit-writer',       true),
  ('agent-observe', 'audit-exporter',     'service', NULL, 'audit-exporter',     true),
  ('agent-sensors', 'lifecycle-recorder', 'service', NULL, 'lifecycle-recorder', true),
  ('agent-control', 'node-readiness',     'service', NULL, 'node-readiness',     true)
ON CONFLICT (namespace, ksa) DO NOTHING;

-- control-health caller principals (TASK-10 3.2; COMMON required leases).
INSERT INTO health.component_principals
  (principal_san, component, allowed_scopes, allowed_hold_reasons, releasable_hold_reasons) VALUES
  ('spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer',       'audit-db',           ARRAY['global'], ARRAY['db_unavailable'], ARRAY['db_unavailable']),
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder', 'lifecycle-recorder', ARRAY['node'],   ARRAY[]::text[],          ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-control/sa/node-readiness',     'node-readiness',     ARRAY['global'], ARRAY[]::text[],          ARRAY[]::text[])
ON CONFLICT (principal_san) DO NOTHING;

COMMIT;
