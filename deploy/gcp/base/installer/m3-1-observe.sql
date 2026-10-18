-- M3-1 observe/contact install data (TASK-07, TASK-10, TASK-03, TASK-16 step 3).
--
-- Run once per installation after m3-1-action-path.sql and before the
-- contact services, the audit exporter, correlation and deploy/gcp/sensors
-- are applied, as the migration installer login (#156 db-installer). Same
-- rules as m3-1-action-path.sql: idempotent, an existing row with other values
-- is NOT overwritten, and the checks at the end then fail and roll back the
-- whole transaction for a human decision.
--
--   psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 \
--     -v writer_login='audit-writer-db@PROJECT.iam' \
--     -v exporter_login='audit-exporter-db@PROJECT.iam' \
--     -v correlation_login='correlation-db@PROJECT.iam' \
--     -v broker_login='credential-broker-db@PROJECT.iam' \
--     -v health_audit_source_id=control-health \
--     -v correlation_audit_source_id=correlation \
--     -f deploy/gcp/base/installer/m3-1-observe.sql
--
-- writer_login is `contact_services["audit-writer"].db_user`; the others are
-- `workload_services[*].db_user`. health_audit_source_id is the value given to
-- m3-1-action-path.sql; correlation_audit_source_id is the rendered
-- CORRELATION_AUDIT_SOURCE_ID (correlation --audit-source-id).
--
-- This file covers what tests/m3-1/local-install.sql grants the local E2E
-- run (audit-writer, audit exporter, credential broker, control-health
-- business events, contact-service and node-side registered workloads and
-- principals) plus correlation and the netpol collector. The audit exporter
-- principal (component audit-export) is seeded by migration
-- 20261017172319_health_audit_integrity and only checked here.

\set ON_ERROR_STOP on
BEGIN;

-- 0. Schema owner roles, taken and revoked as in m3-1-action-path.sql.
DO $$
DECLARE
  r text;
  granted text[] := '{}';
BEGIN
  FOR r IN SELECT DISTINCT o.rolname FROM pg_namespace n JOIN pg_roles o ON o.oid = n.nspowner
           WHERE n.nspname IN ('audit', 'identity', 'health') LOOP
    IF NOT (pg_has_role(current_user, r, 'USAGE') AND pg_has_role(current_user, r, 'SET')) THEN
      EXECUTE format('GRANT %I TO CURRENT_USER WITH INHERIT TRUE, SET TRUE', r);
      granted := granted || r;
    END IF;
  END LOOP;
  PERFORM set_config('m31_install.granted_owners', array_to_string(granted, ','), true);
END $$;

-- 1. Login memberships (services/audit, services/credential-broker READMEs,
--    deploy/gcp/base/correlation/README.md).
GRANT audit_writer   TO :"writer_login";
GRANT audit_exporter TO :"exporter_login";
GRANT broker_reader  TO :"broker_login";
GRANT correlation_writer, correlation_reader TO :"correlation_login";

-- The writer checks the live registered principal of every caller (TASK-07
-- 3.2, services/audit README step 4).
GRANT SELECT (namespace, ksa, role, service_principal, enabled) ON identity.registered_workloads TO audit_writer;

-- 2. Audit sources. The writer is the proxy source; correlation appends its
--    own events through audit_append().
INSERT INTO audit.db_role_sources (db_role, source_id, proxy) VALUES
  (:'writer_login',      'audit-writer',                 true),
  (:'correlation_login', :'correlation_audit_source_id', false)
ON CONFLICT (db_role) DO NOTHING;

-- 3. Producer event grants. Every source below emits with tenant '*'
--    (kernel ingest, receiver gap events, control-health holds and lease
--    transitions, correlation results/findings/gaps).
CREATE TEMP TABLE m31_observe_grants (source_id text, event_type text) ON COMMIT DROP;
INSERT INTO m31_observe_grants VALUES
  -- TASK-09 exporter (tetragon SAN) kernel batches, and the writer's
  -- receiver gap events (services/audit README, kernel/lifecycle ingest).
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon', 'kernel_event_observed'),
  ('audit-writer', 'sequence_range_abandoned'),
  ('audit-writer', 'observation_gap_recorded');
INSERT INTO m31_observe_grants
SELECT :'health_audit_source_id', e
FROM unnest(ARRAY['execution_held', 'hold_requested', 'source_health_changed']) AS e;
INSERT INTO m31_observe_grants
SELECT :'correlation_audit_source_id', e
FROM unnest(ARRAY['network_finding_recorded', 'observation_gap_recorded', 'sequence_range_abandoned',
                  'evidence_gap_resolved', 'kernel_correlation_checked']) AS e;
INSERT INTO audit.producer_event_grants (source_id, event_type, tenant)
SELECT source_id, event_type, '*' FROM m31_observe_grants
ON CONFLICT DO NOTHING;

-- 4. Workload certificate principals (services/identity/seed/registered_workloads.yaml).
--    workload-identity records its own server certificate in
--    identity.issued_certificates, whose (namespace, ksa) references this table.
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal, enabled) VALUES
  ('agent-control', 'workload-identity',  'service', NULL, 'workload-identity',  true),
  ('agent-control', 'credential-broker',  'service', NULL, 'credential-broker',  true),
  ('agent-observe', 'control-health',     'service', NULL, 'control-health',     true),
  ('agent-observe', 'audit-writer',       'service', NULL, 'audit-writer',       true),
  ('agent-observe', 'audit-exporter',     'service', NULL, 'audit-exporter',     true),
  ('agent-observe', 'correlation',        'service', NULL, 'correlation',        true),
  ('agent-sensors', 'lifecycle-recorder', 'service', NULL, 'lifecycle-recorder', true),
  ('agent-sensors', 'netpol-collector',   'service', NULL, 'netpol-collector',   true)
ON CONFLICT (namespace, ksa) DO NOTHING;

-- 5. control-health caller principals (TASK-10 3.2; COMMON required leases).
INSERT INTO health.component_principals
  (principal_san, component, allowed_scopes, allowed_hold_reasons, releasable_hold_reasons) VALUES
  -- audit-db global lease and its own db_unavailable hold.
  ('spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer',       'audit-db',           ARRAY['global'],   ARRAY['db_unavailable'], ARRAY['db_unavailable']),
  -- per-node leases (source <component>-node/<node_uid>), no holds.
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder', 'lifecycle-recorder', ARRAY['node'],     ARRAY[]::text[],          ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector',   'netpol-collector',   ARRAY['node'],     ARRAY[]::text[],          ARRAY[]::text[]),
  -- correlation: workload risk_event holds only (services/correlation/internal/risk).
  ('spiffe://agentarium.internal/ns/agent-observe/sa/correlation',        'correlation',        ARRAY['workload'], ARRAY['risk_event'],      ARRAY[]::text[])
ON CONFLICT (principal_san) DO NOTHING;

-- Checks: fail (and roll back) when an existing row disagrees with this file.
SELECT 1 / (count(*) = 2)::int AS db_role_sources_ok FROM audit.db_role_sources
WHERE (db_role::text, source_id, proxy) IN ((:'writer_login', 'audit-writer', true),
  (:'correlation_login', :'correlation_audit_source_id', false));
SELECT 1 / (count(*) = 0)::int AS producer_event_grants_ok FROM m31_observe_grants e
WHERE NOT EXISTS (SELECT 1 FROM audit.producer_event_grants g
                  WHERE g.source_id = e.source_id AND g.event_type = e.event_type AND g.tenant = '*');
SELECT 1 / (count(*) = 8)::int AS registered_workloads_ok FROM identity.registered_workloads
WHERE enabled AND role = 'service' AND service_principal = ksa AND adapter_id IS NULL
  AND (namespace, ksa) IN (('agent-control', 'workload-identity'), ('agent-control', 'credential-broker'),
  ('agent-observe', 'control-health'), ('agent-observe', 'audit-writer'), ('agent-observe', 'audit-exporter'),
  ('agent-observe', 'correlation'), ('agent-sensors', 'lifecycle-recorder'), ('agent-sensors', 'netpol-collector'));
SELECT 1 / (count(*) = 5)::int AS component_principals_ok FROM health.component_principals
WHERE (principal_san, component, allowed_scopes, allowed_hold_reasons, releasable_hold_reasons) IN (
  ('spiffe://agentarium.internal/ns/agent-observe/sa/audit-writer', 'audit-db', ARRAY['global'], ARRAY['db_unavailable'], ARRAY['db_unavailable']),
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder', 'lifecycle-recorder', ARRAY['node'], ARRAY[]::text[], ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/netpol-collector', 'netpol-collector', ARRAY['node'], ARRAY[]::text[], ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-observe/sa/correlation', 'correlation', ARRAY['workload'], ARRAY['risk_event'], ARRAY[]::text[]),
  -- seeded by migration 20261017172319; the exporter cannot report audit-export without it.
  ('spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter', 'audit-export', ARRAY['global', 'node'], ARRAY['export_lag'], ARRAY['export_lag']));
SELECT 1 / (pg_has_role(:'writer_login', 'audit_writer', 'USAGE')
  AND pg_has_role(:'exporter_login', 'audit_exporter', 'USAGE')
  AND pg_has_role(:'broker_login', 'broker_reader', 'USAGE')
  AND pg_has_role(:'correlation_login', 'correlation_writer', 'USAGE')
  AND pg_has_role(:'correlation_login', 'correlation_reader', 'USAGE'))::int AS memberships_ok;

-- Revoke the owner roles step 0 took.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY coalesce(string_to_array(nullif(current_setting('m31_install.granted_owners', true), ''), ','), '{}') LOOP
    EXECUTE format('REVOKE %I FROM CURRENT_USER', r);
  END LOOP;
END $$;
COMMIT;
