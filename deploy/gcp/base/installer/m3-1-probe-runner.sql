-- M3-1 answer probe install data (TASK-10 3.2, TASK-03 registered_workloads).
--
-- Run once per installation after m3-1-action-path.sql and before
-- deploy/gcp/base/probe-runner/ is applied, as the migration installer login
-- (#156 db-installer). Same rules as m3-1-action-path.sql: idempotent, an
-- existing row with other values is NOT overwritten, and the checks at the
-- end then fail and roll back the transaction.
--
--   psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 \
--     -f deploy/gcp/base/installer/m3-1-probe-runner.sql
--
-- The probe runners get Pod-bound certificates
-- (spiffe://.../ns/<ns>/sa/probe-runner/pod/<uid>); control-health authorizes
-- them by the service SAN without the /pod/<uid> suffix
-- (health.ProbeRunnerSAN). The agent-exec runner reports through the gateway
-- relay, which needs no row here beyond the existing gateway principal.

\set ON_ERROR_STOP on
BEGIN;

-- 0. Schema owner roles, taken and revoked as in m3-1-action-path.sql.
DO $$
DECLARE
  r text;
  granted text[] := '{}';
BEGIN
  FOR r IN SELECT DISTINCT o.rolname FROM pg_namespace n JOIN pg_roles o ON o.oid = n.nspowner
           WHERE n.nspname IN ('identity', 'health') LOOP
    IF NOT (pg_has_role(current_user, r, 'USAGE') AND pg_has_role(current_user, r, 'SET')) THEN
      EXECUTE format('GRANT %I TO CURRENT_USER WITH INHERIT TRUE, SET TRUE', r);
      granted := granted || r;
    END IF;
  END LOOP;
  PERFORM set_config('m31_install.granted_owners', array_to_string(granted, ','), true);
END $$;

-- 1. Certificate principals (services/identity/seed/registered_workloads.yaml).
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal, enabled) VALUES
  ('agent-exec',     'probe-runner', 'probe',   NULL, NULL,         true),
  ('agent-adapters', 'probe-runner', 'probe',   NULL, NULL,         true),
  ('agent-targets',  'probe-sink',   'service', NULL, 'probe-sink', true)
ON CONFLICT (namespace, ksa) DO NOTHING;

-- 2. control-health reporters: node answer probes only (COMMON
--    ControlHealthLease.component probe-runner, scope node, no holds).
INSERT INTO health.component_principals
  (principal_san, component, allowed_scopes, allowed_hold_reasons, releasable_hold_reasons) VALUES
  ('spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner',     'probe-runner', ARRAY['node'], ARRAY[]::text[], ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner', 'probe-runner', ARRAY['node'], ARRAY[]::text[], ARRAY[]::text[])
ON CONFLICT (principal_san) DO NOTHING;

-- Checks: fail (and roll back) when an existing row disagrees with this file.
SELECT 1 / (count(*) = 3)::int AS registered_workloads_ok FROM identity.registered_workloads
WHERE enabled AND (namespace, ksa, role) IN (('agent-exec', 'probe-runner', 'probe'),
  ('agent-adapters', 'probe-runner', 'probe'), ('agent-targets', 'probe-sink', 'service'))
  AND (role <> 'service' OR service_principal = ksa) AND (role <> 'probe' OR service_principal IS NULL);
SELECT 1 / (count(*) = 2)::int AS component_principals_ok FROM health.component_principals
WHERE component = 'probe-runner' AND allowed_scopes = ARRAY['node'] AND allowed_hold_reasons = ARRAY[]::text[]
  AND releasable_hold_reasons = ARRAY[]::text[]
  AND principal_san IN ('spiffe://agentarium.internal/ns/agent-exec/sa/probe-runner',
                        'spiffe://agentarium.internal/ns/agent-adapters/sa/probe-runner');

-- Revoke the owner roles step 0 took.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY coalesce(string_to_array(nullif(current_setting('m31_install.granted_owners', true), ''), ','), '{}') LOOP
    EXECUTE format('REVOKE %I FROM CURRENT_USER', r);
  END LOOP;
END $$;
COMMIT;
