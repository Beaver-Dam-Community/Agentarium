-- M3-1 action path install data (TASK-01 3, TASK-06 3.3, TASK-16 step 3/5).
--
-- Run once per installation, after every migration of the M3-1 code PRs is
-- applied, as the migration installer login (#156 db-installer, a
-- cloudsqlsuperuser member that owns the migrated objects). Every statement is
-- idempotent: rerunning changes nothing, and a row that already exists with
-- different values is NOT overwritten; the checks at the end then fail and
-- the transaction rolls back for a human decision.
--
-- No secret value appears here. The receiver API key is referenced by its
-- Secret Manager resource name and pinned numeric version only.
--
--   psql "$INSTALLER_DSN" -v ON_ERROR_STOP=1 \
--     -v tenant=hackathon \
--     -v identity_login='workload-identity-db@PROJECT.iam' \
--     -v gateway_login='policy-gateway-db@PROJECT.iam' \
--     -v coordinator_login='coordinator-db@PROJECT.iam' \
--     -v adapter_login='receiver-sender-db@PROJECT.iam' \
--     -v receiver_login='receiver-db@PROJECT.iam' \
--     -v collector_login='evidence-collector-db@PROJECT.iam' \
--     -v health_login='control-health-db@PROJECT.iam' \
--     -v health_audit_source_id=control-health \
--     -v receiver_api_key_secret='projects/NUMBER/secrets/NAME' \
--     -v receiver_api_key_version=1 \
--     -f deploy/gcp/base/installer/m3-1-action-path.sql
--
-- Login names are the Terraform outputs `workload_services[*].db_user` and
-- `contact_services[*].db_user` (GSA e-mail without .gserviceaccount.com).
-- Audit source ids equal the rendered --audit-source-id flags in
-- action-path/services.yaml and contact-services/contacts.yaml.

\set ON_ERROR_STOP on
BEGIN;

-- 0. Schema owner roles. Each migration takes its schema owner role (for
--    example audit_owner) only for its own transaction and revokes it at the
--    end, so the installer login is not a member afterwards. This file takes
--    the owner roles of the schemas it writes the same way (PostgreSQL 16:
--    the creating installer holds ADMIN on them) and revokes them before
--    COMMIT. The installer owns no other object through them after the run.
DO $$
DECLARE
  r text;
  granted text[] := '{}';
BEGIN
  FOR r IN SELECT DISTINCT o.rolname FROM pg_namespace n JOIN pg_roles o ON o.oid = n.nspowner
           WHERE n.nspname IN ('audit', 'identity', 'decisions', 'broker', 'health') LOOP
    IF NOT (pg_has_role(current_user, r, 'USAGE') AND pg_has_role(current_user, r, 'SET')) THEN
      EXECUTE format('GRANT %I TO CURRENT_USER WITH INHERIT TRUE, SET TRUE', r);
      granted := granted || r;
    END IF;
  END LOOP;
  PERFORM set_config('m31_install.granted_owners', array_to_string(granted, ','), true);
END $$;

-- 1. Role memberships (COMMON DB roles; migrations already make every *_app
--    role an audit_producer member and grant the *_reader roles).
GRANT identity_app       TO :"identity_login";
GRANT gateway_app        TO :"gateway_login";
GRANT coordinator_app    TO :"coordinator_login";
GRANT adapter_app        TO :"adapter_login";
-- The receiver runs one pool per role (receiver.NewRolePool): both memberships.
GRANT receiver_writer, receipt_reader TO :"receiver_login";
GRANT evidence_collector TO :"collector_login";
-- control-health appends session_worker_* / work_readiness_* events in its own
-- transaction (#228) through audit_append().
GRANT control_health_writer, audit_producer TO :"health_login";

-- SPEC-QUESTION (COMMON cross-task read table): control-health resolves every
-- caller certificate with identity.issued_certificates JOIN
-- identity.registered_workloads (healthdb Certificate query), but the table
-- lists only identity.work_readiness_session_view for control_health_writer.
-- Without these column grants every control-health mTLS call is denied.
-- role: the session-worker runtime lookup (store/workers.go lookupRuntime)
-- also requires w.role = 'runtime'.
GRANT USAGE ON SCHEMA identity TO control_health_writer;
GRANT SELECT (serial, san_uri, namespace, ksa, pod_uid, node_uid, boot_id, issued_at, expires_at, revoked_at)
  ON identity.issued_certificates TO control_health_writer;
GRANT SELECT (namespace, ksa, role, enabled)
  ON identity.registered_workloads TO control_health_writer;

-- 2. Audit sources: DB login -> source_id (TASK-07 3.2, audit_append checks
--    session_user against this table).
INSERT INTO audit.db_role_sources (db_role, source_id) VALUES
  (:'identity_login',    'workload-identity'),
  (:'gateway_login',     'policy-gateway'),
  (:'coordinator_login', 'coordinator'),
  (:'adapter_login',     'receiver-sender'),
  (:'collector_login',   'evidence-collector'),
  (:'health_login',      :'health_audit_source_id')
ON CONFLICT (db_role) DO NOTHING;

-- 3. Producer event grants for the demo tenant.
CREATE TEMP TABLE m31_expected_grants (source_id text, event_type text) ON COMMIT DROP;
INSERT INTO m31_expected_grants VALUES
  -- identity (#220)
  ('workload-identity', 'session_created'), ('workload-identity', 'session_claimed'),
  ('workload-identity', 'contract_created'), ('workload-identity', 'approval_granted'),
  -- gateway (#223)
  ('policy-gateway', 'request_received'), ('policy-gateway', 'request_rejected'),
  ('policy-gateway', 'policy_decided'), ('policy-gateway', 'policy_evaluation_failed'),
  ('policy-gateway', 'approval_requested'), ('policy-gateway', 'action_reevaluated'),
  ('policy-gateway', 'dispatch_enqueued'),
  -- coordinator (#222)
  ('coordinator', 'attempt_planned'), ('coordinator', 'attempt_released'),
  ('coordinator', 'attempt_uncertain'), ('coordinator', 'activation_probe_registered'),
  -- receiver-sender adapter (#225)
  ('receiver-sender', 'preflight_passed'), ('receiver-sender', 'preflight_rejected'),
  ('receiver-sender', 'dispatch_started'), ('receiver-sender', 'response_received'),
  ('receiver-sender', 'attempt_uncertain'), ('receiver-sender', 'attempt_failed'),
  -- evidence collector (#227)
  ('evidence-collector', 'destination_observed'),
  -- runtime work events relayed gateway -> audit-writer (#236/#237); the
  -- source is the runtime's service SAN, the writer is a proxy source.
  ('spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime', 'agent_work_start_requested'),
  ('spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime', 'agent_work_started'),
  ('spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime', 'agent_work_paused'),
  ('spiffe://agentarium.internal/ns/agent-exec/sa/agent-runtime', 'agent_work_finished');
-- control-health session worker / work readiness events (#228), session tenant.
INSERT INTO m31_expected_grants
SELECT :'health_audit_source_id', e
FROM unnest(ARRAY['session_worker_registered', 'session_worker_observed', 'session_worker_closed',
                  'session_worker_invalidated', 'work_readiness_requested', 'work_readiness_passed',
                  'work_readiness_blocked']) AS e;
INSERT INTO audit.producer_event_grants (source_id, event_type, tenant)
SELECT source_id, event_type, :'tenant' FROM m31_expected_grants
ON CONFLICT DO NOTHING;

-- 4. Adapter DB login -> adapter_id (TASK-04 decisions.adapter_db_roles).
INSERT INTO decisions.adapter_db_roles (db_role, adapter_id) VALUES (:'adapter_login', 'receiver-sender')
ON CONFLICT (db_role) DO NOTHING;

-- 5. Workload certificate principals (TASK-03 registered_workloads). Every
--    SAN in the M3-1 path; service_principal = KSA for services.
INSERT INTO identity.registered_workloads (namespace, ksa, role, adapter_id, service_principal, enabled) VALUES
  ('agent-control',  'policy-gateway',     'service', NULL,              'policy-gateway',     true),
  ('agent-control',  'coordinator',        'service', NULL,              'coordinator',        true),
  ('agent-adapters', 'receiver-sender',    'adapter', 'receiver-sender', NULL,                 true),
  ('agent-targets',  'receiver',           'service', NULL,              'receiver',           true),
  ('agent-observe',  'evidence-collector', 'service', NULL,              'evidence-collector', true),
  ('agent-sensors',  'tetragon',           'service', NULL,              'tetragon',           true),
  -- node-readiness (#273): control-health node-scope reader and global lease.
  ('agent-control',  'node-readiness',     'service', NULL,              'node-readiness',     true),
  -- runtime (#234): certificate bootstrap through the gateway relay.
  ('agent-exec',     'agent-runtime',      'runtime', NULL,              NULL,                 true)
ON CONFLICT (namespace, ksa) DO NOTHING;

-- 6. control-health caller principals (TASK-10, COMMON ControlHealthLease.component).
INSERT INTO health.component_principals
  (principal_san, component, allowed_scopes, allowed_hold_reasons, releasable_hold_reasons) VALUES
  ('spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway',      'gateway',              ARRAY['global'],   ARRAY[]::text[], ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-control/sa/coordinator',         'coordinator',          ARRAY['global'],   ARRAY[]::text[], ARRAY[]::text[]),
  ('spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender',    'adapter',              ARRAY['workload'], ARRAY[]::text[], ARRAY[]::text[]),
  -- collector: target/receiver-primary lease, probe results and its own
  -- probe_failed hold (#227 probe.go).
  ('spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector',  'destination-evidence', ARRAY['target'],   ARRAY['probe_failed'], ARRAY['probe_failed']),
  -- node-sensors: per-node lease and node nonce results (#228, #232). An
  -- existing row from the #165 install is kept as is.
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon',            'node-sensors',         ARRAY['node'],     ARRAY[]::text[], ARRAY[]::text[]),
  -- node-readiness (#273): its own global lease (scope_id '*'), no holds.
  ('spiffe://agentarium.internal/ns/agent-control/sa/node-readiness',      'node-readiness',       ARRAY['global'],   ARRAY[]::text[], ARRAY[]::text[])
ON CONFLICT (principal_san) DO NOTHING;

-- 7. Broker credential binding for receiver.submit (TASK-06 3.3, TASK-08 #169).
INSERT INTO broker.credential_bindings
  (credential_binding, adapter_id, operation_id, secret_resource, secret_version,
   header_name, header_format, enabled, updated_at, updated_by)
VALUES ('receiver-api-key', 'receiver-sender', 'receiver.submit', :'receiver_api_key_secret',
        :'receiver_api_key_version', 'X-Agentarium-Receiver-Key', 'raw', true, now(), 'installer:m3-1')
ON CONFLICT (credential_binding) DO NOTHING;

-- Checks: fail (and roll back) when an existing row disagrees with this file.
SELECT 1 / (count(*) = 6)::int AS db_role_sources_ok FROM audit.db_role_sources
WHERE (db_role::text, source_id) IN ((:'identity_login', 'workload-identity'), (:'gateway_login', 'policy-gateway'),
  (:'coordinator_login', 'coordinator'), (:'adapter_login', 'receiver-sender'),
  (:'collector_login', 'evidence-collector'), (:'health_login', :'health_audit_source_id'));
SELECT 1 / (count(*) = 1)::int AS adapter_db_role_ok FROM decisions.adapter_db_roles
WHERE db_role::text = :'adapter_login' AND adapter_id = 'receiver-sender';
SELECT 1 / (count(*) = 8)::int AS registered_workloads_ok FROM identity.registered_workloads
WHERE enabled AND (namespace, ksa, role) IN (('agent-control', 'policy-gateway', 'service'),
  ('agent-control', 'coordinator', 'service'), ('agent-adapters', 'receiver-sender', 'adapter'),
  ('agent-targets', 'receiver', 'service'), ('agent-observe', 'evidence-collector', 'service'),
  ('agent-sensors', 'tetragon', 'service'), ('agent-exec', 'agent-runtime', 'runtime'),
  ('agent-control', 'node-readiness', 'service'));
SELECT 1 / (count(*) = 6)::int AS component_principals_ok FROM health.component_principals
WHERE (principal_san, component) IN (
  ('spiffe://agentarium.internal/ns/agent-control/sa/policy-gateway', 'gateway'),
  ('spiffe://agentarium.internal/ns/agent-control/sa/coordinator', 'coordinator'),
  ('spiffe://agentarium.internal/ns/agent-adapters/sa/receiver-sender', 'adapter'),
  ('spiffe://agentarium.internal/ns/agent-observe/sa/evidence-collector', 'destination-evidence'),
  ('spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon', 'node-sensors'),
  ('spiffe://agentarium.internal/ns/agent-control/sa/node-readiness', 'node-readiness'));
SELECT 1 / (count(*) = 1)::int AS credential_binding_ok FROM broker.credential_bindings
WHERE credential_binding = 'receiver-api-key' AND enabled AND adapter_id = 'receiver-sender'
  AND operation_id = 'receiver.submit' AND secret_resource = :'receiver_api_key_secret'
  AND secret_version = :'receiver_api_key_version' AND header_name = 'X-Agentarium-Receiver-Key'
  AND header_format = 'raw';
SELECT 1 / (count(*) = 0)::int AS producer_event_grants_ok FROM m31_expected_grants e
WHERE NOT EXISTS (SELECT 1 FROM audit.producer_event_grants g
                  WHERE g.source_id = e.source_id AND g.event_type = e.event_type AND g.tenant = :'tenant');

-- Revoke the owner roles step 0 took.
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY coalesce(string_to_array(nullif(current_setting('m31_install.granted_owners', true), ''), ','), '{}') LOOP
    EXECUTE format('REVOKE %I FROM CURRENT_USER', r);
  END LOOP;
END $$;
COMMIT;
