-- TASK-05 adapter writer role (M3-1 receiver-sender wiring).
--
-- 20261016110000_adapter_results left the writer role of the adapter tables
-- to the integration change. adapter_app is that NOLOGIN group: each adapter
-- login (its Cloud SQL IAM DB user) is made a member at install time
-- (TASK-16), next to its decisions.adapter_db_roles row and its
-- audit.db_role_sources row. adapter_app is a member of adapter_reader
-- (TASK-05, COMMON read access to other Task tables), so the login reads the
-- decision, its adapter views and desired_bundle through it.
--
-- SPEC-QUESTION: COMMON names no adapter writer role; adapter_app follows the
-- identity_app / coordinator_app / gateway_app naming.
--
-- Privileges are exactly what packages/adapters/store runs:
--   adapter_executions: INSERT ... ON CONFLICT DO NOTHING (SELECT on the key),
--     SELECT, UPDATE of state / attempt_id / the two event_id columns /
--     updated_at;
--   pending_outcomes, action_results: INSERT ... ON CONFLICT DO NOTHING and
--     SELECT; no UPDATE or DELETE;
--   workload_data_state: upsert (UPDATE of the raised columns only; the
--     trigger still refuses lowering).
-- No DELETE or TRUNCATE anywhere.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adapter_app') THEN
        CREATE ROLE adapter_app NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA adapter TO adapter_app;
GRANT SELECT, INSERT ON adapter.adapter_executions, adapter.pending_outcomes,
    adapter.action_results, adapter.workload_data_state TO adapter_app;
GRANT UPDATE (state, attempt_id, preflight_passed_event_id, preflight_rejected_event_id, updated_at)
    ON adapter.adapter_executions TO adapter_app;
GRANT UPDATE (data_class_high_water, data_sources, updated_by_attempt_id, updated_at)
    ON adapter.workload_data_state TO adapter_app;
GRANT adapter_reader TO adapter_app;
