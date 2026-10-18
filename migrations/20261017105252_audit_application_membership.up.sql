-- TASK-07 / COMMON DB function registry: the existing TASK-03 identity and
-- coordinator roles and TASK-04 gateway role are audit_producer members.
-- Apply after identity_workload_pki, audit_store and coordinator_dispatch.
-- Missing roles fail closed; this migration never creates application roles.
-- The installer needs ADMIN OPTION on audit_producer (CREATEROLE alone does
-- not provide it for pre-existing roles on PostgreSQL 16+).
-- IAM login membership, db_role_sources, producer_event_grants and runtime
-- service audit wiring remain separate installation/implementation steps.
BEGIN;
GRANT audit_producer TO identity_app, coordinator_app, gateway_app;
COMMIT;
