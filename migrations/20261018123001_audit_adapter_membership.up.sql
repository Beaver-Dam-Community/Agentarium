-- TASK-07 / COMMON DB function registry: the TASK-05 adapter role is an
-- audit_producer member, like identity_app, coordinator_app and gateway_app
-- (20261017105252_audit_application_membership). Apply after
-- 20261018123000_adapter_app_role. The installer needs ADMIN OPTION on
-- audit_producer. db_role_sources and producer_event_grants for each adapter
-- login stay installation inputs (preflight_passed, preflight_rejected,
-- dispatch_started, response_received, attempt_uncertain, attempt_failed).
BEGIN;
GRANT audit_producer TO adapter_app;
COMMIT;
