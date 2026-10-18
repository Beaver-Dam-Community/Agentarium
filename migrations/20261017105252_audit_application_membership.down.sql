-- Remove only these three application-role memberships. Audit rows, outbox,
-- source registrations, roles and function/table ACLs remain unchanged.
BEGIN;
REVOKE audit_producer FROM identity_app, coordinator_app, gateway_app;
COMMIT;
