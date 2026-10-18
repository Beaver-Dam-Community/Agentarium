-- Refuses while audit_integrity history exists; such holds need a forward migration.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_integrity_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM health.holds WHERE reason='audit_integrity') THEN
  RAISE EXCEPTION 'audit_integrity holds exist; refusing to drop the reason' USING ERRCODE='55000';
 END IF;
END $$;
DELETE FROM health.component_principals WHERE principal_san IN (
 'spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter','spiffe://agentarium.internal/ns/agent-observe/sa/audit-verifier');
ALTER TABLE health.holds DROP CONSTRAINT holds_reason_check,
  ADD CONSTRAINT holds_reason_check CHECK (reason IN (
    'export_lag','db_unavailable','probe_failed','lease_expired','start_unknown','sensor_degraded',
    'control_drift','bypass_detected','sensor_tampering','alignment_mismatch','risk_event',
    'policy_activation','operator_stop'));
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_integrity_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
