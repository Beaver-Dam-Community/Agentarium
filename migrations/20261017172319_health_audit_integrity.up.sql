-- TASK-10 3.2/3.6 with TASK-07 #163: audit_integrity is a security hold reason
-- (operator approval only), and the audit exporter/verifier principals get
-- exactly the reasons and scopes that spec assigns them.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_integrity_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
ALTER TABLE health.holds DROP CONSTRAINT holds_reason_check,
  ADD CONSTRAINT holds_reason_check CHECK (reason IN (
    'export_lag','db_unavailable','probe_failed','lease_expired','start_unknown','sensor_degraded',
    'control_drift','bypass_detected','sensor_tampering','alignment_mismatch','audit_integrity','risk_event',
    'policy_activation','operator_stop'));
-- An installer-seeded row with different grants is a conflict, never overwritten.
DO $$
DECLARE want record;
BEGIN
 FOR want IN SELECT * FROM (VALUES
   ('spiffe://agentarium.internal/ns/agent-observe/sa/audit-exporter','audit-export',ARRAY['global','node'],ARRAY['export_lag'],ARRAY['export_lag']),
   ('spiffe://agentarium.internal/ns/agent-observe/sa/audit-verifier','audit-verifier',ARRAY['global'],ARRAY['audit_integrity'],ARRAY[]::text[])
 ) AS v(san,component,scopes,reasons,releasable) LOOP
  INSERT INTO health.component_principals VALUES (want.san,want.component,want.scopes,want.reasons,want.releasable)
   ON CONFLICT (principal_san) DO NOTHING;
  IF NOT EXISTS (SELECT 1 FROM health.component_principals p WHERE p.principal_san=want.san AND p.component=want.component
     AND p.allowed_scopes=want.scopes AND p.allowed_hold_reasons=want.reasons AND p.releasable_hold_reasons=want.releasable) THEN
   RAISE EXCEPTION 'component principal % already registered with different grants', want.san USING ERRCODE='55000';
  END IF;
 END LOOP;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_integrity_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
