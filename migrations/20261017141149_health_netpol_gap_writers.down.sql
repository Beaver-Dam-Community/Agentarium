BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_netpol_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
REVOKE UPDATE (end_at, recovery_state, evidence_refs, affected_workloads) ON health.observation_gaps FROM correlation_writer;
REVOKE SELECT, INSERT ON health.observation_gaps FROM correlation_writer;
DROP FUNCTION health.record_netpol_collector_gap(uuid, text, timestamptz, jsonb);
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_netpol_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
