-- Refuses to destroy declared loss evidence; history needs a forward migration.
BEGIN;
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM correlation.network_policy_abandoned_ranges) OR EXISTS (SELECT 1 FROM correlation.network_policy_rotation_losses) THEN
    RAISE EXCEPTION 'netpol loss declarations exist; refusing to drop evidence' USING ERRCODE='55000';
  END IF;
END $$;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('correlation_receiver_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
REVOKE SELECT (source_id, first_reported_at) ON health.control_health_leases FROM correlation_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('correlation_receiver_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
REVOKE EXECUTE ON FUNCTION identity.audit_source_certificate(text,text,text) FROM correlation_writer;
-- Shared schema USAGE is also required by identity.pod_workloads.
DROP TABLE correlation.network_policy_rotation_losses;
DROP TABLE correlation.network_policy_abandoned_ranges;
COMMIT;
