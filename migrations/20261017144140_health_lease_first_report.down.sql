BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_first_report_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
ALTER TABLE health.control_health_leases DROP COLUMN first_reported_at;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_first_report_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
