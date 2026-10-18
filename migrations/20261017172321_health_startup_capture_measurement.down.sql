-- Drops only the measurement column; startup_capture values are unchanged.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_measurement_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
ALTER TABLE health.node_boot_generation DROP COLUMN startup_capture_measurement;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_measurement_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
