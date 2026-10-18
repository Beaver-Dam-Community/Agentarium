-- TASK-10 NodeFacts: record whether a boot's startup_capture came from a
-- measured Q0 result. Requires shared spec #189. No default: every insert
-- must state the measurement (a default would record "measured" fail-open).
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_measurement_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
LOCK TABLE health.node_boot_generation IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
 -- Production NodeFacts was unwired before this change, so no boot can hold
 -- a proven guarded result. Refuse to guess for any such row.
 IF EXISTS (SELECT FROM health.node_boot_generation WHERE startup_capture = 'guarded') THEN
  RAISE EXCEPTION 'guarded node boots without measurement evidence; resolve before migrating' USING ERRCODE = '55000';
 END IF;
END $$;
ALTER TABLE health.node_boot_generation ADD COLUMN startup_capture_measurement text;
UPDATE health.node_boot_generation SET startup_capture_measurement = 'not_measured';
ALTER TABLE health.node_boot_generation
  ALTER COLUMN startup_capture_measurement SET NOT NULL,
  ADD CONSTRAINT node_boot_generation_measurement_values
    CHECK (startup_capture_measurement IN ('measured','not_measured')),
  ADD CONSTRAINT node_boot_generation_guarded_measured
    CHECK (startup_capture = 'unsupported' OR startup_capture_measurement = 'measured');
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_measurement_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
