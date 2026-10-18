-- TASK-10 3.7: keep each lease source's first report time so a netpol
-- collector that never had a record acknowledged opens its gap at its first
-- lease (conservative start), not at a later report.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_first_report_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
ALTER TABLE health.control_health_leases ADD COLUMN first_reported_at timestamptz;
-- Existing rows only know their latest report; that is the earliest known bound.
UPDATE health.control_health_leases SET first_reported_at = reported_at;
ALTER TABLE health.control_health_leases ALTER COLUMN first_reported_at SET NOT NULL,
  ADD CONSTRAINT control_health_leases_first_report CHECK (first_reported_at <= reported_at);
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_first_report_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
