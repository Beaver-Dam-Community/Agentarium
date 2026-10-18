-- TASK-07 grants for the TASK-10 correlation reader (TASK-07 grant list:
-- schema USAGE and SELECT on kernel_events, lifecycle_events, abandoned_ranges).
-- correlation_writer inherits them through correlation_reader membership.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('correlation_reader_migration.granted_owner','on',true);
 END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='correlation_reader') THEN
  RAISE EXCEPTION 'correlation_reader (TASK-10) must be installed first' USING ERRCODE='55000';
 END IF;
END $$;
SET ROLE audit_owner;
GRANT USAGE ON SCHEMA audit TO correlation_reader;
GRANT SELECT ON audit.kernel_events, audit.lifecycle_events, audit.abandoned_ranges TO correlation_reader;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('correlation_reader_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
