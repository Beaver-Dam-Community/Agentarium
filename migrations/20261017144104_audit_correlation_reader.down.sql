BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('correlation_reader_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
REVOKE SELECT ON audit.kernel_events, audit.lifecycle_events, audit.abandoned_ranges FROM correlation_reader;
REVOKE USAGE ON SCHEMA audit FROM correlation_reader;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('correlation_reader_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
