BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('worker_exec_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DROP FUNCTION audit.worker_exec_evidence(uuid, uuid, text, text);
-- Fails while a health foreign key still uses it; the TASK-10 migration goes
-- down first.
REVOKE REFERENCES (source_event_id) ON audit.kernel_events FROM health_owner;
REVOKE USAGE ON SCHEMA audit FROM health_owner;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('worker_exec_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
