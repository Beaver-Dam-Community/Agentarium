-- Drops the work-readiness records. TASK-10 keeps them at least 30 days;
-- run only on an installation where none must be retained.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_readiness_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
DROP TABLE health.worker_evidence;
DROP TABLE health.worker_challenges;
DROP TABLE health.work_readiness_checks;
DROP TABLE health.session_process_bindings;
DROP FUNCTION health.work_readiness_check_transition();
DROP FUNCTION health.session_process_binding_transition();
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_readiness_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
