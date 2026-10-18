BEGIN;
-- The installer temporarily assumes the existing raw-evidence owner only
-- to create/drop its trigger, using the repository's membership pattern.
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('queue_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DROP TRIGGER correlation_enqueue ON audit.kernel_events;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('queue_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
DROP TRIGGER correlation_enqueue ON correlation.network_policy_records;
DROP FUNCTION correlation.enqueue_input();
DROP TABLE correlation.pending_inputs;
-- Keep schema USAGE: other independently installed audit integrations may use it.
COMMIT;
