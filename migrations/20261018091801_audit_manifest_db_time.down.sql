-- Restores exporter-supplied timestamps; only for rollback of this change.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('manifest_time_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DROP TRIGGER IF EXISTS manifest_intents_db_time ON audit.manifest_intents;
DROP TRIGGER IF EXISTS export_manifests_db_time ON audit.export_manifests;
DROP FUNCTION IF EXISTS audit._manifest_db_time();
GRANT INSERT ON audit.manifest_intents, audit.export_manifests TO audit_exporter;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('manifest_time_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
