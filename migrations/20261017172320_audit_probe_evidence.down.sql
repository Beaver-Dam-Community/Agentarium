BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('probe_evidence_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DROP FUNCTION audit.probe_evidence_events(uuid, text, text[], timestamptz, timestamptz);
RESET ROLE;
DO $$ BEGIN
 IF current_setting('probe_evidence_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
