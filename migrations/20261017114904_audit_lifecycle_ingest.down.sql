BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('lifecycle_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DROP FUNCTION audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text);
DROP FUNCTION audit.lifecycle_checkpoint(text,text);
DROP FUNCTION audit._lifecycle_record(jsonb,text,text);
DROP FUNCTION audit._lifecycle_proxy(text);
-- Retain provenance/checkpoint/gap links and uuid-ossp. Dropping these columns
-- would destroy replay and audit history; this down disables only the API.
RESET ROLE;
DO $$ BEGIN
 IF current_setting('lifecycle_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
