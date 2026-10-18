-- Removing the kernel ingest functions leaves stored kernel rows, gaps and
-- watermarks intact; only the receive path is disabled again.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('kernel_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DROP FUNCTION IF EXISTS audit.ingest_kernel_batch(text,jsonb,text,text,text,text);
DROP FUNCTION IF EXISTS audit._kernel_record(jsonb,text,text);
UPDATE audit.event_types SET required_payload_fields='["source_event_id", "source_epoch", "source_sequence", "process_exec_id", "event_type"]'::jsonb
 WHERE event_type='kernel_event_observed';
RESET ROLE;
DO $$ BEGIN
 IF current_setting('kernel_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
