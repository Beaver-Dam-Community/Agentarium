-- Run before starting the queue-enabled correlation service. Triggers from the
-- previous migration capture concurrent inserts; ON CONFLICT handles overlap.
-- This one-time retained-history scan may be large. It is separate from DDL so
-- inserts are not blocked by the trigger-installation table lock during backfill.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('queue_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
INSERT INTO correlation.pending_inputs
 SELECT 'kernel',source_event_id,node_uid,source_time,received_at FROM audit.kernel_events
 ON CONFLICT DO NOTHING;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('queue_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
INSERT INTO correlation.pending_inputs
 SELECT 'netpol' ,record_id,node_uid,source_time,received_at FROM correlation.network_policy_records
 ON CONFLICT DO NOTHING;
COMMIT;
