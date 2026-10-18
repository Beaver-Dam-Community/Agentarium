-- Internal retry queue. Enqueue in the same transaction as evidence insertion;
-- no timestamp watermark can miss an earlier transaction that commits later.
BEGIN;
CREATE TABLE correlation.pending_inputs (
 input_kind text NOT NULL CHECK(input_kind IN ('kernel','netpol')),
 input_id uuid NOT NULL,
 node_uid uuid NOT NULL,
 source_time timestamptz NOT NULL,
 received_at timestamptz NOT NULL,
 PRIMARY KEY(input_kind,input_id)
);
CREATE INDEX pending_inputs_node_received ON correlation.pending_inputs
 (node_uid,received_at,input_kind,input_id) INCLUDE(source_time);
REVOKE ALL ON correlation.pending_inputs FROM PUBLIC;
GRANT SELECT, DELETE ON correlation.pending_inputs TO correlation_writer;
-- Invoker triggers need only INSERT into this internal queue. No new access to
-- raw evidence and no installer-owned SECURITY DEFINER execution is introduced.
GRANT USAGE ON SCHEMA correlation TO audit_owner;
GRANT INSERT ON correlation.pending_inputs TO audit_owner,correlation_writer;
CREATE FUNCTION correlation.enqueue_input() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_SCHEMA='audit' AND TG_TABLE_NAME='kernel_events' THEN
  INSERT INTO correlation.pending_inputs VALUES('kernel',NEW.source_event_id,NEW.node_uid,NEW.source_time,NEW.received_at);
 ELSIF TG_TABLE_SCHEMA='correlation' AND TG_TABLE_NAME='network_policy_records' THEN
  INSERT INTO correlation.pending_inputs VALUES('netpol',NEW.record_id,NEW.node_uid,NEW.source_time,NEW.received_at);
 ELSE
  RAISE EXCEPTION 'unsupported correlation input table';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION correlation.enqueue_input() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION correlation.enqueue_input() TO audit_owner,correlation_writer;
-- The installer temporarily assumes the existing raw-evidence owner only
-- to create/drop its trigger, using the repository's membership pattern.
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('queue_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
CREATE TRIGGER correlation_enqueue AFTER INSERT ON audit.kernel_events
 FOR EACH ROW EXECUTE FUNCTION correlation.enqueue_input();
RESET ROLE;
DO $$ BEGIN
 IF current_setting('queue_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
CREATE TRIGGER correlation_enqueue AFTER INSERT ON correlation.network_policy_records
 FOR EACH ROW EXECUTE FUNCTION correlation.enqueue_input();
COMMIT;
