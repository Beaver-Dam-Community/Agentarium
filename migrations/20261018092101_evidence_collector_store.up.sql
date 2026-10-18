-- TASK-08 3.2: evidence collector cursor, receipt poll schedule and
-- append-only observation revisions (schema evidence, owner evidence_owner).
--
-- Apply after audit_store and receiver_collector_reads. evidence_collector
-- (NOLOGIN group role) is created if absent and becomes an audit_producer
-- member so destination_observed is appended with audit.audit_append() in the
-- same transaction as its observation revision. The installer needs ADMIN on
-- audit_producer. The collector's IAM login membership, audit.db_role_sources
-- and audit.producer_event_grants rows ('destination_observed', tenant) remain
-- installation inputs. timeline_reader (TASK-11) gets SELECT on observations
-- only when the role already exists.
--
-- Additions to the TASK-08 3.2 DDL: destination_observations is append-only
-- (UPDATE/DELETE/TRUNCATE rejected by trigger), event_id is unique, and a
-- partial index serves the due-poll query.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='evidence_owner') THEN CREATE ROLE evidence_owner NOLOGIN; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='evidence_collector') THEN CREATE ROLE evidence_collector NOLOGIN; END IF;
  IF NOT pg_has_role(current_user,'evidence_owner','SET') THEN
    -- Remember this grantor's own membership before temporarily enabling SET;
    -- never revoke a membership that this or another grantor already gave.
    PERFORM set_config('evidence_store.had_own_membership', EXISTS(
      SELECT FROM pg_auth_members WHERE roleid='evidence_owner'::regrole
      AND member=(SELECT oid FROM pg_roles WHERE rolname = current_user)
      AND grantor=(SELECT oid FROM pg_roles WHERE rolname = current_user))::text,true);
    GRANT evidence_owner TO CURRENT_USER WITH SET TRUE;
    PERFORM set_config('evidence_store.enabled_set','on',true);
  END IF;
END $$;
CREATE SCHEMA evidence AUTHORIZATION evidence_owner;
SET LOCAL ROLE evidence_owner;
CREATE TABLE evidence.collector_cursors (
  feed text PRIMARY KEY,                    -- 'audit.collector_feed'
  last_received_at timestamptz NOT NULL,
  last_event_id uuid NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE TABLE evidence.destination_observations (
  action_id uuid NOT NULL,
  revision integer NOT NULL CHECK (revision >= 1),
  attempt_id uuid,
  tenant text NOT NULL,
  evidence_level text NOT NULL CHECK (evidence_level IN
    ('none','accepted','effect_verified','effect_mismatch','unknown')),
  rule_id text NOT NULL,
  receipt_digest char(64),
  effect_count integer,
  source_time timestamptz NOT NULL,
  event_id uuid NOT NULL UNIQUE,
  PRIMARY KEY (action_id, revision)
);
CREATE TABLE evidence.receipt_polls (
  action_id uuid PRIMARY KEY,
  first_seen_at timestamptz NOT NULL,
  deadline_at timestamptz NOT NULL,
  next_poll_at timestamptz,
  polls integer NOT NULL DEFAULT 0
);
CREATE INDEX receipt_polls_due ON evidence.receipt_polls (next_poll_at) WHERE next_poll_at IS NOT NULL;
CREATE FUNCTION evidence.reject_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION 'evidence.% is append-only (% rejected)', TG_TABLE_NAME, TG_OP;
END $$;
REVOKE ALL ON FUNCTION evidence.reject_change() FROM PUBLIC;
CREATE TRIGGER destination_observations_append_only BEFORE UPDATE OR DELETE ON evidence.destination_observations
  FOR EACH ROW EXECUTE FUNCTION evidence.reject_change();
CREATE TRIGGER destination_observations_no_truncate BEFORE TRUNCATE ON evidence.destination_observations
  FOR EACH STATEMENT EXECUTE FUNCTION evidence.reject_change();
REVOKE ALL ON ALL TABLES IN SCHEMA evidence FROM PUBLIC;
GRANT USAGE ON SCHEMA evidence TO evidence_collector;
GRANT SELECT, INSERT, UPDATE ON evidence.collector_cursors, evidence.receipt_polls TO evidence_collector;
GRANT SELECT, INSERT ON evidence.destination_observations TO evidence_collector;
DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname='timeline_reader') THEN   -- TASK-11
    GRANT USAGE ON SCHEMA evidence TO timeline_reader;
    GRANT SELECT ON evidence.destination_observations TO timeline_reader;
  END IF;
END $$;
RESET ROLE;
GRANT audit_producer TO evidence_collector;
DO $$ BEGIN
  IF current_setting('evidence_store.enabled_set',true)='on' THEN
    IF current_setting('evidence_store.had_own_membership',true)='true' THEN
      GRANT evidence_owner TO CURRENT_USER WITH SET FALSE;
    ELSE
      REVOKE evidence_owner FROM CURRENT_USER;
    END IF;
  END IF;
END $$;
COMMIT;
