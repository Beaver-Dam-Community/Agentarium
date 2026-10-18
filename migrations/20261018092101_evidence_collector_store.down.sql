-- Reverts 20261018092101_evidence_collector_store.up.sql: drops the evidence
-- schema (cursor, poll schedule and observation revisions) and the collector's
-- audit_producer membership. Audit events already appended remain in audit.*.
-- evidence_owner and evidence_collector are left in place: install-time
-- memberships and receiver_collector_reads grants may refer to them.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
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
REVOKE audit_producer FROM evidence_collector;
SET LOCAL ROLE evidence_owner;
DROP TABLE evidence.destination_observations;
DROP TABLE evidence.receipt_polls;
DROP TABLE evidence.collector_cursors;
DROP FUNCTION evidence.reject_change();
RESET ROLE;
DROP SCHEMA evidence;
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
