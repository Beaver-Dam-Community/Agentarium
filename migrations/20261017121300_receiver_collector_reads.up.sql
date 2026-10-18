-- TASK-08 §3.2 / TASK-07 / COMMON: existing collector role reads two views.
-- Apply after audit_store and gateway_decisions. The installer must own the
-- decisions schema/view (or hold its grant options) and ADMIN on audit_owner.
-- No login membership, tenant mapping, base-table access or audit write grant.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE c.relkind='v' AND ((n.nspname='audit' AND c.relname='collector_feed')
      OR (n.nspname='decisions' AND c.relname='actions_target_view'))) <> 2 THEN
    RAISE EXCEPTION 'collector read views must be installed first' USING ERRCODE='55000';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='evidence_collector') THEN
    CREATE ROLE evidence_collector NOLOGIN;
  END IF;
  IF NOT pg_has_role(current_user,'audit_owner','SET') THEN
    -- Remember this grantor's own membership before temporarily enabling SET.
    -- Do not revoke an existing membership owned by this or another grantor.
    -- Owner-approved in-place edit before any environment applied this file:
    -- current_user::regrole rejects IAM login names such as x@p.iam.
    PERFORM set_config('collector_reads.had_own_membership', EXISTS(
      SELECT FROM pg_auth_members WHERE roleid='audit_owner'::regrole
      AND member=(SELECT oid FROM pg_roles WHERE rolname = current_user)
      AND grantor=(SELECT oid FROM pg_roles WHERE rolname = current_user))::text,true);
    GRANT audit_owner TO CURRENT_USER WITH SET TRUE;
    PERFORM set_config('collector_reads.enabled_set','on',true);
  END IF;
END $$;
SET LOCAL ROLE audit_owner;
GRANT USAGE ON SCHEMA audit TO evidence_collector;
GRANT SELECT ON audit.collector_feed TO evidence_collector;
RESET ROLE;
GRANT USAGE ON SCHEMA decisions TO evidence_collector;
GRANT SELECT ON decisions.actions_target_view TO evidence_collector;
DO $$ BEGIN
  IF current_setting('collector_reads.enabled_set',true)='on' THEN
    IF current_setting('collector_reads.had_own_membership',true)='true' THEN
      GRANT audit_owner TO CURRENT_USER WITH SET FALSE;
    ELSE
      REVOKE audit_owner FROM CURRENT_USER;
    END IF;
  END IF;
END $$;
COMMIT;
