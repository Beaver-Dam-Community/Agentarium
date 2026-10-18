-- Revoke only the specified view reads. Keep the reusable NOLOGIN role and all
-- audit/action data; other collector memberships or future storage are untouched.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
  IF NOT pg_has_role(current_user,'audit_owner','SET') THEN
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
REVOKE SELECT ON audit.collector_feed FROM evidence_collector;
REVOKE USAGE ON SCHEMA audit FROM evidence_collector;
RESET ROLE;
REVOKE SELECT ON decisions.actions_target_view FROM evidence_collector;
REVOKE USAGE ON SCHEMA decisions FROM evidence_collector;
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
