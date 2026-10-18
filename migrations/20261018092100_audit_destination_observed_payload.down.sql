-- Remove the destination_observed-only check and restore the audit_store
-- registry fields. Stored audit events, outbox rows and grants are unchanged.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
  IF NOT pg_has_role(current_user,'audit_owner','SET') THEN
    -- Remember this grantor's own membership before temporarily enabling SET;
    -- never revoke a membership that this or another grantor already gave.
    PERFORM set_config('destination_payload.had_own_membership', EXISTS(
      SELECT FROM pg_auth_members WHERE roleid='audit_owner'::regrole
      AND member=(SELECT oid FROM pg_roles WHERE rolname = current_user)
      AND grantor=(SELECT oid FROM pg_roles WHERE rolname = current_user))::text,true);
    GRANT audit_owner TO CURRENT_USER WITH SET TRUE;
    PERFORM set_config('destination_payload.enabled_set','on',true);
  END IF;
END $$;
SET LOCAL ROLE audit_owner;
DROP TRIGGER audit_events_destination_observed ON audit.audit_events;
DROP FUNCTION audit._check_destination_observed();
UPDATE audit.event_types
   SET required_payload_fields='["action_id", "action_key", "wire_body_digest", "bytes", "effect_count"]'::jsonb
 WHERE event_type='destination_observed';
RESET ROLE;
DO $$ BEGIN
  IF current_setting('destination_payload.enabled_set',true)='on' THEN
    IF current_setting('destination_payload.had_own_membership',true)='true' THEN
      GRANT audit_owner TO CURRENT_USER WITH SET FALSE;
    ELSE
      REVOKE audit_owner FROM CURRENT_USER;
    END IF;
  END IF;
END $$;
COMMIT;
