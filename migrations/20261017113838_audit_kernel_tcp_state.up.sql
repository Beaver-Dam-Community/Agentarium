-- TASK-07 requires tcp_new_state for tcp_state records. Preserve stored evidence.
BEGIN;
DO $$ BEGIN
  IF NOT (pg_has_role(current_user, 'audit_owner', 'USAGE') AND pg_has_role(current_user, 'audit_owner', 'SET')) THEN
    GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    PERFORM set_config('audit_kernel_tcp_state.granted_owner', 'on', true);
  END IF;
END $$;
SET ROLE audit_owner;
SET LOCAL lock_timeout = '2s';
LOCK TABLE audit.kernel_events IN ACCESS EXCLUSIVE MODE;
-- Do not invent the missing TCP state or rewrite its original record_digest.
-- The lock makes this precondition and constraint installation atomic.
DO $$ BEGIN
  IF EXISTS (SELECT FROM audit.kernel_events WHERE event_type='tcp_state' AND tcp_new_state IS NULL) THEN
    RAISE EXCEPTION 'legacy tcp_state without tcp_new_state requires an evidence-preserving migration; no automatic state/digest rewrite' USING ERRCODE='55000';
  END IF;
END $$;
ALTER TABLE audit.kernel_events
  ADD CONSTRAINT kernel_events_tcp_state_required
  CHECK (event_type <> 'tcp_state' OR tcp_new_state IS NOT NULL);
RESET ROLE;
DO $$ BEGIN
  IF current_setting('audit_kernel_tcp_state.granted_owner', true) = 'on' THEN
    REVOKE audit_owner FROM CURRENT_USER;
  END IF;
END $$;
COMMIT;
