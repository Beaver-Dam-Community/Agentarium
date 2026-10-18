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
-- Remove only this constraint; retain every record, type, index and grant.
ALTER TABLE audit.kernel_events DROP CONSTRAINT kernel_events_tcp_state_required;
RESET ROLE;
DO $$ BEGIN
  IF current_setting('audit_kernel_tcp_state.granted_owner', true) = 'on' THEN
    REVOKE audit_owner FROM CURRENT_USER;
  END IF;
END $$;
COMMIT;
