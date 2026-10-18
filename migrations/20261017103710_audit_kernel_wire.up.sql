-- TASK-07/09 approved KernelEvent wire: nullable tcp_state process identity
-- and exact unsigned 64-bit pointer text. Never rewrite a merged migration.
BEGIN;
DO $$ BEGIN
  IF NOT (pg_has_role(current_user, 'audit_owner', 'USAGE') AND pg_has_role(current_user, 'audit_owner', 'SET')) THEN
    GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    PERFORM set_config('audit_kernel_wire.granted_owner', 'on', true);
  END IF;
END $$;
SET ROLE audit_owner;
-- Numeric -> hex would change the canonical JSON type covered by the original
-- record_digest. Retaining bits alone does not preserve the original record.
-- There was no merged kernel receiver before this migration; installations
-- with manually populated legacy pointers need an explicit preservation plan.
-- Hold the same bounded exclusive lock for the precondition and type change.
SET LOCAL lock_timeout = '2s';
LOCK TABLE audit.kernel_events IN ACCESS EXCLUSIVE MODE;
DO $$ BEGIN
  IF EXISTS (SELECT FROM audit.kernel_events WHERE sock_ptr IS NOT NULL) THEN
    RAISE EXCEPTION 'legacy kernel sock_ptr requires an evidence-preserving migration; no automatic digest/type rewrite' USING ERRCODE='55000';
  END IF;
END $$;
ALTER TABLE audit.kernel_events
  ALTER COLUMN process_exec_id DROP NOT NULL,
  ALTER COLUMN sock_ptr TYPE text USING sock_ptr::text,
  ADD CONSTRAINT kernel_events_process_identity CHECK (process_exec_id IS NOT NULL OR event_type='tcp_state'),
  ADD CONSTRAINT kernel_events_sock_ptr_hex CHECK (sock_ptr IS NULL OR sock_ptr ~ '^[0-9a-f]{16}$');
RESET ROLE;
DO $$ BEGIN
  IF current_setting('audit_kernel_wire.granted_owner', true) = 'on' THEN
    REVOKE audit_owner FROM CURRENT_USER;
  END IF;
END $$;
COMMIT;
