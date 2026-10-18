-- Reverting would invalidate nullable tcp_state records and change the pointer
-- JSON type covered by retained record digests. Preserve history instead.
DO $$ BEGIN
  RAISE EXCEPTION 'kernel wire migration is irreversible; use a forward migration preserving original records';
END $$;
