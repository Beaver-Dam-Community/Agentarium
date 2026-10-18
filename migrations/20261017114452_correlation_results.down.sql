-- Append-only revisions are referenced by committed audit events. They cannot
-- be dropped or renumbered safely by a down migration; use a forward migration.
DO $$ BEGIN
  RAISE EXCEPTION 'correlation results are irreversible; use a forward migration preserving revisions';
END $$;
