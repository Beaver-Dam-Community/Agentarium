-- Drops only TASK-07 objects. Shared login/group roles survive rollback.
BEGIN;
DO $$ BEGIN
  IF NOT (pg_has_role(current_user, 'audit_owner', 'USAGE') AND pg_has_role(current_user, 'audit_owner', 'SET')) THEN
    GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
    PERFORM set_config('audit_migration.granted_owner', 'on', true);
  END IF;
END $$;
DROP SCHEMA audit CASCADE;
DO $$ BEGIN
  IF current_setting('audit_migration.granted_owner', true) = 'on' THEN
    REVOKE audit_owner FROM CURRENT_USER;
  END IF;
END $$;
COMMIT;
