BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user, 'broker_owner', 'USAGE') AND pg_has_role(current_user, 'broker_owner', 'SET')) THEN
  EXECUTE 'GRANT broker_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE';
  PERFORM set_config('broker_migration.granted_owner', 'on', true);
 END IF;
END $$;
SET LOCAL ROLE broker_owner;
DROP TABLE broker.credential_bindings;
DROP SCHEMA broker;
-- Shared runtime roles may have memberships/grants in other schemas.
RESET ROLE;
DO $$ BEGIN
 IF current_setting('broker_migration.granted_owner', true) = 'on' THEN
  EXECUTE 'REVOKE broker_owner FROM CURRENT_USER';
 END IF;
END $$;
COMMIT;
