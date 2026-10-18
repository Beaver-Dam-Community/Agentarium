BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='broker_owner') THEN CREATE ROLE broker_owner NOLOGIN; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='broker_reader') THEN CREATE ROLE broker_reader NOLOGIN; END IF;
 -- PostgreSQL 17 CREATEROLE alone does not imply INHERIT or SET membership.
 -- Match the receiver migration: borrow ownership for this transaction only.
 IF NOT (pg_has_role(current_user, 'broker_owner', 'USAGE') AND pg_has_role(current_user, 'broker_owner', 'SET')) THEN
  EXECUTE 'GRANT broker_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE';
  PERFORM set_config('broker_migration.granted_owner', 'on', true);
 END IF;
END $$;
CREATE SCHEMA broker AUTHORIZATION broker_owner;
SET LOCAL ROLE broker_owner;
CREATE TABLE broker.credential_bindings (
 credential_binding text PRIMARY KEY,
 adapter_id text NOT NULL,
 operation_id text NOT NULL,
 secret_resource text NOT NULL,
 secret_version text NOT NULL CHECK (secret_version ~ '^[0-9]+$'),
 header_name text NOT NULL,
 header_format text NOT NULL CHECK (header_format IN ('bearer','raw')),
 enabled boolean NOT NULL DEFAULT true,
 updated_at timestamptz NOT NULL,
 updated_by text NOT NULL
);
REVOKE ALL ON SCHEMA broker FROM PUBLIC;
REVOKE ALL ON broker.credential_bindings FROM PUBLIC;
GRANT USAGE ON SCHEMA broker TO broker_reader;
GRANT SELECT ON broker.credential_bindings TO broker_reader;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('broker_migration.granted_owner', true) = 'on' THEN
  EXECUTE 'REVOKE broker_owner FROM CURRENT_USER';
 END IF;
END $$;
COMMIT;
