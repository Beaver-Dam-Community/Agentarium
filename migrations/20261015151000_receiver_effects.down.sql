-- Reverts 20261015151000_receiver_effects.up.sql. Like the up migration, a
-- non-superuser migrator gets receiver_owner only for this transaction: the
-- schema, the tables and receiver.reject_change() belong to receiver_owner.
-- The append-only triggers cover UPDATE, DELETE and TRUNCATE, not DROP.

BEGIN;

DO $$
BEGIN
    IF NOT (pg_has_role(current_user, 'receiver_owner', 'USAGE') AND pg_has_role(current_user, 'receiver_owner', 'SET')) THEN
        EXECUTE 'GRANT receiver_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE';
        PERFORM set_config('receiver_migration.granted_owner', 'on', true);
    END IF;
END
$$;

DROP TABLE receiver.receiver_attempts;
DROP TABLE receiver.receiver_effects;
DROP FUNCTION receiver.reject_change();
DROP SCHEMA receiver;

DO $$
BEGIN
    IF current_setting('receiver_migration.granted_owner', true) = 'on' THEN
        EXECUTE 'REVOKE receiver_owner FROM CURRENT_USER';
    END IF;
END
$$;

COMMIT;
-- receiver_owner, receiver_writer and receipt_reader are left in place:
-- install-time memberships may refer to them.
