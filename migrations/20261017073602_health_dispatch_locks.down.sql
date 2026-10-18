BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_lock_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
DROP FUNCTION health.lock_dispatch_holds(uuid,text,text,uuid,uuid);
DROP FUNCTION health.lock_dispatch_node(uuid);
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_lock_migration.granted_owner',true)='on' THEN
  REVOKE health_owner FROM CURRENT_USER;
 END IF;
END $$;
COMMIT;
