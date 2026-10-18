-- TASK-10 restricted runtime source lookup for TASK-07. Requires shared spec #93.
-- The caller must first authenticate the current certificate through identity;
-- this function only checks the established health boot, not TLS or readiness.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_source_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
CREATE FUNCTION health.audit_source_current_boot(node_uid uuid, certificate_boot_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, health, pg_temp
AS $function$
 SELECT count(*) = 1 AND coalesce(bool_and(b.boot_id = $2), false)
 FROM health.node_boot_generation AS b
 WHERE b.node_uid = $1 AND b.state <> 'retired';
$function$;
REVOKE ALL ON FUNCTION health.audit_source_current_boot(uuid,text) FROM PUBLIC;
GRANT USAGE ON SCHEMA health TO audit_writer, audit_owner;
GRANT EXECUTE ON FUNCTION health.audit_source_current_boot(uuid,text) TO audit_writer, audit_owner;
COMMENT ON FUNCTION health.audit_source_current_boot(uuid,text) IS
 'Runtime source boot match only; preparing, ready and held remain observable. Does not release holds or authorize Pod watcher scopes.';
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_source_migration.granted_owner',true)='on' THEN
  REVOKE health_owner FROM CURRENT_USER;
 END IF;
END $$;
COMMIT;
