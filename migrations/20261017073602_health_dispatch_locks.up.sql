BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_lock_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
-- TASK-10; depends on shared spec PR #79. No reader table UPDATE grants.
CREATE FUNCTION health.lock_dispatch_holds(
 p_node_uid uuid, p_workload_id text, p_target_id text,
 p_session_id uuid, p_service_session_id uuid
) RETURNS TABLE(hold_id uuid, reason text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, health, pg_temp
AS $function$
BEGIN
 IF p_workload_id = '' OR p_target_id = '' THEN
  RAISE EXCEPTION 'empty hold selector' USING ERRCODE='22023';
 END IF;
 RETURN QUERY SELECT h.hold_id, h.reason FROM health.holds AS h
 WHERE h.released_at IS NULL AND (
   (h.scope='global' AND h.scope_id='*') OR
   (h.scope='node' AND h.scope_id=p_node_uid::text) OR
   (h.scope='workload' AND h.scope_id=p_workload_id) OR
   (h.scope='target' AND h.scope_id=p_target_id) OR
   (h.scope='session' AND (h.scope_id=p_session_id::text OR h.scope_id=p_service_session_id::text))
 ) ORDER BY h.hold_id FOR SHARE OF h;
END;
$function$;
CREATE FUNCTION health.lock_dispatch_node(p_node_uid uuid)
RETURNS TABLE(boot_id text, sensor_generation bigint, guard_generation bigint, state text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, health, pg_temp
AS $function$
BEGIN
 IF p_node_uid IS NULL THEN
  RAISE EXCEPTION 'node uid required' USING ERRCODE='22023';
 END IF;
 RETURN QUERY SELECT n.boot_id, n.sensor_generation, n.guard_generation, n.state
 FROM health.node_boot_generation AS n
 WHERE n.node_uid=p_node_uid AND n.state <> 'retired'
 ORDER BY n.boot_id FOR SHARE OF n;
END;
$function$;
REVOKE ALL ON FUNCTION health.lock_dispatch_holds(uuid,text,text,uuid,uuid), health.lock_dispatch_node(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION health.lock_dispatch_holds(uuid,text,text,uuid,uuid), health.lock_dispatch_node(uuid) TO coordinator_reader;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_lock_migration.granted_owner',true)='on' THEN
  REVOKE health_owner FROM CURRENT_USER;
 END IF;
END $$;
COMMIT;
