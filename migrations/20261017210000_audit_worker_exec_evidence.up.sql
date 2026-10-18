-- TASK-07 objects for the TASK-10 session worker witness (TASK-10 3.5b,
-- COMMON session-dedicated worker contract 5).
--
-- * REFERENCES on audit.kernel_events(source_event_id) for health_owner, so
--   health.session_process_bindings.exec_event_ref can be the foreign key the
--   TASK-10 3.6 DDL defines.
-- * audit.worker_exec_evidence(): control-health must match the node witness
--   to one committed kernel process_exec row by node/boot/container/host PID
--   and exec ID, without table SELECT on kernel_events (COMMON read access to
--   other Task tables gives control_health_writer none). Same pattern as
--   audit.probe_evidence_events.
-- SPEC-QUESTION: COMMON's DB function registry has no row for this lookup;
-- the name and columns are proposed in the PR.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('worker_exec_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
GRANT USAGE ON SCHEMA audit TO health_owner;
GRANT REFERENCES (source_event_id) ON audit.kernel_events TO health_owner;
-- Returns the referenced row only if it is a process_exec on exactly this
-- node, boot and container, plus how many process_exec rows on that
-- node/boot/container share its host PID (PID reuse or duplicate candidates
-- make the match ambiguous) and whether a process_exit of the same exec ID
-- is stored. Never returns other columns or other rows.
CREATE FUNCTION audit.worker_exec_evidence(p_source_event_id uuid, p_node_uid uuid, p_boot_id text, p_container_id text)
RETURNS TABLE(source_event_id uuid, process_exec_id text, parent_exec_id text, host_pid integer,
  process_start timestamptz, sensor_generation bigint, rule_hash text, source_time timestamptz,
  same_pid_execs bigint, exited boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, audit, pg_temp AS $$
BEGIN
  IF p_source_event_id IS NULL OR p_node_uid IS NULL OR p_boot_id IS NULL OR p_boot_id = ''
     OR p_container_id IS NULL OR p_container_id = '' THEN
    RAISE EXCEPTION 'worker exec lookup requires event, node, boot and container' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
    SELECT k.source_event_id, k.process_exec_id, k.parent_exec_id, k.host_pid, k.process_start,
      k.sensor_generation, k.rule_hash::text, k.source_time,
      (SELECT count(*) FROM audit.kernel_events o
        WHERE o.node_uid = k.node_uid AND o.boot_id = k.boot_id AND o.container_id = k.container_id
          AND o.event_type = 'process_exec' AND o.host_pid = k.host_pid),
      EXISTS (SELECT 1 FROM audit.kernel_events x
        WHERE x.node_uid = k.node_uid AND x.boot_id = k.boot_id AND x.event_type = 'process_exit'
          AND x.process_exec_id = k.process_exec_id)
    FROM audit.kernel_events k
    WHERE k.source_event_id = p_source_event_id AND k.node_uid = p_node_uid AND k.boot_id = p_boot_id
      AND k.container_id = p_container_id AND k.event_type = 'process_exec' AND k.host_pid IS NOT NULL;
END $$;
REVOKE ALL ON FUNCTION audit.worker_exec_evidence(uuid, uuid, text, text) FROM PUBLIC;
GRANT USAGE ON SCHEMA audit TO control_health_writer;
GRANT EXECUTE ON FUNCTION audit.worker_exec_evidence(uuid, uuid, text, text) TO control_health_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('worker_exec_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
