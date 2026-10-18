-- TASK-07 function for TASK-10 answer probe evidence re-checks (#179).
-- Returns only the needed columns of the runner's containers on one node/boot
-- in a bounded window, plus matching tcp_state rows; no table SELECT.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('probe_evidence_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
CREATE FUNCTION audit.probe_evidence_events(p_node_uid uuid, p_boot_id text, p_container_ids text[],
  p_from timestamptz, p_to timestamptz)
RETURNS TABLE(source_event_id uuid, event_type text, source_time timestamptz, saddr inet, sport integer,
  daddr inet, dport integer, tcp_new_state smallint, return_value bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, audit, pg_temp AS $$
BEGIN
  IF p_node_uid IS NULL OR p_boot_id IS NULL OR p_boot_id = '' OR p_container_ids IS NULL
     OR cardinality(p_container_ids) = 0 OR cardinality(p_container_ids) > 16
     OR p_from IS NULL OR p_to IS NULL OR p_to < p_from OR p_to - p_from > interval '30 seconds' THEN
    RAISE EXCEPTION 'probe evidence lookup requires node, boot, 1..16 containers and a window of at most 30 seconds' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
    WITH own AS (
      SELECT k.source_event_id, k.event_type, k.source_time, k.saddr, k.sport, k.daddr, k.dport, k.tcp_new_state,
        coalesce(k.safe_attributes->>'return_code', k.safe_attributes->>'return_errno')::bigint AS return_value
      FROM audit.kernel_events k
      WHERE k.node_uid = p_node_uid AND k.boot_id = p_boot_id AND k.container_id = ANY (p_container_ids)
        AND k.event_type IN ('process_exec','process_exit','tcp_connect','file_open','openat')
        AND k.source_time >= p_from AND k.source_time <= p_to)
    SELECT * FROM own
    UNION ALL
    SELECT s.source_event_id, s.event_type, s.source_time, s.saddr, s.sport, s.daddr, s.dport, s.tcp_new_state, NULL::bigint
    FROM audit.kernel_events s
    WHERE s.node_uid = p_node_uid AND s.boot_id = p_boot_id AND s.event_type = 'tcp_state'
      AND s.source_time >= p_from AND s.source_time <= p_to
      AND EXISTS (SELECT 1 FROM own c WHERE c.event_type = 'tcp_connect' AND c.saddr = s.saddr AND c.sport = s.sport
        AND c.daddr = s.daddr AND c.dport = s.dport)
    ORDER BY 3, 1;
END $$;
REVOKE ALL ON FUNCTION audit.probe_evidence_events(uuid, text, text[], timestamptz, timestamptz) FROM PUBLIC;
GRANT USAGE ON SCHEMA audit TO control_health_writer;
GRANT EXECUTE ON FUNCTION audit.probe_evidence_events(uuid, text, text[], timestamptz, timestamptz) TO control_health_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('probe_evidence_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
