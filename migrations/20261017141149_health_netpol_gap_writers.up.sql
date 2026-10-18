-- TASK-10 3.6/3.7 network_policy_log gap writers. control-health opens
-- collector-stopped gaps; the correlation receiver closes them on recovery and
-- may change only the recovery columns and affected workloads.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_netpol_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
-- control-health opens collector-stopped gaps only through this definer
-- function, which fixes every server value; it has no direct INSERT.
CREATE FUNCTION health.record_netpol_collector_gap(p_node_uid uuid, p_boot_id text, p_start_at timestamptz, p_evidence_refs jsonb)
RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, health, pg_temp AS $$
DECLARE v_gap uuid;
BEGIN
  IF p_node_uid IS NULL OR p_start_at IS NULL OR p_evidence_refs IS NULL OR jsonb_typeof(p_evidence_refs) <> 'array' THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE = '22023';
  END IF;
  INSERT INTO health.observation_gaps(gap_id, stage, reason, node_uid, boot_id, source_id, start_at, loss_count,
    count_quality, evidence_refs, recovery_state, created_by)
  VALUES (gen_random_uuid(), 'network_policy_log', 'NETPOL_COLLECTOR_STOPPED', p_node_uid, p_boot_id,
    'netpol-node/' || p_node_uid::text, p_start_at, NULL, 'unknown', p_evidence_refs, 'open', 'TASK-10')
  ON CONFLICT (stage, source_id, reason) WHERE stage = 'network_policy_log' AND recovery_state = 'open' DO NOTHING
  RETURNING gap_id INTO v_gap;
  RETURN v_gap;   -- NULL when the node already has an open collector-stopped gap
END $$;
REVOKE ALL ON FUNCTION health.record_netpol_collector_gap(uuid, text, timestamptz, jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION health.record_netpol_collector_gap(uuid, text, timestamptz, jsonb) TO control_health_writer;
GRANT USAGE ON SCHEMA health TO correlation_writer;
GRANT SELECT, INSERT ON health.observation_gaps TO correlation_writer;
GRANT UPDATE (end_at, recovery_state, evidence_refs, affected_workloads) ON health.observation_gaps TO correlation_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_netpol_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
