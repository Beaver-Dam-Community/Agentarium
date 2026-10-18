-- Do not restore broader grants on rollback. The prior main migration does not
-- require receiver INSERT until the lifecycle receiver is installed.
BEGIN;
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_gap_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;
REVOKE INSERT (gap_id,stage,reason,node_uid,boot_id,source_id,source_epoch,
 sequence_from,sequence_to,range_digest,start_at,end_at,affected_workloads,
 loss_count,count_quality,evidence_refs,recovery_state,created_by)
 ON health.observation_gaps FROM audit_owner;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_gap_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
