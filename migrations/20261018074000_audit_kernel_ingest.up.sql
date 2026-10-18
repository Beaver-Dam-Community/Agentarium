-- TASK-07 3.3 kernel batch ingest with the six trusted arguments of COMMON
-- "Kernel source authentication and epoch" (#184, #92). Same atomic gap/audit/outbox/
-- watermark write and idempotency as the lifecycle ingest (#88/#95). Requires
-- the lifecycle ingest migration (proxy check, uuid-ossp, abandoned links).
-- Never rewrite a merged migration; this one only adds functions.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('kernel_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE audit_owner;
DO $$ BEGIN
 IF to_regprocedure('audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text)') IS NULL OR to_regprocedure('audit._lifecycle_proxy(text)') IS NULL THEN
  RAISE EXCEPTION 'lifecycle ingest prerequisite missing' USING ERRCODE='55000';
 END IF;
 -- No kernel receiver existed before. Refuse to invent provenance for
 -- manually imported kernel watermarks.
 IF EXISTS(SELECT FROM audit.ingest_watermarks WHERE stream='kernel' AND (node_uid IS NULL OR boot_id IS NULL)) THEN
  RAISE EXCEPTION 'existing kernel watermarks require verified provenance migration' USING ERRCODE='55000';
 END IF;
 -- COMMON registry: process_exec_id is conditional (absent for tcp_state);
 -- the per-event-type rule is enforced below and by table constraints.
 UPDATE audit.event_types SET required_payload_fields='["source_event_id","source_epoch","source_sequence","event_type","record_digest"]'::jsonb
  WHERE event_type='kernel_event_observed' AND storage_table='kernel_events' AND source_class='kernel';
 IF NOT FOUND THEN RAISE EXCEPTION 'kernel_event_observed registry prerequisite missing' USING ERRCODE='55000'; END IF;
END $$;

-- Validates one COMMON KernelEvent. Every failure is 22023/22P02/22003 class
-- and becomes an individual SCHEMA_INVALID rejection in the caller.
CREATE FUNCTION audit._kernel_record(v jsonb, wanted_source text, wanted_epoch text)
RETURNS audit.kernel_events
LANGUAGE plpgsql SET search_path=pg_catalog,audit,pg_temp AS $$
DECLARE r audit.kernel_events; f text; t jsonb; a inet;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 PERFORM audit._canonical_json(v);
 IF EXISTS(SELECT FROM jsonb_object_keys(v) k WHERE k <> ALL(ARRAY[
  'source_event_id','sensor_id','source_epoch','source_sequence','exporter_instance_id','sensor_generation','node_uid','boot_id',
  'source_time','spooled_at','process_exec_id','parent_exec_id','process_start','host_pid','container_id','docker_id_prefix',
  'pod_uid','netns_inode','socket_tuple','sock_ptr','tcp_new_state','lifecycle_record_id','metadata_status',
  'normalization_version','upstream_event_ref','event_type','safe_attributes','rule_hash','coverage','record_digest'])) THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 FOREACH f IN ARRAY ARRAY['source_event_id','sensor_id','source_epoch','exporter_instance_id','node_uid','boot_id','source_time',
   'spooled_at','metadata_status','normalization_version','event_type','rule_hash','coverage','record_digest'] LOOP
  IF jsonb_typeof(v->f) IS DISTINCT FROM 'string' OR v->>f='' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['source_sequence','sensor_generation'] LOOP
  IF jsonb_typeof(v->f) IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 IF jsonb_typeof(v->'safe_attributes') IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 FOREACH f IN ARRAY ARRAY['process_exec_id','parent_exec_id','process_start','container_id','docker_id_prefix','pod_uid','sock_ptr',
   'lifecycle_record_id','upstream_event_ref'] LOOP
  IF v ? f AND jsonb_typeof(v->f) NOT IN ('string','null') THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['host_pid','netns_inode','tcp_new_state'] LOOP
  IF v ? f AND jsonb_typeof(v->f) NOT IN ('number','null') THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['source_event_id','node_uid','pod_uid','lifecycle_record_id'] LOOP
  IF v->>f IS NOT NULL AND v->>f !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
   RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['source_time','spooled_at','process_start'] LOOP
  IF v->>f IS NOT NULL AND v->>f !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN
   RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
 END LOOP;
 IF v->>'sock_ptr' IS NOT NULL AND v->>'sock_ptr' !~ '^[0-9a-f]{16}$' OR v->>'docker_id_prefix' IS NOT NULL AND v->>'docker_id_prefix' !~ '^[0-9a-f]{15}$'
    OR v->>'rule_hash' !~ '^[0-9a-f]{64}$' OR v->>'record_digest' !~ '^[0-9a-f]{64}$'
    OR (v->>'sensor_generation')::numeric < 1 OR (v->>'host_pid')::numeric <= 0 OR (v->>'netns_inode')::numeric < 0 THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 CASE v->>'event_type'
  WHEN 'process_exec','process_exit','tcp_connect','file_open','openat' THEN
   IF jsonb_typeof(v->'process_exec_id') IS DISTINCT FROM 'string' OR v->>'process_exec_id'='' OR v->>'tcp_new_state' IS NOT NULL THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
  WHEN 'tcp_state' THEN
   IF v->>'process_exec_id'='' OR v->>'tcp_new_state' IS NULL OR (v->>'tcp_new_state')::numeric NOT IN (1,7) THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
  ELSE RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END CASE;
 IF v ? 'socket_tuple' AND v->'socket_tuple' <> 'null'::jsonb THEN
  t:=v->'socket_tuple';
  IF jsonb_typeof(t) IS DISTINCT FROM 'object' OR t-ARRAY['saddr','sport','daddr','dport']<>'{}'::jsonb
     OR jsonb_typeof(t->'saddr') IS DISTINCT FROM 'string' OR jsonb_typeof(t->'daddr') IS DISTINCT FROM 'string'
     OR jsonb_typeof(t->'sport') IS DISTINCT FROM 'number' OR jsonb_typeof(t->'dport') IS DISTINCT FROM 'number'
     OR (t->>'sport')::numeric NOT BETWEEN 0 AND 65535 OR (t->>'dport')::numeric NOT BETWEEN 0 AND 65535 THEN
   RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  FOREACH f IN ARRAY ARRAY['saddr','daddr'] LOOP
   -- A plain address, not a prefix or zoned address.
   IF t->>f ~ '[/%]' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
   a:=(t->>f)::inet;
  END LOOP;
 END IF;
 IF v->>'sensor_id' IS DISTINCT FROM wanted_source OR v->>'source_epoch' IS DISTINCT FROM wanted_epoch
    OR (v->>'source_sequence')::numeric NOT BETWEEN 1 AND 9007199254740991
    OR v->>'record_digest' IS DISTINCT FROM encode(sha256(convert_to(audit._canonical_json(v-'record_digest'),'UTF8')),'hex')
    OR v->>'source_event_id' IS DISTINCT FROM audit.uuid_generate_v5('62aec079-204c-5723-a898-7fa567e82eb4'::uuid,
       wanted_source||'/'||wanted_epoch||'/'||(v->>'source_sequence'))::text THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 r:=jsonb_populate_record(NULL::audit.kernel_events, v-'socket_tuple');
 r.source_id:=wanted_source;
 IF t IS NOT NULL THEN
  r.saddr:=(t->>'saddr')::inet; r.sport:=(t->>'sport')::integer; r.daddr:=(t->>'daddr')::inet; r.dport:=(t->>'dport')::integer;
 END IF;
 RETURN r;
END $$;

CREATE FUNCTION audit.ingest_kernel_batch(source_id text,batch jsonb,certificate_serial text,exact_san text,writer_version text,writer_epoch text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,audit,pg_temp SET lock_timeout='2s' AS $$
DECLARE
 src text := $1; b jsonb := $2; ep text := $2->>'source_epoch';
 receiver text; cert record; bound_boot text; w audit.ingest_watermarks;
 r audit.kernel_events; old audit.kernel_events; a jsonb; v jsonb; f text; id text; why text;
 accepted jsonb := '[]'; duplicates jsonb := '[]'; rejected jsonb := '[]';
 prior_range audit.abandoned_ranges; new_gap uuid; seq_event uuid; gap_event uuid; event jsonb; payload jsonb;
 fr bigint; upto bigint; next_ack bigint; covered bigint; t timestamptz := statement_timestamp();
BEGIN
 receiver:=audit._lifecycle_proxy(src);
 IF src IS DISTINCT FROM $4 OR src IS DISTINCT FROM 'spiffe://agentarium.internal/ns/agent-sensors/sa/tetragon'
    OR writer_version IS NULL OR writer_version='' OR octet_length(writer_version)>16384
    OR writer_epoch IS NULL OR writer_epoch='' OR octet_length(writer_epoch)>16384 THEN
  RAISE EXCEPTION 'source/server identity invalid' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT FROM audit.producer_event_grants g JOIN audit.event_types et USING(event_type)
 WHERE g.source_id=src AND g.event_type='kernel_event_observed' AND g.tenant='*'
 AND et.storage_table='kernel_events' AND et.source_class='kernel') THEN
  RAISE EXCEPTION 'producer not allowed' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR octet_length(audit._canonical_json(b))>1048576
 OR EXISTS(SELECT FROM jsonb_object_keys(b) k WHERE k<>ALL(ARRAY['batch_id','source_epoch','records','sequence_range_abandoned','batch_digest']))
 OR jsonb_typeof(b->'batch_id') IS DISTINCT FROM 'string' OR b->>'batch_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR jsonb_typeof(b->'source_epoch') IS DISTINCT FROM 'string' OR ep !~ '^[0-9a-f]{128}$'
 OR jsonb_typeof(b->'records') IS DISTINCT FROM 'array' OR jsonb_typeof(b->'sequence_range_abandoned') IS DISTINCT FROM 'array'
 OR jsonb_array_length(b->'records')+jsonb_array_length(b->'sequence_range_abandoned')>100
 OR jsonb_typeof(b->'batch_digest') IS DISTINCT FROM 'string'
 OR b->>'batch_digest' IS DISTINCT FROM encode(sha256(convert_to(audit._canonical_json(b-'batch_digest'),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 SELECT * INTO cert FROM identity.audit_source_certificate($3,$4,substr(ep,33,64));
 IF NOT FOUND OR cert.namespace IS DISTINCT FROM 'agent-sensors' OR cert.ksa IS DISTINCT FROM 'tetragon' THEN
  RAISE EXCEPTION 'certificate not allowed' USING ERRCODE='42501';
 END IF;
 IF cert.node_uid IS NULL OR cert.certificate_boot_id IS NULL OR cert.certificate_boot_id=''
   OR NOT health.audit_source_current_boot(cert.node_uid,cert.certificate_boot_id)
   OR replace(cert.node_uid::text,'-','')<>substr(ep,1,32) THEN
  RAISE EXCEPTION 'current runtime boot not allowed' USING ERRCODE='42501';
 END IF;
 -- A busy epoch fails immediately (55P03) instead of waiting unboundedly.
 IF NOT pg_try_advisory_xact_lock(hashtextextended('kernel/epoch/'||src||'/'||ep,0)) THEN RAISE EXCEPTION 'source busy' USING ERRCODE='55P03'; END IF;
 SELECT * INTO w FROM audit.ingest_watermarks m WHERE m.source_id=src AND m.stream='kernel' AND m.source_epoch=ep FOR UPDATE;
 IF FOUND THEN
  IF w.node_uid IS DISTINCT FROM cert.node_uid OR w.boot_id IS NULL OR
     encode(sha256(convert_to(w.boot_id,'UTF8')),'hex')<>substr(ep,33,64) THEN
   RAISE EXCEPTION 'epoch provenance mismatch' USING ERRCODE='42501';
  END IF;
 ELSE
  IF encode(sha256(convert_to(cert.certificate_boot_id,'UTF8')),'hex')=substr(ep,33,64) THEN bound_boot:=cert.certificate_boot_id;
  ELSE bound_boot:=cert.historical_boot_id; END IF;
  IF bound_boot IS NULL THEN RAISE EXCEPTION 'historical epoch has no issuance evidence' USING ERRCODE='42501'; END IF;
  INSERT INTO audit.ingest_watermarks(source_id,stream,source_epoch,acked_through,max_seen,updated_at,node_uid,boot_id,watch_scope)
  VALUES(src,'kernel',ep,0,0,t,cert.node_uid,bound_boot,NULL) RETURNING * INTO w;
 END IF;
 FOR v IN SELECT value FROM jsonb_array_elements(b->'records') LOOP
  id:=CASE WHEN jsonb_typeof(v->'source_event_id')='string' THEN v->>'source_event_id' ELSE '' END; why:=NULL;
  BEGIN
   r:=audit._kernel_record(v,src,ep);
   FOR f IN SELECT jsonb_array_elements_text(et.required_payload_fields) FROM audit.event_types et WHERE et.event_type='kernel_event_observed' LOOP
    IF NOT (v ? f) OR v->f='null'::jsonb THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
   END LOOP;
   IF r.node_uid IS DISTINCT FROM w.node_uid OR r.boot_id IS DISTINCT FROM w.boot_id THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
  EXCEPTION WHEN invalid_parameter_value OR invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow OR invalid_datetime_format OR not_null_violation OR check_violation THEN
   why:='SCHEMA_INVALID';
  END;
  IF why IS NULL THEN
   IF EXISTS(SELECT FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='kernel' AND ar.source_epoch=ep
             AND r.source_sequence BETWEEN ar.from_seq AND ar.to_seq) THEN
    why:='EVENT_ID_CONFLICT';
   ELSE
    r.received_at:=t;
    BEGIN
     INSERT INTO audit.kernel_events SELECT (r).* ON CONFLICT DO NOTHING;
    EXCEPTION WHEN check_violation OR not_null_violation THEN why:='SCHEMA_INVALID';
    END;
    IF why IS NOT NULL THEN
     NULL;
    ELSIF FOUND THEN
     INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state)
     VALUES('kernel_event',r.source_event_id::text,'gcs','kernel',octet_length(audit._canonical_json(v)),'pending');
     accepted:=accepted||jsonb_build_array(id);
    ELSE
     SELECT * INTO old FROM audit.kernel_events e WHERE e.source_event_id=r.source_event_id;
     IF old.source_id=src AND old.source_epoch=ep AND old.source_sequence=r.source_sequence AND old.record_digest=r.record_digest THEN
      duplicates:=duplicates||jsonb_build_array(id);
     ELSE
      -- Only an actual same-source record with a different digest is an
      -- incident, atomic with the accepted batch writes.
      IF old.source_id=src AND old.record_digest<>r.record_digest THEN
       PERFORM audit.audit_record_conflict('kernel_event',r.source_event_id::text,r.record_digest,src);
      END IF;
      why:='EVENT_ID_CONFLICT';
     END IF;
    END IF;
   END IF;
   IF why IS NULL THEN w.max_seen:=greatest(w.max_seen,r.source_sequence); END IF;
  END IF;
  IF why IS NOT NULL THEN rejected:=rejected||jsonb_build_array(jsonb_build_object('id',id,'reason_codes',jsonb_build_array(why))); END IF;
 END LOOP;
 FOR a IN SELECT value FROM jsonb_array_elements(b->'sequence_range_abandoned') LOOP
  id:=ep||':'||coalesce(a->>'from_seq','')||'-'||coalesce(a->>'to_seq',''); why:=NULL;
  BEGIN
   IF jsonb_typeof(a) IS DISTINCT FROM 'object' OR a-ARRAY['from_seq','to_seq','reason','range_digest']<>'{}'::jsonb
      OR jsonb_typeof(a->'from_seq') IS DISTINCT FROM 'number' OR jsonb_typeof(a->'to_seq') IS DISTINCT FROM 'number'
      OR jsonb_typeof(a->'reason') IS DISTINCT FROM 'string' OR a->>'reason'=''
      OR jsonb_typeof(a->'range_digest') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
   fr:=(a->>'from_seq')::bigint; upto:=(a->>'to_seq')::bigint;
   IF fr<1 OR upto<fr OR upto>9007199254740991 OR a->>'range_digest' IS DISTINCT FROM encode(sha256(convert_to(audit._canonical_json(
      jsonb_build_object('source_id',src,'stream','kernel','source_epoch',ep,'from_seq',fr,'to_seq',upto,'reason',a->>'reason')),'UTF8')),'hex') THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
  EXCEPTION WHEN invalid_parameter_value OR invalid_text_representation OR numeric_value_out_of_range THEN why:='SCHEMA_INVALID';
  END;
  IF why IS NULL THEN
   SELECT * INTO prior_range FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='kernel' AND ar.source_epoch=ep AND ar.from_seq=fr;
   IF FOUND AND prior_range.to_seq=upto AND prior_range.reason=a->>'reason' AND prior_range.range_digest=a->>'range_digest' THEN
    duplicates:=duplicates||jsonb_build_array(id);
   ELSIF FOUND OR fr<=w.acked_through OR EXISTS(SELECT FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='kernel' AND ar.source_epoch=ep AND ar.from_seq<=upto AND ar.to_seq>=fr)
    OR EXISTS(SELECT FROM audit.kernel_events e WHERE e.source_id=src AND e.source_epoch=ep AND e.source_sequence BETWEEN fr AND upto) THEN
    why:='EVENT_ID_CONFLICT';
   ELSE
    new_gap:=gen_random_uuid(); seq_event:=gen_random_uuid(); gap_event:=gen_random_uuid();
    INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,boot_id,source_id,source_epoch,sequence_from,sequence_to,range_digest,
      start_at,end_at,affected_workloads,loss_count,count_quality,evidence_refs,recovery_state,created_by)
    VALUES(new_gap,'kernel_sensor_export','SEQUENCE_RANGE_ABANDONED',w.node_uid,w.boot_id,src,ep,fr,upto,a->>'range_digest',t,NULL,'{}',upto-fr+1,'exact','[]','unrecoverable','TASK-07');
    FOREACH f IN ARRAY ARRAY['sequence_range_abandoned','observation_gap_recorded'] LOOP
     IF f='sequence_range_abandoned' THEN
      payload:=jsonb_build_object('source_id',src,'stream','kernel','source_epoch',ep,'range',jsonb_build_object('from_seq',fr,'to_seq',upto),'reason',a->>'reason','range_digest',a->>'range_digest');
     ELSE payload:=jsonb_build_object('gap_id',new_gap,'stage','kernel_sensor_export','reason','SEQUENCE_RANGE_ABANDONED','sequence_range',jsonb_build_object('from_seq',fr,'to_seq',upto),'count_quality','exact'); END IF;
     event:=jsonb_build_object('event_id',CASE WHEN f='sequence_range_abandoned' THEN seq_event ELSE gap_event END,'event_type',f,
      'tenant','*','source_id',receiver,'source_version',writer_version,'source_epoch',writer_epoch,'source_sequence',NULL,
      'source_time',to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'schema_version',1,
      'authenticated_actor','service:'||cert.namespace||'/'||cert.ksa,'evidence_refs','[]'::jsonb,'safe_payload',payload);
     event:=event||jsonb_build_object('payload_digest',encode(sha256(convert_to(audit._canonical_json(event),'UTF8')),'hex'));
     IF audit.audit_append(event,ARRAY['gcs'])<>'created' THEN RAISE EXCEPTION 'gap audit not created'; END IF;
    END LOOP;
    INSERT INTO audit.abandoned_ranges(source_id,stream,source_epoch,from_seq,to_seq,reason,range_digest,gap_id,received_at,sequence_event_id,gap_event_id)
    VALUES(src,'kernel',ep,fr,upto,a->>'reason',a->>'range_digest',new_gap,t,seq_event,gap_event);
    accepted:=accepted||jsonb_build_array(id);
   END IF;
   IF why IS NULL THEN w.max_seen:=greatest(w.max_seen,upto); END IF;
  END IF;
  IF why IS NOT NULL THEN rejected:=rejected||jsonb_build_array(jsonb_build_object('id',id,'reason_codes',jsonb_build_array(why))); END IF;
 END LOOP;
 -- Jump over contiguous stored runs and accepted ranges; stop at the first hole.
 next_ack:=w.acked_through;
 LOOP
  SELECT max(ar.to_seq) INTO covered FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='kernel' AND ar.source_epoch=ep AND ar.from_seq<=next_ack+1 AND ar.to_seq>=next_ack+1;
  IF covered IS NOT NULL THEN next_ack:=covered; CONTINUE; END IF;
  SELECT max(q.source_sequence) INTO covered FROM (
   SELECT e.source_sequence,row_number() OVER(ORDER BY e.source_sequence) AS ordinal
   FROM audit.kernel_events e WHERE e.source_id=src AND e.source_epoch=ep AND e.source_sequence>next_ack
  ) q WHERE q.source_sequence=next_ack+q.ordinal;
  IF covered IS NULL THEN EXIT; END IF;
  next_ack:=covered;
 END LOOP;
 UPDATE audit.ingest_watermarks m SET acked_through=next_ack,max_seen=w.max_seen,updated_at=t
 WHERE m.source_id=src AND m.stream='kernel' AND m.source_epoch=ep;
 -- Collections identify records, not positions. Rejection wins on repeats.
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',q.id,'reason_codes',q.reasons) ORDER BY q.id),'[]') INTO rejected
 FROM (SELECT j->>'id' AS id,jsonb_agg(DISTINCT reason) AS reasons
  FROM jsonb_array_elements(rejected) j CROSS JOIN LATERAL jsonb_array_elements(j->'reason_codes') reason GROUP BY j->>'id') q;
 SELECT coalesce(jsonb_agg(q.id ORDER BY q.id),'[]') INTO accepted FROM (
  SELECT DISTINCT entries.entry_id AS id FROM jsonb_array_elements_text(accepted) AS entries(entry_id)
  WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(rejected) j WHERE j->>'id'=entries.entry_id)) q;
 SELECT coalesce(jsonb_agg(q.id ORDER BY q.id),'[]') INTO duplicates FROM (
  SELECT DISTINCT entries.entry_id AS id FROM jsonb_array_elements_text(duplicates) AS entries(entry_id)
  WHERE NOT EXISTS(SELECT FROM jsonb_array_elements(rejected) j WHERE j->>'id'=entries.entry_id)
    AND NOT (accepted ? entries.entry_id)) q;
 RETURN jsonb_build_object('batch_id',b->>'batch_id','accepted_ids',accepted,'duplicate_ids',duplicates,'rejected',rejected,
   'watermarks',jsonb_build_array(jsonb_build_object('source_epoch',ep,'acked_through',next_ack)));
END $$;
REVOKE ALL ON FUNCTION audit._kernel_record(jsonb,text,text),audit.ingest_kernel_batch(text,jsonb,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.ingest_kernel_batch(text,jsonb,text,text,text,text) TO audit_writer;
-- A two-argument kernel signature must never bypass these source checks.
DO $$ BEGIN
 IF to_regprocedure('audit.ingest_kernel_batch(text,jsonb)') IS NOT NULL THEN
  EXECUTE 'REVOKE ALL ON FUNCTION audit.ingest_kernel_batch(text,jsonb) FROM PUBLIC,audit_writer,audit_producer';
 END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('kernel_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
