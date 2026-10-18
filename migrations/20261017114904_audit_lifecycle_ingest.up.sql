-- TASK-07 3.3. Requires #87/#93/#94/#95 and the identity/health source helpers.
-- uuid-ossp is a trusted PostgreSQL extension supported by Cloud SQL. Installation
-- needs database CREATE, not a runtime grant. No custom SHA-1 implementation.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 IF NOT (pg_has_role(current_user,'audit_owner','USAGE') AND pg_has_role(current_user,'audit_owner','SET')) THEN
  GRANT audit_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('lifecycle_migration.granted_owner','on',true);
 END IF;
END $$;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA audit;
-- Do not silently move an extension already installed for another consumer.
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
                WHERE e.extname='uuid-ossp' AND n.nspname='audit') THEN
  RAISE EXCEPTION 'uuid-ossp must be installed in audit schema';
 END IF;
END $$;
SET ROLE audit_owner;
-- #95: proxy receivers need their own installed audit source. Existing NULL or
-- empty proxy rows must be configured explicitly before installation; no backfill.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='audit.db_role_sources'::regclass AND conname='db_role_sources_proxy_receiver_source') THEN
  ALTER TABLE audit.db_role_sources ADD CONSTRAINT db_role_sources_proxy_receiver_source
   CHECK (NOT proxy OR (source_id IS NOT NULL AND source_id <> ''));
 END IF;
END $$;
ALTER TABLE audit.ingest_watermarks ADD COLUMN IF NOT EXISTS node_uid uuid, ADD COLUMN IF NOT EXISTS boot_id text, ADD COLUMN IF NOT EXISTS watch_scope text;
-- Main had no production ingest function. Refuse to invent provenance for
-- pre-existing manually/imported lifecycle watermark rows.
DO $$ BEGIN
 IF EXISTS(SELECT FROM audit.ingest_watermarks WHERE stream='lifecycle' AND (node_uid IS NULL OR boot_id IS NULL) AND watch_scope IS NULL) THEN
  RAISE EXCEPTION 'existing lifecycle watermarks require verified provenance migration';
 END IF;
END $$;
ALTER TABLE audit.watch_checkpoints ALTER COLUMN lifecycle_event_id DROP NOT NULL,
 ADD COLUMN IF NOT EXISTS checkpoint_revision bigint NOT NULL DEFAULT 1 CHECK(checkpoint_revision BETWEEN 1 AND 9007199254740991),
 ADD COLUMN IF NOT EXISTS last_batch_id uuid, ADD COLUMN IF NOT EXISTS last_batch_digest char(64);
-- Existing checkpoints retain their actual cursor/time/FK with revision 1 and
-- NULL last-batch metadata: never fabricate an old request or treat it as retry.
ALTER TABLE audit.watch_checkpoints ALTER COLUMN checkpoint_revision DROP DEFAULT;
ALTER TABLE audit.abandoned_ranges ADD COLUMN IF NOT EXISTS sequence_event_id uuid REFERENCES audit.audit_events(event_id),
 ADD COLUMN IF NOT EXISTS gap_event_id uuid REFERENCES audit.audit_events(event_id);
DO $$ BEGIN
 IF EXISTS(SELECT FROM audit.abandoned_ranges WHERE sequence_event_id IS NULL OR gap_event_id IS NULL) THEN
  RAISE EXCEPTION 'existing abandoned ranges require verified audit links; no automatic backfill' USING ERRCODE='55000';
 END IF;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='audit.watch_checkpoints'::regclass AND conname='watch_checkpoint_last_batch_pair') THEN
  ALTER TABLE audit.watch_checkpoints ADD CONSTRAINT watch_checkpoint_last_batch_pair CHECK ((last_batch_id IS NULL)=(last_batch_digest IS NULL));
 END IF;
 IF NOT EXISTS(SELECT FROM pg_constraint WHERE conrelid='audit.abandoned_ranges'::regclass AND conname='abandoned_range_audit_pair') THEN
  ALTER TABLE audit.abandoned_ranges ADD CONSTRAINT abandoned_range_audit_pair CHECK ((sequence_event_id IS NULL)=(gap_event_id IS NULL));
 END IF;
END $$;

-- #95 target state applies to both streams, without enabling a kernel receiver.
-- Never create replacement historical events to satisfy these links.
ALTER TABLE audit.abandoned_ranges
 ALTER COLUMN sequence_event_id SET NOT NULL,
 ALTER COLUMN gap_event_id SET NOT NULL;
DO $$ BEGIN
 UPDATE audit.event_types SET producer_task='TASK-07',
   required_payload_fields='["source_id","stream","source_epoch","range","reason","range_digest"]'::jsonb
 WHERE event_type='sequence_range_abandoned';
 IF NOT FOUND THEN RAISE EXCEPTION 'sequence_range_abandoned registry prerequisite missing' USING ERRCODE='55000'; END IF;
END $$;

CREATE FUNCTION audit._lifecycle_proxy(wanted_source text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,audit,pg_temp AS $$
DECLARE receiver text;
BEGIN
 SELECT s.source_id INTO receiver FROM audit.db_role_sources s
 WHERE s.db_role=session_user AND s.proxy;
 IF receiver IS NULL OR receiver='' OR wanted_source IS NULL OR wanted_source=''
    OR NOT pg_has_role(session_user,'audit_writer','MEMBER') THEN
  RAISE EXCEPTION 'lifecycle proxy not allowed' USING ERRCODE='42501';
 END IF;
 RETURN receiver;
END $$;

CREATE FUNCTION audit.lifecycle_checkpoint(source_id text, requested_scope text)
RETURNS TABLE(scope text,resource_version text,committed_at timestamptz,checkpoint_revision bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,audit,pg_temp AS $$
BEGIN
 PERFORM audit._lifecycle_proxy($1);
 IF $1 <> 'spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher' THEN
  RAISE EXCEPTION 'not a Pod watcher' USING ERRCODE='42501';
 END IF;
 RETURN QUERY SELECT c.scope,c.resource_version,c.committed_at,c.checkpoint_revision
 FROM audit.watch_checkpoints c WHERE c.source_id=$1 AND c.scope=$2;
END $$;

CREATE FUNCTION audit._lifecycle_record(v jsonb, wanted_source text, wanted_epoch text)
RETURNS audit.lifecycle_events
LANGUAGE plpgsql SET search_path=pg_catalog,audit,pg_temp AS $$
DECLARE r audit.lifecycle_events; f text;
BEGIN
 IF jsonb_typeof(v) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 PERFORM audit._canonical_json(v);
 IF EXISTS(SELECT FROM jsonb_object_keys(v) k WHERE k <> ALL(ARRAY[
 'lifecycle_event_id','source_id','source_epoch','source_sequence','cluster_uid','pod_uid','namespace','pod_name',
 'node_uid','boot_id','container_id','cgroups_path','cgroup_inode','container_name','restart_instance','image_id',
 'image_manifest_digest','transition','source_time','resource_version','mapping_version','evidence_refs','missing_reason','record_digest'])) THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 FOREACH f IN ARRAY ARRAY['lifecycle_event_id','source_id','source_epoch','cluster_uid','pod_uid','namespace','pod_name','transition','record_digest'] LOOP
  IF jsonb_typeof(v->f) IS DISTINCT FROM 'string' OR v->>f='' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['node_uid','boot_id','container_id','cgroups_path','container_name','image_id','image_manifest_digest','source_time','resource_version','missing_reason'] LOOP
  IF v ? f AND jsonb_typeof(v->f) NOT IN ('string','null') THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['source_sequence','mapping_version'] LOOP
  IF jsonb_typeof(v->f) IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['cgroup_inode','restart_instance'] LOOP
  IF v ? f AND jsonb_typeof(v->f) NOT IN ('number','null') THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 FOREACH f IN ARRAY ARRAY['lifecycle_event_id','cluster_uid','pod_uid','node_uid'] LOOP
  IF v->>f IS NOT NULL AND v->>f !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
   RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
 END LOOP;
 IF v->>'source_time' IS NOT NULL AND v->>'source_time' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$' THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 IF jsonb_typeof(v->'evidence_refs') IS DISTINCT FROM 'array' OR v->>'source_id' IS DISTINCT FROM wanted_source
    OR v->>'source_epoch' IS DISTINCT FROM wanted_epoch OR (v->>'source_sequence')::bigint NOT BETWEEN 1 AND 9007199254740991
    OR v->>'record_digest' !~ '^[0-9a-f]{64}$'
    OR v->>'record_digest' IS DISTINCT FROM encode(sha256(convert_to(audit._canonical_json(v-'record_digest'),'UTF8')),'hex')
    OR v->>'lifecycle_event_id' IS DISTINCT FROM audit.uuid_generate_v5('690f05df-a5fe-51bb-8f23-99c4492afc61'::uuid,
       wanted_source||'/'||wanted_epoch||'/'||(v->>'source_sequence'))::text THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 r:=jsonb_populate_record(NULL::audit.lifecycle_events,v);
 RETURN r;
END $$;

CREATE FUNCTION audit.ingest_lifecycle_batch(source_id text,batch jsonb,certificate_serial text,exact_san text,writer_version text,writer_epoch text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,audit,pg_temp SET lock_timeout='2s' AS $$
DECLARE
 src text := $1; b jsonb := $2; ep text := $2->>'source_epoch'; scope_value text := $2->>'scope';
 receiver text; kind text; cert record; bound_boot text; bound_node uuid; w audit.ingest_watermarks;
 r audit.lifecycle_events; old audit.lifecycle_events; a jsonb; v jsonb; f text; id text; why text;
 accepted jsonb := '[]'; duplicates jsonb := '[]'; rejected jsonb := '[]'; cp jsonb := 'null';
 prior_range audit.abandoned_ranges; new_gap uuid; seq_event uuid; gap_event uuid; event jsonb; payload jsonb;
 fr bigint; upto bigint; next_ack bigint; covered bigint; batch_last bigint := 0; expected bigint;
 checkpoint_row audit.watch_checkpoints; last_record uuid; lock_key bigint; t timestamptz := statement_timestamp();
BEGIN
 receiver:=audit._lifecycle_proxy(src);
 IF src IS DISTINCT FROM $4 OR writer_version IS NULL OR writer_version='' OR octet_length(writer_version)>16384
    OR writer_epoch IS NULL OR writer_epoch='' OR octet_length(writer_epoch)>16384 THEN
  RAISE EXCEPTION 'source/server identity invalid' USING ERRCODE='42501';
 END IF;
 CASE src
  WHEN 'spiffe://agentarium.internal/ns/agent-sensors/sa/lifecycle-recorder' THEN kind:='runtime';
  WHEN 'spiffe://agentarium.internal/ns/agent-observe/sa/pod-watcher' THEN kind:='pod_watcher';
  ELSE RAISE EXCEPTION 'source not allowed' USING ERRCODE='42501';
 END CASE;
 IF NOT EXISTS(SELECT FROM audit.producer_event_grants g JOIN audit.event_types et USING(event_type)
 WHERE g.source_id=src AND g.event_type='lifecycle_recorded' AND g.tenant='*'
 AND et.storage_table='lifecycle_events' AND et.source_class='lifecycle') THEN
  RAISE EXCEPTION 'producer not allowed' USING ERRCODE='42501';
 END IF;
 IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR octet_length(audit._canonical_json(b))>1048576
 OR EXISTS(SELECT FROM jsonb_object_keys(b) k WHERE k<>ALL(ARRAY['batch_id','source_epoch','scope','records','sequence_range_abandoned','cursor','batch_digest']))
 OR jsonb_typeof(b->'batch_id') IS DISTINCT FROM 'string' OR b->>'batch_id' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
 OR jsonb_typeof(b->'source_epoch') IS DISTINCT FROM 'string' OR ep !~ '^[A-Za-z0-9_-]{1,128}$'
 OR jsonb_typeof(b->'records') IS DISTINCT FROM 'array' OR jsonb_typeof(b->'sequence_range_abandoned') IS DISTINCT FROM 'array'
 OR jsonb_array_length(b->'records')+jsonb_array_length(b->'sequence_range_abandoned')>100
 OR jsonb_typeof(b->'batch_digest') IS DISTINCT FROM 'string'
 OR b->>'batch_digest' IS DISTINCT FROM encode(sha256(convert_to(audit._canonical_json(b-'batch_digest'),'UTF8')),'hex') THEN
  RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
 END IF;
 IF kind='runtime' THEN
  IF ep !~ '^[0-9a-f]{128}$' OR b ? 'scope' OR b ? 'cursor' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 ELSE
  IF ep !~ '^[0-9a-f]{32}_[1-9][0-9]{0,15}$' OR split_part(ep,'_',2)::numeric>9007199254740991
    OR jsonb_typeof(b->'scope') IS DISTINCT FROM 'string' OR scope_value='' THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
 END IF;
 IF b ? 'cursor' THEN
  IF jsonb_typeof(b->'cursor') IS DISTINCT FROM 'object'
     OR (b->'cursor')-ARRAY['scope','resource_version','expected_checkpoint_revision'] <> '{}'::jsonb
     OR jsonb_typeof(b->'cursor'->'scope') IS DISTINCT FROM 'string'
     OR b->'cursor'->>'scope' IS DISTINCT FROM scope_value
     OR jsonb_typeof(b->'cursor'->'resource_version') IS DISTINCT FROM 'string' OR b->'cursor'->>'resource_version'=''
     OR jsonb_typeof(b->'cursor'->'expected_checkpoint_revision') IS DISTINCT FROM 'number'
     OR (b->'cursor'->>'expected_checkpoint_revision')::numeric NOT BETWEEN 0 AND 9007199254740991 THEN
   RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  expected:=(b->'cursor'->>'expected_checkpoint_revision')::bigint;
 END IF;
 SELECT * INTO cert FROM identity.audit_source_certificate($3,$4,CASE WHEN kind='runtime' THEN substr(ep,33,64) ELSE NULL END);
 IF NOT FOUND THEN RAISE EXCEPTION 'certificate not allowed' USING ERRCODE='42501'; END IF;
 IF kind='runtime' THEN
  IF cert.node_uid IS NULL OR cert.certificate_boot_id IS NULL OR cert.certificate_boot_id=''
    OR NOT health.audit_source_current_boot(cert.node_uid,cert.certificate_boot_id)
    OR replace(cert.node_uid::text,'-','')<>substr(ep,1,32) THEN
   RAISE EXCEPTION 'current runtime boot not allowed' USING ERRCODE='42501';
  END IF;
 END IF;
 -- Advisory transaction locks serialize first INSERT too. A busy source fails
 -- immediately rather than leaving a writer hanging behind an unbounded lock.
 lock_key:=hashtextextended('lifecycle/epoch/'||src||'/'||ep,0);
 IF NOT pg_try_advisory_xact_lock(lock_key) THEN RAISE EXCEPTION 'source busy' USING ERRCODE='55P03'; END IF;
 SELECT * INTO w FROM audit.ingest_watermarks m WHERE m.source_id=src AND m.stream='lifecycle' AND m.source_epoch=ep FOR UPDATE;
 IF FOUND THEN
  IF kind='runtime' THEN
   IF w.node_uid IS DISTINCT FROM cert.node_uid OR w.boot_id IS NULL OR
      encode(sha256(convert_to(w.boot_id,'UTF8')),'hex')<>substr(ep,33,64) THEN
    RAISE EXCEPTION 'epoch provenance mismatch' USING ERRCODE='42501';
   END IF;
  ELSIF w.watch_scope IS DISTINCT FROM scope_value THEN RAISE EXCEPTION 'epoch scope mismatch' USING ERRCODE='42501';
  END IF;
 ELSE
  IF kind='runtime' THEN
   bound_node:=cert.node_uid;
   IF encode(sha256(convert_to(cert.certificate_boot_id,'UTF8')),'hex')=substr(ep,33,64) THEN bound_boot:=cert.certificate_boot_id;
   ELSE bound_boot:=cert.historical_boot_id; END IF;
   IF bound_boot IS NULL THEN RAISE EXCEPTION 'historical epoch has no issuance evidence' USING ERRCODE='42501'; END IF;
  END IF;
  INSERT INTO audit.ingest_watermarks(source_id,stream,source_epoch,acked_through,max_seen,updated_at,node_uid,boot_id,watch_scope)
  VALUES(src,'lifecycle',ep,0,0,t,bound_node,bound_boot,CASE WHEN kind='pod_watcher' THEN scope_value END) RETURNING * INTO w;
 END IF;
 FOR v IN SELECT value FROM jsonb_array_elements(b->'records') LOOP
  id:=CASE WHEN jsonb_typeof(v->'lifecycle_event_id')='string' THEN v->>'lifecycle_event_id' ELSE '' END; why:=NULL;
  BEGIN
   r:=audit._lifecycle_record(v,src,ep);
   FOR f IN SELECT jsonb_array_elements_text(et.required_payload_fields) FROM audit.event_types et WHERE et.event_type='lifecycle_recorded' LOOP
    IF NOT (v ? f) OR v->f='null'::jsonb THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
   END LOOP;
   IF kind='runtime' AND (r.node_uid IS DISTINCT FROM w.node_uid OR r.boot_id IS DISTINCT FROM w.boot_id) THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
   IF kind='pod_watcher' AND scope_value LIKE 'namespace/%' AND r.namespace<>substr(scope_value,11) THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
  EXCEPTION WHEN invalid_parameter_value OR invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow OR invalid_datetime_format OR not_null_violation OR check_violation THEN
   why:='SCHEMA_INVALID';
  END;
  IF why IS NULL THEN
   IF EXISTS(SELECT FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='lifecycle' AND ar.source_epoch=ep
             AND r.source_sequence BETWEEN ar.from_seq AND ar.to_seq) THEN
    why:='EVENT_ID_CONFLICT';
   ELSE
    r.source_kind:=kind; r.received_at:=t;
    INSERT INTO audit.lifecycle_events SELECT (r).* ON CONFLICT DO NOTHING;
    IF FOUND THEN
     INSERT INTO audit.audit_outbox(record_kind,record_id,destination,source_class,record_bytes,state)
     VALUES('lifecycle_event',r.lifecycle_event_id::text,'gcs','lifecycle',octet_length(audit._canonical_json(v)),'pending');
     accepted:=accepted||jsonb_build_array(id); last_record:=r.lifecycle_event_id;
    ELSE
     SELECT * INTO old FROM audit.lifecycle_events e WHERE e.lifecycle_event_id=r.lifecycle_event_id;
     IF old.source_id=src AND old.source_epoch=ep AND old.source_sequence=r.source_sequence AND old.record_digest=r.record_digest THEN
      duplicates:=duplicates||jsonb_build_array(id); last_record:=r.lifecycle_event_id;
     ELSE
      -- Only an actual same-source record with a different digest belongs in
      -- event_conflicts. Keep the incident atomic with accepted batch writes;
      -- storage failures escape and roll back the whole batch.
      IF old.source_id=src AND old.record_digest<>r.record_digest THEN
       PERFORM audit.audit_record_conflict('lifecycle_event',r.lifecycle_event_id::text,r.record_digest,src);
      END IF;
      why:='EVENT_ID_CONFLICT';
     END IF;
    END IF;
   END IF;
   IF why IS NULL THEN
    batch_last:=greatest(batch_last,r.source_sequence);
    w.max_seen:=greatest(w.max_seen,r.source_sequence);
   END IF;
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
      jsonb_build_object('source_id',src,'stream','lifecycle','source_epoch',ep,'from_seq',fr,'to_seq',upto,'reason',a->>'reason')),'UTF8')),'hex') THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
   END IF;
  EXCEPTION WHEN invalid_parameter_value OR invalid_text_representation OR numeric_value_out_of_range THEN why:='SCHEMA_INVALID';
  END;
  IF why IS NULL THEN
   SELECT * INTO prior_range FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='lifecycle' AND ar.source_epoch=ep AND ar.from_seq=fr;
   IF FOUND AND prior_range.to_seq=upto AND prior_range.reason=a->>'reason' AND prior_range.range_digest=a->>'range_digest' THEN
    duplicates:=duplicates||jsonb_build_array(id);
   ELSIF FOUND OR fr<=w.acked_through OR EXISTS(SELECT FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='lifecycle' AND ar.source_epoch=ep AND ar.from_seq<=upto AND ar.to_seq>=fr)
    OR EXISTS(SELECT FROM audit.lifecycle_events e WHERE e.source_id=src AND e.source_epoch=ep AND e.source_sequence BETWEEN fr AND upto) THEN
    why:='EVENT_ID_CONFLICT';
   ELSE
    new_gap:=gen_random_uuid(); seq_event:=gen_random_uuid(); gap_event:=gen_random_uuid();
    INSERT INTO health.observation_gaps(gap_id,stage,reason,node_uid,boot_id,source_id,source_epoch,sequence_from,sequence_to,range_digest,
      start_at,end_at,affected_workloads,loss_count,count_quality,evidence_refs,recovery_state,created_by)
    VALUES(new_gap,'lifecycle_capture','SEQUENCE_RANGE_ABANDONED',w.node_uid,w.boot_id,src,ep,fr,upto,a->>'range_digest',t,NULL,'{}',upto-fr+1,'exact','[]','unrecoverable','TASK-07');
    FOREACH f IN ARRAY ARRAY['sequence_range_abandoned','observation_gap_recorded'] LOOP
     IF f='sequence_range_abandoned' THEN
      payload:=jsonb_build_object('source_id',src,'stream','lifecycle','source_epoch',ep,'range',jsonb_build_object('from_seq',fr,'to_seq',upto),'reason',a->>'reason','range_digest',a->>'range_digest');
     ELSE payload:=jsonb_build_object('gap_id',new_gap,'stage','lifecycle_capture','reason','SEQUENCE_RANGE_ABANDONED','sequence_range',jsonb_build_object('from_seq',fr,'to_seq',upto),'count_quality','exact'); END IF;
     event:=jsonb_build_object('event_id',CASE WHEN f='sequence_range_abandoned' THEN seq_event ELSE gap_event END,'event_type',f,
      'tenant','*','source_id',receiver,'source_version',writer_version,'source_epoch',writer_epoch,'source_sequence',NULL,
      'source_time',to_char(t AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'schema_version',1,
      'authenticated_actor','service:'||cert.namespace||'/'||cert.ksa,'evidence_refs','[]'::jsonb,'safe_payload',payload);
     event:=event||jsonb_build_object('payload_digest',encode(sha256(convert_to(audit._canonical_json(event),'UTF8')),'hex'));
     IF audit.audit_append(event,ARRAY['gcs'])<>'created' THEN RAISE EXCEPTION 'gap audit not created'; END IF;
    END LOOP;
    INSERT INTO audit.abandoned_ranges(source_id,stream,source_epoch,from_seq,to_seq,reason,range_digest,gap_id,received_at,sequence_event_id,gap_event_id)
    VALUES(src,'lifecycle',ep,fr,upto,a->>'reason',a->>'range_digest',new_gap,t,seq_event,gap_event);
    accepted:=accepted||jsonb_build_array(id);
   END IF;
   IF why IS NULL THEN
    batch_last:=greatest(batch_last,upto); w.max_seen:=greatest(w.max_seen,upto);
   END IF;
  END IF;
  IF why IS NOT NULL THEN rejected:=rejected||jsonb_build_array(jsonb_build_object('id',id,'reason_codes',jsonb_build_array(why))); END IF;
 END LOOP;
 -- Never iterate each missing sequence in a large range. Jump over contiguous
 -- stored runs and accepted abandoned ranges, stopping at the first real hole.
 next_ack:=w.acked_through;
 LOOP
  SELECT max(ar.to_seq) INTO covered FROM audit.abandoned_ranges ar WHERE ar.source_id=src AND ar.stream='lifecycle' AND ar.source_epoch=ep AND ar.from_seq<=next_ack+1 AND ar.to_seq>=next_ack+1;
  IF covered IS NOT NULL THEN next_ack:=covered; CONTINUE; END IF;
  SELECT max(q.source_sequence) INTO covered FROM (
   SELECT e.source_sequence,row_number() OVER(ORDER BY e.source_sequence) AS ordinal
   FROM audit.lifecycle_events e WHERE e.source_id=src AND e.source_epoch=ep AND e.source_sequence>next_ack
  ) q WHERE q.source_sequence=next_ack+q.ordinal;
  IF covered IS NULL THEN EXIT; END IF;
  next_ack:=covered;
 END LOOP;
 UPDATE audit.ingest_watermarks m SET acked_through=next_ack,max_seen=w.max_seen,updated_at=t
 WHERE m.source_id=src AND m.stream='lifecycle' AND m.source_epoch=ep;
 IF b ? 'cursor' THEN
  IF NOT pg_try_advisory_xact_lock(hashtextextended('lifecycle/checkpoint/'||src||'/'||scope_value,0)) THEN RAISE EXCEPTION 'checkpoint busy' USING ERRCODE='55P03'; END IF;
  SELECT * INTO checkpoint_row FROM audit.watch_checkpoints c WHERE c.source_id=src AND c.scope=scope_value FOR UPDATE;
  IF checkpoint_row.last_batch_id=(b->>'batch_id')::uuid AND checkpoint_row.last_batch_digest=b->>'batch_digest' THEN
   cp:=jsonb_build_object('scope',checkpoint_row.scope,'resource_version',checkpoint_row.resource_version,'checkpoint_revision',checkpoint_row.checkpoint_revision);
  ELSIF (checkpoint_row.last_batch_id IS NULL OR checkpoint_row.last_batch_id<>(b->>'batch_id')::uuid)
    AND expected=coalesce(checkpoint_row.checkpoint_revision,0) AND jsonb_array_length(rejected)=0 AND next_ack>=batch_last
    AND (jsonb_array_length(b->'records')+jsonb_array_length(b->'sequence_range_abandoned')>0 OR next_ack=w.max_seen) THEN
   IF coalesce(checkpoint_row.checkpoint_revision,0)>=9007199254740991 THEN RAISE EXCEPTION 'checkpoint revision overflow' USING ERRCODE='22003'; END IF;
   INSERT INTO audit.watch_checkpoints(source_id,scope,resource_version,lifecycle_event_id,committed_at,checkpoint_revision,last_batch_id,last_batch_digest)
   VALUES(src,scope_value,b->'cursor'->>'resource_version',coalesce(last_record,checkpoint_row.lifecycle_event_id),t,coalesce(checkpoint_row.checkpoint_revision,0)+1,(b->>'batch_id')::uuid,b->>'batch_digest')
   ON CONFLICT ON CONSTRAINT watch_checkpoints_pkey DO UPDATE SET resource_version=EXCLUDED.resource_version,lifecycle_event_id=EXCLUDED.lifecycle_event_id,
    committed_at=EXCLUDED.committed_at,checkpoint_revision=EXCLUDED.checkpoint_revision,last_batch_id=EXCLUDED.last_batch_id,last_batch_digest=EXCLUDED.last_batch_digest
   RETURNING * INTO checkpoint_row;
   cp:=jsonb_build_object('scope',checkpoint_row.scope,'resource_version',checkpoint_row.resource_version,'checkpoint_revision',checkpoint_row.checkpoint_revision);
  END IF;
 END IF;
 -- ACK collections identify records, not array positions. Repeated IDs must
 -- not produce overlapping accepted/duplicate/rejected sets. Rejection wins.
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
   'watermarks',jsonb_build_array(jsonb_build_object('source_epoch',ep,'acked_through',next_ack)),'checkpoint',cp);
END $$;
REVOKE ALL ON FUNCTION audit._lifecycle_proxy(text),audit._lifecycle_record(jsonb,text,text),
 audit.lifecycle_checkpoint(text,text),audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit.lifecycle_checkpoint(text,text),audit.ingest_lifecycle_batch(text,jsonb,text,text,text,text) TO audit_writer;
-- A legacy two-argument implementation may not bypass the current source checks.
DO $$ BEGIN
 IF to_regprocedure('audit.ingest_lifecycle_batch(text,jsonb)') IS NOT NULL THEN
  EXECUTE 'REVOKE ALL ON FUNCTION audit.ingest_lifecycle_batch(text,jsonb) FROM PUBLIC,audit_writer,audit_producer';
 END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('lifecycle_migration.granted_owner',true)='on' THEN REVOKE audit_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
