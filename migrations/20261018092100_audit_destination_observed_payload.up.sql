-- TASK-07 follow-up required by TASK-08 3.2 (destination_observed payload, #142/#174).
-- The merged audit_store registry row requires wire_body_digest, bytes and
-- effect_count to be non-null, which rejects the specified R2(65+)/R3/R4/R5/R6
-- payloads. The merged migration is not edited: this one narrows the generic
-- required fields and adds a destination_observed-only check on the
-- audit_append() insert path. Violations raise SCHEMA_INVALID (22023).
-- Apply after audit_store. The installer needs SET on audit_owner.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
  IF NOT pg_has_role(current_user,'audit_owner','SET') THEN
    -- Remember this grantor's own membership before temporarily enabling SET;
    -- never revoke a membership that this or another grantor already gave.
    PERFORM set_config('destination_payload.had_own_membership', EXISTS(
      SELECT FROM pg_auth_members WHERE roleid='audit_owner'::regrole
      AND member=(SELECT oid FROM pg_roles WHERE rolname = current_user)
      AND grantor=(SELECT oid FROM pg_roles WHERE rolname = current_user))::text,true);
    GRANT audit_owner TO CURRENT_USER WITH SET TRUE;
    PERFORM set_config('destination_payload.enabled_set','on',true);
  END IF;
END $$;
SET LOCAL ROLE audit_owner;
DO $$ BEGIN
  UPDATE audit.event_types SET required_payload_fields='["action_id", "rule_id", "evidence_level"]'::jsonb
   WHERE event_type='destination_observed';
  IF NOT FOUND THEN RAISE EXCEPTION 'destination_observed registry prerequisite missing' USING ERRCODE='55000'; END IF;
END $$;

-- Situation table of TASK-08 3.2: every key is present (null when absent),
-- rule_id/evidence_level is a table pair, and the null combination and
-- missing_reason match one row. No zero, adapter value or first effect may
-- stand in for an absent receiver fact.
CREATE FUNCTION audit._check_destination_observed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, audit, pg_temp AS $$
DECLARE
  p jsonb := NEW.safe_payload;
  hex64 constant text := '^[0-9a-f]{64}$';
  uuid_re constant text := '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
  keys constant text[] := ARRAY['action_id','action_key','rule_id','evidence_level','receipt_digest',
                                'effect_count','wire_body_digest','bytes','effects','missing_reason'];
  rule text; level text; reason text; n bigint; item jsonb;
  has_receipt boolean; has_scalars boolean;
BEGIN
  IF jsonb_typeof(p) IS DISTINCT FROM 'object'
     OR EXISTS (SELECT FROM jsonb_object_keys(p) k WHERE k <> ALL(keys))
     OR EXISTS (SELECT FROM unnest(keys) k WHERE NOT p ? k) THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  rule := p->>'rule_id'; level := p->>'evidence_level'; reason := p->>'missing_reason';
  IF jsonb_typeof(p->'action_id') IS DISTINCT FROM 'string' OR p->>'action_id' !~ uuid_re
     OR NEW.action_id IS NULL OR NEW.action_id::text <> p->>'action_id'
     OR jsonb_typeof(p->'rule_id') IS DISTINCT FROM 'string'
     OR jsonb_typeof(p->'evidence_level') IS DISTINCT FROM 'string'
     OR (rule, level) NOT IN (('R1','effect_verified'),('R2','effect_mismatch'),('R3','effect_mismatch'),
                              ('R4','accepted'),('R5','unknown'),('R6','none'))
     OR jsonb_typeof(p->'action_key') NOT IN ('string','null')
     OR (jsonb_typeof(p->'action_key')='string' AND p->>'action_key' <> p->>'action_id')
     OR jsonb_typeof(p->'receipt_digest') NOT IN ('string','null')
     OR (jsonb_typeof(p->'receipt_digest')='string' AND p->>'receipt_digest' !~ hex64)
     OR jsonb_typeof(p->'effect_count') NOT IN ('number','null')
     OR (jsonb_typeof(p->'effect_count')='number' AND (p->>'effect_count' !~ '^[0-9]+$' OR (p->>'effect_count')::numeric > 9007199254740991))
     OR jsonb_typeof(p->'wire_body_digest') NOT IN ('string','null')
     OR (jsonb_typeof(p->'wire_body_digest')='string' AND p->>'wire_body_digest' !~ hex64)
     OR jsonb_typeof(p->'bytes') NOT IN ('number','null')
     OR (jsonb_typeof(p->'bytes')='number' AND (p->>'bytes' !~ '^[0-9]+$' OR (p->>'bytes')::numeric > 9007199254740991))
     OR jsonb_typeof(p->'effects') NOT IN ('array','null')
     OR jsonb_typeof(p->'missing_reason') NOT IN ('string','null') THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  IF jsonb_typeof(p->'effects')='array' THEN
    IF jsonb_array_length(p->'effects') > 64 THEN RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023'; END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(p->'effects') LOOP
      IF jsonb_typeof(item) IS DISTINCT FROM 'object'
         OR (SELECT count(*) FROM jsonb_object_keys(item)) <> 2
         OR jsonb_typeof(item->'wire_body_digest') IS DISTINCT FROM 'string' OR item->>'wire_body_digest' !~ hex64
         OR jsonb_typeof(item->'body_bytes') IS DISTINCT FROM 'number' OR item->>'body_bytes' !~ '^[0-9]+$'
         OR (item->>'body_bytes')::numeric > 9007199254740991 THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
    END LOOP;
  END IF;
  -- wire_body_digest and bytes are present together or absent together.
  IF (jsonb_typeof(p->'wire_body_digest')='null') <> (jsonb_typeof(p->'bytes')='null') THEN
    RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END IF;
  has_scalars := jsonb_typeof(p->'wire_body_digest')='string';
  has_receipt := jsonb_typeof(p->'receipt_digest')='string';
  n := CASE WHEN jsonb_typeof(p->'effect_count')='number' THEN (p->>'effect_count')::bigint END;
  IF has_scalars THEN
    -- Exactly one effect: the scalars are that effect's receiver values.
    IF reason IS NOT NULL OR rule NOT IN ('R1','R2') OR NOT has_receipt OR n IS DISTINCT FROM 1
       OR jsonb_typeof(p->'action_key') <> 'string'
       OR jsonb_typeof(p->'effects') <> 'array' OR jsonb_array_length(p->'effects') <> 1
       OR p->'effects'->0->'wire_body_digest' IS DISTINCT FROM p->'wire_body_digest'
       OR p->'effects'->0->'body_bytes' IS DISTINCT FROM p->'bytes' THEN
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
    END IF;
    RETURN NEW;
  END IF;
  CASE reason
    WHEN 'MULTIPLE_EFFECTS' THEN
      IF rule <> 'R2' OR NOT has_receipt OR n IS NULL OR n < 2 OR n > 64
         OR jsonb_typeof(p->'action_key') <> 'string'
         OR jsonb_typeof(p->'effects') <> 'array' OR jsonb_array_length(p->'effects') <> n THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
    WHEN 'EFFECT_LIST_LIMIT_EXCEEDED' THEN
      IF rule <> 'R2' OR NOT has_receipt OR n IS NULL OR n < 65
         OR jsonb_typeof(p->'action_key') <> 'string' OR jsonb_typeof(p->'effects') <> 'null' THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
    WHEN 'NO_RECEIVER_EFFECT', 'NO_RECEIVER_ATTEMPT' THEN
      IF (reason='NO_RECEIVER_EFFECT' AND rule NOT IN ('R2','R3'))
         OR (reason='NO_RECEIVER_ATTEMPT' AND rule NOT IN ('R5','R6'))
         OR NOT has_receipt OR n IS DISTINCT FROM 0
         OR jsonb_typeof(p->'action_key') <> 'string'
         OR p->'effects' IS DISTINCT FROM '[]'::jsonb THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
    WHEN 'RECEIPT_UNAVAILABLE' THEN
      IF rule <> 'R5' OR has_receipt OR n IS NOT NULL
         OR jsonb_typeof(p->'action_key') <> 'string' OR jsonb_typeof(p->'effects') <> 'null' THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
    WHEN 'NOT_RECEIVER_TARGET' THEN
      IF rule <> 'R4' OR has_receipt OR n IS NOT NULL
         OR jsonb_typeof(p->'action_key') <> 'null' OR jsonb_typeof(p->'effects') <> 'null' THEN
        RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
      END IF;
    ELSE
      RAISE EXCEPTION 'SCHEMA_INVALID' USING ERRCODE='22023';
  END CASE;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION audit._check_destination_observed() FROM PUBLIC;
CREATE TRIGGER audit_events_destination_observed
  BEFORE INSERT ON audit.audit_events
  FOR EACH ROW WHEN (NEW.event_type = 'destination_observed')
  EXECUTE FUNCTION audit._check_destination_observed();
RESET ROLE;
DO $$ BEGIN
  IF current_setting('destination_payload.enabled_set',true)='on' THEN
    IF current_setting('destination_payload.had_own_membership',true)='true' THEN
      GRANT audit_owner TO CURRENT_USER WITH SET FALSE;
    ELSE
      REVOKE audit_owner FROM CURRENT_USER;
    END IF;
  END IF;
END $$;
COMMIT;
