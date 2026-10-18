-- TASK-10 3.5a/3.5b/3.6: session worker registration and independent
-- observation (health.session_process_bindings) and work-readiness checks
-- (health.work_readiness_checks), COMMON agent work start contract.
--
-- The two tables follow the TASK-10 3.6 DDL. The DDL asks for "immutable evidence of the
-- nonce result, required binding keys, transition CAS" in the migration without
-- naming tables, so two INSERT-only tables are added:
--   * health.worker_challenges: one row per nonce TASK-10 assigns to a node/boot
--     (pending_worker_observation_challenges, pending_work_readiness_challenges);
--   * health.worker_evidence: immutable controls reports, node witness results
--     and pod observation results that bindings/checks reference.
-- SPEC-QUESTION: both table names and columns are proposed in the PR.
-- correlation.kernel_session_attributions and correlation.session_worker_summary
-- (correlation service) are not in this migration.
BEGIN;
SET LOCAL lock_timeout = '2s';
DO $$ BEGIN
 -- TASK-10 correlation role (also created by the correlation migrations).
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='correlation_writer') THEN CREATE ROLE correlation_writer NOLOGIN; END IF;
 IF NOT (pg_has_role(current_user,'health_owner','USAGE') AND pg_has_role(current_user,'health_owner','SET')) THEN
  GRANT health_owner TO CURRENT_USER WITH INHERIT TRUE, SET TRUE;
  PERFORM set_config('health_readiness_migration.granted_owner','on',true);
 END IF;
END $$;
SET ROLE health_owner;

CREATE TABLE health.session_process_bindings (
  worker_binding_id uuid PRIMARY KEY,
  worker_instance_id uuid NOT NULL UNIQUE,
  session_id uuid NOT NULL,
  workload_id text NOT NULL,
  caller_identity text NOT NULL,
  runtime_process_epoch uuid NOT NULL,
  supervisor_process_hint jsonb NOT NULL,
  worker_process_hint jsonb NOT NULL,
  isolation_profile_digest char(64) NOT NULL,
  controls_report_ref uuid NOT NULL,
  registration_digest char(64) NOT NULL,
  instance_binding jsonb,
  root_exec_id text,
  host_pid integer CHECK (host_pid > 0),
  process_start timestamptz,
  exec_event_ref uuid REFERENCES audit.kernel_events(source_event_id),
  node_evidence_ref uuid,
  sensor_generation bigint,
  state text NOT NULL CHECK (state IN ('pending','observed','closed','invalidated')),
  registered_at timestamptz NOT NULL,
  observed_at timestamptz,
  ended_at timestamptz,
  reason_codes text[] NOT NULL DEFAULT '{}',
  audit_event_ref uuid NOT NULL,
  UNIQUE (worker_binding_id, worker_instance_id, session_id, runtime_process_epoch),
  CHECK (state <> 'observed' OR (instance_binding IS NOT NULL AND root_exec_id IS NOT NULL
    AND host_pid IS NOT NULL AND process_start IS NOT NULL AND exec_event_ref IS NOT NULL
    AND node_evidence_ref IS NOT NULL AND sensor_generation IS NOT NULL AND observed_at IS NOT NULL)),
  CHECK (state NOT IN ('closed','invalidated') OR ended_at IS NOT NULL),
  CHECK (reason_codes <@ ARRAY['WORKER_OBSERVATION_NOT_READY','WORKER_BINDING_MISMATCH','WORKER_EXITED',
    'WORKER_ISOLATION_NOT_READY','WORKER_REGISTRATION_CONFLICT']::text[])
);
CREATE UNIQUE INDEX session_one_active_worker ON health.session_process_bindings(session_id)
  WHERE state IN ('pending','observed');
CREATE UNIQUE INDEX worker_root_exec_not_reassigned
  ON health.session_process_bindings((instance_binding->>'node_uid'),
    (instance_binding->>'boot_id'), (instance_binding->>'container_id'), root_exec_id)
  WHERE root_exec_id IS NOT NULL;

CREATE TABLE health.work_readiness_checks (
  check_id uuid PRIMARY KEY,
  work_run_id uuid NOT NULL,
  checkpoint text NOT NULL CHECK (checkpoint IN ('start','resume','control_step')),
  session_id uuid NOT NULL,
  workload_id text NOT NULL,
  caller_identity text NOT NULL,
  runtime_process_epoch uuid NOT NULL,
  worker_instance_id uuid NOT NULL,
  worker_binding_id uuid NOT NULL,
  root_exec_id text,
  worker_evidence_refs jsonb NOT NULL DEFAULT '[]',
  FOREIGN KEY (worker_binding_id, worker_instance_id, session_id, runtime_process_epoch)
    REFERENCES health.session_process_bindings
      (worker_binding_id, worker_instance_id, session_id, runtime_process_epoch),
  instance_binding jsonb,
  sensor_generation bigint,
  rule_hash text,
  policy_epoch bigint,
  challenge_id uuid UNIQUE,
  challenge_evidence_refs jsonb NOT NULL DEFAULT '[]',
  state text NOT NULL CHECK (state IN ('pending','ready','blocked','expired')),
  reason_codes text[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL,
  checked_at timestamptz,
  expires_at timestamptz,
  audit_event_ref uuid NOT NULL,
  CHECK (state <> 'ready' OR (instance_binding IS NOT NULL
    AND jsonb_typeof(instance_binding) = 'object'
    AND instance_binding ?& ARRAY['cluster_uid','pod_uid','node_uid','boot_id','container_id',
      'restart_instance','cgroup_inode','image_manifest_digest']
    AND sensor_generation IS NOT NULL AND root_exec_id IS NOT NULL
    AND jsonb_array_length(worker_evidence_refs) > 0
    AND rule_hash IS NOT NULL AND policy_epoch IS NOT NULL AND challenge_id IS NOT NULL
    AND jsonb_array_length(challenge_evidence_refs) > 0 AND checked_at IS NOT NULL
    AND expires_at IS NOT NULL AND expires_at > checked_at
    AND expires_at <= checked_at + interval '3 seconds'))
);
CREATE INDEX work_readiness_checks_binding ON health.work_readiness_checks (worker_binding_id) WHERE state IN ('pending','ready');

-- Nonces are never reused: a timed-out challenge stays and a new row gets a
-- new challenge_id. COMMON challenge_timeout_seconds = 15.
CREATE TABLE health.worker_challenges (
  challenge_id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('worker_observation','work_readiness')),
  worker_binding_id uuid NOT NULL REFERENCES health.session_process_bindings(worker_binding_id),
  check_id uuid UNIQUE REFERENCES health.work_readiness_checks(check_id),
  node_uid uuid NOT NULL,
  boot_id text NOT NULL CHECK (boot_id <> ''),
  expected_sensor_generation bigint NOT NULL CHECK (expected_sensor_generation >= 1),
  rule_hash text,
  issued_at timestamptz NOT NULL,
  deadline timestamptz NOT NULL,
  CHECK ((kind = 'work_readiness') = (check_id IS NOT NULL)),
  CHECK (deadline > issued_at AND deadline <= issued_at + interval '15 seconds')
);
CREATE INDEX worker_challenges_node ON health.worker_challenges (node_uid, boot_id, deadline);
CREATE INDEX worker_challenges_binding ON health.worker_challenges (worker_binding_id, issued_at);

-- Immutable evidence. body_digest is the JCS SHA-256 of body; a re-report of
-- the same challenge is accepted only with the same digest.
CREATE TABLE health.worker_evidence (
  evidence_id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('controls_report','worker_observation','pod_observation','close_report')),
  worker_binding_id uuid NOT NULL REFERENCES health.session_process_bindings(worker_binding_id),
  check_id uuid REFERENCES health.work_readiness_checks(check_id),
  challenge_id uuid UNIQUE REFERENCES health.worker_challenges(challenge_id),
  reporter_san text NOT NULL,
  body jsonb NOT NULL CHECK (jsonb_typeof(body) = 'object'),
  body_digest char(64) NOT NULL CHECK (body_digest ~ '^[0-9a-f]{64}$'),
  reported_at timestamptz,
  received_at timestamptz NOT NULL,
  CHECK ((kind IN ('worker_observation','pod_observation')) = (challenge_id IS NOT NULL AND reported_at IS NOT NULL)),
  CHECK ((kind = 'pod_observation') = (check_id IS NOT NULL))
);

-- Transition CAS (TASK-10 3.5b): pending→observed/closed/invalidated or
-- observed→closed/invalidated. Registration content never changes; the
-- observation columns are written once, by the pending→observed transition.
CREATE FUNCTION health.session_process_binding_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'session process bindings are never deleted';
  END IF;
  IF (NEW.worker_binding_id, NEW.worker_instance_id, NEW.session_id, NEW.workload_id, NEW.caller_identity,
      NEW.runtime_process_epoch, NEW.supervisor_process_hint, NEW.worker_process_hint,
      NEW.isolation_profile_digest, NEW.controls_report_ref, NEW.registration_digest, NEW.registered_at,
      NEW.audit_event_ref)
     IS DISTINCT FROM
     (OLD.worker_binding_id, OLD.worker_instance_id, OLD.session_id, OLD.workload_id, OLD.caller_identity,
      OLD.runtime_process_epoch, OLD.supervisor_process_hint, OLD.worker_process_hint,
      OLD.isolation_profile_digest, OLD.controls_report_ref, OLD.registration_digest, OLD.registered_at,
      OLD.audit_event_ref) THEN
    RAISE EXCEPTION 'session process binding registration is immutable';
  END IF;
  IF NOT ((OLD.state = 'pending' AND NEW.state IN ('observed','closed','invalidated'))
       OR (OLD.state = 'observed' AND NEW.state IN ('closed','invalidated'))) THEN
    RAISE EXCEPTION 'session process binding transition % -> % is not allowed', OLD.state, NEW.state;
  END IF;
  IF NOT (OLD.state = 'pending' AND NEW.state = 'observed') AND
     (NEW.instance_binding, NEW.root_exec_id, NEW.host_pid, NEW.process_start, NEW.exec_event_ref,
      NEW.node_evidence_ref, NEW.sensor_generation, NEW.observed_at)
     IS DISTINCT FROM
     (OLD.instance_binding, OLD.root_exec_id, OLD.host_pid, OLD.process_start, OLD.exec_event_ref,
      OLD.node_evidence_ref, OLD.sensor_generation, OLD.observed_at) THEN
    RAISE EXCEPTION 'session process binding observation is written only by pending -> observed';
  END IF;
  IF OLD.state = 'pending' AND NEW.state = 'observed' AND
     (OLD.instance_binding - 'image_manifest_digest') IS DISTINCT FROM (NEW.instance_binding - 'image_manifest_digest') THEN
    RAISE EXCEPTION 'observed instance binding differs from the registered binding';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER session_process_binding_transition BEFORE UPDATE OR DELETE ON health.session_process_bindings
  FOR EACH ROW EXECUTE FUNCTION health.session_process_binding_transition();

-- pending→ready/blocked/expired only (TASK-10 3.5a). A re-check is a new row.
CREATE FUNCTION health.work_readiness_check_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'work readiness checks are never deleted';
  END IF;
  IF OLD.state <> 'pending' OR NEW.state NOT IN ('ready','blocked','expired') THEN
    RAISE EXCEPTION 'work readiness transition % -> % is not allowed', OLD.state, NEW.state;
  END IF;
  IF (NEW.check_id, NEW.work_run_id, NEW.checkpoint, NEW.session_id, NEW.workload_id, NEW.caller_identity,
      NEW.runtime_process_epoch, NEW.worker_instance_id, NEW.worker_binding_id, NEW.instance_binding,
      NEW.policy_epoch, NEW.challenge_id, NEW.created_at)
     IS DISTINCT FROM
     (OLD.check_id, OLD.work_run_id, OLD.checkpoint, OLD.session_id, OLD.workload_id, OLD.caller_identity,
      OLD.runtime_process_epoch, OLD.worker_instance_id, OLD.worker_binding_id, OLD.instance_binding,
      OLD.policy_epoch, OLD.challenge_id, OLD.created_at) THEN
    RAISE EXCEPTION 'work readiness check identity is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER work_readiness_check_transition BEFORE UPDATE OR DELETE ON health.work_readiness_checks
  FOR EACH ROW EXECUTE FUNCTION health.work_readiness_check_transition();

REVOKE ALL ON health.session_process_bindings, health.work_readiness_checks,
  health.worker_challenges, health.worker_evidence FROM PUBLIC;
REVOKE ALL ON FUNCTION health.session_process_binding_transition(), health.work_readiness_check_transition() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON health.work_readiness_checks, health.session_process_bindings TO control_health_writer;
GRANT SELECT, INSERT ON health.worker_challenges, health.worker_evidence TO control_health_writer;
GRANT SELECT ON health.session_process_bindings TO coordinator_reader, health_reader, correlation_writer;
RESET ROLE;
DO $$ BEGIN
 IF current_setting('health_readiness_migration.granted_owner',true)='on' THEN REVOKE health_owner FROM CURRENT_USER; END IF;
END $$;
COMMIT;
