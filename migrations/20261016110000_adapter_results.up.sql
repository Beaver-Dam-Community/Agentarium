-- TASK-05 3.4 (M2-7): adapter execution state, results and data high-water.
--
-- Scope: adapter_executions, action_results and workload_data_state (COMMON
-- AdapterExecution, ActionResult, WorkloadDataState) and the TASK-05 internal
-- recovery table pending_outcomes. model_turns belongs to the model adapter
-- and comes with it.
--
-- SPEC-QUESTION: COMMON names adapter_reader (TASK-05) only as the SELECT
-- role on TASK-04 decisions/action_contents and desired_bundle, and names no
-- writer role for these tables; gateway_reader (TASK-04) must SELECT
-- workload_data_state, action_results and adapter_executions. Roles and
-- grants are left to the integration change instead of inventing a name or
-- granting to roles that do not exist yet.
--
-- SPEC-QUESTION: COMMON says a restart redoes the commit order for rows that
-- are not completed, but no COMMON structure keeps the response until
-- action_results is written. pending_outcomes is that recovery record. It
-- holds the redacted result and the AdapterObservation, never credentials.

CREATE SCHEMA IF NOT EXISTS adapter;

-- COMMON: Postgres enum order none < synthetic < internal < confidential, so
-- GREATEST() raises the high-water mark and never lowers it.
CREATE TYPE adapter.data_class AS ENUM ('none', 'synthetic', 'internal', 'confidential');

CREATE TABLE adapter.adapter_executions (
    decision_id uuid PRIMARY KEY,
    action_id   uuid NOT NULL,
    adapter_id  text NOT NULL CHECK (adapter_id IN ('kubernetes-reader', 'receiver-sender', 'model', 'evidence-reader')),
    state       text NOT NULL CHECK (state IN ('received', 'preflight_rejected', 'reserved', 'completed', 'failed')),
    attempt_id  uuid NULL,
    -- event_id of the events sent before the reservation, stored before the
    -- event is sent so a reprocessed received row re-sends the same ID.
    preflight_passed_event_id   uuid NULL,
    preflight_rejected_event_id uuid NULL,
    updated_at  timestamptz NOT NULL,
    CHECK (state <> 'reserved' OR attempt_id IS NOT NULL)
);
CREATE INDEX adapter_executions_unfinished ON adapter.adapter_executions (adapter_id, state)
    WHERE state IN ('received', 'reserved');
CREATE INDEX adapter_executions_by_action ON adapter.adapter_executions (action_id);

CREATE TABLE adapter.action_results (
    attempt_id        uuid PRIMARY KEY,
    action_id         uuid NOT NULL,
    execution_state   text NOT NULL CHECK (execution_state IN (
        'denied', 'approval_pending', 'dispatch_pending', 'preflight_rejected', 'attempt_planned',
        'dispatched', 'accepted', 'effect_verified', 'effect_mismatch', 'failed', 'unknown')),
    data_class        adapter.data_class NOT NULL,
    result_body       jsonb NOT NULL,                 -- JSON null when nothing is kept
    truncated         boolean NOT NULL,
    truncation_reason text NULL,
    evidence_level    text NOT NULL CHECK (evidence_level IN ('none', 'accepted', 'effect_verified', 'effect_mismatch', 'unknown')),
    result_digest     char(64) NOT NULL CHECK (result_digest ~ '^[0-9a-f]{64}$'),
    created_at        timestamptz NOT NULL,
    CHECK (truncated OR truncation_reason IS NULL)
);
CREATE INDEX action_results_by_action ON adapter.action_results (action_id, created_at);

-- Key: workload_id for a user session, service_session_id for a service
-- session (exactly one). No row means data_class_high_water = none.
CREATE TABLE adapter.workload_data_state (
    workload_id           text NULL,
    service_session_id    uuid NULL,
    data_class_high_water adapter.data_class NOT NULL,
    data_sources          text[] NOT NULL DEFAULT '{}',
    updated_by_attempt_id uuid NULL,
    updated_at            timestamptz NOT NULL,
    CHECK (num_nonnulls(workload_id, service_session_id) = 1)
);
CREATE UNIQUE INDEX workload_data_state_workload ON adapter.workload_data_state (workload_id)
    WHERE workload_id IS NOT NULL;
CREATE UNIQUE INDEX workload_data_state_service_session ON adapter.workload_data_state (service_session_id)
    WHERE service_session_id IS NOT NULL;

-- The high-water mark never goes down (COMMON state table).
CREATE FUNCTION adapter.workload_data_state_no_lowering() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, adapter AS $$
BEGIN
    IF NEW.data_class_high_water < OLD.data_class_high_water THEN
        RAISE EXCEPTION 'workload_data_state.data_class_high_water cannot be lowered';
    END IF;
    IF NEW.workload_id IS DISTINCT FROM OLD.workload_id
       OR NEW.service_session_id IS DISTINCT FROM OLD.service_session_id THEN
        RAISE EXCEPTION 'workload_data_state key cannot change';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER workload_data_state_no_lowering BEFORE UPDATE ON adapter.workload_data_state
    FOR EACH ROW EXECUTE FUNCTION adapter.workload_data_state_no_lowering();

CREATE TABLE adapter.pending_outcomes (
    decision_id  uuid PRIMARY KEY REFERENCES adapter.adapter_executions,
    attempt_id   uuid NOT NULL,
    transition   text NOT NULL CHECK (transition IN ('response_received', 'failed', 'unknown')),
    reason_codes text[] NOT NULL,
    observation  jsonb NOT NULL,
    event        jsonb NULL,
    result       jsonb NULL,
    created_at   timestamptz NOT NULL,
    CHECK ((transition = 'response_received') = (result IS NOT NULL))
);
