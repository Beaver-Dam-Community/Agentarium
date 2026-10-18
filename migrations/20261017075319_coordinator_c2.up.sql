-- TASK-03 3.2 (M2-5): dispatch coordinator, second part.
--
-- Scope: the AdapterObservation columns that the TASK-03 DDL lacks and the DB
-- functions bind_activation_probe_action and resolve_unknown_attempt (COMMON
-- DB function, view and identifier registry). The view attempt_credential_scope is not created
-- here: TASK-03 creates it in the follow-up migration
-- *_coordinator_credential_scope, which runs after the TASK-04 decisions
-- schema and the TASK-06 broker_reader role exist.
--
-- SPEC-QUESTION: COMMON AdapterObservation has dialed_addr and peer_addr_kind,
-- but the TASK-03 attempt_observations DDL does not. Both are added here so
-- the outcome API stores the whole observation. dialed_addr holds the IP that
-- DialContext chose, without its port (peer_port carries the port).
ALTER TABLE coordinator.attempt_observations
    ADD COLUMN dialed_addr    inet NULL,
    ADD COLUMN peer_addr_kind text NULL CHECK (peer_addr_kind IN ('service_vip', 'endpoint', 'external'));

-- SPEC-QUESTION: the coordinator authenticates the TASK-14 releaser at
-- POST /internal/dispatch/activation-probes by its service-session token,
-- which needs SELECT on identity.session_tokens. The TASK-03 role table does
-- not list it.
GRANT SELECT ON identity.session_tokens TO coordinator_app;

-- bind_activation_probe_action fills activation_probes.action_id from the
-- TASK-04 decision transaction (COMMON activation-probe-only dispatch, step
-- 3). The registration must be exactly (service_session_id,
-- client_request_key); the service session must be a live activation_probe
-- session whose change_id is the probe's change_id; the probe must be
-- unexpired. A null action_id is filled; the same action_id again is an
-- idempotent success; any other action_id fails. Returns the
-- activation_probe_id.
--
-- Errors: SQLSTATE P0002 when no usable registration exists (the gateway
-- answers HOLD_ACTIVE, COMMON step 4), P0001 when the registration is bound to
-- another action. A second probe for an action that is already bound fails on
-- UNIQUE (action_id) with 23505.
--
-- Locks: service_sessions FOR SHARE, then the probe row FOR UPDATE, the same
-- order as the coordinator reservation (service_sessions → budget rows →
-- activation_probes).
CREATE FUNCTION coordinator.bind_activation_probe_action(p_service_session_id uuid, p_client_request_key text, p_action_id uuid)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_profile  text;
    v_live     boolean;
    v_change   uuid;
    v_probe    uuid;
    v_pchange  uuid;
    v_action   uuid;
    v_unexpired boolean;
BEGIN
    IF p_service_session_id IS NULL OR p_client_request_key IS NULL OR p_action_id IS NULL THEN
        RAISE EXCEPTION 'service_session_id, client_request_key and action_id are required' USING ERRCODE = 'P0002';
    END IF;
    SELECT s.profile, s.state = 'active' AND s.expires_at > statement_timestamp(), s.change_id
    INTO v_profile, v_live, v_change
    FROM identity.service_sessions s
    WHERE s.service_session_id = p_service_session_id
    FOR SHARE;
    IF NOT FOUND OR v_profile <> 'activation_probe' OR NOT v_live OR v_change IS NULL THEN
        RAISE EXCEPTION 'no live activation_probe service session %', p_service_session_id USING ERRCODE = 'P0002';
    END IF;
    SELECT p.activation_probe_id, p.change_id, p.action_id, p.expires_at > statement_timestamp()
    INTO v_probe, v_pchange, v_action, v_unexpired
    FROM coordinator.activation_probes p
    WHERE p.service_session_id = p_service_session_id AND p.client_request_key = p_client_request_key
    FOR UPDATE;
    IF NOT FOUND OR v_pchange <> v_change OR NOT v_unexpired THEN
        RAISE EXCEPTION 'no usable activation probe registration for this session and key' USING ERRCODE = 'P0002';
    END IF;
    IF v_action IS NULL THEN
        UPDATE coordinator.activation_probes SET action_id = p_action_id WHERE activation_probe_id = v_probe;
    ELSIF v_action <> p_action_id THEN
        RAISE EXCEPTION 'activation probe % is bound to another action', v_probe USING ERRCODE = 'P0001';
    END IF;
    RETURN v_probe;
END
$$;

-- resolve_unknown_attempt moves an unknown attempt to resolved and records
-- the TASK-11 resolution (COMMON: TASK-11 resolutions transaction is the only
-- caller). The same resolution_id again returns the row without change;
-- anything else that is not unknown fails with P0001, a missing attempt with
-- P0002. Locks reservations → attempts like every coordinator transaction.
--
-- SPEC-QUESTION: COMMON says the function leaves unknown_resolved. It cannot
-- build a full AuditEvent (source_id, source_epoch, event_id, payload_digest,
-- resolution, evidence_refs, resolved_by_actor) from its arguments, so it
-- returns the rows and the caller (TASK-11) appends unknown_resolved with
-- audit_append() in the same transaction; a failed append rolls the
-- resolution back.
CREATE FUNCTION coordinator.resolve_unknown_attempt(p_attempt_id uuid, p_resolution_id uuid)
RETURNS TABLE (attempt_id uuid, action_id uuid, reservation_id uuid, adapter_id text, resolution_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    v_res   uuid;
    v_state text;
    v_resolution uuid;
BEGIN
    IF p_attempt_id IS NULL OR p_resolution_id IS NULL THEN
        RAISE EXCEPTION 'attempt_id and resolution_id are required' USING ERRCODE = 'P0002';
    END IF;
    SELECT a.reservation_id INTO v_res FROM coordinator.attempts a WHERE a.attempt_id = p_attempt_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'attempt % does not exist', p_attempt_id USING ERRCODE = 'P0002';
    END IF;
    PERFORM 1 FROM coordinator.reservations r WHERE r.reservation_id = v_res FOR UPDATE;
    SELECT a.state, a.resolution_id INTO v_state, v_resolution
    FROM coordinator.attempts a WHERE a.attempt_id = p_attempt_id FOR UPDATE;
    IF v_state = 'unknown' THEN
        UPDATE coordinator.attempts a
        SET state = 'resolved', resolution_id = p_resolution_id, updated_at = statement_timestamp()
        WHERE a.attempt_id = p_attempt_id;
    ELSIF NOT (v_state = 'resolved' AND v_resolution = p_resolution_id) THEN
        RAISE EXCEPTION 'attempt % is %, not unknown', p_attempt_id, v_state USING ERRCODE = 'P0001';
    END IF;
    RETURN QUERY
    SELECT a.attempt_id, a.action_id, a.reservation_id, a.adapter_id, a.resolution_id
    FROM coordinator.attempts a WHERE a.attempt_id = p_attempt_id;
END
$$;

REVOKE ALL ON FUNCTION coordinator.bind_activation_probe_action(uuid, text, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION coordinator.resolve_unknown_attempt(uuid, uuid) FROM PUBLIC;

-- EXECUTE goes only to the caller roles COMMON names (bind → gateway_app,
-- resolve → timeline_app), once those roles exist; they are not created here.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
        GRANT USAGE ON SCHEMA coordinator TO gateway_app;
        GRANT EXECUTE ON FUNCTION coordinator.bind_activation_probe_action(uuid, text, uuid) TO gateway_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'timeline_app') THEN
        GRANT USAGE ON SCHEMA coordinator TO timeline_app;
        GRANT EXECUTE ON FUNCTION coordinator.resolve_unknown_attempt(uuid, uuid) TO timeline_app;
    END IF;
END
$$;
