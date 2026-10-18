-- TASK-02 3.4 / COMMON "discovery_candidates / TASK-02": candidate state
-- transitions and reproduction run references, plus the snapshot and run rows
-- they refer to.
--
-- SPEC-QUESTION: COMMON does not name the discovery DB role, so this migration
-- grants nothing. COMMON also lists only intent_checks, alignment_results,
-- mismatches, issues, proposals and regression_runs as Python-owned writable
-- tables; discovery_candidates is TASK-02-owned and written by the Python
-- discovery service.

CREATE SCHEMA IF NOT EXISTS discovery;

CREATE TABLE discovery.discovery_snapshots (
    snapshot_id     text PRIMARY KEY CHECK (snapshot_id ~ '^[0-9a-f]{64}$'),
    tenant          text NOT NULL,
    library         text NOT NULL CHECK (length(library) BETWEEN 1 AND 256),
    library_version text NOT NULL CHECK (length(library_version) BETWEEN 1 AND 128),
    language        text NOT NULL CHECK (language IN ('go', 'python')),
    source_uri      text NOT NULL,
    source_digest   text NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
    file_count      integer NOT NULL CHECK (file_count >= 0),
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE discovery.discovery_snapshot_requests (
    request_id         uuid PRIMARY KEY,
    tenant             text NOT NULL,
    library            text NOT NULL,
    library_version    text NOT NULL,
    language           text NOT NULL CHECK (language IN ('go', 'python')),
    source_uri         text NOT NULL,
    source_digest      text NOT NULL CHECK (source_digest ~ '^[0-9a-f]{64}$'),
    state              text NOT NULL CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    requested_by_actor text NOT NULL,
    job_name           text,
    snapshot_id        text REFERENCES discovery.discovery_snapshots (snapshot_id),
    error              text,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant, language, source_uri, source_digest),
    CHECK (state <> 'succeeded' OR snapshot_id IS NOT NULL)
);

CREATE TABLE discovery.discovery_runs (
    run_id                 uuid PRIMARY KEY,
    tenant                 text NOT NULL,
    snapshot_id            text NOT NULL REFERENCES discovery.discovery_snapshots (snapshot_id),
    scenario_set_id        text NOT NULL CHECK (scenario_set_id ~ '^[A-Za-z0-9._-]{1,128}$'),
    state                  text NOT NULL CHECK (state IN ('queued', 'analyzing', 'reproducing', 'completed', 'failed')),
    created_by_actor       text NOT NULL,
    static_analysis_status text CHECK (static_analysis_status IN ('completed', 'not_run')),
    -- TASK-13 regression run (run_kind = discovery)
    reproduction_run_id    uuid,
    model_calls            integer NOT NULL DEFAULT 0 CHECK (model_calls BETWEEN 0 AND 20),
    read_calls             integer NOT NULL DEFAULT 0 CHECK (read_calls BETWEEN 0 AND 50),
    error                  text,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX discovery_runs_queued_idx ON discovery.discovery_runs (created_at) WHERE state = 'queued';

CREATE TABLE discovery.discovery_candidates (
    candidate_id            uuid PRIMARY KEY,
    seq                     bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
    tenant                  text NOT NULL,
    run_id                  uuid NOT NULL REFERENCES discovery.discovery_runs (run_id),
    snapshot_id             text NOT NULL REFERENCES discovery.discovery_snapshots (snapshot_id),
    -- static: model output from static analysis. observed: observed_not_static.
    origin                  text NOT NULL CHECK (origin IN ('static', 'observed')),
    library                 text NOT NULL,
    library_version         text NOT NULL,
    call_site               text,
    trigger_condition       text,
    destination_template    text NOT NULL CHECK (length(destination_template) BETWEEN 1 AND 512),
    retry_redirect_behavior text,
    evidence_ref            text NOT NULL,
    model_run_ref           text,
    -- Gemini explanation. A note only; it never drives state.
    model_annotation        text,
    dynamic_match           text CHECK (dynamic_match IN ('observed_not_static', 'static_not_observed', 'matched')),
    path_unverified         boolean,
    reproduction_run_id     uuid,
    state                   text NOT NULL DEFAULT 'candidate'
                            CHECK (state IN ('candidate', 'reproduced', 'promoted', 'rejected')),
    promotion_kind          text CHECK (promotion_kind IN ('allow_operation', 'deny_fixture', 'sdk_setting_check')),
    reviewed_by_actor       text,
    review_note             text,
    reject_reason           text,
    catalog_change_ref      text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT static_has_model_fields CHECK (
        origin <> 'static' OR (call_site IS NOT NULL AND trigger_condition IS NOT NULL
                               AND retry_redirect_behavior IS NOT NULL AND model_run_ref IS NOT NULL)),
    CONSTRAINT observed_is_observed_not_static CHECK (
        origin <> 'observed' OR dynamic_match IS NOT DISTINCT FROM 'observed_not_static'),
    CONSTRAINT matched_needs_run CHECK (
        dynamic_match IS NULL OR reproduction_run_id IS NOT NULL),
    CONSTRAINT matched_has_path_flag CHECK (
        (dynamic_match IS NOT DISTINCT FROM 'matched') = (path_unverified IS NOT NULL)),
    -- promoted only after dynamic reproduction and human review (COMMON enum)
    CONSTRAINT reproduced_is_matched CHECK (
        state NOT IN ('reproduced', 'promoted') OR dynamic_match IS NOT DISTINCT FROM 'matched'),
    CONSTRAINT promoted_is_reviewed CHECK (
        (state = 'promoted') = (promotion_kind IS NOT NULL)
        AND (state <> 'promoted' OR reviewed_by_actor IS NOT NULL)),
    CONSTRAINT rejected_has_reason CHECK (
        state <> 'rejected' OR reject_reason IS NOT NULL)
);

CREATE INDEX discovery_candidates_run_idx ON discovery.discovery_candidates (tenant, run_id, seq);
CREATE INDEX discovery_candidates_state_idx ON discovery.discovery_candidates (tenant, state, seq);

CREATE TABLE discovery.discovery_candidate_transitions (
    transition_id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    candidate_id        uuid NOT NULL REFERENCES discovery.discovery_candidates (candidate_id),
    from_state          text,
    to_state            text NOT NULL,
    dynamic_match       text,
    reproduction_run_id uuid,
    actor               text NOT NULL,
    note                text,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX discovery_candidate_transitions_idx ON discovery.discovery_candidate_transitions (candidate_id, transition_id);

-- Allowed transitions: candidate -> reproduced | rejected, reproduced ->
-- promoted | rejected. promoted and rejected are final. Identity and
-- model-output columns never change.
CREATE FUNCTION discovery.discovery_candidates_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, discovery AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'discovery_candidates rows are not deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'candidate' THEN
            RAISE EXCEPTION 'new candidates start in state candidate';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state IN ('promoted', 'rejected') THEN
        RAISE EXCEPTION 'candidate % is final (%)', OLD.candidate_id, OLD.state;
    END IF;
    IF NOT (NEW.state = OLD.state
            OR (OLD.state = 'candidate' AND NEW.state IN ('reproduced', 'rejected'))
            OR (OLD.state = 'reproduced' AND NEW.state IN ('promoted', 'rejected'))) THEN
        RAISE EXCEPTION 'invalid transition % -> %', OLD.state, NEW.state;
    END IF;
    IF (NEW.candidate_id, NEW.seq, NEW.tenant, NEW.run_id, NEW.snapshot_id, NEW.origin, NEW.library,
        NEW.library_version, NEW.call_site, NEW.trigger_condition, NEW.destination_template,
        NEW.retry_redirect_behavior, NEW.evidence_ref, NEW.model_run_ref, NEW.created_at)
       IS DISTINCT FROM
       (OLD.candidate_id, OLD.seq, OLD.tenant, OLD.run_id, OLD.snapshot_id, OLD.origin, OLD.library,
        OLD.library_version, OLD.call_site, OLD.trigger_condition, OLD.destination_template,
        OLD.retry_redirect_behavior, OLD.evidence_ref, OLD.model_run_ref, OLD.created_at) THEN
        RAISE EXCEPTION 'immutable candidate columns changed';
    END IF;
    -- Match results are written once, while the candidate is still open.
    IF OLD.dynamic_match IS NOT NULL
       AND (NEW.dynamic_match, NEW.path_unverified, NEW.reproduction_run_id)
           IS DISTINCT FROM (OLD.dynamic_match, OLD.path_unverified, OLD.reproduction_run_id) THEN
        RAISE EXCEPTION 'match result already recorded';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

CREATE TRIGGER discovery_candidates_guard
    BEFORE INSERT OR UPDATE OR DELETE ON discovery.discovery_candidates
    FOR EACH ROW EXECUTE FUNCTION discovery.discovery_candidates_guard();

-- Every state change is logged. The app sets discovery.actor with
-- set_config(..., true) in the same transaction.
CREATE FUNCTION discovery.discovery_candidates_log() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, discovery AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.state = OLD.state THEN
        RETURN NULL;
    END IF;
    INSERT INTO discovery.discovery_candidate_transitions
        (candidate_id, from_state, to_state, dynamic_match, reproduction_run_id, actor, note)
    VALUES (NEW.candidate_id,
            CASE WHEN TG_OP = 'UPDATE' THEN OLD.state END,
            NEW.state, NEW.dynamic_match, NEW.reproduction_run_id,
            COALESCE(NULLIF(current_setting('discovery.actor', true), ''), 'service:discovery'),
            CASE NEW.state WHEN 'promoted' THEN NEW.review_note WHEN 'rejected' THEN NEW.reject_reason END);
    RETURN NULL;
END;
$$;

CREATE TRIGGER discovery_candidates_log
    AFTER INSERT OR UPDATE ON discovery.discovery_candidates
    FOR EACH ROW EXECUTE FUNCTION discovery.discovery_candidates_log();

CREATE FUNCTION discovery.discovery_append_only() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$;

CREATE TRIGGER discovery_candidate_transitions_append_only
    BEFORE UPDATE OR DELETE ON discovery.discovery_candidate_transitions
    FOR EACH ROW EXECUTE FUNCTION discovery.discovery_append_only();

-- Events committed with the state change and delivered to
-- POST /internal/audit/events afterwards.
CREATE TABLE discovery.discovery_event_outbox (
    event_id            uuid PRIMARY KEY,
    event_type          text NOT NULL CHECK (event_type IN ('discovery_candidate_recorded', 'discovery_candidate_promoted')),
    tenant              text NOT NULL,
    source_epoch        bigint NOT NULL CHECK (source_epoch >= 1),
    source_time         timestamptz NOT NULL,
    authenticated_actor text,
    payload             jsonb NOT NULL,
    sent_at             timestamptz,
    attempts            integer NOT NULL DEFAULT 0
);

CREATE INDEX discovery_event_outbox_pending_idx ON discovery.discovery_event_outbox (source_time) WHERE sent_at IS NULL;

-- AuditEvent source_epoch: incremented on each producer process start.
CREATE TABLE discovery.discovery_producer_epochs (
    source_id text PRIMARY KEY,
    epoch     bigint NOT NULL CHECK (epoch >= 1)
);
