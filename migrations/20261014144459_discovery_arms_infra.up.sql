-- TASK-02 3.4 / COMMON DiscoveryCandidate (PR #19):
-- - matched_arms: control arms (off/on) that reproduced a candidate.
-- - observed_not_static candidates are stored reproduced and may promote only
--   to deny_fixture or sdk_setting_check, never allow_operation.
-- - infra_filtered: observations to Agentarium infrastructure, counted per run.
--
-- 20261013161333_discovery_candidates is merged, so these are separate
-- changes. A matched or observed_not_static row written before this migration
-- has no matched_arms; matched_arms_recorded then fails and the migration
-- stops instead of inventing arms (no such rows exist before first deployment).

ALTER TABLE discovery.discovery_runs
    ADD COLUMN infra_filtered integer NOT NULL DEFAULT 0 CHECK (infra_filtered >= 0);

ALTER TABLE discovery.discovery_candidates
    ADD COLUMN matched_arms text[],
    ADD CONSTRAINT matched_arms_valid CHECK (
        matched_arms IS NULL OR matched_arms IN ('{off}'::text[], '{on}'::text[], '{off,on}'::text[])),
    ADD CONSTRAINT matched_arms_recorded CHECK (
        COALESCE(dynamic_match IN ('matched', 'observed_not_static'), false) = (matched_arms IS NOT NULL)),
    -- No allow from observation alone.
    ADD CONSTRAINT observed_not_allowed CHECK (
        dynamic_match IS DISTINCT FROM 'observed_not_static' OR promotion_kind IS DISTINCT FROM 'allow_operation'),
    DROP CONSTRAINT reproduced_is_matched,
    -- promoted only after dynamic reproduction and human review (COMMON enum);
    -- an observed_not_static candidate is reproduced by the observation itself.
    -- COALESCE: a NULL dynamic_match must fail the check, not pass it.
    ADD CONSTRAINT reproduced_is_matched CHECK (
        state NOT IN ('reproduced', 'promoted')
        OR COALESCE(dynamic_match IN ('matched', 'observed_not_static'), false));

-- Allowed transitions: candidate -> reproduced | rejected, reproduced ->
-- promoted | rejected. promoted and rejected are final. Identity and
-- model-output columns never change. Static candidates are inserted as
-- candidate, observed ones as reproduced.
CREATE OR REPLACE FUNCTION discovery.discovery_candidates_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, discovery AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'discovery_candidates rows are not deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT (NEW.state = 'candidate' OR (NEW.origin = 'observed' AND NEW.state = 'reproduced')) THEN
            RAISE EXCEPTION 'new candidates start in state candidate (observed: reproduced)';
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
    -- Match results (including matched_arms) are written once, while the
    -- candidate is still open.
    IF OLD.dynamic_match IS NOT NULL
       AND (NEW.dynamic_match, NEW.path_unverified, NEW.matched_arms, NEW.reproduction_run_id)
           IS DISTINCT FROM (OLD.dynamic_match, OLD.path_unverified, OLD.matched_arms, OLD.reproduction_run_id) THEN
        RAISE EXCEPTION 'match result already recorded';
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;
