-- Reverts 20261014144459_discovery_arms_infra. Fails if observed_not_static
-- candidates were stored reproduced or promoted, because the original
-- reproduced_is_matched does not allow them.

CREATE OR REPLACE FUNCTION discovery.discovery_candidates_guard() RETURNS trigger
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

ALTER TABLE discovery.discovery_candidates
    DROP CONSTRAINT reproduced_is_matched,
    ADD CONSTRAINT reproduced_is_matched CHECK (
        state NOT IN ('reproduced', 'promoted') OR dynamic_match IS NOT DISTINCT FROM 'matched'),
    DROP CONSTRAINT observed_not_allowed,
    DROP CONSTRAINT matched_arms_recorded,
    DROP CONSTRAINT matched_arms_valid,
    DROP COLUMN matched_arms;

ALTER TABLE discovery.discovery_runs DROP COLUMN infra_filtered;
