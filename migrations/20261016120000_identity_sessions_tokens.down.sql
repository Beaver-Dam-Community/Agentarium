DROP TABLE identity.issue_candidate_counters;
DROP TABLE identity.issue_candidates;
DROP TABLE identity.service_session_counters;
DROP TABLE identity.session_tokens;
DROP TABLE identity.service_sessions;
ALTER TABLE identity.sessions DROP COLUMN requested_target_ids;
