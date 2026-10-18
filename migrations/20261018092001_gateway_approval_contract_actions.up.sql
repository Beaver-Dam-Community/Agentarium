-- TASK-04 view read by the TASK-03 approval contract renderer (#47 item 1).
--
-- The renderer needs the action's canonical_target, disclosure_fields and
-- content_digest; pending_approval_actions and action_content_previews do not
-- carry them, and identity_app must not read decisions.actions. This view
-- exposes exactly those columns (plus target_id, which is
-- canonical_target->>'target_id') for user-session actions that have an
-- envelope, with the verdict of the action's latest decision.
-- SPEC-QUESTION: #47 is still open; this PR proposes registering the view in
-- COMMON's identity_app read row (docs/tech-specs/COMMON.md).

CREATE VIEW decisions.approval_contract_actions WITH (security_barrier) AS
SELECT a.action_id, a.session_id, a.tenant, a.environment, a.operation_id,
       a.canonical_target->>'target_id' AS target_id,
       a.canonical_target, a.disclosure_fields, a.content_digest,
       d.verdict
FROM decisions.actions a
JOIN LATERAL (
    SELECT dd.verdict FROM decisions.decisions dd
    WHERE dd.action_id = a.action_id
    ORDER BY dd.seq DESC
    LIMIT 1
) d ON true
WHERE a.session_kind = 'user' AND a.envelope IS NOT NULL;

REVOKE ALL ON decisions.approval_contract_actions FROM PUBLIC;
GRANT SELECT ON decisions.approval_contract_actions TO identity_app;
