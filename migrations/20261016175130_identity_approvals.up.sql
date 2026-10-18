-- TASK-03 3.1 / 3.2 (M2-5): approvals, approval nonces and the policy-change
-- revocation function.

CREATE TABLE identity.approvals (
    approval_id               uuid NOT NULL,
    revision                  integer NOT NULL CHECK (revision >= 1),
    approval_kind             text NOT NULL CHECK (approval_kind = 'action'),
    action_id                 uuid NOT NULL,
    authenticated_actor       text NOT NULL,
    session_id                uuid NOT NULL REFERENCES identity.sessions,
    contract_digest           char(64) NOT NULL,
    displayed_contract_digest char(64) NOT NULL CHECK (displayed_contract_digest = contract_digest),
    allowed_operation         text NOT NULL,
    canonical_target          jsonb NOT NULL,
    disclosure_fields         text[] NOT NULL,
    content_digest            char(64) NULL,
    max_actions               integer NOT NULL CHECK (max_actions = 1),
    used_actions              integer NOT NULL DEFAULT 0 CHECK (used_actions >= 0 AND used_actions <= max_actions),
    policy_epoch              bigint NOT NULL,
    contract_version          text NOT NULL,
    intent_check_id           uuid NULL,
    acknowledged_findings     text[] NOT NULL DEFAULT '{}',
    created_at                timestamptz NOT NULL,
    expires_at                timestamptz NOT NULL,
    revoked_at                timestamptz NULL,
    revoke_reason             text NULL CHECK (revoke_reason IN ('user_revoked', 'operator_revoked', 'policy_changed', 'session_ended')),
    PRIMARY KEY (approval_id, revision),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX approvals_by_action ON identity.approvals (action_id, revision DESC)
    WHERE revoked_at IS NULL;

-- intent_check_id and required_ack_finding_ids snapshot the intent check the
-- console showed, so the acknowledge check at POST uses exactly that result.
-- SPEC-QUESTION: these two columns are additions to the TASK-03 3.2 DDL.
CREATE TABLE identity.approval_nonces (
    nonce                    text PRIMARY KEY,
    action_id                uuid NOT NULL,
    authenticated_actor      text NOT NULL,
    contract_digest          char(64) NOT NULL,
    intent_check_id          uuid NULL,
    required_ack_finding_ids text[] NOT NULL DEFAULT '{}',
    expires_at               timestamptz NOT NULL      -- issued + 10 min
);

GRANT SELECT, INSERT, UPDATE ON identity.approvals TO identity_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON identity.approval_nonces TO identity_app;

-- COMMON policy changes and approval invalidation. Only a narrowing of
-- receiver.allowed_disclosure_fields revokes approvals: unused, unexpired,
-- unrevoked approvals from an older epoch whose disclosure_fields are not a
-- subset of the new set become policy_changed. Every other patch kind keeps
-- approvals (the next reservation re-evaluates them).
--
-- The function returns the revoked rows. The caller (TASK-14 releaser) appends
-- an approval_revoked AuditEvent for each row with audit_append() in the same
-- activation transaction, so a failed audit write rolls the revocation back.
-- SPEC-QUESTION: COMMON says the function itself leaves approval_revoked; it
-- cannot build a full AuditEvent (source_id, source_epoch, event_id,
-- payload_digest) from its arguments.
CREATE FUNCTION identity.revoke_approvals_for_policy_change(new_epoch bigint, patch_kind text, allowed_fields text[])
RETURNS TABLE (approval_id uuid, revision integer, policy_epoch bigint, session_id uuid)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = identity, pg_temp
AS $$
BEGIN
    IF new_epoch IS NULL OR patch_kind IS NULL THEN
        RAISE EXCEPTION 'new_epoch and patch_kind are required';
    END IF;
    IF patch_kind <> 'receiver.allowed_disclosure_fields' THEN
        RETURN;
    END IF;
    IF allowed_fields IS NULL THEN
        RAISE EXCEPTION 'allowed_fields is required for receiver.allowed_disclosure_fields';
    END IF;
    RETURN QUERY
    UPDATE identity.approvals a
    SET revoked_at = statement_timestamp(), revoke_reason = 'policy_changed'
    WHERE a.revoked_at IS NULL
      AND a.used_actions = 0
      AND a.expires_at > statement_timestamp()
      AND a.policy_epoch < new_epoch
      AND NOT (a.disclosure_fields <@ allowed_fields)
    RETURNING a.approval_id, a.revision, a.policy_epoch, a.session_id;
END
$$;

REVOKE ALL ON FUNCTION identity.revoke_approvals_for_policy_change(bigint, text, text[]) FROM PUBLIC;
-- EXECUTE goes to releaser_app (TASK-14) once that role exists; it is not
-- created here (see the M2-6a DB role issue).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'releaser_app') THEN
        GRANT EXECUTE ON FUNCTION identity.revoke_approvals_for_policy_change(bigint, text, text[]) TO releaser_app;
    END IF;
END
$$;
