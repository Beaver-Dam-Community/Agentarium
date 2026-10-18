-- TASK-04 (M2-6, PR-A): gateway decision store.
--
-- Scope: schema decisions with actions, action_contents, decision_inputs,
-- decisions, execute_requests and intent_checks (TASK-04 chapter 4 "storage units",
-- COMMON common data structures), the per-adapter login mapping adapter_db_roles,
-- the read views other Tasks use (actions_target_view,
-- pending_approval_actions, action_content_previews, adapter_action_envelopes,
-- adapter_action_contents), the role gateway_app and, if missing, the group
-- role adapter_reader.
--
-- Not in this migration (they come with the gateway service PR or with the
-- owning Task):
--   * SELECT for the gateway on other Tasks' objects (identity, coordinator,
--     release, health, TASK-05 tables). COMMON names that reader
--     gateway_reader, TASK-04 names gateway_app; see SPEC-QUESTION below.
--   * bind_activation_probe_action() (TASK-03) and
--     audit.enqueue_decision_input() (TASK-07) and their EXECUTE grants.
--   * gateway_app membership in audit_producer (TASK-07).
--
-- Roles: gateway_app is owned by TASK-04 and created here as a NOLOGIN group
-- role; the Cloud SQL IAM user of the gateway KSA is made a member at install
-- time (TASK-16), as with identity_app and coordinator_app. The migration
-- owner is not gateway_app, so the gateway cannot change the DDL or bypass the
-- grants below.
--
-- SPEC-QUESTION: COMMON "read access to other Tasks' tables" names gateway_reader;
-- TASK-04 chapter 4 names gateway_app for the same reads plus the writes. This
-- migration creates only gateway_app for TASK-04's own tables.
--
-- SPEC-QUESTION: TASK-04 3.1 records a normalize-stage rejection with
-- "part of the envelope" for unregistered operations/targets and schema violations;
-- COMMON records no action for those and only CONTENT_PATTERN_DENIED as a
-- normalize-stage decision. The envelope columns of actions are nullable so
-- either reading can be stored; action_digest and envelope are null together.
--
-- SPEC-QUESTION: TASK-03 renders the approval contract from the action's
-- canonical_target, disclosure_fields and content_digest, but COMMON gives
-- identity_app only pending_approval_actions and action_content_previews,
-- which do not carry them. No object for that read is created here; it needs
-- a shared-contract change first (see the PR's issue).
--
-- The coordinator reads only decisions.decisions (COMMON: coordinator_reader
-- SELECT decisions). The action fields it needs (session, workload,
-- operation, target) are copied into each decision row from its action by a
-- trigger, so the coordinator never reads decisions.actions.
--
-- SPEC-QUESTION: TASK-04 chapter 4 says action_content_previews holds the first
-- 512 characters; TASK-03 contractview caps content_preview.text at 2000.
-- This view follows TASK-04 (512); the renderer reads the same view at GET
-- and POST, so the contract digest is stable.
--
-- Key of action_contents: COMMON ActionContent and the state table make
-- content_digest alone the key. Then a second action with byte-identical
-- content would find the first action's row, and the adapter rejects it
-- (canonical.VerifyContent requires the row's action_id and tenant to be the
-- envelope's: CONTENT_DIGEST_MISMATCH). Here the key is
-- (content_digest, action_id): each action owns its content row, and rows are
-- still found by content_digest (the leading key column). The same key is
-- being added to COMMON in a separate shared-spec PR.
--
-- Adapter reads: COMMON gives adapter_reader (TASK-05) SELECT on decisions
-- and on its own action_contents rows, but TASK-05 also compares the stored
-- envelope, which lives in decisions.actions. adapter_reader therefore gets
-- two views instead of the base tables: adapter_action_envelopes
-- (action_id, envelope) and adapter_action_contents (unexpired
-- action_contents rows). Each view shows only actions that have an allow
-- decision for the calling adapter. The database identifies that adapter by
-- its login: decisions.adapter_db_roles maps each PostgreSQL login name (the
-- Cloud SQL IAM DB user an adapter connects as, i.e. what session_user
-- returns) to one adapter_id. session_user stays the login name after
-- SET ROLE, so a member that switches to adapter_reader still sees only its
-- own adapter's rows, and a login without a mapping sees no rows. The two
-- views and adapter_db_roles are being added to COMMON in a separate
-- shared-spec PR.
--
-- adapter_reader is owned by TASK-05 and created here, if missing, as a
-- NOLOGIN group role so the grants below exist from the start. At install
-- time (TASK-05/TASK-16) each adapter's Cloud SQL IAM user is made a member
-- of adapter_reader and given one adapter_db_roles row; the migration owner
-- writes that row, adapters cannot.

CREATE SCHEMA decisions;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'gateway_app') THEN
        CREATE ROLE gateway_app NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'adapter_reader') THEN
        CREATE ROLE adapter_reader NOLOGIN;
    END IF;
END
$$;

-- One logical action per (actor, session, client_request_key). The first
-- request's raw_body_digest decides later resubmissions (409
-- CLIENT_KEY_BODY_CONFLICT on a different body).
CREATE TABLE decisions.actions (
    action_id                uuid PRIMARY KEY,
    request_id               uuid NOT NULL,                -- request that created the action
    authenticated_actor      text NOT NULL CHECK (authenticated_actor <> ''),
    session_kind             text NOT NULL CHECK (session_kind IN ('user', 'service')),
    session_id               uuid NOT NULL,                -- sessions.session_id or service_sessions.service_session_id
    workload_id              text NULL,                    -- user sessions only
    client_request_key       text NOT NULL CHECK (client_request_key ~ '^[A-Za-z0-9_-]{8,64}$'),
    raw_body_digest          char(64) NOT NULL CHECK (raw_body_digest ~ '^[0-9a-f]{64}$'),
    tenant                   text NOT NULL CHECK (tenant <> ''),
    environment              text NOT NULL CHECK (environment <> ''),
    operation_id             text NOT NULL CHECK (operation_id <> ''),
    -- ActionEnvelope fields; null only for a normalize-stage rejection that
    -- has no envelope.
    schema_version           text NULL,
    endpoint_id              text NULL,
    canonical_target         jsonb NULL,
    disclosure_fields        text[] NULL,
    data_class               text NULL CHECK (data_class IN ('none', 'synthetic', 'internal', 'confidential')),
    data_sources             text[] NULL,
    content_digest           char(64) NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    content_ref              char(64) NULL CHECK (content_ref ~ '^[0-9a-f]{64}$'),
    bytes                    bigint NULL CHECK (bytes >= 0),
    limits                   jsonb NULL,
    catalog_digest           char(64) NULL CHECK (catalog_digest ~ '^[0-9a-f]{64}$'),
    catalog_version          text NULL,
    canonicalization_version text NULL,
    action_digest            char(64) NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    envelope                 jsonb NULL,                   -- the full ActionEnvelope as evaluated
    created_at               timestamptz NOT NULL,
    UNIQUE (authenticated_actor, session_id, client_request_key),
    -- Target of the action_contents foreign key (its content row must be the
    -- action's content_ref in the action's tenant).
    UNIQUE (action_id, content_ref, tenant),
    -- The envelope jsonb is exactly the ActionEnvelope of the columns: the 24
    -- COMMON keys, each equal to its column (absent optional values are JSON
    -- null, as canonical.ActionEnvelope marshals them). Readers can use either
    -- form without comparing them.
    CHECK (envelope IS NULL OR envelope = jsonb_build_object(
        'schema_version', schema_version,
        'action_id', action_id,
        'request_id', request_id,
        'authenticated_actor', authenticated_actor,
        'session_kind', session_kind,
        'session_id', session_id,
        'workload_id', workload_id,
        'endpoint_id', endpoint_id,
        'operation_id', operation_id,
        'canonical_target', canonical_target,
        'environment', environment,
        'tenant', tenant,
        'disclosure_fields', to_jsonb(disclosure_fields),
        'data_class', data_class,
        'data_sources', to_jsonb(data_sources),
        'content_digest', content_digest,
        'content_ref', content_ref,
        'bytes', bytes,
        'limits', limits,
        'catalog_digest', catalog_digest,
        'catalog_version', catalog_version,
        'canonicalization_version', canonicalization_version,
        'raw_body_digest', raw_body_digest,
        'action_digest', action_digest)),
    CHECK ((session_kind = 'user') = (workload_id IS NOT NULL)),
    CHECK ((action_digest IS NULL) = (envelope IS NULL)),
    CHECK (envelope IS NULL OR (canonical_target IS NOT NULL AND disclosure_fields IS NOT NULL
        AND endpoint_id IS NOT NULL AND data_class IS NOT NULL AND data_sources IS NOT NULL
        AND bytes IS NOT NULL AND limits IS NOT NULL AND catalog_digest IS NOT NULL
        AND catalog_version IS NOT NULL AND canonicalization_version IS NOT NULL
        AND schema_version IS NOT NULL)),
    CHECK ((content_digest IS NULL) = (content_ref IS NULL))
);
CREATE INDEX actions_by_session ON decisions.actions (session_id);

-- COMMON ActionContent, one row per action (key SPEC-QUESTION above): two
-- actions with byte-identical content each have their own row with their own
-- action_id and tenant. The row is the action's content: content_digest is
-- the action's content_ref and tenant the action's tenant.
CREATE TABLE decisions.action_contents (
    content_digest char(64) NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    tenant         text NOT NULL,
    action_id      uuid NOT NULL,
    adapter_id     text NOT NULL,
    content_bytes  bytea NOT NULL,
    created_at     timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,                  -- created_at + 30 days
    PRIMARY KEY (content_digest, action_id),
    FOREIGN KEY (action_id, content_digest, tenant) REFERENCES decisions.actions (action_id, content_ref, tenant),
    CHECK (expires_at > created_at)
);

-- COMMON DecisionInput. sanitized_input is the OPA input as evaluated; it
-- holds digests and refs only, no secret, raw log or raw content.
CREATE TABLE decisions.decision_inputs (
    decision_input_digest char(64) PRIMARY KEY CHECK (decision_input_digest ~ '^[0-9a-f]{64}$'),
    tenant                text NOT NULL,
    sanitized_input       jsonb NOT NULL,
    policy_bundle_id      text NOT NULL,
    created_at            timestamptz NOT NULL
);

-- COMMON GatewayDecision. Rows are immutable: gateway_app has INSERT and
-- SELECT only, and the trigger below refuses UPDATE for every role.
CREATE TABLE decisions.decisions (
    decision_id            uuid PRIMARY KEY,
    seq                    bigint GENERATED ALWAYS AS IDENTITY UNIQUE,  -- insertion order; the latest decision of an action has the largest seq
    request_id             uuid NOT NULL,
    action_id              uuid NOT NULL REFERENCES decisions.actions,
    -- Copied from the action by decisions.fill_decision_action(); the
    -- coordinator reads them here instead of reading decisions.actions.
    session_kind           text NOT NULL CHECK (session_kind IN ('user', 'service')),
    session_id             uuid NOT NULL,
    workload_id            text NULL,
    operation_id           text NOT NULL,
    target_id              text NULL,                     -- canonical_target.target_id; null without an envelope
    action_digest          char(64) NULL CHECK (action_digest ~ '^[0-9a-f]{64}$'),
    adapter_id             text NULL,
    verdict                text NOT NULL CHECK (verdict IN ('allow', 'approval_required', 'deny')),
    reason_codes           text[] NOT NULL,
    decision_basis         text NULL CHECK (decision_basis IN ('approval', 'standing_rule', 'service_scope', 'activation_probe')),
    approval_id            uuid NULL,
    standing_rule_id       text NULL,
    service_session_id     uuid NULL,
    activation_probe_id    uuid NULL,
    intent_check_id        uuid NULL,
    matched_rule_ids       text[] NOT NULL CHECK (cardinality(matched_rule_ids) > 0),
    evaluated_rule_ids     text[] NOT NULL CHECK (cardinality(evaluated_rule_ids) > 0),
    rego_result            jsonb NULL,                    -- {verdict, reason_codes, matched_rule_ids}; null at normalize
    gateway_added_rule_ids text[] NOT NULL DEFAULT '{}',
    decision_stage         text NOT NULL CHECK (decision_stage IN ('normalize', 'opa')),
    decision_input_ref     char(64) NULL REFERENCES decisions.decision_inputs (decision_input_digest),
    decision_input_digest  char(64) NULL,
    policy_bundle_id       text NOT NULL CHECK (policy_bundle_id <> ''),
    policy_epoch           bigint NULL,
    opa_bundle_revision    text NULL,
    catalog_digest         char(64) NOT NULL CHECK (catalog_digest ~ '^[0-9a-f]{64}$'),
    catalog_version        text NOT NULL,
    expires_at             timestamptz NOT NULL,          -- created_at + 10 s (decision TTL)
    authenticated_gateway  text NOT NULL CHECK (authenticated_gateway <> ''),
    created_at             timestamptz NOT NULL,
    CHECK (decision_input_ref IS NOT DISTINCT FROM decision_input_digest),
    -- decision_input_ref is null only for a normalize-stage decision.
    CHECK ((decision_stage = 'normalize') = (decision_input_ref IS NULL)),
    CHECK (decision_stage = 'opa' OR (verdict = 'deny' AND rego_result IS NULL AND opa_bundle_revision IS NULL)),
    CHECK (decision_stage = 'normalize' OR (rego_result IS NOT NULL AND opa_bundle_revision IS NOT NULL
        AND policy_epoch IS NOT NULL AND action_digest IS NOT NULL)),
    -- decision_basis is set exactly for allow (COMMON enum decision_basis).
    CHECK ((verdict = 'allow') = (decision_basis IS NOT NULL)),
    CHECK (verdict = 'allow' OR cardinality(reason_codes) > 0),
    CHECK (decision_basis IS DISTINCT FROM 'approval' OR approval_id IS NOT NULL),
    CHECK (decision_basis IS DISTINCT FROM 'service_scope' OR service_session_id IS NOT NULL),
    CHECK (decision_basis IS DISTINCT FROM 'standing_rule' OR standing_rule_id IS NOT NULL),
    CHECK (decision_basis IS DISTINCT FROM 'activation_probe'
        OR (standing_rule_id IS NOT NULL AND activation_probe_id IS NOT NULL AND service_session_id IS NOT NULL)),
    -- allow carries the adapter that executes it.
    CHECK (verdict <> 'allow' OR adapter_id IS NOT NULL),
    CHECK ((session_kind = 'user') = (workload_id IS NOT NULL)),
    CHECK (decision_stage = 'normalize' OR target_id IS NOT NULL),
    CHECK (expires_at > created_at)
);
CREATE INDEX decisions_latest ON decisions.decisions (action_id, seq DESC);

CREATE FUNCTION decisions.refuse_decision_update() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'decisions.decisions rows are immutable';
END
$$;
CREATE TRIGGER decisions_immutable BEFORE UPDATE ON decisions.decisions
    FOR EACH ROW EXECUTE FUNCTION decisions.refuse_decision_update();

-- Fills the action columns of a new decision from its action, overriding
-- whatever the writer passed, so they always match the action row.
CREATE FUNCTION decisions.fill_decision_action() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    SELECT a.session_kind, a.session_id, a.workload_id, a.operation_id, a.canonical_target->>'target_id'
    INTO NEW.session_kind, NEW.session_id, NEW.workload_id, NEW.operation_id, NEW.target_id
    FROM decisions.actions a
    WHERE a.action_id = NEW.action_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'decision % refers to unknown action %', NEW.decision_id, NEW.action_id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER decisions_fill_action BEFORE INSERT ON decisions.decisions
    FOR EACH ROW EXECUTE FUNCTION decisions.fill_decision_action();

-- Durable execute handoff (COMMON durable dispatch). One row per allow decision,
-- written in the decision transaction.
CREATE TABLE decisions.execute_requests (
    decision_id     uuid PRIMARY KEY REFERENCES decisions.decisions,
    action_id       uuid NOT NULL REFERENCES decisions.actions,
    adapter_id      text NOT NULL CHECK (adapter_id <> ''),
    state           text NOT NULL CHECK (state IN ('pending', 'delivered', 'expired')),
    attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL,
    lease_until     timestamptz NULL,                     -- a worker's claim on the row while it calls the adapter
    updated_at      timestamptz NOT NULL
);
CREATE INDEX execute_requests_due ON decisions.execute_requests (next_attempt_at) WHERE state = 'pending';

-- COMMON IntentCheckResult, written by the Python intent checker (TASK-04
-- services/intent_check/).
-- SPEC-QUESTION: no DB role is named for the intent checker; its INSERT grant
-- comes with that service.
CREATE TABLE decisions.intent_checks (
    intent_check_id        uuid PRIMARY KEY,
    -- No foreign key: on the standing-rule path the check runs before the
    -- decision transaction writes the action (TASK-04 chapter 3, step 6).
    action_id              uuid NOT NULL,
    session_id             uuid NOT NULL,
    contract_digest        char(64) NOT NULL CHECK (contract_digest ~ '^[0-9a-f]{64}$'),
    task_statement_digest  char(64) NOT NULL CHECK (task_statement_digest ~ '^[0-9a-f]{64}$'),
    model_id               text NOT NULL,
    prompt_template_digest char(64) NOT NULL CHECK (prompt_template_digest ~ '^[0-9a-f]{64}$'),
    intent_check_status    text NOT NULL CHECK (intent_check_status IN ('completed', 'not_run')),
    overall                text NULL CHECK (overall IN ('consistent', 'divergent', 'unclear')),
    findings               jsonb NOT NULL DEFAULT '[]',
    findings_digest        char(64) NOT NULL CHECK (findings_digest ~ '^[0-9a-f]{64}$'),
    not_run_reason         text NULL,
    created_at             timestamptz NOT NULL,
    CHECK ((intent_check_status = 'completed') = (overall IS NOT NULL)),
    CHECK ((intent_check_status = 'not_run') = (not_run_reason IS NOT NULL))
);
CREATE INDEX intent_checks_by_action ON decisions.intent_checks (action_id);

-- PostgreSQL login of each adapter (header). db_role is the name session_user
-- returns for that adapter's connections; one login maps to one adapter. Rows
-- are written at install time by the migration owner; no application role
-- can read or change them.
CREATE TABLE decisions.adapter_db_roles (
    db_role    name PRIMARY KEY,
    adapter_id text NOT NULL CHECK (adapter_id <> '')
);

-- ---- views for other Tasks (COMMON DB function, view and identifier registry) ----------------

-- TASK-08 evidence_collector: receipt target check.
CREATE VIEW decisions.actions_target_view AS
SELECT a.action_id, a.tenant, a.operation_id, a.canonical_target
FROM decisions.actions a
WHERE a.canonical_target IS NOT NULL;

-- TASK-03 identity service: actions whose latest decision is
-- approval_required and that have no usable approval (unrevoked, unexpired,
-- used_actions < max_actions). created_at is when the action was submitted.
CREATE VIEW decisions.pending_approval_actions AS
SELECT a.action_id, a.session_id, a.operation_id, d.decision_id, a.created_at
FROM decisions.actions a
JOIN LATERAL (
    SELECT x.decision_id, x.verdict
    FROM decisions.decisions x
    WHERE x.action_id = a.action_id
    ORDER BY x.seq DESC
    LIMIT 1
) d ON true
WHERE a.session_kind = 'user'
  AND d.verdict = 'approval_required'
  AND NOT EXISTS (
    SELECT 1 FROM identity.approvals p
    WHERE p.action_id = a.action_id
      AND p.revoked_at IS NULL
      AND p.used_actions < p.max_actions
      AND p.expires_at > statement_timestamp()
  );

-- TASK-03 contract renderer: the first 512 characters of synthetic-data
-- content (TASK-04 chapter 4). Only content whose action was evaluated at data
-- class synthetic is shown. data_class is the workload high-water mark, so
-- none only says nothing was read yet, not that the content is synthetic;
-- such content has no preview and its contract rendering fails closed (503)
-- until a provenance rule exists (SPEC-QUESTION in the PR). action_contents
-- itself stays readable only by the gateway; adapters read it through
-- adapter_action_contents below. Identical content of several actions has
-- identical bytes, so the view gives one row per content_digest.
CREATE VIEW decisions.action_content_previews AS
SELECT DISTINCT c.content_digest,
       left(convert_from(c.content_bytes, 'UTF8'), 512) AS preview_text,
       char_length(convert_from(c.content_bytes, 'UTF8')) > 512 AS truncated
FROM decisions.action_contents c
JOIN decisions.actions a ON a.action_id = c.action_id
WHERE a.data_class = 'synthetic';

-- TASK-05 adapters (adapter_reader; header). Only actions that have an allow
-- decision for the calling adapter are visible: an adapter executes nothing
-- else. The calling adapter is the adapter_db_roles row of session_user; a
-- login without a row sees nothing. The views run with the owner's rights
-- (not security_invoker), so adapter_reader needs no grant on the base tables
-- or on adapter_db_roles. The envelope is the full ActionEnvelope; the CHECK
-- on decisions.actions keeps it equal to the typed columns.
CREATE VIEW decisions.adapter_action_envelopes WITH (security_barrier) AS
SELECT a.action_id, a.envelope
FROM decisions.actions a
WHERE a.envelope IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM decisions.decisions d
    WHERE d.action_id = a.action_id AND d.verdict = 'allow'
      AND d.adapter_id = (SELECT r.adapter_id FROM decisions.adapter_db_roles r WHERE r.db_role = session_user)
  );

-- Unexpired content rows of actions allowed for the calling adapter, whose
-- content row also names that adapter.
CREATE VIEW decisions.adapter_action_contents WITH (security_barrier) AS
SELECT c.content_digest, c.tenant, c.action_id, c.adapter_id, c.content_bytes, c.created_at, c.expires_at
FROM decisions.action_contents c
WHERE c.expires_at > statement_timestamp()
  AND EXISTS (
    SELECT 1 FROM decisions.decisions d
    WHERE d.action_id = c.action_id AND d.verdict = 'allow' AND d.adapter_id = c.adapter_id
      AND d.adapter_id = (SELECT r.adapter_id FROM decisions.adapter_db_roles r WHERE r.db_role = session_user)
  );

-- ---- grants ------------------------------------------------------------------

GRANT USAGE ON SCHEMA decisions TO gateway_app;
GRANT SELECT, INSERT ON
    decisions.actions,
    decisions.action_contents,
    decisions.decision_inputs,
    decisions.decisions,
    decisions.execute_requests
TO gateway_app;
GRANT SELECT ON decisions.intent_checks TO gateway_app;
GRANT UPDATE (state, attempts, next_attempt_at, lease_until, updated_at) ON decisions.execute_requests TO gateway_app;

-- TASK-03 identity service (identity_app exists from identity_workload_pki).
GRANT USAGE ON SCHEMA decisions TO identity_app;
GRANT SELECT ON
    decisions.pending_approval_actions,
    decisions.action_content_previews,
    decisions.intent_checks
TO identity_app;

-- TASK-03 coordinator DecisionSource (coordinator_app exists from coordinator_dispatch).
GRANT USAGE ON SCHEMA decisions TO coordinator_app;
GRANT SELECT ON decisions.decisions TO coordinator_app;

-- TASK-05 adapters (COMMON adapter_reader; views per the header). The
-- base tables and the login mapping stay closed to adapter_reader and PUBLIC;
-- the REVOKEs make that explicit whatever default privileges exist.
REVOKE ALL ON
    decisions.actions,
    decisions.action_contents,
    decisions.decision_inputs,
    decisions.execute_requests,
    decisions.intent_checks,
    decisions.adapter_db_roles
FROM PUBLIC, adapter_reader;
REVOKE ALL ON decisions.decisions FROM PUBLIC;
REVOKE ALL ON decisions.adapter_action_envelopes, decisions.adapter_action_contents FROM PUBLIC;
GRANT USAGE ON SCHEMA decisions TO adapter_reader;
GRANT SELECT ON
    decisions.decisions,
    decisions.adapter_action_envelopes,
    decisions.adapter_action_contents
TO adapter_reader;

-- Readers owned by other Tasks (COMMON read access to other Tasks' tables), granted
-- here when the role already exists. A role created later gets its grant
-- from a new TASK-04 migration (migrations/README: the owner of the granted
-- object writes the GRANT).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'evidence_collector') THEN      -- TASK-08
        GRANT USAGE ON SCHEMA decisions TO evidence_collector;
        GRANT SELECT ON decisions.actions_target_view TO evidence_collector;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_exporter') THEN          -- TASK-07
        GRANT USAGE ON SCHEMA decisions TO audit_exporter;
        GRANT SELECT ON decisions.decision_inputs TO audit_exporter;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'coordinator_reader') THEN      -- TASK-03/10
        GRANT USAGE ON SCHEMA decisions TO coordinator_reader;
        GRANT SELECT ON decisions.decisions TO coordinator_reader;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'proposer_reader') THEN         -- TASK-12
        GRANT USAGE ON SCHEMA decisions TO proposer_reader;
        GRANT SELECT ON decisions.decisions, decisions.decision_inputs TO proposer_reader;
    END IF;
END
$$;
