-- sqlc projection of existing views. Deployed definitions remain the immutable
-- audit_store and gateway_decisions migrations, not new views in this Task.
CREATE SCHEMA audit;
CREATE TABLE audit.collector_feed (
 event_id uuid NOT NULL, event_type text NOT NULL, tenant text NOT NULL,
 action_id uuid, attempt_id uuid, source_time timestamptz NOT NULL,
 received_at timestamptz NOT NULL, safe_payload jsonb NOT NULL
);
CREATE SCHEMA decisions;
CREATE TABLE decisions.actions_target_view (
 action_id uuid NOT NULL, tenant text NOT NULL, operation_id text NOT NULL,
 canonical_target jsonb NOT NULL
);
