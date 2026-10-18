-- TASK-05 3.1 (model profile, reference resolution and functionResponse): the model
-- adapter's model_turns and the turn_index counter of each conversation.
--
-- Every received model response stores the raw candidate parts (thought
-- signatures included) in model_turns, in the same transaction as the
-- workload_data_state raise and the pending_outcomes recovery record
-- (packages/adapters/store SavePending). pending_outcomes, action_results,
-- events and logs never hold raw_parts.
--
-- SPEC-QUESTION: TASK-05 3.1 says model_turns is for the model adapter only
-- and no other role reads it, but COMMON names no model adapter role. No
-- grant is made here; the integration change adds the role instead of
-- inventing a name.
--
-- SPEC-QUESTION: TASK-05 3.1 says turn_index rises by 1 within a
-- conversation_id but not where it starts; the first turn is 0 (the TASK-02
-- model_turn ref accepts turn_index >= 0). The retention limit is the
-- session's expires_at; no purge job deletes expired rows yet.

-- One row per conversation: the next turn_index, taken with INSERT ... ON
-- CONFLICT DO UPDATE ... RETURNING, so concurrent turns of a conversation are
-- ordered by the row lock instead of a UNIQUE violation. session_key binds
-- the conversation to the session of its first turn.
CREATE TABLE adapter.model_conversations (
    conversation_id uuid PRIMARY KEY,
    session_key     uuid NOT NULL,
    next_turn_index bigint NOT NULL CHECK (next_turn_index >= 1),
    updated_at      timestamptz NOT NULL
);

CREATE TABLE adapter.model_turns (
    conversation_id uuid NOT NULL REFERENCES adapter.model_conversations,
    turn_index      bigint NOT NULL CHECK (turn_index >= 0),
    -- user session_id or service_session_id (TASK-05 3.1)
    session_key     uuid NOT NULL,
    action_id       uuid NOT NULL,
    raw_parts       jsonb NOT NULL CHECK (jsonb_typeof(raw_parts) = 'array'),
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (conversation_id, turn_index),
    CHECK (expires_at > created_at)
);
CREATE INDEX model_turns_by_action ON adapter.model_turns (action_id);
CREATE INDEX model_turns_expiry ON adapter.model_turns (expires_at);
