-- Reverts 20261016181826_gateway_decisions.up.sql. gateway_app and
-- adapter_reader are left in place: install-time memberships may refer to
-- them.

DROP VIEW decisions.adapter_action_contents;
DROP VIEW decisions.adapter_action_envelopes;
DROP VIEW decisions.action_content_previews;
DROP VIEW decisions.pending_approval_actions;
DROP VIEW decisions.actions_target_view;
DROP TABLE decisions.adapter_db_roles;
DROP TABLE decisions.intent_checks;
DROP TABLE decisions.execute_requests;
DROP TABLE decisions.decisions;
DROP FUNCTION decisions.refuse_decision_update();
DROP FUNCTION decisions.fill_decision_action();
DROP TABLE decisions.decision_inputs;
DROP TABLE decisions.action_contents;
DROP TABLE decisions.actions;
DROP SCHEMA decisions;
