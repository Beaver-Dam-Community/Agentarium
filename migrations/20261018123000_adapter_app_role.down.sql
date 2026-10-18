-- The role is cluster-wide and may hold grants in other databases; only this
-- migration's grants are removed.
REVOKE adapter_reader FROM adapter_app;
REVOKE ALL ON adapter.adapter_executions, adapter.pending_outcomes,
    adapter.action_results, adapter.workload_data_state FROM adapter_app;
REVOKE USAGE ON SCHEMA adapter FROM adapter_app;
