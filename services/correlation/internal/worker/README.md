# Correlation worker (TASK-10 3.1)

`Worker.Run(node, from, to)` correlates every stored `tcp_connect` of a node
with `source_time` in `[from, to)`. It reads from PostgreSQL:

- `audit.kernel_events` connects and `tcp_state` transitions (1 = ESTABLISHED,
  7 = CLOSE) through the TASK-07 `correlation_reader` grant
  (`20261017144104_audit_correlation_reader`);
- `correlation.lifecycle_intervals`, only the latest `mapping_version` of each
  interval identity; an interval without a start or a verified
  `<namespace>/<ksa>` workload makes its whole container ambiguous instead of
  being dropped;
- TASK-03 `coordinator.attempt_observations` joined to `coordinator.attempts`
  for the action relation, limited to the node's adapter attempts; rows with
  unspecified addresses or bad windows are skipped, never failing the run;
- `correlation.tuple_normalization_rules` for the selected algorithm version
  (migration `20261017144515_correlation_tuple_rules`; rows are Q0 results).

The snapshot widens to every observation window that overlaps the range, so
uniqueness is decided over all candidates. `join.Match` computes the result;
the worker translates it to the documented columns (`method =
kernel_socket_join`, reason = the engine diagnostic, typed evidence refs
`kernel_event:`, `attempt:`, `lifecycle_interval:`, `lifecycle_event:`,
`q0_run:`, and `process_exec:` for confirmed) and appends it through
`results.Store` based on the latest stored revision, so a rerun with the same
inputs writes nothing and late evidence appends a new revision.

Verification: `bash tests/correlation/run-worker-local.sh` (PostgreSQL 16, all
merged migrations, a login holding only `correlation_writer` and
`audit_producer`) covers confirmed, `state_event_missing`, the exec cap,
unknown containers, destinations without a measured rule, idempotent reruns
and a late second observation lowering confidence while revision 1 is kept.

Windows younger than `MinDelay` (60s) are not correlated yet; a risk
evaluator must use the latest revision after that delay. Connects with an
unusable socket identity are stored as `unlinked`, and connects whose kernel
metadata is unresolved (no container) carry `metadata_unresolved`.

Not implemented or verified: the TASK-03 grant of `attempt_observations` and
`attempts` (attempt_id, action_id, adapter_node_uid) SELECT to
`correlation_reader` (TASK-10 3.1 requested it; the test grants it as a
stand-in; TASK-03 adds the real grant and any index), a verified workload source (injected), the service
binary and its scheduling, late lifecycle re-evaluation after 10 minutes,
`kernel_session_attributions`, Q0 rule measurement and any GKE run.
