# Network segment classification

`NewClassifier` and `Classify` implement the ordered destination table in
TASK-10 section 3.7. An internal adapter supplies a verified environment-lock
snapshot, TASK-06 metadata/PGA ranges and catalog target CIDRs. These Go types
do not add an API or change the environment lock schema.

Classification uses the policy log's endpoint namespace, exact pinned
infrastructure addresses and configured CIDRs. It does not resolve DNS, infer
Pod identities from IPs, or treat all private addresses as internal. The two
pinned Service IP exceptions include the lock digest in `Reason`; unknown
ClusterIPs without a destination namespace retain `dnat_unmeasured`. Unknown
source Pods remain `unclassified`, with the independently derived destination
boundary. Missing or invalid destination addresses remain `unknown`.

The result is descriptive evidence. It does not authorize traffic, produce
`confirmed` correlation, identify a session, or create a hold. Callers must
preserve the rule version, reason and limitations when recording a finding.

Validation: `go test -race ./services/correlation/netpol/...` covers the full
ordered table, every source role, overlapping evidence precedence, missing
identities, malformed addresses, missing/invalid configuration and immutable
concurrent snapshots. The package has no external I/O.

## Records, findings and collection gaps (M2-9, TASK-10 3.7)

`Store.Ingest` stores one collector batch for a verified `NodeIdentity`.
Duplicates by `(node_uid, source_epoch, source_sequence)` are acknowledged with
their stored ID. The watermark moves only over contiguous sequences and keeps
the acknowledged record's `source_time`. A final flush is recorded only once
acknowledged through its sequence. A `caught_up_at`, accepted only when every
stored sequence of the epoch is acknowledged, closes the node's open
`NETPOL_COLLECTOR_STOPPED` gap as `backfilled` with `end_at = caught_up_at` and
the sequence range in `evidence_refs`, together with `evidence_gap_resolved`.

`Judge` applies the four 3.7 rules to one merge key. A connect without
ESTABLISHED and a matching deny record is `blocked_attempt`. An established
connect outside the allow table is `unregistered_established` (allow records
only add policy names). A tcp deny without a connect is `unmatched_deny`, while
udp/icmp is `blocked_attempt` with `no_kernel_hook_for_protocol`. An attempt
with neither record nor adapter correlation is `unmatched_attempt` with
`log_drop_unmeasured`. Allowed established connections, adapter-correlated
attempts and allow-only records produce no finding. An overlapping open
collection gap adds `network_policy_log_gap`, and sensor gaps make kernel
counts `estimated`.

`Store.Evaluate` reads node `tcp_connect`/`tcp_state` rows older than the 60s
judge delay, maps each connect to a unique Pod through `lifecycle_intervals`
(observed namespaces `agent-exec`/`agent-adapters` only), resolves policy
records by `(namespace, pod_name)` at their source time, and classifies the
segment. Each changed judgement appends a revision to the same `finding_id`
(merge key plus `[window_start - 7s, window_end + 900s]`) with
`network_finding_recorded` in the same transaction; unchanged input appends
nothing and earlier revisions are never modified. Findings never create holds,
`confirmed` correlations, sessions or actions.

control-health `RecordNetpolGaps` opens the gap when a `netpol-collector` lease
expires, starting at the node's latest acknowledged `source_time` (after a
final flush: after the 120s grace, at `final_flush_caught_up_at`; with no
acknowledged record: the earliest first lease of any collector of the node
since its latest ack, kept in
`control_health_leases.first_reported_at` by migration
`20261017144140_health_lease_first_report`), with
`source_health_changed` and `observation_gap_recorded`. No hold is created.

Migrations `20261017141148_correlation_network_policy` and
`20261017141149_health_netpol_gap_writers` add the 3.7 tables, view and grants.
The TASK-07 migration `20261017144104_audit_correlation_reader` grants
`correlation_reader` exactly the TASK-07 list: audit schema USAGE and SELECT on
`kernel_events`, `lifecycle_events` and `abandoned_ranges`.

Verification: `bash tests/correlation/run-netpol-local.sh` (PostgreSQL 16, all
merged migrations, restricted runtime login) and the control-health
`TestNetpolGapPostgres` in `tests/correlation/run-health-local.sh`.

The collector receiver is `services/correlation/internal/receiver`: the shared
`netpol-collector` SAN is bound to its node/boot through
`identity.audit_source_certificate`, `record_id` must equal
`canonical.NetworkPolicyRecordID`, abandoned ranges become exact
`SEQUENCE_RANGE_ABANDONED` gaps and `rotation_loss` records
`NETPOL_FILE_ROTATION_LOSS` (closing the open collector-stopped gap as
`partially_recovered` or `unrecoverable`). Workloads and the allow table come
from `services/correlation/internal/sources` (environment lock, network values,
TASK-06 allow matrix; workloads through the TASK-03 lookup requested in #206).

Not implemented or not verified: node deletion handling, `affected_workloads`,
`NODE_LOST_BEFORE_ACK`, lease `details.reported` (#170), TASK-12 issue calls,
`timeline_reader` grants, Q0 measurements and any GKE run.
