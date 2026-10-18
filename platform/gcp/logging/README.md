# Network-policy log storage exclusion

TASK-06 section 3.4 stores network-policy evidence through the node file collector
and TASK-10 receiver. This module adds one enabled exclusion for the exact
`projects/PROJECT/logs/policy-action` log name and `k8s_node` resource type.
It also enables the Logging API without disabling it on removal.

Google's [exclusions.create API](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/exclusions/create)
adds the exclusion to the project's `_Default` sink. This resource does not take
ownership of that sink, replace its other filters, or affect `_Required` and
custom/aggregated sinks. Other sinks can still store matching records; inventory
them separately before claiming that no Cloud Logging bucket stores this data.

[GKE network-policy logging](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/network-policy-logging)
continues to produce node files. The Terraform exclusion does not configure
NetworkLogging, deploy the collector, verify its WAL/ack durability, or prove
that any connection was blocked.

## Validation and installation

`terraform init -backend=false`, `terraform validate`, and `terraform test` use
mock providers in this directory. The production root supplies its project ID
from the platform module. There is no cloud apply in CI.

Before applying, inspect the plan for one exclusion and the additive Logging API
enablement. Confirm the intended node-file evidence path and installed collector.
Record the installation time and read back the `_Default` sink's enabled
exclusion. Run the TASK-06 forbidden-path probe, observe the matching node file
and persisted TASK-10 record, then query the `_Default` bucket over the same
post-installation time range. The expected stored count is zero. An empty query
without corresponding generated and durably stored node evidence is inconclusive.
Older entries are not deleted by an exclusion. Retain the query bounds, bucket,
source node, probe result, and collector acknowledgement as evidence.

Removing or disabling this exclusion restores future duplicate storage and may
increase costs; it cannot recover entries excluded in the meantime. Do not
claim this configuration is functionally verified until the end-to-end comparison
has run. Runtime IAM grants, collector deployment, and its service implementation
are separate tasks.
