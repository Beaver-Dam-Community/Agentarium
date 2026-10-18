# TASK-10 3.2 answer probe

`probe-runner.yaml` runs the answer probe runner (`services/probe-runner`) as a
DaemonSet in `agent-exec` (exec nodes) and `agent-adapters` (control nodes).
`probe-sink.yaml` is the tcp probe target in `agent-targets`. Every 60s each
runner execs `/probe/bin/marker`, connects to the sink and opens/denies
`/work/protected-fixture`, then reports each kind 25s later. control-health
lifts `agentarium.io/observe-not-ready` from a node only after two passes per
kind with matching kernel evidence.

- The agent-exec runner has no DNS egress and no direct control-health path
  (TASK-06): it bootstraps and reports through the gateway at the lock
  `network.gateway_cluster_ip`, and dials the sink at `PROBE_SINK_CLUSTER_IP`.
  The gateway relays the report with the runner's certificate identity.
- The agent-adapters runner talks to workload-identity and control-health
  directly.
- Both runners and the sink tolerate only the start taint (and, on exec, the
  exec role taint). The runner image needs `PROBE_IMAGES`,
  `AGENT_ADAPTERS_IMAGES` and the `PROBE_ENTRYPOINTS` pair
  `<image>=/probe/bin/probe-runner`; `render.py` refuses values admission would
  reject.

Apply after the contact services and the action path are ready, and after
`installer/m3-1-probe-runner.sql`: first `probe-sink.yaml`, then
`probe-runner.yaml`.
