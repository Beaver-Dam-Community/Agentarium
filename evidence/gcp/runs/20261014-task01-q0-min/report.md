# 20261014-task01-q0-min

| Item | Value |
| --- | --- |
| Task | TASK-01 (M0-3 Q0 minimum items) |
| run_kind | `q0_min_observation` |
| Status | `incomplete` (observable scope recording completed; some rows are partially supported or unexecuted) |
| Environment | `agentarium-prod`, GKE `1.36.4-gke.1495002`, COS, kernel `6.12.105+`, containerd 2.2.7 |
| Sensor | Tetragon 1.7.1 (`deploy/gcp/sensors/tetragon-values.yaml`), 3 TracingPolicies (original text of TASK-09 3.2) |
| Execution Time | 2026-10-14T13:16Z~13:20Z |

## What Was Done

The M0-3 completion criteria are to "observe three types of kernel behaviors and record the node file format of network policy logs."

- **Kernel behavior:** Executed `q0-stimulus` under the probe-runner profile on a single exec node. This program generates 30 stimuli per type and records one line of JSON per stimulus. Those records were compared against the Tetragon export events on the same node.
  - **process:** Executes itself as a child.
  - **tcp:** Connects to kube-dns `:53`.
  - **Protected file:** Opens `/work/protected-fixture` via allowed open and denied open (after `chmod 000`).
- **Network policy logs:** Applied a temporary NetworkPolicy on the same node and generated 3 allowed connections and 3 denied connections. Then, read `/var/log/network/policy_action.log` on the node as read-only.

## Support Table

| Row | Result | Verdict |
| --- | --- | --- |
| process exec/exit | 31 `process_exec` events, 31 `process_exit` events (30 children and 1 container start) | Supported |
| `tcp_connect` | Stimulus port matching 30/30. Destination `daddr` is kube-dns ClusterIP `10.30.0.10:53` (address before DNAT) | Supported |
| `tcp_set_state`, default export deny list | ESTABLISHED 10/30, CLOSE 6/30 | Not supported with default settings |
| `tcp_set_state`, excluding `""` from deny list | ESTABLISHED 29/30, CLOSE 25/30. 48 events had no Pod information, and 6 events were misattributed to the tetragon Pod | Partially supported |
| `security_file_open` | 31 events (30 allowed opens and 1 creation), path `/work/protected-fixture`, return 0. Denied opens did not appear | Supported |
| `sys_openat` | 61 events = 31 events returning an fd and 30 events returning `-13` (EACCES) | Supported |
| `sys_openat2` | Go runtime only used openat, failing to stimulate | Unexecuted |
| `enableProcessNs` | 10 types including net, mnt, pid, and cgroup appeared in `process.ns` | Supported |
| Network policy log node file | 3 allowed events (including `policies[]`), 2 denied records (batched by count). `src` and `dest` lack `workload_name` and `workload_kind` from the specification | Partially supported |
| Network policy log rotation, delivery delay, batched record `timestamp`, drop counter | Not measured | Unexecuted |

Detailed contents of the node file format are in `netpol-log-format.json`.

## Findings

1. **The export deny list drops state transition events.** Tetragon chart defaults exclude events from namespaces `""`, `cilium`, and `kube-system` from export. In softirq context, `tcp_set_state` events are attributed to whatever task was running on the CPU at that time, resulting in empty Pod information or attribution to other Pods, so they were caught by these rules and dropped. This is the item that TASK-09 3.1 noted to "verify in Q0." Even in run2, where only `""` was excluded, some were dropped, and in the run leaving only `health_check` (20261015-task01-q0-min-2), it became 30/30. The locked value retains only `health_check`.
2. **The process field of state transition events cannot be used.** Attribution is empty or appears as another Pod. Therefore, they are linked to connect events using the same node, the same sock cookie, the same source address and port, and a timestamp after connect (the `sock_ptr`, tuple, and time window from TASK-09 3.2). Because Tetragon's `cookie` is a kernel sock pointer, it is reused. There were only 18 cookies across 30 connect events, so they cannot be linked by cookie alone. The comparison script is `tests/platform/q0/analyze_q0_min.py`.
3. **TracingPolicy return type warning:** While `returnArg` for `sys_openat`/`sys_openat2` in the original TASK-09 text is `int`, Tetragon emitted a "syscall return type is not long int" warning. The policy was loaded and the return values (fd, `-13`) were produced normally. Later, changing to `long` and `int64` yielded the same warning (20261015-task01-q0-min-2). Therefore, the warning is considered unrelated to the return type designation, and the specification value is maintained.
4. **The gateway locked ClusterIP overlaps with the kube-dns address.** GKE has already assigned the lock default value `network.gateway_cluster_ip = 10.30.0.10` to the kube-dns Service. As it stands, the gateway Service cannot be created. The default value in the TASK-01 lock table must be changed.
5. **Destination address in network policy logs:** `dest_ip` is not the Service's ClusterIP, but the translated backend address. kube-dns was recorded as a Pod IP, and the API server was recorded as the private endpoint `10.10.0.2`. For destinations that are not Pods, only `instance` remains in `dest`.
6. **count in denied records:** 3 denied connections were batched into 2 records, and count was a value that counted up through SYN retransmissions, such as 6 and 3. It should not be read as the number of attempts (TASK-10 3.7).

## Limitations

- **Scope:** Executed on only one node and one kernel. Event loss and load were not measured.
- **Ground truth:** The stimulus program's own records were used as ground truth. There is no independent observer.
- **CLOSE comparison:** Only CLOSE transitions observed within the collection window were counted. The reason why 5 out of 30 were missing in run2 could not be identified in this run. It was later confirmed in [20261015-task01-q0-min-2](../20261015-task01-q0-min-2/report.md) that the kube-system namespace rule was the cause.
- **Network policy logs:** Did not test whether traffic originating from hostNetwork Pods and the node is recorded.
- **COMMON baseline rows:** This run covers the M0-3 minimum items. It does not replace the entire COMMON Q0 rows that require 30 iterations per type and independent ground-truth verification.

## What Was Left in the Cluster

- **Retained:** Tetragon DaemonSet, 3 TracingPolicies, `NetworkLogging default`, sensors image allowlist. Continued in TASK-09 and TASK-06.
- **Deleted:** Test Pod, temporary NetworkPolicy, test ServiceAccount.
- **Reverted:** Probe image allowlist was reverted to an empty value.

## Raw Data and Reproduction

The cleaned raw data is in `raw/` (`raw/README.md`). Events from other Pods were not included. `values_sha256` in `manifest.json` is the hash of `deploy/gcp/sensors/tetragon-values.yaml` at the time of `implementation_commit`. The deny list values overlaid on run2 were written to `sensor.run2_overlay`.
