# 20261015-task01-q0-min-2

| Item | Value |
| --- | --- |
| Task | TASK-01 (M0-3 Q0 minimum items, follow-up) |
| run_kind | `q0_min_observation` |
| Status | `incomplete` (4 rows supported, 1 row cause unverified) |
| Environment | `agentarium-prod`, exec node `gke-agentarium-prod-exec-pool-eaf0304a-x10z` |
| Sensor | Tetragon 1.7.1, export deny list using only `{"health_check":true}` |

## Why It Was Rerun

This is what 3iuy-prog pointed out in the #17 review. In run2 of the first run, 5 CLOSE events were missing, and the suggestion was that the cause might be the kube-system rule in the deny list rather than TIME_WAIT. This run verifies that hypothesis. In the same run, we also tried changing the `returnArg` type of TracingPolicy.

## Results

| Row | Result | Verdict |
| --- | --- | --- |
| `tcp_set_state` | ESTABLISHED 30/30, CLOSE 30/30. Attribution: 39 cases without Pod, 12 cases to agent-sensors, 8 cases to kube-system, 1 case to agent-exec | Supported |
| `tcp_connect` | 30/30. Destination is ClusterIP `10.30.0.10:53` | Supported |
| process exec/exit | 31/31 | Supported |
| Protected file open | 31 cases of `security_file_open` return 0, 31 cases of `sys_openat` fd and 30 cases of `-13` | Supported |
| `returnArg` type | "syscall return type is not long int" warning for all of `int`, `long`, `int64`. Loading and return values are normal | Cause unverified |

## Conclusion

- **deny list:** The hypothesis was correct. Because state transition events are also attributed to kube-system Pods, any namespace rule drops some events. Changed the fixed value to just `{"health_check":true}` (`deploy/gcp/sensors/tetragon-values.yaml`). Events that are not observation targets are filtered by the exporter using lifecycle records and tuples (TASK-09 3.2). The export volume increases accordingly, and that volume was not measured.
- **`returnArg`:** The suggestion to change the return type to `long` did not eliminate the warning. Kept the specification value `int`, and reverted the policy back to the original specification.

## Raw Data

The cleaned raw data is in `raw/`. It contains stimulus records, events used for comparison, analysis output, Pod definitions, and logs by `returnArg` variant.

Reproduction: `python3 tests/platform/q0/analyze_q0_min.py --stimuli raw/run3-stimuli.jsonl --events raw/run3-events.relevant.jsonl --pod q0-stimulus-3`
