# 20261015-task01-admission-delta

| Item | Value |
| --- | --- |
| Task | TASK-01 |
| run_kind | `platform_admission_live` |
| Status | `pass` (21/21) |
| Environment | `agentarium-prod`, GKE `1.36.4-gke.1495002` |
| Execution script | `tests/platform/admission/live_delta_check.py` |

## Why Record Separately

After completing the first run (`20261014-task01-admission`), three policies were added.

- `agent-role-status-metadata`(#11)
- Denial of `pods/resize` in `agent-exec-profile`(#11)
- Limiting target nodes in `node-readiness-scope`(#7)

Until now, these policies were only verified on the cluster without keeping records. The same was true for the VAP type check results. This run re-ran those items and `agent-sensors-contract`, which had 0 cases in the first run, using the execution script to record them.

## Results

| Group | Passed/Total | Details |
| --- | --- | --- |
| VAP type check | 7/7 | All 7 policies have `observedGeneration == generation` and 0 `expressionWarnings` |
| `agent-role-status-metadata` | 3/3 | Modifying labels and adding annotations via `pods/status` on `agent-targets` Pods are denied; modifying only status is allowed |
| `agent-exec-profile` | 2/2 | CPU limit resize of a running probe Pod is denied with `EXEC_RESIZE_FORBIDDEN`. Relabeling via status is also denied (by the earlier-triggered check `EXEC_ROLE_LABEL_INVALID`) |
| `node-readiness-scope` | 4/4 | Adding a startup taint to a system node using the node-readiness KSA is denied, removing the startup taint from an exec node is allowed, and adding other taints or modifying protected labels is denied |
| `agent-sensors-contract` | 5/5 | Running Tetragon DaemonSet is allowed (Ready 5). Images outside the allowlist, hostPath outside the allowlist (`/etc`), hostIPC, and label/SA mismatches are denied |

## Methods and Limitations

- **Change requests:** All were sent with `dryRun=All`. The only resources actually created were one Pod for status testing and one Pod for resize testing, and they were deleted after testing.
- **node-readiness test:** The node-readiness KSA does not yet have RBAC. Therefore, permissions specified by the spec (nodes `get/list/watch/patch`) were temporarily granted only during testing, and the KSA was impersonated using `--as`. They were deleted after the test. The controller itself was not deployed.
- **sensors denial cases:** A dry-run modifying the Tetragon Pod template.
- **Repetitions:** Executed once.
- **Post-test cleanup:** The probe and target image allowlists were reset back to empty values.
