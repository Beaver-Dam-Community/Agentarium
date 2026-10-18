# Test result records

This collects the results of tests run in the actual environment. The record format follows the [COMMON result recording contract](../../docs/tech-specs/COMMON.md#result-recording-contract-ref).

- **Location:** Create one `runs/<run_id>/` per run.
- **run_id:** The format is `<UTC date>-<task>-<topic>` (e.g. `20261014-task01-admission`).
- **Files:** Each run contains `manifest.json` (environment and inputs), `expected.json`, `observed.jsonl`, `summary.json`, and `report.md`.
- **What is kept in Git:** Only sanitized results, digests, and safe references. Secrets, tokens, and cluster access addresses are not kept.
- **Status values:** The `status` in `summary.json` uses the COMMON report status enum. Values that were not measured are set to `null`, not 0.

## Results by Task

| Task | run_id | Scope | Status | Passed/total | Run date |
| --- | --- | --- | --- | --- | --- |
| TASK-01 | [20261014-task01-admission](runs/20261014-task01-admission/report.md) | Chapter 7 placement bypass, exec profile separation, quota separation (partial) | `pass` | 34/34 | 2026-10-14 |
| TASK-01 | [20261015-task01-admission-delta](runs/20261015-task01-admission-delta/report.md) | Policies added after the first run (limited to status, resize, and node-readiness targets), VAP type checking, sensors policy | `pass` | 21/21 | 2026-10-15 |
| TASK-01 | [20261014-task01-q0-min](runs/20261014-task01-q0-min/report.md) | M0-3 Q0 minimum items: three kinds of kernel behavior, network policy log node file format | `incomplete` | 5 supported, 2 partially supported, 1 unsupported by default configuration, 5 not run | 2026-10-14 |
| TASK-01 | [20261015-task01-q0-min-2](runs/20261015-task01-q0-min-2/report.md) | M0-3 follow-up: deny list with only `health_check`, `returnArg` type comparison | `incomplete` | 4 supported, 1 cause unconfirmed | 2026-10-15 |

Even if one run is `pass`, it does not mean that the Task is finished. Whether a Task is complete is judged by the `implementation_status` and `functional_verification` in each Task document.
