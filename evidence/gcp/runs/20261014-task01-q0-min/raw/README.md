# raw

This is the refined raw data. Events from other Pods were not included.

| File | Content |
| --- | --- |
| `run1-stimuli.jsonl`, `run2-stimuli.jsonl` | Stimulus records of q0-stimulus (ground truth records) |
| `run1-events.relevant.jsonl`, `run2-events.relevant.jsonl` | Events used for comparison from the Tetragon export (events from the stimulus Pod and `tcp_set_state` associated with the stimulus socket) |
| `analysis.json` | Output of `tests/platform/q0/analyze_q0_min.py` |
| `netpol-policy_action.log` | Corresponding records from the node file `/var/log/network/policy_action.log` |
| `netpol-a-stimuli.jsonl`, `netpol-b-stimuli.jsonl` | Stimulus records of the network policy log test |
| `netpol-test-manifests.yaml`, `stimulus-pod.yaml` | NetworkPolicy and Pod definitions for testing (`stimulus-pod.yaml` is in run3 format, and run1 and 2 share only the name and node) |

Reproduction: `python3 tests/platform/q0/analyze_q0_min.py --stimuli raw/run2-stimuli.jsonl --events raw/run2-events.relevant.jsonl --pod q0-stimulus-2`
