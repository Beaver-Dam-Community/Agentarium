#!/usr/bin/env python3
"""Match a q0-stimulus self-record against Tetragon export events (M0-3 Q0).

  python3 tests/platform/q0/analyze_q0_min.py --stimuli stimuli.jsonl \
      --events tetragon-export.jsonl --pod q0-stimulus [--relevant-out events.relevant.jsonl]

Matching (TASK-09 3.2):
- process: process_exec / process_exit whose process.pod.name is the stimulus Pod.
- tcp_connect: kprobe events of the stimulus Pod whose sock_arg sport is one of
  the stimulus local ports. Each yields the socket cookie, the tuple and the
  destination address as seen at connect time (ClusterIP or backend).
- tcp_set_state: joined to a connect event on the same node with the same
  sock cookie (Tetragon reports the kernel sock pointer, which is reused once a
  socket is freed), the same source address and port, and an event time at or
  after that connect; the latest such connect wins (TASK-09 3.2: sock_ptr,
  tuple and time window). Never by process or Pod fields (softirq context),
  and never by port alone (the cluster-scoped policy sees every netns).
- file opens: security_file_open and __x64_sys_openat events of the Pod, with
  their return values.
--relevant-out writes only the events used above (no other Pods' events).
"""

from __future__ import annotations

import argparse
import collections
import json


def load(path: str) -> list[dict]:
    out = []
    for line in open(path):
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def body(e: dict) -> tuple[str, dict]:
    for t in ("process_exec", "process_exit", "process_kprobe"):
        if t in e:
            return t, e[t]
    return "", {}


def sock(b: dict) -> dict | None:
    return next((a["sock_arg"] for a in b.get("args", []) if "sock_arg" in a), None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stimuli", required=True)
    ap.add_argument("--events", required=True)
    ap.add_argument("--pod", required=True)
    ap.add_argument("--relevant-out")
    a = ap.parse_args()

    stim = load(a.stimuli)
    ev = load(a.events)
    ports = {int(r["local"].rsplit(":", 1)[1]) for r in stim if r["kind"] == "tcp" and r.get("local")}

    relevant: list[dict] = []
    counts: collections.Counter = collections.Counter()
    returns: collections.Counter = collections.Counter()
    connects: list[dict] = []  # one per stimulus connect
    daddr: collections.Counter = collections.Counter()
    for e in ev:
        t, b = body(e)
        pod = ((b.get("process") or {}).get("pod") or {}).get("name")
        if pod != a.pod:
            continue
        fn = b.get("function_name", "")
        counts[f"{t}:{fn}" if fn else t] += 1
        relevant.append(e)
        if fn in ("security_file_open", "__x64_sys_openat", "__x64_sys_openat2"):
            returns[f"{fn}={(b.get('return') or {}).get('int_arg')}"] += 1
        s = sock(b)
        if fn == "tcp_connect" and s and s.get("sport") in ports:
            connects.append({"node": e.get("node_name"), "time": e.get("time", ""), **s})
            daddr[f"{s.get('daddr')}:{s.get('dport')}"] += 1

    est, close = set(), set()
    attribution: collections.Counter = collections.Counter()
    by_port_only = 0
    for e in ev:
        t, b = body(e)
        if b.get("function_name") != "tcp_set_state":
            continue
        s = sock(b)
        if not s:
            continue
        if s.get("sport") in ports:
            by_port_only += 1
        t_ev = e.get("time", "")
        cands = [c for c in connects if c["node"] == e.get("node_name") and c.get("cookie") == s.get("cookie")
                 and c.get("sport") == s.get("sport") and c.get("saddr") == s.get("saddr") and c["time"] <= t_ev]
        if not cands:
            continue
        c = max(cands, key=lambda x: x["time"])
        state = next((x.get("int_arg") for x in b["args"] if "int_arg" in x), None)
        (est if state == 1 else close).add((c["cookie"], c["sport"], c["time"]))
        ns = ((b.get("process") or {}).get("pod") or {}).get("namespace") or "(empty)"
        attribution[ns] += 1
        relevant.append(e)

    result = {
        "stimuli": dict(collections.Counter(r["kind"] for r in stim)),
        "stimuli_ok": dict(collections.Counter(r["kind"] for r in stim if r.get("ok"))),
        "events_for_pod": dict(sorted(counts.items())),
        "open_returns": dict(sorted(returns.items())),
        "tcp": {
            "stimulus_ports": len(ports),
            "connect_matched": len(connects),
            "distinct_cookies": len({c.get("cookie") for c in connects}),
            "connect_daddr": dict(daddr),
            "established_matched": len(est),
            "close_matched": len(close),
            "set_state_events_with_stimulus_sport": by_port_only,
            "set_state_attribution_namespace": dict(attribution),
        },
    }
    print(json.dumps(result, indent=1))
    if a.relevant_out:
        with open(a.relevant_out, "w") as f:
            for e in relevant:
                f.write(json.dumps(e) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
