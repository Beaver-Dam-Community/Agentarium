#!/usr/bin/env python3
"""Read-only live RBAC checks for TASK-06 workload Roles (deploy/gcp/base/rbac).

For node-readiness, correlation, control-health, pod-watcher, discovery and
releaser, every granted permission must be allowed and the listed neighbouring
permissions must be denied. Each case creates a SelfSubjectAccessReview under
kubectl impersonation of the ServiceAccount and its groups; an empty namespace
means all namespaces. Only `allowed` without an `evaluationError` is a result.
API, credential, impersonation and authorizer evaluation errors are
`observed: null` and stop the run. The JSON report contains no tokens.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

ROLE_NAMESPACES = ("agent-exec", "agent-control", "agent-adapters", "agent-observe",
                   "agent-release", "agent-targets", "agent-sensors")
TCP_CONNECT, PROTECTED_FILE = "agentarium-tcp-connect", "agentarium-protected-file"
TRACING_NS = "tracingpoliciesnamespaced.cilium.io"

# (namespace, verb, resource, name) granted by the manifests; "" namespace is
# cluster scope and "" name is any object.
ALLOWED = {
    ("agent-control", "node-readiness"): [("", v, "nodes", "") for v in ("get", "list", "watch", "patch")],
    ("agent-observe", "correlation"): [("", v, "nodes", "") for v in ("get", "list", "watch")],
    ("agent-observe", "control-health"): [(ns, v, "deployments.apps", "")
                                          for ns in ("agent-control", "agent-adapters")
                                          for v in ("get", "list", "watch")],
    ("agent-observe", "pod-watcher"): [("agent-exec", v, "pods", "") for v in ("list", "watch")],
    ("agent-observe", "discovery"): [("agent-observe", "create", "jobs.batch", ""),
                                     ("agent-observe", "get", "jobs.batch", ""),
                                     ("agent-observe", "list", "pods", "")],
    ("agent-release", "releaser"): [("agent-exec", v, TRACING_NS, n)
                                    for n in (TCP_CONNECT, PROTECTED_FILE)
                                    for v in ("get", "update", "patch")],
}

DENIED = {
    ("agent-control", "node-readiness"): [("", "update", "nodes", ""), ("", "patch", "nodes/status", ""),
                                          ("", "update", "nodes/status", ""), ("", "delete", "nodes", ""),
                                          ("", "create", "nodes", ""), ("", "patch", "namespaces", "")],
    ("agent-observe", "correlation"): [("", v, "nodes", "") for v in ("patch", "update", "delete", "create")]
                                      + [("", "list", "pods", "")],
    ("agent-observe", "control-health"): [(ns, v, "deployments.apps", "")
                                          for ns in ("agent-control", "agent-adapters")
                                          for v in ("create", "update", "patch", "delete")]
                                         + [(ns, "update", "deployments.apps/scale", "")
                                            for ns in ("agent-control", "agent-adapters")]
                                         + [(ns, "list", "deployments.apps", "")
                                            for ns in ("agent-exec", "agent-observe", "agent-release", "")]
                                         + [("agent-control", "list", "pods", "")],
    ("agent-observe", "pod-watcher"): [("agent-exec", v, "pods", "") for v in ("get", "create", "update", "patch", "delete")]
                                      + [("agent-exec", "get", "pods/log", "")]
                                      + [(ns, "list", "pods", "") for ns in
                                         ("agent-control", "agent-adapters", "agent-observe", "agent-targets", "")],
    ("agent-observe", "discovery"): [("agent-observe", v, "jobs.batch", "") for v in ("list", "watch", "update", "patch", "delete")]
                                    + [(ns, "create", "jobs.batch", "") for ns in ("agent-exec", "agent-control", "agent-adapters")]
                                    + [("agent-observe", v, "pods", "") for v in ("get", "create", "delete")]
                                    + [("agent-observe", "get", "pods/log", ""), ("agent-exec", "list", "pods", ""),
                                       ("agent-observe", "create", "cronjobs.batch", "")],
    ("agent-release", "releaser"): [("agent-exec", v, TRACING_NS, "") for v in ("create", "delete", "list")]
                                   + [("agent-exec", "update", TRACING_NS, "other-policy"),
                                      ("agent-adapters", "update", TRACING_NS, TCP_CONNECT),
                                      ("", "update", "tracingpolicies.cilium.io", "agentarium-tcp-state"),
                                      ("", "patch", "networkloggings.networking.gke.io", "default"),
                                      ("agent-exec", "patch", "networkpolicies.networking.k8s.io", "")],
}


def common_denials():
    for namespace in ROLE_NAMESPACES:
        yield namespace, "get", "secrets", ""
        yield namespace, "list", "secrets", ""
        yield namespace, "create", "pods/exec", ""
        yield namespace, "create", "serviceaccounts/token", ""
        yield namespace, "create", "rolebindings.rbac.authorization.k8s.io", ""
        yield namespace, "impersonate", "serviceaccounts", ""
    yield "", "create", "clusterrolebindings.rbac.authorization.k8s.io", ""
    yield "", "escalate", "clusterroles.rbac.authorization.k8s.io", ""


def cases():
    """Yield (subject namespace, KSA, namespace, verb, resource, name, expected)."""
    for subject, allowed in ALLOWED.items():
        for case in allowed:
            yield subject + case + (True,)
        for case in DENIED[subject]:
            yield subject + case + (False,)
        for case in common_denials():
            yield subject + case + (False,)


def review(namespace, verb, resource, name):
    kind, _, subresource = resource.partition("/")
    plural, _, group = kind.partition(".")
    attributes = {"namespace": namespace, "verb": verb, "group": group, "resource": plural}
    if subresource:
        attributes["subresource"] = subresource
    if name:
        attributes["name"] = name
    return {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": attributes}}


def command(kubeconfig, context, subject_ns, ksa):
    cmd = ["kubectl", "--kubeconfig", kubeconfig, "--context", context,
           "--request-timeout=10s", "create", "-f", "-", "-o", "json",
           "--as", f"system:serviceaccount:{subject_ns}:{ksa}"]
    for group in ("system:authenticated", "system:serviceaccounts", f"system:serviceaccounts:{subject_ns}"):
        cmd += ["--as-group", group]
    return cmd


def decide(response):
    """Return (observed, detail); errors are (None, detail)."""
    if response.returncode != 0:
        return None, None
    try:
        status = json.loads(response.stdout)["status"]
    except (ValueError, KeyError, TypeError):
        return None, None
    if not isinstance(status, dict) or not isinstance(status.get("allowed"), bool):
        return None, None
    if status.get("evaluationError"):
        return None, status["evaluationError"]
    return status["allowed"], status.get("reason") or None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-allowed", action="store_true",
                        help="Print the expected allowed cases offline and exit")
    parser.add_argument("--kubeconfig")
    parser.add_argument("--context", help="Exact installed cluster context, never an implicit default")
    args = parser.parse_args(argv)
    if args.print_allowed:
        json.dump({f"{n}/{k}": [list(c) for c in v] for (n, k), v in ALLOWED.items()}, sys.stdout)
        print()
        return 0
    if not args.kubeconfig or not args.context:
        parser.error("--kubeconfig and --context are required")
    results = []
    for subject_ns, ksa, namespace, verb, resource, name, expected in cases():
        try:
            response = subprocess.run(
                command(args.kubeconfig, args.context, subject_ns, ksa),
                input=json.dumps(review(namespace, verb, resource, name)),
                capture_output=True, text=True, timeout=20, check=False)
            observed, detail = decide(response)
        except (OSError, subprocess.TimeoutExpired):
            observed, detail = None, None
        results.append(dict(subject=f"{subject_ns}/{ksa}", namespace=namespace or None, verb=verb,
                            resource=resource, name=name or None, expected=expected,
                            observed=observed, detail=detail,
                            passed=observed is not None and observed == expected))
        if observed is None:
            break
    total = len(list(cases()))
    passed = sum(row["passed"] for row in results)
    json.dump(dict(subjects=[f"{n}/{k}" for n, k in ALLOWED], expected_checks=total,
                   executed=len(results), passed=passed, complete=len(results) == total,
                   results=results), sys.stdout, indent=2)
    print()
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
