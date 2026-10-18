#!/usr/bin/env python3
"""Read-only live permission checks after TASK-06 reader RBAC installation.

Runs SelfSubjectAccessReview through kubectl impersonation. The invoking
operator needs impersonation permission. The JSON report contains no tokens.
This does not exercise the adapter's namespace/Pod UID authorization checks.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

SUBJECT = "system:serviceaccount:agent-adapters:kubernetes-reader"
GROUPS = ("system:authenticated", "system:serviceaccounts",
          "system:serviceaccounts:agent-adapters")


def cases():
    for resource, verbs in (("pods", ("get", "list")),
                            ("events", ("get", "list")),
                            ("pods/log", ("get",))):
        for verb in verbs:
            yield "agent-targets", verb, resource, True
    for namespace in ("agent-targets", "agent-exec", "agent-adapters", "agent-control",
                      "agent-observe", "agent-release", "agent-sensors", "kube-system", "default"):
        for resource in ("secrets", "serviceaccounts/token"):
            for verb in ("get", "list", "create"):
                yield namespace, verb, resource, False
        for resource in ("pods/exec", "pods/attach", "pods/portforward", "pods/proxy"):
            for verb in ("get", "create"):
                yield namespace, verb, resource, False
        for resource in ("pods", "events"):
            for verb in ("create", "update", "patch", "delete", "deletecollection", "watch"):
                yield namespace, verb, resource, False
        yield namespace, "impersonate", "serviceaccounts", False
        if namespace != "agent-targets":
            for resource in ("pods", "events", "pods/log"):
                yield namespace, "get", resource, False
            for resource in ("pods", "events"):
                yield namespace, "list", resource, False
    for resource in ("pods", "events"):
        for verb in ("list", "watch"):
            yield "", verb, resource, False
    for resource in ("roles.rbac.authorization.k8s.io", "rolebindings.rbac.authorization.k8s.io"):
        for verb in ("create", "update", "patch", "bind", "escalate"):
            yield "agent-targets", verb, resource, False
    for resource in ("nodes", "networkloggings.networking.gke.io"):
        for verb in ("get", "list", "watch", "patch", "update", "delete"):
            yield "", verb, resource, False
    for resource in ("clusterroles.rbac.authorization.k8s.io",
                     "clusterrolebindings.rbac.authorization.k8s.io"):
        for verb in ("create", "update", "patch", "bind", "escalate"):
            yield "", verb, resource, False
    for resource in ("users", "groups"):
        yield "", "impersonate", resource, False


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--context", required=True,
                        help="Exact installed cluster context, never an implicit default")
    args = parser.parse_args(argv)
    results = []
    for namespace, verb, resource, expected in cases():
        name, _, subresource = resource.partition("/")
        command = ["kubectl", "--kubeconfig", args.kubeconfig, "--context", args.context,
                   "--request-timeout=10s", "auth", "can-i", verb, name,
                   "--as", SUBJECT]
        for group in GROUPS:
            command += ["--as-group", group]
        if subresource:
            command += ["--subresource", subresource]
        if namespace:
            command += ["--namespace", namespace]
        else:
            # Empty scope must not inherit the kubeconfig's default namespace.
            command += ["--all-namespaces"]
        detail = None
        try:
            response = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
            output = response.stdout.strip()
            observed = {("yes", 0): True, ("no", 1): False}.get(
                (output, response.returncode))
            # kubectl adds the authorization reason/evaluation detail after
            # this delimiter. Do not treat arbitrary "no..." errors as denial.
            if response.returncode == 1 and output.startswith("no - "):
                observed = False
                detail = output[len("no - "):]
        except (OSError, subprocess.TimeoutExpired):
            observed = None
        results.append(dict(namespace=namespace or None, verb=verb, resource=resource,
                            expected=expected, observed=observed, detail=detail,
                            passed=observed is not None and observed == expected))
        # Avoid repeating an unavailable API/credential/impersonation failure.
        if observed is None:
            break
    total = len(list(cases()))
    passed = sum(row["passed"] for row in results)
    json.dump(dict(subject=SUBJECT, expected_checks=total, executed=len(results),
                   passed=passed, complete=len(results) == total,
                   results=results), sys.stdout, indent=2)
    print()
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
