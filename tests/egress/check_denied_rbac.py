#!/usr/bin/env python3
"""Read-only live RBAC denial checks for execution and release KSAs (TASK-06).

TASK-06 section 7 requires that execution ServiceAccounts cannot read Secrets,
exec into Pods or change NetworkPolicy. TASK-01 also forbids them Pod,
Deployment, Namespace, admission policy, binding and node changes. Section 3.4
of TASK-06 requires that neither
execution nor release ServiceAccounts hold any verb on NetworkLogging. Every
case here expects denial. Creates SelfSubjectAccessReview objects through
kubectl impersonation including the ServiceAccount groups; an empty namespace
means all namespaces. The JSON report contains no tokens. API, credential or
impersonation errors and authorizer evaluation errors are `observed: null` and
stop the run; they never count as a denial.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys

EXEC_KSAS = ("agent-runtime", "probe-runner", "start-fixture")
NAMESPACES = ("agent-exec", "agent-control", "agent-adapters", "agent-observe",
              "agent-release", "agent-targets", "agent-sensors", "kube-system", "default")
NETWORK_LOGGING = "networkloggings.networking.gke.io"
ALL_VERBS = ("get", "list", "watch", "create", "update", "patch", "delete", "deletecollection")


def subjects():
    for ksa in EXEC_KSAS:
        yield "agent-exec", ksa
    yield "agent-release", "releaser"
    yield "agent-release", "regression-dispatcher"


def groups(namespace):
    return ("system:authenticated", "system:serviceaccounts",
            f"system:serviceaccounts:{namespace}")


def exec_cases():
    for namespace in NAMESPACES:
        for verb in ("get", "list", "watch", "create"):
            yield namespace, verb, "secrets"
        yield namespace, "create", "serviceaccounts/token"
        for resource in ("pods/exec", "pods/attach", "pods/portforward"):
            for verb in ("get", "create"):
                yield namespace, verb, resource
        for verb in ("create", "update", "patch", "delete", "deletecollection"):
            yield namespace, verb, "networkpolicies.networking.k8s.io"
            yield namespace, verb, "pods"
            yield namespace, verb, "deployments.apps"
        for verb in ("create", "update", "patch", "bind", "escalate"):
            yield namespace, verb, "roles.rbac.authorization.k8s.io"
            yield namespace, verb, "rolebindings.rbac.authorization.k8s.io"
        yield namespace, "impersonate", "serviceaccounts"
    for verb in ("create", "update", "patch", "bind", "escalate"):
        yield "", verb, "clusterroles.rbac.authorization.k8s.io"
        yield "", verb, "clusterrolebindings.rbac.authorization.k8s.io"
    for verb in ("create", "update", "patch", "delete"):
        yield "", verb, "namespaces"
        yield "", verb, "validatingadmissionpolicies.admissionregistration.k8s.io"
        yield "", verb, "validatingadmissionpolicybindings.admissionregistration.k8s.io"
    for verb in ("update", "patch"):
        yield "", verb, "nodes"
    for resource in ("users", "groups"):
        yield "", "impersonate", resource


def cases():
    """Yield (subject namespace, KSA, namespace, verb, resource); all expect denial."""
    for subject_ns, ksa in subjects():
        if subject_ns == "agent-exec":
            for case in exec_cases():
                yield (subject_ns, ksa) + case
        for verb in ALL_VERBS:
            yield subject_ns, ksa, "", verb, NETWORK_LOGGING


def review(namespace, verb, resource):
    """SelfSubjectAccessReview body; impersonation makes it the subject's review."""
    name, _, subresource = resource.partition("/")
    plural, _, group = name.partition(".")
    attributes = {"namespace": namespace, "verb": verb, "group": group, "resource": plural}
    if subresource:
        attributes["subresource"] = subresource
    return {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectAccessReview",
            "spec": {"resourceAttributes": attributes}}


def command(kubeconfig, context, subject_ns, ksa):
    cmd = ["kubectl", "--kubeconfig", kubeconfig, "--context", context,
           "--request-timeout=10s", "create", "-f", "-", "-o", "json",
           "--as", f"system:serviceaccount:{subject_ns}:{ksa}"]
    for group in groups(subject_ns):
        cmd += ["--as-group", group]
    return cmd


def decide(response):
    """Return (observed, detail). Only a clean allowed=false is a denial."""
    if response.returncode != 0:
        return None, None
    try:
        status = json.loads(response.stdout)["status"]
    except (ValueError, KeyError, TypeError):
        return None, None
    if not isinstance(status, dict) or not isinstance(status.get("allowed"), bool):
        return None, None
    # An authorizer evaluation error also yields allowed=false; it is not a denial.
    if status.get("evaluationError"):
        return None, status["evaluationError"]
    return status["allowed"], status.get("reason") or None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", required=True)
    parser.add_argument("--context", required=True,
                        help="Exact installed cluster context, never an implicit default")
    args = parser.parse_args(argv)
    results = []
    for subject_ns, ksa, namespace, verb, resource in cases():
        try:
            response = subprocess.run(
                command(args.kubeconfig, args.context, subject_ns, ksa),
                input=json.dumps(review(namespace, verb, resource)),
                capture_output=True, text=True, timeout=20, check=False)
            observed, detail = decide(response)
        except (OSError, subprocess.TimeoutExpired):
            observed, detail = None, None
        results.append(dict(subject=f"{subject_ns}/{ksa}", namespace=namespace or None, verb=verb,
                            resource=resource, expected=False, observed=observed, detail=detail,
                            passed=observed is False))
        if observed is None:
            break
    total = len(list(cases()))
    passed = sum(row["passed"] for row in results)
    json.dump(dict(subjects=[f"{n}/{k}" for n, k in subjects()], expected_checks=total,
                   executed=len(results), passed=passed, complete=len(results) == total,
                   results=results), sys.stdout, indent=2)
    print()
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
