"""Check denial report semantics; fixture decisions are not live RBAC evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("denied_check", Path(__file__).with_name("check_denied_rbac.py"))
denied = importlib.util.module_from_spec(spec)
spec.loader.exec_module(denied)


def status(command, allowed, **extra):
    body = {"kind": "SelfSubjectAccessReview", "status": dict(allowed=allowed, **extra)}
    return subprocess.CompletedProcess(command, 0, json.dumps(body), "")


def deny(command, **kwargs):
    return status(command, False)


class DeniedReportTest(unittest.TestCase):
    def run_report(self, effect):
        out = io.StringIO()
        with patch.object(denied.subprocess, "run", side_effect=effect) as run, contextlib.redirect_stdout(out):
            code = denied.main(["--kubeconfig", "/test/config", "--context", "fixture"])
        return code, json.loads(out.getvalue()), run

    def test_all_denied_is_complete_and_impersonates_each_subject(self):
        decisions = iter(denied.cases())
        def execute(command, **kwargs):
            subject_ns, ksa, namespace, verb, resource = next(decisions)
            self.assertEqual(command[:11], ["kubectl", "--kubeconfig", "/test/config", "--context", "fixture",
                                            "--request-timeout=10s", "create", "-f", "-", "-o", "json"])
            self.assertEqual(command[command.index("--as") + 1], f"system:serviceaccount:{subject_ns}:{ksa}")
            as_groups = [command[i + 1] for i, arg in enumerate(command) if arg == "--as-group"]
            self.assertEqual(as_groups, ["system:authenticated", "system:serviceaccounts",
                                         f"system:serviceaccounts:{subject_ns}"])
            self.assertNotIn("--namespace", command)
            body = json.loads(kwargs["input"])
            self.assertEqual(body["kind"], "SelfSubjectAccessReview")
            attrs = body["spec"]["resourceAttributes"]
            self.assertEqual((attrs["namespace"], attrs["verb"]), (namespace, verb))
            name, _, sub = resource.partition("/")
            plural, _, group = name.partition(".")
            self.assertEqual((attrs["resource"], attrs["group"], attrs.get("subresource", "")), (plural, group, sub))
            self.assertEqual(kwargs["timeout"], 20)
            return deny(command)
        code, report, run = self.run_report(execute)
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        self.assertEqual(report["passed"], report["expected_checks"])
        self.assertEqual(run.call_count, report["expected_checks"])

    def test_resource_attributes(self):
        self.assertEqual(denied.review("agent-exec", "create", "pods/exec")["spec"]["resourceAttributes"],
                         {"namespace": "agent-exec", "verb": "create", "group": "", "resource": "pods",
                          "subresource": "exec"})
        self.assertEqual(denied.review("", "patch", denied.NETWORK_LOGGING)["spec"]["resourceAttributes"],
                         {"namespace": "", "verb": "patch", "group": "networking.gke.io",
                          "resource": "networkloggings"})

    def test_required_cases_are_present(self):
        matrix = set(denied.cases())
        for ksa in ("agent-runtime", "probe-runner", "start-fixture"):
            for namespace in denied.NAMESPACES:
                for case in ((namespace, "get", "secrets"), (namespace, "create", "pods/exec"),
                             (namespace, "patch", "networkpolicies.networking.k8s.io"),
                             (namespace, "delete", "networkpolicies.networking.k8s.io"),
                             (namespace, "patch", "deployments.apps"),
                             (namespace, "create", "rolebindings.rbac.authorization.k8s.io"),
                             (namespace, "escalate", "roles.rbac.authorization.k8s.io")):
                    self.assertIn(("agent-exec", ksa) + case, matrix)
            for case in (("", "create", "namespaces"), ("", "patch", "nodes"),
                         ("", "delete", "validatingadmissionpolicybindings.admissionregistration.k8s.io")):
                self.assertIn(("agent-exec", ksa) + case, matrix)
        for subject in (("agent-exec", "agent-runtime"), ("agent-exec", "probe-runner"),
                        ("agent-exec", "start-fixture"), ("agent-release", "releaser"),
                        ("agent-release", "regression-dispatcher")):
            for verb in denied.ALL_VERBS:
                self.assertIn(subject + ("", verb, denied.NETWORK_LOGGING), matrix)
        # The releaser's TASK-14 TracingPolicy grants are out of this check's scope.
        self.assertFalse(any(c[0] == "agent-release" and c[4] != denied.NETWORK_LOGGING for c in matrix))

    def test_any_single_grant_fails(self):
        for target in (("agent-exec", "agent-runtime", "agent-exec", "get", "secrets"),
                       ("agent-release", "releaser", "", "patch", denied.NETWORK_LOGGING)):
            with self.subTest(target=target):
                decisions = iter(denied.cases())
                def execute(command, **kwargs):
                    return status(command, next(decisions) == target)
                code, report, _ = self.run_report(execute)
                self.assertEqual(code, 1)
                self.assertTrue(report["complete"])
                self.assertEqual(report["passed"], report["expected_checks"] - 1)

    def test_denial_reason_is_retained(self):
        code, report, _ = self.run_report(lambda c, **k: status(c, False, reason="no RBAC rule"))
        self.assertEqual(code, 0)
        self.assertEqual({row["detail"] for row in report["results"]}, {"no RBAC rule"})

    def test_evaluation_error_is_not_a_denial(self):
        code, report, run = self.run_report(
            lambda c, **k: status(c, False, evaluationError="webhook unavailable"))
        self.assertEqual(code, 1)
        self.assertFalse(report["complete"])
        self.assertIsNone(report["results"][0]["observed"])
        self.assertEqual(report["results"][0]["detail"], "webhook unavailable")
        self.assertEqual(run.call_count, 1)

    def test_errors_never_count_as_denial(self):
        for stdout, returncode in (("", 1), ("not json", 0), ('{"status": {}}', 0),
                                   ('{"status": {"allowed": "false"}}', 0), ('{"kind": "x"}', 0),
                                   (json.dumps({"status": {"allowed": False}}), 1)):
            with self.subTest(stdout=stdout, returncode=returncode):
                code, report, run = self.run_report(
                    lambda c, **k: subprocess.CompletedProcess(c, returncode, stdout, ""))
                self.assertEqual(code, 1)
                self.assertFalse(report["complete"])
                self.assertIsNone(report["results"][0]["observed"])
                self.assertEqual(run.call_count, 1)

    def test_timeout_stops_without_claiming_denial(self):
        def timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], 20)
        code, report, run = self.run_report(timeout)
        self.assertEqual(code, 1)
        self.assertIsNone(report["results"][0]["observed"])
        self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
