"""Check report semantics; fixture decisions are not live RBAC evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("reader_check", Path(__file__).with_name("check_reader_rbac.py"))
reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reader)


class ReaderReportTest(unittest.TestCase):
    def run_report(self, effect):
        out = io.StringIO()
        with patch.object(reader.subprocess, "run", side_effect=effect) as run, contextlib.redirect_stdout(out):
            code = reader.main(["--kubeconfig", "/test/config", "--context", "fixture"])
        return code, json.loads(out.getvalue()), run

    def test_mixed_permissions_are_complete_and_include_sa_groups(self):
        decisions = iter(reader.cases())
        def execute(command, **kwargs):
            namespace, verb, resource, expected = next(decisions)
            self.assertEqual(command[:5], ["kubectl", "--kubeconfig", "/test/config", "--context", "fixture"])
            for group in reader.GROUPS:
                self.assertIn(group, command)
                self.assertEqual(command[command.index(group) - 1], "--as-group")
            self.assertEqual(kwargs["timeout"], 20)
            if namespace:
                self.assertEqual(command[command.index("--namespace") + 1], namespace)
                self.assertNotIn("--all-namespaces", command)
            else:
                self.assertIn("--all-namespaces", command)
                self.assertNotIn("--namespace", command)
            if "/" in resource:
                self.assertEqual(command[command.index("--subresource") + 1], resource.split("/")[1])
            return subprocess.CompletedProcess(command, 0 if expected else 1, "yes\n" if expected else "no\n", "")
        code, report, _ = self.run_report(execute)
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        self.assertEqual(report["passed"], report["expected_checks"])

    def test_denial_detail_is_retained_and_check_continues(self):
        decisions = iter(reader.cases())
        detail = "denied by policy - additional evaluation detail"
        def execute(command, **kwargs):
            expected = next(decisions)[3]
            return subprocess.CompletedProcess(command, 0 if expected else 1,
                                               "yes\n" if expected else f"no - {detail}\n", "")
        code, report, _ = self.run_report(execute)
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        for row in report["results"]:
            self.assertEqual(row["detail"], None if row["expected"] else detail)

    def test_no_prefix_and_wrong_exit_codes_are_not_denials(self):
        for output, returncode in (("not found", 1), ("no permission", 1),
                                   ("no - denied", 0), ("no - denied", 2)):
            with self.subTest(output=output, returncode=returncode):
                code, report, run = self.run_report(
                    lambda *a, **k: subprocess.CompletedProcess(a, returncode, output, ""))
                self.assertEqual(code, 1)
                self.assertIsNone(report["results"][0]["observed"])
                self.assertEqual(run.call_count, 1)

    def test_cross_namespace_cluster_and_event_write_grants_fail(self):
        matrix = set(reader.cases())
        forbidden = [("agent-targets", verb, "events", False)
                     for verb in ("create", "update", "patch", "delete", "deletecollection")]
        for namespace in ("agent-exec", "agent-adapters", "agent-control", "agent-observe",
                          "agent-release", "agent-sensors", "kube-system", "default", ""):
            for resource in ("pods", "events"):
                for verb in ("list", "watch"):
                    forbidden.append((namespace, verb, resource, False))
        for case in forbidden:
            with self.subTest(case=case):
                self.assertIn(case, matrix)
                decisions = iter(reader.cases())
                def execute(command, **kwargs):
                    current = next(decisions)
                    allowed = current[3] or current == case
                    return subprocess.CompletedProcess(command, 0 if allowed else 1,
                                                       "yes\n" if allowed else "no\n", "")
                code, report, _ = self.run_report(execute)
                self.assertEqual(code, 1)
                self.assertTrue(report["complete"])
                self.assertEqual(report["passed"], report["expected_checks"] - 1)

    def test_transport_error_never_counts_as_denial(self):
        code, report, run = self.run_report(lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "credential error"))
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

    def test_excess_permission_fails(self):
        code, report, _ = self.run_report(lambda *a, **k: subprocess.CompletedProcess(a, 0, "yes\n", ""))
        self.assertEqual(code, 1)
        self.assertTrue(report["complete"])
        self.assertEqual(report["passed"], 5)


if __name__ == "__main__":
    unittest.main()
