"""Check workload RBAC report semantics; fixture decisions are not live evidence."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("workload_check", Path(__file__).with_name("check_workload_rbac.py"))
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def status(command, allowed, **extra):
    return subprocess.CompletedProcess(command, 0, json.dumps({"status": dict(allowed=allowed, **extra)}), "")


class WorkloadReportTest(unittest.TestCase):
    def run_report(self, effect):
        out = io.StringIO()
        with patch.object(check.subprocess, "run", side_effect=effect) as run, contextlib.redirect_stdout(out):
            code = check.main(["--kubeconfig", "/test/config", "--context", "fixture"])
        return code, json.loads(out.getvalue()), run

    def replay(self, override=None):
        decisions = iter(check.cases())
        def execute(command, **kwargs):
            case = next(decisions)
            subject_ns, ksa, namespace, verb, resource, name, want = case
            self.assertEqual(command[command.index("--as") + 1], f"system:serviceaccount:{subject_ns}:{ksa}")
            self.assertEqual([command[i + 1] for i, a in enumerate(command) if a == "--as-group"],
                             ["system:authenticated", "system:serviceaccounts", f"system:serviceaccounts:{subject_ns}"])
            attrs = json.loads(kwargs["input"])["spec"]["resourceAttributes"]
            self.assertEqual((attrs["namespace"], attrs["verb"], attrs.get("name", "")), (namespace, verb, name))
            return status(command, want if override is None or case != override else not want)
        return execute

    def test_expected_decisions_pass(self):
        code, report, run = self.run_report(self.replay())
        self.assertEqual(code, 0)
        self.assertTrue(report["complete"])
        self.assertEqual(report["passed"], report["expected_checks"])
        self.assertEqual(run.call_count, report["expected_checks"])

    def test_cases_are_consistent(self):
        rows = list(check.cases())
        self.assertEqual(len(rows), len(set(rows)))
        keys = [r[:6] for r in rows]
        self.assertEqual(len(keys), len(set(keys)), "a case cannot expect both allow and deny")
        for subject in check.ALLOWED:
            self.assertTrue(any(r[:2] == subject and r[6] for r in rows))
            self.assertTrue(any(r[:2] == subject and not r[6] for r in rows))

    def test_missing_grant_and_extra_grant_fail(self):
        rows = list(check.cases())
        for target in (next(r for r in rows if r[6]), next(r for r in rows if not r[6])):
            with self.subTest(target=target):
                code, report, _ = self.run_report(self.replay(target))
                self.assertEqual(code, 1)
                self.assertTrue(report["complete"])
                self.assertEqual(report["passed"], report["expected_checks"] - 1)

    def test_resource_names_and_subresources(self):
        attrs = check.review("agent-exec", "patch", check.TRACING_NS, check.TCP_CONNECT)["spec"]["resourceAttributes"]
        self.assertEqual(attrs, {"namespace": "agent-exec", "verb": "patch", "group": "cilium.io",
                                 "resource": "tracingpoliciesnamespaced", "name": check.TCP_CONNECT})
        attrs = check.review("", "patch", "nodes/status", "")["spec"]["resourceAttributes"]
        self.assertEqual(attrs, {"namespace": "", "verb": "patch", "group": "", "resource": "nodes",
                                 "subresource": "status"})

    def test_errors_are_not_results(self):
        for response in (lambda c, **k: status(c, False, evaluationError="webhook"),
                         lambda c, **k: subprocess.CompletedProcess(c, 1, "", "forbidden"),
                         lambda c, **k: subprocess.CompletedProcess(c, 0, "not json", ""),
                         lambda c, **k: subprocess.CompletedProcess(c, 0, '{"status": {"allowed": "yes"}}', "")):
            with self.subTest(response=response):
                code, report, run = self.run_report(response)
                self.assertEqual(code, 1)
                self.assertFalse(report["complete"])
                self.assertIsNone(report["results"][0]["observed"])
                self.assertEqual(run.call_count, 1)

    def test_live_arguments_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            check.main([])


if __name__ == "__main__":
    unittest.main()
