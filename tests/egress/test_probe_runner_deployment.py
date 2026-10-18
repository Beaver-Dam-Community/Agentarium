"""Offline TASK-10 3.2 answer probe runner and probe sink manifest checks; not GKE runtime evidence."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
DIR = ROOT / "deploy/gcp/base/probe-runner"
sibling = importlib.util.spec_from_file_location("base_render_test", Path(__file__).with_name("test_base_render.py"))
base_render_test = importlib.util.module_from_spec(sibling)
sibling.loader.exec_module(base_render_test)
renderer = base_render_test.renderer
START_TAINT = {"key": "agentarium.io/observe-not-ready", "operator": "Equal", "value": "true", "effect": "NoSchedule"}
EXEC_TAINT = {"key": "agentarium-role", "operator": "Equal", "value": "exec", "effect": "NoSchedule"}


def env(container):
    return {e["name"]: e["value"] for e in container["env"]}


class ProbeRunnerManifests(unittest.TestCase):
    def setUp(self):
        self.runner = json.loads((DIR / "probe-runner.yaml").read_text())["items"]
        self.sink = json.loads((DIR / "probe-sink.yaml").read_text())["items"]

    def daemonset(self, namespace):
        ds, = [o for o in self.runner if o["kind"] == "DaemonSet" and o["metadata"]["namespace"] == namespace]
        return ds["spec"]["template"]["spec"]

    def test_runner_objects(self):
        self.assertEqual(sorted((o["kind"], o["metadata"]["namespace"], o["metadata"]["name"]) for o in self.runner), [
            ("DaemonSet", "agent-adapters", "probe-runner"), ("DaemonSet", "agent-exec", "probe-runner"),
            ("ServiceAccount", "agent-adapters", "probe-runner"), ("ServiceAccount", "agent-exec", "probe-runner")])
        for o in self.runner:
            if o["kind"] == "ServiceAccount":
                self.assertFalse(o["automountServiceAccountToken"])
                self.assertNotIn("annotations", o["metadata"])
        seed = (ROOT / "services/identity/seed/registered_workloads.yaml").read_text()
        for ns in ("agent-exec", "agent-adapters"):
            self.assertIn(f"{{namespace: {ns}, ksa: probe-runner, role: probe}}", seed)

    def test_runner_pod_contract(self):
        for ns, role, tolerations in (("agent-exec", "exec", [EXEC_TAINT, START_TAINT]), ("agent-adapters", "control", [START_TAINT])):
            with self.subTest(namespace=ns):
                pod = self.daemonset(ns)
                self.assertEqual(pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": role})
                self.assertEqual(pod["tolerations"], tolerations)
                self.assertEqual(pod["serviceAccountName"], "probe-runner")
                self.assertFalse(pod["automountServiceAccountToken"])
                for key in ("hostNetwork", "hostPID", "nodeName", "priorityClassName", "runtimeClassName", "initContainers"):
                    self.assertNotIn(key, pod)
                c, = pod["containers"]
                self.assertEqual(c["image"], "${PROBE_RUNNER_IMAGE}")
                self.assertEqual(c["command"], [renderer.PROBE_RUNNER_ENTRYPOINT])
                self.assertNotIn("args", c)
                self.assertNotIn("envFrom", c)
                self.assertTrue(all("valueFrom" not in e for e in c["env"]))
                self.assertEqual(c["securityContext"], {"runAsNonRoot": True, "runAsUser": 10001, "runAsGroup": 10001,
                                                        "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                        "capabilities": {"drop": ["ALL"]}})
                vols = {v["name"]: v for v in pod["volumes"]}
                self.assertEqual(set(vols), {"work", "identity"})
                self.assertIn("sizeLimit", vols["work"]["emptyDir"])
                token, = vols["identity"]["projected"]["sources"]
                self.assertEqual(token["serviceAccountToken"]["audience"], "agentarium-identity")
                mounts = {m["mountPath"] for m in c["volumeMounts"]}
                # The protected fixture lives in /work (tetragon file policy).
                self.assertEqual(mounts, {"/work", "/run/agentarium/identity"})

    def test_runner_peers(self):
        e = env(self.daemonset("agent-exec")["containers"][0])
        # agent-exec has no DNS egress: fixed ClusterIPs only, all through the gateway.
        self.assertEqual(e["AGENTARIUM_BOOTSTRAP_URL"], "https://${GATEWAY_CLUSTER_IP}:8443")
        self.assertEqual(e["AGENTARIUM_REPORT_URL"], "https://${GATEWAY_CLUSTER_IP}:8443")
        self.assertEqual(e["AGENTARIUM_PROBE_SINK"], "${PROBE_SINK_CLUSTER_IP}:8443")
        a = env(self.daemonset("agent-adapters")["containers"][0])
        self.assertEqual(a["AGENTARIUM_BOOTSTRAP_URL"], "https://workload-identity.agent-control.svc:8443")
        self.assertEqual(a["AGENTARIUM_REPORT_URL"], "https://control-health.agent-observe.svc:8443")
        self.assertEqual(a["AGENTARIUM_PROBE_SINK"], "${PROBE_SINK_CLUSTER_IP}:8443")

    def test_sink(self):
        kinds = {o["kind"]: o for o in self.sink}
        self.assertEqual(sorted(kinds), ["Deployment", "Service", "ServiceAccount"])
        for o in self.sink:
            self.assertEqual(o["metadata"], {"name": "probe-sink", "namespace": "agent-targets"})
        pod = kinds["Deployment"]["spec"]["template"]["spec"]
        self.assertEqual(pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": "control"})
        self.assertEqual(pod["tolerations"], [START_TAINT])
        c, = pod["containers"]
        self.assertEqual(c["image"], "${PROBE_SINK_IMAGE}")
        self.assertEqual([p["containerPort"] for p in c["ports"]], [8443])
        svc = kinds["Service"]["spec"]
        self.assertEqual(svc["clusterIP"], "${PROBE_SINK_CLUSTER_IP}")
        self.assertEqual([(p["port"], p["protocol"]) for p in svc["ports"]], [(8443, "TCP")])
        self.assertEqual(svc["selector"], {"app.kubernetes.io/name": "probe-sink"})


class ProbeRunnerRender(unittest.TestCase):
    base = base_render_test.BaseNetworkRender()

    def render(self, values):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            self.base.render(values, out)
            return (json.loads((out / "probe-runner/probe-runner.yaml").read_text())["items"],
                    json.loads((out / "probe-runner/probe-sink.yaml").read_text())["items"])

    def test_render_is_concrete(self):
        runner, sink = self.render(self.base.values())
        text = json.dumps(runner + sink)
        self.assertNotIn("${", text)
        svc, = [o for o in sink if o["kind"] == "Service"]
        self.assertEqual(svc["spec"]["clusterIP"], "10.30.0.23")

    def test_render_rejects_unadmittable_values(self):
        image = "us-central1-docker.pkg.dev/test-project/agentarium/test@sha256:" + "a" * 64
        other = "us-central1-docker.pkg.dev/test-project/agentarium/other@sha256:" + "b" * 64
        for key, value, message in (
                ("PROBE_IMAGES", other, "PROBE_IMAGES"),
                ("PROBE_ENTRYPOINTS", image + "=/app/bin/probe-runner", "PROBE_ENTRYPOINTS"),
                ("PROBE_RUNNER_IMAGE", "", ""),
                ("PROBE_SINK_IMAGE", "docker.io/library/sink:latest", ""),
                ("PROBE_SINK_CLUSTER_IP", "10.30.0.20", "differ"),
                ("PROBE_SINK_CLUSTER_IP", "10.30.0.10", ""),
                ("PROBE_SINK_CLUSTER_IP", "10.99.0.23", "")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = self.base.values()
                values[key] = value
                with self.assertRaisesRegex(renderer.RenderError, message):
                    self.base.render(values, Path(tmp) / "base")
        with self.subTest("runner image missing from AGENT_ADAPTERS_IMAGES"), tempfile.TemporaryDirectory() as tmp:
            values = self.base.values()
            values["PROBE_RUNNER_IMAGE"] = other
            values["PROBE_IMAGES"] = other
            values["PROBE_ENTRYPOINTS"] = other + "=" + renderer.PROBE_RUNNER_ENTRYPOINT
            with self.assertRaisesRegex(renderer.RenderError, "AGENT_ADAPTERS_IMAGES"):
                self.base.render(values, Path(tmp) / "base")


if __name__ == "__main__":
    unittest.main()
