"""Offline node-readiness Deployment checks (TASK-01 3.2.1, 3.5); not GKE runtime evidence."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/gcp/base/node-readiness/node-readiness.yaml"
NAME, NAMESPACE = "node-readiness", "agent-control"
START_TAINT = {"key": "agentarium.io/observe-not-ready", "operator": "Equal", "value": "true", "effect": "NoSchedule"}
sibling = importlib.util.spec_from_file_location("base_render_test", Path(__file__).with_name("test_base_render.py"))
base_render_test = importlib.util.module_from_spec(sibling)
sibling.loader.exec_module(base_render_test)
renderer = base_render_test.renderer


class NodeReadinessDeployment(unittest.TestCase):
    def setUp(self):
        items = json.loads(MANIFEST.read_text())["items"]
        self.assertEqual(sorted(o["kind"] for o in items), ["Deployment", "ServiceAccount"])
        self.kinds = {o["kind"]: o for o in items}
        for o in items:
            self.assertEqual(o["metadata"], {"name": NAME, "namespace": NAMESPACE})
        self.deploy = self.kinds["Deployment"]["spec"]
        self.pod = self.deploy["template"]["spec"]
        self.app, = self.pod["containers"]

    def test_identity_matches_rbac_vap_netpol_and_registration(self):
        self.assertFalse(self.kinds["ServiceAccount"]["automountServiceAccountToken"])
        self.assertNotIn("annotations", self.kinds["ServiceAccount"]["metadata"])
        self.assertEqual(self.deploy["selector"]["matchLabels"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(self.deploy["template"]["metadata"]["labels"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(self.pod["serviceAccountName"], NAME)
        # No leader election: exactly one controller patches taints.
        self.assertEqual(self.deploy["replicas"], 1)
        # Recreate so a rollout never runs two controllers at once.
        self.assertEqual(self.deploy["strategy"], {"type": "Recreate"})
        rbac = (ROOT / "deploy/gcp/base/rbac/node-readiness.yaml").read_text()
        self.assertIn(f"name: {NAME}\n    namespace: {NAMESPACE}", rbac)
        vap = (ROOT / "deploy/gcp/base/admission/node-readiness-scope.yaml").read_text()
        self.assertIn(f"system:serviceaccount:{NAMESPACE}:{NAME}", vap)
        matrix = json.loads((ROOT / "deploy/gcp/base/network/allow-matrix.yaml").read_text())
        self.assertIn(f"{NAMESPACE}/{NAME}", matrix["workloads"])
        seed = (ROOT / "services/identity/seed/registered_workloads.yaml").read_text()
        self.assertRegex(seed, rf"namespace: {NAMESPACE}, ksa: {NAME}, role: service")
        main = (ROOT / "services/node-readiness/main.go").read_text()
        self.assertIn(f'"spiffe://agentarium.internal/ns/{NAMESPACE}/sa/{NAME}"', main)

    def test_placement_is_control_with_only_the_start_taint_toleration(self):
        self.assertEqual(self.pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": "control"})
        self.assertEqual(self.pod["schedulerName"], "default-scheduler")
        # Bootstrap role (TASK-01 3 item 3, 3.5): it removes the taint, so it must tolerate it.
        self.assertEqual(self.pod["tolerations"], [START_TAINT])
        for key in ("nodeName", "priorityClassName", "runtimeClassName", "hostNetwork"):
            self.assertNotIn(key, self.pod)

    def test_args_use_identity_bootstrap_and_known_flags(self):
        self.assertEqual(self.app["image"], "${NODE_READINESS_IMAGE}")
        main = (ROOT / "services/node-readiness/main.go").read_text()
        flags = set(re.findall(r'flag\.(?:String|Duration|Int)\("([a-z-]+)"', main))
        given = {a[2:].split("=", 1)[0] for a in self.app["args"]}
        self.assertLessEqual(given, flags)
        self.assertEqual(self.app["args"], [
            "--control-health-url=https://control-health.agent-observe.svc:8443",
            "--identity-url=https://workload-identity.agent-control.svc:8443",
            "--bootstrap-token=/var/run/agentarium-bootstrap/token",
            "--tls-ca-file=/etc/agentarium-trust/ca.pem"])
        self.assertEqual(self.app["env"], [{"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}}])
        self.assertNotIn("ports", self.app)

    def test_tokens_secretless_and_hardened(self):
        self.assertFalse(self.pod["automountServiceAccountToken"])
        volumes = {v["name"]: v for v in self.pod["volumes"]}
        self.assertEqual(set(volumes), {"trust", "bootstrap", "api-token"})
        self.assertEqual(volumes["trust"], {"name": "trust", "configMap": {"name": "agentarium-trust"}})
        boot, = volumes["bootstrap"]["projected"]["sources"]
        self.assertEqual(boot["serviceAccountToken"], {"path": "token", "expirationSeconds": 600, "audience": "agentarium-identity"})
        api = volumes["api-token"]["projected"]["sources"]
        self.assertEqual(api[0]["serviceAccountToken"], {"path": "token", "expirationSeconds": 600})
        mounts = {m["name"]: m for m in self.app["volumeMounts"]}
        self.assertEqual(mounts["api-token"]["mountPath"], "/var/run/secrets/kubernetes.io/serviceaccount")
        self.assertTrue(all(m["readOnly"] for m in self.app["volumeMounts"]))
        self.assertEqual(self.app["securityContext"], {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                                       "capabilities": {"drop": ["ALL"]}})
        self.assertEqual(self.pod["securityContext"]["seccompProfile"], {"type": "RuntimeDefault"})
        self.assertTrue(self.pod["securityContext"]["runAsNonRoot"])
        self.assertIn("limits", self.app["resources"])

    def test_render_requires_a_listed_image(self):
        helper = base_render_test.BaseNetworkRender()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            values = helper.values()
            helper.render(values, out)
            text = (out / "node-readiness/node-readiness.yaml").read_text()
            self.assertNotIn("${", text)
            self.assertIn('"image": "' + values["NODE_READINESS_IMAGE"] + '"', text)
        for value in ("", "docker.io/library/node-readiness:latest"):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                values = helper.values()
                values["NODE_READINESS_IMAGE"] = value
                with self.assertRaises(renderer.RenderError):
                    helper.render(values, Path(tmp) / "base")
        with tempfile.TemporaryDirectory() as tmp:
            values = helper.values()
            # A digest that is not on the agent-control list (other control
            # services may share the list, so only this image is left off).
            values["NODE_READINESS_IMAGE"] = values["NODE_READINESS_IMAGE"].rsplit(":", 1)[0] + ":" + "b" * 64
            with self.assertRaisesRegex(renderer.RenderError, "NODE_READINESS_IMAGE: must also be listed in AGENT_CONTROL_IMAGES"):
                helper.render(values, Path(tmp) / "base")


if __name__ == "__main__":
    unittest.main()
