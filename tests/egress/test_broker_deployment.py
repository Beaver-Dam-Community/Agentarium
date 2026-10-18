"""Offline credential broker Deployment checks; not GKE runtime evidence."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/gcp/base/credential-broker/broker.yaml"
NAME, NAMESPACE = "credential-broker", "agent-control"
sibling = importlib.util.spec_from_file_location("base_render_test", Path(__file__).with_name("test_base_render.py"))
base_render_test = importlib.util.module_from_spec(sibling)
sibling.loader.exec_module(base_render_test)
renderer = base_render_test.renderer


def objects(items):
    return {o["kind"]: o for o in items}


class BrokerDeployment(unittest.TestCase):
    def setUp(self):
        items = json.loads(MANIFEST.read_text())["items"]
        self.assertEqual(sorted(o["kind"] for o in items), ["Deployment", "Service", "ServiceAccount"])
        self.kinds = objects(items)
        for o in items:
            self.assertEqual(o["metadata"], {"name": NAME, "namespace": NAMESPACE})
        self.pod = self.kinds["Deployment"]["spec"]["template"]["spec"]

    def test_identity_and_label_match_ksa(self):
        sa = self.kinds["ServiceAccount"]
        self.assertFalse(sa["automountServiceAccountToken"])
        self.assertNotIn("annotations", sa["metadata"])
        deploy = self.kinds["Deployment"]["spec"]
        self.assertEqual(deploy["selector"]["matchLabels"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(deploy["template"]["metadata"]["labels"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(self.pod["serviceAccountName"], NAME)
        self.assertFalse(self.pod["automountServiceAccountToken"])
        main = (ROOT / "services/credential-broker/cmd/broker/main.go").read_text()
        self.assertIn(f'"spiffe://agentarium.internal/ns/{NAMESPACE}/sa/{NAME}"', main)
        seed = (ROOT / "services/identity/seed/registered_workloads.yaml").read_text()
        self.assertRegex(seed, rf"namespace: {NAMESPACE}, ksa: {NAME}, role: service")

    def test_placement_is_control_with_only_the_bootstrap_toleration(self):
        self.assertEqual(self.pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": "control"})
        self.assertEqual(self.pod["schedulerName"], "default-scheduler")
        self.assertNotIn("nodeName", self.pod)
        # agent-control is a bootstrap role Namespace (TASK-01 3 item 3, 3.5):
        # its Pods tolerate exactly the observation start taint.
        self.assertEqual(self.pod["tolerations"], [{"key": "agentarium.io/observe-not-ready", "operator": "Equal",
                                                    "value": "true", "effect": "NoSchedule"}])
        self.assertNotIn("priorityClassName", self.pod)
        self.assertNotIn("runtimeClassName", self.pod)
        self.assertNotIn("hostNetwork", self.pod)

    def test_only_proxy_impersonates_db_gsa(self):
        proxy, = self.pod["initContainers"]
        self.assertEqual(proxy["restartPolicy"], "Always")
        for arg in ("--auto-iam-authn", "--private-ip", "--address=127.0.0.1", "--port=5432"):
            self.assertIn(arg, proxy["args"])
        self.assertEqual([a for a in proxy["args"] if "impersonate" in a],
                         ["--impersonate-service-account=${BROKER_DB_GSA}"])
        app, = self.pod["containers"]
        self.assertFalse(any("impersonate" in a or "gcp-service-account" in a for a in app["args"]))
        env = {e["name"]: e["value"] for e in app["env"]}
        self.assertEqual(env["DB_USER"], "${BROKER_DB_USER}")
        self.assertTrue(env["DATABASE_URL"].startswith("host=127.0.0.1 port=5432 "))

    def test_args_are_exactly_the_broker_flags(self):
        app, = self.pod["containers"]
        self.assertEqual(app["image"], "${BROKER_IMAGE}")
        main = (ROOT / "services/credential-broker/cmd/broker/main.go").read_text()
        flags = set(re.findall(r'flag\.String\("([a-z-]+)"', main))
        given = {a[2:].split("=", 1)[0] for a in app["args"]}
        self.assertEqual(given, flags)
        self.assertIn("--identity-url=https://workload-identity.agent-control.svc:8443", app["args"])
        self.assertIn("--listen=:8443", app["args"])

    def test_bootstrap_token_secretless_and_hardened(self):
        tokens = [s["serviceAccountToken"] for v in self.pod["volumes"]
                  for s in v.get("projected", {}).get("sources", []) if "serviceAccountToken" in s]
        self.assertEqual(tokens, [{"path": "token", "expirationSeconds": 600, "audience": "agentarium-identity"}])
        self.assertFalse(any("secret" in v for v in self.pod["volumes"]))
        app, = self.pod["containers"]
        self.assertFalse(any("valueFrom" in e for e in app["env"]))
        self.assertTrue(self.pod["securityContext"]["runAsNonRoot"])
        for container in self.pod["containers"] + self.pod["initContainers"]:
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])
            self.assertEqual(container["securityContext"]["capabilities"], {"drop": ["ALL"]})
            self.assertIn("limits", container["resources"])

    def test_service_matches_rendered_network_policy(self):
        svc = self.kinds["Service"]["spec"]
        self.assertEqual(svc["selector"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(svc["ports"], [{"name": "https", "port": 8443, "targetPort": "https"}])
        self.assertNotIn("type", svc)
        app, = self.pod["containers"]
        self.assertEqual(app["ports"], [{"name": "https", "containerPort": 8443}])
        policies = json.loads((ROOT / "deploy/gcp/base/network/rendered/policies.yaml").read_text())["items"]
        policy, = [p for p in policies if p["metadata"] == {"name": f"{NAME}-allow", "namespace": NAMESPACE}]
        ingress, = policy["spec"]["ingress"]
        self.assertEqual(ingress["ports"], [{"port": 8443, "protocol": "TCP"}])
        self.assertEqual(ingress["from"], [{
            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "agent-adapters"}},
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "receiver-sender"}}}])

    def test_render_requires_broker_values(self):
        helper = base_render_test.BaseNetworkRender()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            values = helper.values()
            values.update(BROKER_DB_GSA="credential-broker-db@test-project.iam.gserviceaccount.com",
                          BROKER_DB_USER="credential-broker-db@test-project.iam")
            helper.render(values, out)
            text = (out / "credential-broker/broker.yaml").read_text()
            self.assertNotIn("${", text)
            self.assertIn("--impersonate-service-account=credential-broker-db@test-project.iam.gserviceaccount.com", text)
        for key, value in (("BROKER_IMAGE", ""), ("BROKER_IMAGE", "docker.io/library/broker:latest")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = helper.values()
                values[key] = value
                with self.assertRaises(renderer.RenderError):
                    helper.render(values, Path(tmp) / "base")
        with tempfile.TemporaryDirectory() as tmp:
            values = helper.values()
            del values["BROKER_DB_GSA"]
            with self.assertRaises(renderer.RenderError):
                helper.render(values, Path(tmp) / "base")


if __name__ == "__main__":
    unittest.main()
