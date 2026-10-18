"""Offline correlation Deployment checks; not GKE runtime evidence."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/gcp/base/correlation/correlation.yaml"
NAME, NAMESPACE = "correlation", "agent-observe"
sibling = importlib.util.spec_from_file_location("base_render_test", ROOT / "tests/egress/test_base_render.py")
base_render_test = importlib.util.module_from_spec(sibling)
sibling.loader.exec_module(base_render_test)
renderer = base_render_test.renderer


class CorrelationDeployment(unittest.TestCase):
    def setUp(self):
        items = json.loads(MANIFEST.read_text())["items"]
        self.assertEqual(sorted(o["kind"] for o in items),
                         ["ConfigMap", "Deployment", "PersistentVolumeClaim", "Service", "ServiceAccount"])
        self.kinds = {o["kind"]: o for o in items}
        for o in items:
            self.assertEqual(o["metadata"]["namespace"], NAMESPACE)
        self.pod = self.kinds["Deployment"]["spec"]["template"]["spec"]
        self.app, = self.pod["containers"]

    def test_identity_and_label_match_ksa(self):
        self.assertEqual(self.kinds["ServiceAccount"]["metadata"]["name"], NAME)
        self.assertFalse(self.kinds["ServiceAccount"]["automountServiceAccountToken"])
        deploy = self.kinds["Deployment"]["spec"]
        self.assertEqual(deploy["template"]["metadata"]["labels"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(self.pod["serviceAccountName"], NAME)
        self.assertFalse(self.pod["automountServiceAccountToken"])
        self.assertEqual(self.pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": "control"})
        main = (ROOT / "services/correlation/cmd/correlation/main.go").read_text()
        self.assertIn(f'"spiffe://agentarium.internal/ns/{NAMESPACE}/sa/{NAME}"', main)
        seed = (ROOT / "services/identity/seed/registered_workloads.yaml").read_text()
        self.assertRegex(seed, rf"namespace: {NAMESPACE}, ksa: {NAME}, role: service")

    def test_single_writer_with_durable_epoch(self):
        # The audit source epoch directory is exclusive per process.
        deploy = self.kinds["Deployment"]["spec"]
        self.assertEqual(deploy["replicas"], 1)
        self.assertEqual(deploy["strategy"], {"type": "Recreate"})
        self.assertEqual(self.kinds["PersistentVolumeClaim"]["spec"]["accessModes"], ["ReadWriteOnce"])
        self.assertIn("--epoch-dir=/var/lib/agentarium/correlation-epoch", self.app["args"])

    def test_args_are_main_flags_and_inputs_are_mounted(self):
        main = (ROOT / "services/correlation/cmd/correlation/main.go").read_text()
        flags = set(re.findall(r'flag\.(?:String|Duration)\("([a-z-]+)"', main))
        given = {a[2:].split("=", 1)[0] for a in self.app["args"]}
        self.assertLessEqual(given, flags)
        self.assertEqual(flags - given, {"interval", "lookback", "protected-paths"})
        mounts = {m["mountPath"]: m for m in self.app["volumeMounts"]}
        volumes = {v["name"]: v for v in self.pod["volumes"]}
        for flag, config_map in (("environment-lock", "agentarium-environment-lock"), ("network-values", "correlation-network-values"),
                                 ("allow-matrix", "agentarium-allow-matrix")):
            path, = [a.split("=", 1)[1] for a in self.app["args"] if a.startswith(f"--{flag}=")]
            mount = mounts[str(Path(path).parent)]
            self.assertTrue(mount["readOnly"])
            self.assertEqual(volumes[mount["name"]]["configMap"]["name"], config_map)
        values = json.loads(self.kinds["ConfigMap"]["data"]["network-values.json"])
        self.assertEqual(values, {"control_plane_endpoint": "${control_plane_endpoint}",
                                  "cloudsql_private_ip": "${cloudsql_private_ip}", "node_cidr": "${node_cidr}"})

    def test_only_proxy_impersonates_and_hardened(self):
        proxy, = self.pod["initContainers"]
        self.assertEqual([a for a in proxy["args"] if "impersonate" in a], ["--impersonate-service-account=${CORRELATION_DB_GSA}"])
        self.assertFalse(any("impersonate" in a for a in self.app["args"]))
        self.assertFalse(any("secret" in v for v in self.pod["volumes"]))
        for container in self.pod["containers"] + self.pod["initContainers"]:
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])

    def test_network_policy_matches_receiver_and_hold_client(self):
        policies = json.loads((ROOT / "deploy/gcp/base/network/rendered/policies.yaml").read_text())["items"]
        policy, = [p for p in policies if p["metadata"] == {"name": f"{NAME}-allow", "namespace": NAMESPACE}]
        ingress = json.dumps(policy["spec"]["ingress"])
        self.assertIn('"port": 8443', ingress)
        self.assertIn("${node_cidr}", ingress)  # netpol collectors are hostNetwork
        health, = [p for p in policies if p["metadata"] == {"name": "control-health-allow", "namespace": NAMESPACE}]
        sources = [peer.get("podSelector", {}).get("matchLabels", {}).get("app.kubernetes.io/name")
                   for rule in health["spec"]["ingress"] for peer in rule.get("from", [])]
        self.assertIn(NAME, sources)
        self.assertIn(f'"--control-health-url=https://control-health.{NAMESPACE}.svc:8443"', json.dumps(self.app["args"]))

    def test_render_requires_correlation_values(self):
        helper = base_render_test.BaseNetworkRender()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            helper.render(helper.values(), out)
            text = (out / "correlation/correlation.yaml").read_text()
            self.assertNotIn("${", text)
            self.assertIn("--cluster-uid=6f1c3a4e-8f0e-4d4c-9b55-0d9e0c1b2a3f", text)
        for key, value in (("CORRELATION_IMAGE", ""), ("CORRELATION_IMAGE", "docker.io/library/correlation:latest"),
                           ("CLUSTER_UID", ""), ("CLUSTER_UID", "6F1C3A4E-8F0E-4D4C-9B55-0D9E0C1B2A3F")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = helper.values()
                values[key] = value
                with self.assertRaises(renderer.RenderError):
                    helper.render(values, Path(tmp) / "base")


if __name__ == "__main__":
    unittest.main()
