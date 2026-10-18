"""Offline TASK-07 audit exporter Deployment checks; not GKE runtime evidence."""
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/gcp/base/audit-exporter/audit-exporter.yaml"
NAME, NAMESPACE = "audit-exporter", "agent-observe"
sibling = importlib.util.spec_from_file_location("base_render_test", ROOT / "tests/egress/test_base_render.py")
base_render_test = importlib.util.module_from_spec(sibling)
sibling.loader.exec_module(base_render_test)
renderer = base_render_test.renderer


class AuditExporterDeployment(unittest.TestCase):
    def setUp(self):
        items = json.loads(MANIFEST.read_text())["items"]
        self.assertEqual(sorted(o["kind"] for o in items), ["ConfigMap", "Deployment", "ServiceAccount"])
        self.kinds = {o["kind"]: o for o in items}
        for o in items:
            self.assertEqual(o["metadata"]["namespace"], NAMESPACE)
        self.pod = self.kinds["Deployment"]["spec"]["template"]["spec"]
        self.app, = self.pod["containers"]

    def test_identity_and_label_match_ksa(self):
        self.assertEqual(self.kinds["ServiceAccount"]["metadata"]["name"], NAME)
        self.assertFalse(self.kinds["ServiceAccount"]["automountServiceAccountToken"])
        self.assertNotIn("annotations", self.kinds["ServiceAccount"]["metadata"])
        deploy = self.kinds["Deployment"]["spec"]
        self.assertEqual(deploy["replicas"], 1)
        self.assertEqual(deploy["template"]["metadata"]["labels"], {"app.kubernetes.io/name": NAME})
        self.assertEqual(self.pod["serviceAccountName"], NAME)
        self.assertFalse(self.pod["automountServiceAccountToken"])
        # GCS and KMS use the KSA principal through the GKE metadata server.
        self.assertEqual(self.pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": "control",
                                                    "iam.gke.io/gke-metadata-server-enabled": "true"})
        self.assertEqual(self.pod["tolerations"], [{"key": "agentarium.io/observe-not-ready", "operator": "Equal",
                                                    "value": "true", "effect": "NoSchedule"}])
        main = (ROOT / "services/audit/cmd/exporter/main.go").read_text()
        self.assertIn(f'"spiffe://agentarium.internal/ns/{NAMESPACE}/sa/{NAME}"', main)
        seed = (ROOT / "services/identity/seed/registered_workloads.yaml").read_text()
        self.assertRegex(seed, rf"namespace: {NAMESPACE}, ksa: {NAME}, role: service")

    def test_args_are_main_flags_and_inputs_are_mounted(self):
        main = (ROOT / "services/audit/cmd/exporter/main.go").read_text()
        flags = set(re.findall(r'flag\.(?:String|Duration)\("([a-z-]+)"', main))
        given = {a[2:].split("=", 1)[0] for a in self.app["args"]}
        self.assertLessEqual(given, flags)
        # Optional or test-only flags (file-mode TLS, KMS emulator, intervals).
        self.assertEqual(flags - given, {"kms-endpoint", "instance-id", "tls-cert", "tls-key", "poll-interval",
                                         "lease-renew-interval", "health-interval", "hold-recovery-backoff"})
        args = dict(a[2:].split("=", 1) for a in self.app["args"])
        self.assertEqual(args["health-url"], "https://control-health.agent-observe.svc:8443")
        self.assertEqual(args["identity-url"], "https://workload-identity.agent-control.svc:8443")
        self.assertEqual(args["kms-key-version"], "${AUDIT_EXPORTER_KMS_KEY_VERSION}")
        mounts = {m["mountPath"]: m for m in self.app["volumeMounts"]}
        volumes = {v["name"]: v for v in self.pod["volumes"]}
        for flag, config_map in (("keys", "audit-exporter-keys"), ("tls-ca", "agentarium-trust")):
            mount = mounts[str(Path(args[flag]).parent)]
            self.assertTrue(mount["readOnly"])
            self.assertEqual(volumes[mount["name"]]["configMap"]["name"], config_map)
        self.assertEqual(json.loads(self.kinds["ConfigMap"]["data"]["keys.json"]),
                         {"${AUDIT_EXPORTER_KMS_KEY_VERSION}": "${AUDIT_EXPORTER_PUBLIC_KEY_PEM}"})
        token = volumes[mounts[str(Path(args["bootstrap-token"]).parent)]["name"]]["projected"]["sources"]
        self.assertEqual(token, [{"serviceAccountToken": {"path": "token", "expirationSeconds": 600,
                                                          "audience": "agentarium-identity"}}])
        env = {e["name"]: e["value"] for e in self.app["env"]}
        self.assertEqual(env["DB_USER"], "${AUDIT_EXPORTER_DB_USER}")
        self.assertIn("user=$(DB_USER)", env["DATABASE_URL"])
        self.assertNotIn("ports", self.app)  # the exporter has no listener

    def test_only_proxy_impersonates_and_hardened(self):
        proxy, = self.pod["initContainers"]
        self.assertEqual(proxy["restartPolicy"], "Always")
        self.assertIn("--address=127.0.0.1", proxy["args"])
        self.assertEqual([a for a in proxy["args"] if "impersonate" in a],
                         ["--impersonate-service-account=${AUDIT_EXPORTER_DB_GSA}"])
        self.assertFalse(any("impersonate" in a for a in self.app["args"]))
        self.assertFalse(any("secret" in v or "csi" in v for v in self.pod["volumes"]))
        for container in self.pod["containers"] + self.pod["initContainers"]:
            self.assertTrue(container["securityContext"]["readOnlyRootFilesystem"])
            self.assertFalse(container["securityContext"]["allowPrivilegeEscalation"])

    def test_network_policy_is_egress_only(self):
        policies = json.loads((ROOT / "deploy/gcp/base/network/rendered/policies.yaml").read_text())["items"]
        policy, = [p for p in policies if p["metadata"] == {"name": f"{NAME}-allow", "namespace": NAMESPACE}]
        self.assertEqual(policy["spec"]["podSelector"], {"matchLabels": {"app.kubernetes.io/name": NAME}})
        self.assertEqual(policy["spec"]["ingress"], [])

    def test_render_derives_buckets_and_checks_signing_inputs(self):
        helper = base_render_test.BaseNetworkRender()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            helper.render(helper.values(), out)
            items = json.loads((out / "audit-exporter/audit-exporter.yaml").read_text())["items"]
            self.assertNotIn("${", json.dumps(items))
            keys = json.loads(next(o for o in items if o["kind"] == "ConfigMap")["data"]["keys.json"])
            version = base_render_test.MANIFEST_KEY + "/cryptoKeyVersions/1"
            self.assertEqual(keys, {version: base_render_test.P256_PUBLIC_PEM})
            app = next(o for o in items if o["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
            self.assertIn("--evidence-bucket=test-evidence", app["args"])
            self.assertIn("--decision-bucket=test-decision-inputs", app["args"])
            self.assertIn("--kms-key-version=" + version, app["args"])
        other_image = "us-central1-docker.pkg.dev/test-project/agentarium/other@sha256:" + "b" * 64
        rsa = ("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----\n")
        for key, value in (("AUDIT_EXPORTER_IMAGE", ""), ("AUDIT_EXPORTER_IMAGE", other_image),
                           ("AUDIT_EXPORTER_KMS_KEY_VERSION", base_render_test.MANIFEST_KEY + "/cryptoKeyVersions/latest"),
                           ("AUDIT_EXPORTER_KMS_KEY_VERSION", base_render_test.MANIFEST_KEY.replace("manifest", "bundle") + "/cryptoKeyVersions/1"),
                           ("AUDIT_EXPORTER_KMS_KEY_VERSION", base_render_test.MANIFEST_KEY),
                           ("AUDIT_EXPORTER_PUBLIC_KEY_PEM", ""), ("AUDIT_EXPORTER_PUBLIC_KEY_PEM", base_render_test.PEM),
                           ("AUDIT_EXPORTER_PUBLIC_KEY_PEM", rsa),
                           ("AUDIT_EXPORTER_PUBLIC_KEY_PEM", base_render_test.P256_PUBLIC_PEM * 2),
                           ("AUDIT_EVIDENCE_BUCKET", "test-evidence")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = helper.values()
                values[key] = value
                with self.assertRaises(renderer.RenderError):
                    helper.render(values, Path(tmp) / "base")
        for storage in ({"evidence_bucket": "Bad_Bucket", "decision_input_exports_bucket": "test-decision-inputs"},
                        {"evidence_bucket": "test-evidence", "decision_input_exports_bucket": "test-evidence"},
                        {"evidence_bucket": "test-evidence"}):
            with self.subTest(storage=storage), tempfile.TemporaryDirectory() as tmp:
                lock = helper.lock()
                lock["storage"] = storage
                with self.assertRaises(renderer.RenderError):
                    renderer.render(lock, helper.values(), Path(tmp) / "base")


if __name__ == "__main__":
    unittest.main()
