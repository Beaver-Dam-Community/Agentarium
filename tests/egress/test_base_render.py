"""Offline integration of network templates with the existing base renderer."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("base_render", ROOT / "deploy/gcp/base/render.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake/base64+Q==\n-----END CERTIFICATE-----\n"
# A P-256 SubjectPublicKeyInfo (test key, no private half kept).
P256_PUBLIC_PEM = ("-----BEGIN PUBLIC KEY-----\n"
                   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgdMbEweKdJq6ptGIJNvaI1IkeFrb\n"
                   "Z/ZvnJ+UHHb09A21zFK5d7egEiQyp6ZA0/RBpIO5Bo/pH02WQ5B9dDZ8rg==\n"
                   "-----END PUBLIC KEY-----\n")
MANIFEST_KEY = "projects/test-project/locations/us-central1/keyRings/test-ring/cryptoKeys/manifest-signing"


class BaseNetworkRender(unittest.TestCase):
    def values(self):
        result = {}
        for path in renderer.BASE.rglob("*.yaml"):
            if path.name == "kustomization.yaml":
                continue
            for line in path.read_text().splitlines():
                if not line.lstrip().startswith("#"):
                    for name in re.findall(r"\$\{([A-Za-z0-9_]+)\}", line):
                        result[name] = ""
        for name in renderer.LOCK_DERIVED:
            result.pop(name, None)
        result["CA_POOL_ID"] = "projects/test-project/locations/us-central1/caPools/test-pool"
        result.update(GUARDED_RUNTIME_ENABLED="false", control_plane_endpoint="192.0.2.1",
                      cloudsql_private_ip="192.0.2.2", node_cidr="198.51.100.0/24",
                      pods_range="203.0.113.0/24")
        result["CLUSTER_UID"] = "6f1c3a4e-8f0e-4d4c-9b55-0d9e0c1b2a3f"
        image = "us-central1-docker.pkg.dev/test-project/agentarium/test@sha256:" + "a" * 64
        for name in renderer.SERVICE_IMAGES:
            result[name] = image
        for name in set(renderer.SERVICE_IMAGE_NAMESPACES.values()):
            result[name] = image
        result.update(EVIDENCE_PROBE_ACTION_KEY="00000000-0000-4000-8000-000000000001",
                      AGENTARIUM_TENANT="hackathon", RELEASE_VERSION="m3-1-test", TRUST_BUNDLE_PEM=PEM)
        # TASK-10 probe runner: on probeImages with its entrypoint pair; the
        # sink ClusterIP is a free address of services_range.
        result.update(PROBE_IMAGES=image, PROBE_ENTRYPOINTS=image + "=" + renderer.PROBE_RUNNER_ENTRYPOINT,
                      PROBE_SINK_CLUSTER_IP="10.30.0.23")
        # TASK-07 audit exporter: one exact version of the lock manifest key.
        result.update(AUDIT_EXPORTER_KMS_KEY_VERSION=MANIFEST_KEY + "/cryptoKeyVersions/1",
                      AUDIT_EXPORTER_PUBLIC_KEY_PEM=P256_PUBLIC_PEM)
        return result

    def lock(self, environment="prod", identity=None, receiver=None):
        if identity is None:
            identity = {"claim_key_secret": "projects/123456789012/secrets/identity-claim-key",
                        "claim_key_version": "3"}
        identity = {"oidc_audiences": ["32555940559.apps.googleusercontent.com"],
                    "oidc_allowed_hd": ["example.com"], **identity}
        if receiver is None:
            receiver = {"cluster_ip": "10.30.0.21", "probe_cluster_ip": "10.30.0.22", "receiver_mode": "idempotent",
                        "api_key_secret": "projects/123456789012/secrets/receiver-api-key",
                        "api_key_versions": ["2"]}
        return {"project": {"location": "us-central1-a", "id": "test-project"},
                "gke": {"kubernetes_minor": "1.33"}, "pki": {"ca_pool": "test-pool"}, "environment": environment, "identity": identity,
                "keys": {"bundle_key_id": f"{environment}-v1", "manifest_signing_key": MANIFEST_KEY},
                "storage": {"evidence_bucket": "test-evidence", "decision_input_exports_bucket": "test-decision-inputs"},
                "network": {"services_range": "10.30.0.0/20", "gateway_cluster_ip": "10.30.0.20"},
                "receiver": receiver}

    def render(self, values, out, environment="prod", identity=None, receiver=None):
        return renderer.render(self.lock(environment, identity, receiver), values, out)

    def test_claim_key_comes_from_lock_and_is_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            self.render(self.values(), out)
            items = json.loads((out / "contact-services/contacts.yaml").read_text())["items"]
            spc = next(o for o in items if o["kind"] == "SecretProviderClass")
            self.assertEqual(spc["spec"]["parameters"]["secrets"],
                             '- resourceName: "projects/123456789012/secrets/identity-claim-key/versions/3"\n  path: "claim-key"\n')
        bad = ({}, {"claim_key_secret": "projects/123456789012/secrets/k", "claim_key_version": "latest"},
               {"claim_key_secret": "projects/123456789012/secrets/k", "claim_key_version": "0"},
               {"claim_key_secret": "projects/test-project/secrets/k", "claim_key_version": "1"},
               {"claim_key_secret": "projects/123456789012/secrets/k/versions/1", "claim_key_version": "1"})
        for identity in bad:
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "base"
                with self.assertRaises(renderer.RenderError):
                    self.render(self.values(), out, identity=identity)
                self.assertFalse(out.exists())
        with tempfile.TemporaryDirectory() as tmp:
            values = self.values()
            values["CLAIM_KEY_SECRET_VERSION"] = "9"
            with self.assertRaisesRegex(renderer.RenderError, "comes from the lock"):
                self.render(values, Path(tmp) / "base")

    def test_network_render_is_concrete(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            self.render(self.values(), out)
            policies = json.loads((out / "network/rendered/policies.yaml").read_text())
            cidrs = {peer["ipBlock"]["cidr"] for policy in policies["items"]
                     for direction in ("ingress", "egress") for rule in policy["spec"].get(direction, [])
                     for peer in rule.get("from", []) + rule.get("to", []) if "ipBlock" in peer}
            self.assertTrue({"192.0.2.1/32", "192.0.2.2/32", "198.51.100.0/24"} <= cidrs)
            self.assertFalse(any("${" in value for value in cidrs))

    def test_audit_writer_serves_sensor_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            self.render(self.values(), out)
            items = json.loads((out / "contact-services/contacts.yaml").read_text())["items"]
            writer = next(o for o in items if o["kind"] == "Deployment" and o["metadata"]["name"] == "audit-writer")
            pod = writer["spec"]["template"]["spec"]
            args = next(c for c in pod["containers"] if c["name"] == "audit-writer")["args"]
            for arg in ("--kernel", "--kernel-node-cidrs=198.51.100.0/24,169.254.4.6/32", "--lifecycle",
                        "--lifecycle-node-cidrs=203.0.113.0/24", "--lifecycle-epoch-dir=/var/lib/agentarium/receiver-epoch"):
                self.assertIn(arg, args)
            # The epoch directory is persistent and exclusive to one writer.
            claim = next(v for v in pod["volumes"] if v["name"] == "receiver-epoch")["persistentVolumeClaim"]["claimName"]
            pvc = next(o for o in items if o["kind"] == "PersistentVolumeClaim" and o["metadata"]["name"] == claim)
            self.assertEqual(pvc["spec"]["accessModes"], ["ReadWriteOnce"])
            self.assertEqual((writer["spec"]["replicas"], writer["spec"]["strategy"]["type"]), (1, "Recreate"))

    def test_network_values_reject_wildcards_and_injection(self):
        for key, value in (("node_cidr", "0.0.0.0/0"), ("node_cidr", "::/0"),
                           ("cloudsql_private_ip", "192.0.2.2/32"),
                           ("control_plane_endpoint", "${another}"), ("node_cidr", "198.51.100.1/24"),
                           ("pods_range", "0.0.0.0/0"), ("pods_range", "203.0.113.1/24")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = self.values()
                values[key] = value
                with self.assertRaises(renderer.RenderError):
                    self.render(values, Path(tmp) / "base")

    def test_discovery_snapshot_values_are_checked(self):
        for key, value in (("DISCOVERY_SNAPSHOT_IMAGE", "docker.io/library/scanner:latest"),
                           ("DISCOVERY_SNAPSHOT_IMAGE", "us-central1-docker.pkg.dev/other/agentarium/s@sha256:" + "a" * 64),
                           ("DISCOVERY_BUCKET", "Bad_Bucket"), ("DISCOVERY_BUCKET", "b/../x")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = self.values()
                values[key] = value
                with self.assertRaises(renderer.RenderError):
                    self.render(values, Path(tmp) / "base")
        with tempfile.TemporaryDirectory() as tmp:
            values = self.values()
            values.update(DISCOVERY_SNAPSHOT_IMAGE="us-central1-docker.pkg.dev/test-project/agentarium/s@sha256:" + "b" * 64,
                          DISCOVERY_BUCKET="agentarium-test-discovery")
            out = Path(tmp) / "base"
            self.render(values, out)
            text = (out / "admission/discovery-snapshot.yaml").read_text()
            self.assertIn('bucket: "agentarium-test-discovery"', text)
            self.assertNotIn("${", "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#")))

    def test_missing_network_value_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.values()
            del values["cloudsql_private_ip"]
            with self.assertRaises(renderer.RenderError):
                self.render(values, Path(tmp) / "base")

    def test_identity_environment_is_fixed_by_lock(self):
        for environment in ("prod", "regression"):
            with self.subTest(environment=environment), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "base"
                self.render(self.values(), out, environment)
                items = json.loads((out / "contact-services/contacts.yaml").read_text())["items"]
                identity = next(o for o in items if o["kind"] == "Deployment" and o["metadata"]["name"] == "workload-identity")
                args = identity["spec"]["template"]["spec"]["containers"][0]["args"]
                self.assertEqual([arg for arg in args if arg.startswith("--environment=")],
                                 ["--environment=" + environment])

    def test_identity_environment_cannot_be_overridden(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = self.values()
            values["AGENTARIUM_ENVIRONMENT"] = "regression"
            with self.assertRaisesRegex(renderer.RenderError, "comes from the lock"):
                self.render(values, Path(tmp) / "base")

    def test_invalid_environment_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            with self.assertRaisesRegex(renderer.RenderError, "prod or regression"):
                self.render(self.values(), out, "")
            self.assertFalse(out.exists())

    def test_tetragon_host_paths_must_equal_the_fixed_list(self):
        exact = ",".join(renderer.TETRAGON_HOST_PATHS)
        with tempfile.TemporaryDirectory() as tmp:
            values = self.values()
            values["TETRAGON_HOST_PATHS"] = exact
            self.render(values, Path(tmp) / "ok")
            text = (Path(tmp) / "ok" / "admission" / "constraints.yaml").read_text()
            self.assertIn(exact, text)
            for bad in ("/sys/kernel/btf," + exact, "/proc,/sys/fs/bpf", exact + ",/proc"):
                values["TETRAGON_HOST_PATHS"] = bad
                with self.assertRaisesRegex(renderer.RenderError, "TETRAGON_HOST_PATHS"):
                    self.render(values, Path(tmp) / ("bad" + str(len(bad))))

    def test_tetragon_image_must_be_a_listed_sensor_image(self):
        tetragon = "us-central1-docker.pkg.dev/test-project/agentarium/tetragon@sha256:" + "b" * 64
        other = "us-central1-docker.pkg.dev/test-project/agentarium/exporter@sha256:" + "c" * 64
        with tempfile.TemporaryDirectory() as tmp:
            values = self.values()
            values["TETRAGON_IMAGE"], values["AGENT_SENSORS_IMAGES"] = tetragon, tetragon + "," + other
            self.render(values, Path(tmp) / "ok")
            self.assertIn('agent-sensors.tetragon.image: "' + tetragon + '"',
                          (Path(tmp) / "ok" / "admission" / "constraints.yaml").read_text())
            values["AGENT_SENSORS_IMAGES"] = other
            with self.assertRaisesRegex(renderer.RenderError, "TETRAGON_IMAGE"):
                self.render(values, Path(tmp) / "unlisted")
            values["TETRAGON_IMAGE"], values["AGENT_SENSORS_IMAGES"] = tetragon + "," + other, tetragon + "," + other
            with self.assertRaisesRegex(renderer.RenderError, "TETRAGON_IMAGE"):
                self.render(values, Path(tmp) / "two")

    def test_identity_certificate_templates_are_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            self.render(self.values(), out)
            items = json.loads((out / "contact-services/contacts.yaml").read_text())["items"]
            for deployment in (o for o in items if o["kind"] == "Deployment"):
                args = deployment["spec"]["template"]["spec"]["containers"][0]["args"]
                templates = [arg for arg in args if "certificate-template=" in arg]
                if deployment["metadata"]["name"] == "workload-identity":
                    self.assertEqual(templates, [
                        "--service-certificate-template=projects/test-project/locations/us-central1/certificateTemplates/test-pool-service",
                        "--client-certificate-template=projects/test-project/locations/us-central1/certificateTemplates/test-pool-client",
                    ])
                else:
                    self.assertEqual(templates, [])

    def test_certificate_template_override_and_pool_mismatch_rejected(self):
        for name, value in (("SERVICE_CERTIFICATE_TEMPLATE", "projects/other/locations/us-central1/certificateTemplates/server"),
                            ("CLIENT_CERTIFICATE_TEMPLATE", ""), ("CA_POOL_ID", "projects/test-project/locations/us-east1/caPools/test-pool")):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "base"
                values = self.values()
                values[name] = value
                with self.assertRaises(renderer.RenderError):
                    self.render(values, out)
                self.assertFalse(out.exists())

    def test_template_name_boundaries_match_terraform_fixtures(self):
        # Exact 63-char fixture is asserted in shared.tftest.hcl too, ensuring
        # the independently implemented Terraform and renderer derivations agree.
        def names(pool):
            return renderer.certificate_templates({"pki": {"ca_pool": pool},
                "project": {"id": "example-prod-123", "location": "us-central1-a"}})
        for length in (1, 55, 56, 63):
            pool = "a" * length
            with self.subTest(length=length):
                result = names(pool)
                self.assertEqual(len(set(result.values())), 2)
                for name in result.values():
                    self.assertRegex(name.split("/")[-1], r"^[a-zA-Z0-9_-]{1,63}$")
        self.assertTrue(names("a" * 55)["SERVICE_CERTIFICATE_TEMPLATE"].endswith("a" * 55 + "-service"))
        self.assertTrue(names("a" * 63)["SERVICE_CERTIFICATE_TEMPLATE"].endswith(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-7d3e74a05d7db15b-service"))
        self.assertNotEqual(names("a" * 63), names("a" * 62 + "b"))
        for pool in (None, "", "a" * 64, "../pool", "${POOL}", "pool\n"):
            with self.subTest(invalid=pool), self.assertRaises(renderer.RenderError):
                names(pool)


class ActionPathRender(BaseNetworkRender):
    """M3-1 action path lock inputs and the ClusterIP-only exposure check."""

    def items(self, out, rel):
        return json.loads((out / rel).read_text())["items"]

    def test_action_path_lock_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            self.render(self.values(), out)
            items = self.items(out, "action-path/services.yaml")
            services = {o["metadata"]["name"]: o["spec"] for o in items if o["kind"] == "Service"}
            self.assertEqual(services["policy-gateway"]["clusterIP"], "10.30.0.20")
            self.assertEqual(services["receiver"]["clusterIP"], "10.30.0.21")
            # receiver-probe (TASK-02 targets.yaml): its own lock ClusterIP over the receiver Pods.
            self.assertEqual(services["receiver-probe"]["clusterIP"], "10.30.0.22")
            self.assertEqual(services["receiver-probe"]["selector"], {"app.kubernetes.io/name": "receiver"})
            self.assertEqual(services["receiver-probe"]["ports"], services["receiver"]["ports"])
            for d in (o for o in items if o["kind"] == "Deployment"):
                with self.subTest(deployment=d["metadata"]["name"]):
                    self.assertEqual(d["spec"]["replicas"], 1)
                    self.assertEqual(d["spec"]["template"]["spec"]["nodeSelector"]["iam.gke.io/gke-metadata-server-enabled"], "true")
            self.assertTrue(all(s["type"] == "ClusterIP" for s in services.values()))
            spc = next(o for o in items if o["kind"] == "SecretProviderClass")
            self.assertEqual(spc["spec"]["parameters"]["secrets"],
                             '- resourceName: "projects/123456789012/secrets/receiver-api-key/versions/2"\n  path: "2"\n')
            receiver = next(o for o in items if o["kind"] == "Deployment" and o["metadata"]["name"] == "receiver")
            self.assertIn("--receiver-mode=idempotent", receiver["spec"]["template"]["spec"]["containers"][0]["args"])
            pod = next(o for o in self.items(out, "action-path/agent-runtime.yaml") if o["kind"] == "Pod")
            env = {e["name"]: e["value"] for e in pod["spec"]["containers"][0]["env"]}
            self.assertEqual(env["AGENTARIUM_TRUST_BUNDLE_PEM"], PEM)
            self.assertEqual(env["AGENTARIUM_GATEWAY_URL"], "https://10.30.0.20:8443")
            identity = next(o for o in self.items(out, "contact-services/contacts.yaml")
                            if o["kind"] == "Deployment" and o["metadata"]["name"] == "workload-identity")
            args = identity["spec"]["template"]["spec"]["containers"][0]["args"]
            self.assertIn("--oidc-audience=32555940559.apps.googleusercontent.com", args)
            self.assertIn("--bundle-key-file=/etc/agentarium-bundle-keys/prod-v1.pem", args)
            self.assertFalse(list(out.rglob("*.py")), "generators are not install output")

    def test_bad_action_path_lock_is_rejected(self):
        good = self.lock()["receiver"]
        bad_receivers = [
            dict(good, cluster_ip="10.30.0.20"), dict(good, cluster_ip="10.30.0.10"),
            dict(good, probe_cluster_ip="10.30.0.21"), dict(good, probe_cluster_ip="10.30.0.20"),
            dict(good, probe_cluster_ip="10.30.1.5"), {k: v for k, v in good.items() if k != "probe_cluster_ip"},
            dict(good, cluster_ip="10.31.0.5"), dict(good, cluster_ip="10.30.1.5"),
            dict(good, receiver_mode="sometimes"), dict(good, api_key_versions=["latest"]),
            dict(good, api_key_versions=["1", "2", "3"]), dict(good, api_key_versions=[]),
            dict(good, api_key_secret="projects/123456789012/secrets/identity-claim-key"),
            dict(good, api_key_secret="projects/p/secrets/x/versions/1"),
        ]
        for receiver in bad_receivers:
            with self.subTest(receiver=receiver), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "base"
                with self.assertRaises(renderer.RenderError):
                    self.render(self.values(), out, receiver=receiver)
                self.assertFalse(out.exists())
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(renderer.RenderError, "bundle_key_id"):
            lock = self.lock()
            lock["keys"]["bundle_key_id"] = "regression-v1"
            renderer.render(lock, self.values(), Path(tmp) / "base")
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(renderer.RenderError, "oidc_audiences"):
            lock = self.lock()
            lock["identity"]["oidc_audiences"] = []
            renderer.render(lock, self.values(), Path(tmp) / "base")

    def test_action_path_values_are_checked(self):
        other = "us-central1-docker.pkg.dev/test-project/agentarium/other@sha256:" + "b" * 64
        for key, value in (("EVIDENCE_PROBE_ACTION_KEY", "NOT-A-UUID"), ("AGENTARIUM_TENANT", "a b"),
                           ("RELEASE_VERSION", ""), ("TRUST_BUNDLE_PEM", "not pem"),
                           ("TRUST_BUNDLE_PEM", PEM + "trailing"), ("GATEWAY_IMAGE", ""),
                           ("RECEIVER_IMAGE", other), ("RUNTIME_IMAGE", "docker.io/x:latest")):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as tmp:
                values = self.values()
                values[key] = value
                with self.assertRaises(renderer.RenderError):
                    self.render(values, Path(tmp) / "base")
        for name in ("RECEIVER_MODE", "GATEWAY_CLUSTER_IP", "BUNDLE_KEY_ID", "OIDC_AUDIENCES"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                values = self.values()
                values[name] = "x"
                with self.assertRaisesRegex(renderer.RenderError, "comes from the lock"):
                    self.render(values, Path(tmp) / "base")

    def test_exposure_check_rejects_public_services(self):
        cases = {
            "LoadBalancer": {"type": "LoadBalancer"}, "NodePort": {"type": "NodePort"},
            "ExternalName": {"type": "ExternalName", "externalName": "example.com"},
            "externalIPs": {"type": "ClusterIP", "externalIPs": ["203.0.113.1"]},
            "nodePort": {"ports": [{"port": 8443, "nodePort": 30001}]},
        }
        for name, spec in cases.items():
            with self.subTest(name=name):
                doc = {"kind": "List", "items": [{"kind": "Service", "metadata": {"name": "x"}, "spec": spec}]}
                self.assertTrue(renderer.exposure_errors(Path("x.yaml"), json.dumps(doc)))
        ingress = {"kind": "List", "items": [{"kind": "Ingress", "metadata": {"name": "x"}}]}
        host_port = {"kind": "Pod", "spec": {"containers": [{"ports": [{"containerPort": 1, "hostPort": 1}]}]}}
        for doc in (ingress, host_port):
            self.assertTrue(renderer.exposure_errors(Path("x.yaml"), json.dumps(doc)))
        for text in ("kind: Service\nspec:\n  type: LoadBalancer\n", "apiVersion: networking.k8s.io/v1\nkind: Ingress\n",
                     "spec:\n  externalIPs: [1.2.3.4]\n"):
            self.assertTrue(renderer.exposure_errors(Path("x.yaml"), text), text)
        self.assertFalse(renderer.exposure_errors(Path("x.yaml"), "# type: LoadBalancer is forbidden\nkind: ConfigMap\n"))
        ok = {"kind": "List", "items": [{"kind": "Service", "metadata": {"name": "x"},
                                          "spec": {"type": "ClusterIP", "clusterIP": "10.30.0.20"}}]}
        self.assertFalse(renderer.exposure_errors(Path("x.yaml"), json.dumps(ok)))

    def test_render_fails_closed_on_an_exposed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "src"
            shutil.copytree(renderer.BASE, base, ignore=shutil.ignore_patterns("__pycache__"))
            path = base / "action-path/services.yaml"
            doc = json.loads(path.read_text())
            next(o for o in doc["items"] if o["kind"] == "Service")["spec"]["type"] = "LoadBalancer"
            path.write_text(json.dumps(doc))
            original, renderer.BASE = renderer.BASE, base
            try:
                out = Path(tmp) / "out"
                with self.assertRaisesRegex(renderer.RenderError, "public exposure"):
                    self.render(self.values(), out)
                self.assertFalse(out.exists())
            finally:
                renderer.BASE = original

    def test_example_lock_renders(self):
        """The committed example lock, with its REPLACE_WITH_* fields filled, renders."""
        lock = json.loads((renderer.BASE.parent / "environment.lock.example.json").read_text())
        lock["project"].update(id="test-project", location="us-central1-a")
        lock["gke"]["kubernetes_minor"] = "1.33"
        lock["pki"]["ca_pool"] = "test-pool"
        lock["identity"].update(claim_key_secret="projects/123456789012/secrets/identity-claim-key", claim_key_version="3",
                                oidc_audiences=["32555940559.apps.googleusercontent.com"], oidc_allowed_hd=["example.com"])
        lock["receiver"].update(api_key_secret="projects/123456789012/secrets/receiver-api-key", api_key_versions=["1"])
        lock["storage"].update(evidence_bucket="test-evidence", decision_input_exports_bucket="test-decision-inputs")
        lock["keys"]["manifest_signing_key"] = MANIFEST_KEY
        self.assertFalse("REPLACE_WITH" in json.dumps({k: lock[k] for k in ("identity", "receiver", "network")}))
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "base"
            written = {p.relative_to(out).as_posix() for p in renderer.render(lock, self.values(), out)}
            self.assertTrue({"action-path/services.yaml", "action-path/agent-runtime.yaml"} <= written)
            self.assertTrue((out / "installer/m3-1-action-path.sql").is_file())
            collector = next(o for o in self.items(out, "action-path/services.yaml")
                             if o["kind"] == "Deployment" and o["metadata"]["name"] == "evidence-collector")
            # control-health matches target lease sources against a fixed profile binding.
            self.assertIn("--health-source-id=evidence-collector/receiver-primary",
                          collector["spec"]["template"]["spec"]["containers"][0]["args"])

    def test_action_path_generator_is_current(self):
        spec = importlib.util.spec_from_file_location("generate", renderer.BASE / "action-path/generate.py")
        gen = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gen)
        self.assertEqual(gen.main(["--check"]), 0)
        # The generator refuses a second replica or a Pod without the WI selector.
        for mutate in (lambda d: d["spec"].update(replicas=2),
                       lambda d: d["spec"]["template"]["spec"]["nodeSelector"].pop("iam.gke.io/gke-metadata-server-enabled"),
                       lambda d: d["spec"].pop("strategy")):
            items = gen.services()
            mutate(next(o for o in items if o["kind"] == "Deployment" and o["metadata"]["name"] == "coordinator"))
            with self.assertRaises(SystemExit):
                gen.check(items)
