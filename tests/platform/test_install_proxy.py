import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("install_proxy", ROOT / "platform/gcp/scripts/render-install-proxy.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)


class InstallProxyTests(unittest.TestCase):
    def setUp(self):
        self.lock = {"project": {"id": "example-project", "location": "asia-northeast3-a"},
                     "storage": {"cloudsql_instance": "example-project:asia-northeast3:agentarium"}}
        self.image = "asia-northeast3-docker.pkg.dev/example-project/agentarium/cloud-sql-proxy@sha256:" + "a" * 64
        self.gsa = "workload-identity-db@example-project.iam.gserviceaccount.com"

    def test_operator_connection_does_not_become_runtime_db_identity(self):
        result = renderer.render(self.lock, self.image, self.gsa)
        self.assertEqual([x["kind"] for x in result["items"]], ["ServiceAccount", "Pod"])
        pod = result["items"][1]
        self.assertEqual(pod["metadata"]["labels"]["app.kubernetes.io/name"], pod["spec"]["serviceAccountName"])
        self.assertFalse(pod["spec"]["automountServiceAccountToken"])
        self.assertEqual(pod["spec"]["restartPolicy"], "Never")
        self.assertLessEqual(pod["spec"]["activeDeadlineSeconds"], 1800)
        self.assertNotIn("volumes", pod["spec"])
        self.assertNotIn("initContainers", pod["spec"])
        self.assertNotIn("hostNetwork", pod["spec"])
        self.assertNotIn("nodeName", pod["spec"])
        proxy, = pod["spec"]["containers"]
        args = proxy["args"]
        self.assertIn("--address=127.0.0.1", args)
        self.assertIn("--private-ip", args)
        self.assertNotIn("--auto-iam-authn", args)
        self.assertNotIn("env", proxy)
        self.assertNotIn("volumeMounts", proxy)
        self.assertFalse(proxy["securityContext"]["allowPrivilegeEscalation"])
        self.assertTrue(proxy["securityContext"]["readOnlyRootFilesystem"])
        self.assertNotIn("${", json.dumps(result))

    def test_wrong_project_region_identity_and_unpinned_image_rejected(self):
        for image in ["gcr.io/cloud-sql-connectors/cloud-sql-proxy:latest", self.image.replace("example-project", "foreign-project"), self.image.split("@")[0]+":2.26.2"]:
            with self.subTest(image=image), self.assertRaises(ValueError):
                renderer.render(self.lock, image, self.gsa)
        for gsa in ["", self.gsa.replace("workload-identity-db", "audit-writer-db"), self.gsa.replace("example-project", "foreign-project")]:
            with self.subTest(gsa=gsa), self.assertRaises(ValueError):
                renderer.render(self.lock, self.image, gsa)
        for conn in ["foreign-project:asia-northeast3:agentarium", "example-project:us-central1:agentarium", "example-project:asia-northeast3:bad\ninstance"]:
            with self.subTest(connection=conn), self.assertRaises(ValueError):
                renderer.render({**self.lock, "storage": {"cloudsql_instance": conn}}, self.image, self.gsa)


if __name__ == "__main__":
    unittest.main()
