import importlib.util
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("db_installer_job", ROOT / "platform/gcp/scripts/render-db-installer-job.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

REG = "asia-northeast3-docker.pkg.dev/example-project/agentarium/"
RUNTIME_GSAS = ["workload-identity-db", "audit-writer-db", "control-health-db"]


class DBInstallerJobTests(unittest.TestCase):
    def setUp(self):
        self.lock = {"project": {"id": "example-project", "location": "asia-northeast3-a"},
                     "storage": {"cloudsql_instance": "example-project:asia-northeast3:agentarium"}}
        self.proxy = REG + "cloud-sql-proxy@sha256:" + "a" * 64
        self.migrate = REG + "migrate@sha256:" + "b" * 64
        self.psql = REG + "postgres@sha256:" + "c" * 64
        self.gsa = "db-installer@example-project.iam.gserviceaccount.com"
        self.commit = "d" * 40
        self.migrations = {"20261013161333_discovery_candidates.up.sql": "SELECT 1;",
                           "20261017121300_receiver_collector_reads.up.sql": "SELECT 2;"}

    def render(self, **kw):
        args = dict(lock=self.lock, proxy_image=self.proxy, migrate_image=self.migrate, psql_image=self.psql,
                    db_gsa=self.gsa, db_name="agentarium", commit=self.commit, migrations=self.migrations,
                    previous=None)
        args.update(kw)
        return renderer.render(**args)

    def test_one_shot_job_shape(self):
        result = self.render()
        self.assertEqual([x["kind"] for x in result["items"]], ["ServiceAccount", "ConfigMap", "Job"])
        sa, cm, job = result["items"]
        self.assertEqual({x["metadata"]["namespace"] for x in result["items"]}, {"agent-control"})
        self.assertFalse(sa["automountServiceAccountToken"])
        self.assertNotIn("annotations", sa["metadata"])  # no GSA annotation; Proxy impersonates
        self.assertTrue(cm["immutable"])
        self.assertEqual(sorted(cm["data"]), sorted(self.migrations))
        self.assertEqual(cm["metadata"]["annotations"]["agentarium.io/migrations-commit"], self.commit)
        self.assertEqual(cm["metadata"]["annotations"]["agentarium.io/migrations-latest"], "20261017121300")
        spec = job["spec"]
        self.assertEqual((spec["backoffLimit"], spec["completions"], spec["parallelism"]), (0, 1, 1))
        self.assertLessEqual(spec["activeDeadlineSeconds"], 1800)
        self.assertGreater(spec["ttlSecondsAfterFinished"], 0)
        pod = spec["template"]["spec"]
        self.assertEqual(spec["template"]["metadata"]["labels"]["app.kubernetes.io/name"], pod["serviceAccountName"])
        self.assertEqual(pod["serviceAccountName"], sa["metadata"]["name"])
        self.assertEqual(pod["restartPolicy"], "Never")
        self.assertEqual(pod["nodeSelector"], {"node-restriction.kubernetes.io/agentarium-role": "control", "iam.gke.io/gke-metadata-server-enabled": "true"})
        self.assertEqual(pod["schedulerName"], "default-scheduler")
        self.assertEqual(pod["tolerations"], [{"key": "agentarium.io/observe-not-ready", "operator": "Equal",
                                               "value": "true", "effect": "NoSchedule"}])
        self.assertTrue(pod["securityContext"]["runAsNonRoot"])
        self.assertEqual(pod["securityContext"]["runAsUser"], 65532)
        for key in ["hostNetwork", "hostPID", "hostIPC", "nodeName", "priorityClassName", "runtimeClassName"]:
            self.assertNotIn(key, pod)
        names = [c["name"] for c in pod["initContainers"]] + [c["name"] for c in pod["containers"]]
        self.assertEqual(names, ["cloud-sql-proxy", "bootstrap", "migrate", "verify"])
        self.assertEqual(pod["initContainers"][0]["restartPolicy"], "Always")  # native sidecar
        for c in pod["initContainers"] + pod["containers"]:
            sc = c["securityContext"]
            self.assertFalse(sc["allowPrivilegeEscalation"])
            self.assertTrue(sc["readOnlyRootFilesystem"])
            self.assertEqual(sc["capabilities"]["drop"], ["ALL"])
            self.assertIn(c["image"], [self.proxy, self.migrate, self.psql])
            self.assertIn("limits", c["resources"])

    def test_proxy_logs_in_as_installer_only(self):
        result = self.render()
        pod = result["items"][2]["spec"]["template"]["spec"]
        args = pod["initContainers"][0]["args"]
        for arg in ["--auto-iam-authn", "--private-ip", "--address=127.0.0.1", "--port=5432",
                    "--impersonate-service-account=" + self.gsa, "example-project:asia-northeast3:agentarium"]:
            self.assertIn(arg, args)
        text = json.dumps(result)
        for runtime in RUNTIME_GSAS:
            self.assertNotIn(runtime, text)
        migrate = pod["initContainers"][2]
        self.assertIn("-database=postgres://db-installer%40example-project.iam@127.0.0.1:5432/agentarium?sslmode=disable",
                      migrate["args"])
        self.assertEqual(migrate["args"][-1], "up")
        verify = " ".join(pod["containers"][0]["args"])
        self.assertIn("v <> 20261017121300 OR d", verify)
        for c in (pod["initContainers"][1], pod["containers"][0]):
            self.assertIn("pg_has_role(current_user, 'cloudsqlsuperuser', 'MEMBER')", " ".join(c["args"]))
            self.assertIn("session_user <> 'db-installer@example-project.iam'", " ".join(c["args"]))

    def test_no_credentials_or_service(self):
        result = self.render()
        self.assertNotIn("Service", [x["kind"] for x in result["items"]])
        pod = result["items"][2]["spec"]["template"]["spec"]
        self.assertFalse(pod["automountServiceAccountToken"])
        self.assertEqual(pod["volumes"], [{"name": "migrations", "configMap": {"name": "db-installer-migrations", "defaultMode": 0o444}}])
        for c in pod["initContainers"] + pod["containers"]:
            for m in c.get("volumeMounts", []):
                self.assertEqual(m, {"name": "migrations", "mountPath": "/migrations", "readOnly": True})
            for e in c.get("env", []):
                self.assertNotIn("valueFrom", e)
                self.assertNotRegex(e["name"], r"PASS|TOKEN|SECRET|KEY|CRED")
        text = json.dumps(pod)
        self.assertNotRegex(text, r"(?i)secret|password|projected|hostPath|\"serviceAccountToken\"")
        self.assertNotRegex(text, r"postgres://[^@\"]*:[^@\"]*@")  # no user:password in URL
        self.assertNotIn("${", text)

    def test_args_survive_kubernetes_variable_expansion(self):
        # The kubelet rewrites $$ to $ and expands $(VAR) in command/args, so a
        # DO $$ ... $$ block reaches psql as DO $ ... and fails (first GKE run).
        pod = self.render()["items"][2]["spec"]["template"]["spec"]
        for c in pod["initContainers"] + pod["containers"]:
            for arg in c.get("command", []) + c.get("args", []):
                self.assertNotIn("$$", arg, c["name"])
                self.assertNotRegex(arg, r"\$\(", c["name"])

    def test_rejects_unpinned_foreign_images(self):
        bad = ["migrate/migrate:v4.19.0", "docker.io/migrate/migrate@sha256:" + "b" * 64,
               self.migrate.replace("example-project", "foreign-project"), self.migrate.split("@")[0] + ":v4.19.0",
               REG.replace("asia-northeast3", "us-central1") + "migrate@sha256:" + "b" * 64,
               REG.replace("/agentarium/", "/other/") + "migrate@sha256:" + "b" * 64, ""]
        for slot in ["proxy_image", "migrate_image", "psql_image"]:
            for image in bad:
                with self.subTest(slot=slot, image=image), self.assertRaises(ValueError):
                    self.render(**{slot: image})

    def test_rejects_wrong_project_or_gsa(self):
        for gsa in ["", self.gsa.replace("example-project", "foreign-project"), "db-installer@example-project.iam",
                    *[f"{g}@example-project.iam.gserviceaccount.com" for g in RUNTIME_GSAS]]:
            with self.subTest(gsa=gsa), self.assertRaises(ValueError):
                self.render(db_gsa=gsa)
        for conn in ["foreign-project:asia-northeast3:agentarium", "example-project:us-central1:agentarium",
                     "example-project:asia-northeast3:bad\ninstance", "example-project:agentarium"]:
            with self.subTest(connection=conn), self.assertRaises(ValueError):
                self.render(lock={**self.lock, "storage": {"cloudsql_instance": conn}})
        for name in ["", "Agentarium", "a;drop", "db name", "x" * 64]:
            with self.subTest(db_name=name), self.assertRaises(ValueError):
                self.render(db_name=name)

    def test_rejects_unexpected_migration_inputs(self):
        cases = [{}, {"20261013161333_discovery_candidates.down.sql": "x"}, {"README.md": "x"},
                 {"2026101316133_short.up.sql": "x"}, {"../20261013161333_x.up.sql": "x"},
                 {"20261013161333_a.up.sql": "x", "20261013161333_b.up.sql": "y"},
                 {"20261013161333_a.up.sql": "x" * (renderer.MAX_MIGRATION_BYTES + 1)}]
        for migrations in cases:
            with self.subTest(files=sorted(migrations)), self.assertRaises(ValueError):
                self.render(migrations=migrations)
        for commit in ["HEAD", "d" * 39, "D" * 40]:
            with self.subTest(commit=commit), self.assertRaises(ValueError):
                self.render(commit=commit)

    def test_first_install_is_explicit(self):
        annotations = self.render()["items"][1]["metadata"]["annotations"]
        self.assertEqual(annotations["agentarium.io/migrations-previous-commit"], "first-install")
        with self.assertRaises(TypeError):  # no silent default
            renderer.render(self.lock, self.proxy, self.migrate, self.psql, self.gsa, "agentarium",
                            self.commit, self.migrations)

    def test_accepts_normal_append(self):
        previous = ("e" * 40, dict(self.migrations))
        migrations = {**self.migrations, "20261018110000_gateway_preview_data_class.up.sql": "SELECT 3;"}
        result = self.render(migrations=migrations, previous=previous)
        annotations = result["items"][2]["metadata"]["annotations"]
        self.assertEqual(annotations["agentarium.io/migrations-previous-commit"], "e" * 40)
        self.assertEqual(annotations["agentarium.io/migrations-latest"], "20261018110000")
        self.render(previous=previous)  # rerun of the installed commit adds nothing

    def test_rejects_new_migration_not_newer_than_installed(self):
        # Review of #156: main installed up to 110000; #245 then adds 100000.
        installed = {**self.migrations, "20261018110000_gateway_preview_data_class.up.sql": "SELECT 3;"}
        previous = ("e" * 40, installed)
        for name in ["20261018100000_adapter_model_turns.up.sql", "20261017201000_adapter_app_role.up.sql"]:
            migrations = {**installed, name: "SELECT 4;", "20261018120001_later.up.sql": "SELECT 5;"}
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "not newer than installed latest 20261018110000"):
                self.render(migrations=migrations, previous=previous)

    def test_rejects_changed_or_missing_installed_migration(self):
        previous = ("e" * 40, dict(self.migrations))
        changed = {**self.migrations, "20261013161333_discovery_candidates.up.sql": "SELECT 10;",
                   "20261018120001_later.up.sql": "SELECT 5;"}
        missing = {"20261017121300_receiver_collector_reads.up.sql": "SELECT 2;",
                   "20261018120001_later.up.sql": "SELECT 5;"}
        for migrations in [changed, missing]:
            with self.subTest(files=sorted(migrations)), self.assertRaisesRegex(ValueError, "missing or changed"):
                self.render(migrations=migrations, previous=previous)
        for bad in [("e" * 40, {}), ("HEAD", dict(self.migrations)), ("e" * 40, {"README.md": "x"})]:
            with self.subTest(previous=bad[0], files=sorted(bad[1])), self.assertRaises(ValueError):
                self.render(previous=bad)

    def test_loads_only_committed_merged_up_files(self):
        commit, migrations = renderer.load_migrations("HEAD", "HEAD")
        self.assertRegex(commit, r"^[0-9a-f]{40}$")
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-tree", "--name-only", f"{commit}:migrations"],
                                 check=True, capture_output=True, text=True).stdout.split()
        self.assertEqual(sorted(migrations), sorted(n for n in tracked if n.endswith(".up.sql")))
        self.assertTrue(all(re.fullmatch(r"[0-9]{14}_[a-z0-9_]+\.up\.sql", n) for n in migrations))
        self.render(commit=commit, migrations=migrations)  # every current migration passes validation
        previous = renderer.load_migrations("HEAD~1", commit)  # previous install must be an ancestor
        self.render(commit=commit, migrations=migrations, previous=previous)
        with self.assertRaises(ValueError):
            renderer.load_migrations("HEAD", "HEAD~1")  # not merged into the given main
        with self.assertRaises(ValueError):
            renderer.load_migrations("no-such-ref", "HEAD")


if __name__ == "__main__":
    unittest.main()
