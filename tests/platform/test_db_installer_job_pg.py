"""Run the rendered installer Job containers against disposable PostgreSQL 16.

Opt-in (needs Docker): DB_INSTALLER_DOCKER=1 python3 -m unittest \
    discover -s tests/platform -p 'test_db_installer_job_pg.py' -v

Never points at Cloud SQL. The Cloud SQL Proxy sidecar is not emulated: the
installer login connects over loopback with trust auth, standing in for
automatic IAM authentication. It is a non-superuser member of a local
cloudsqlsuperuser role (CREATEROLE CREATEDB) that owns the database, matching
Cloud SQL's installer privileges. Each container runs with the rendered
command/args/env, non-root uid 65532, read-only root and no capabilities.
"""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("db_installer_job", ROOT / "platform/gcp/scripts/render-db-installer-job.py")
renderer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(renderer)

SERVER_IMAGE = os.environ.get("DB_INSTALLER_POSTGRES_IMAGE", "postgres:16-alpine")
MIGRATE_IMAGE = os.environ.get("DB_INSTALLER_MIGRATE_IMAGE", "migrate/migrate:v4.19.0")
REG = "asia-northeast3-docker.pkg.dev/example-project/agentarium/"
INSTALLER = "db-installer@example-project.iam"


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=check)


@unittest.skipUnless(os.environ.get("DB_INSTALLER_DOCKER") == "1" and shutil.which("docker"), "set DB_INSTALLER_DOCKER=1")
class InstallerJobPostgresTests(unittest.TestCase):
    def setUp(self):
        self.name = f"agentarium-db-installer-test-{os.getpid()}"
        docker("run", "--rm", "-d", "--tmpfs", "/var/lib/postgresql/data:rw,size=512m", "--name", self.name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", SERVER_IMAGE)
        self.addCleanup(docker, "rm", "-fv", self.name, check=False)
        for _ in range(60):
            if docker("exec", self.name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", check=False).returncode == 0:
                break
            time.sleep(1)
        self.admin("CREATE ROLE cloudsqlsuperuser NOLOGIN CREATEROLE CREATEDB",
                   f'CREATE ROLE "{INSTALLER}" LOGIN CREATEROLE CREATEDB IN ROLE cloudsqlsuperuser',
                   'CREATE ROLE "workload-identity-db@example-project.iam" LOGIN',
                   "CREATE DATABASE agentarium OWNER cloudsqlsuperuser")
        commit, self.migrations = renderer.load_migrations("HEAD", "HEAD")
        lock = {"project": {"id": "example-project", "location": "asia-northeast3-a"},
                "storage": {"cloudsql_instance": "example-project:asia-northeast3:agentarium"}}
        result = renderer.render(lock, REG + "cloud-sql-proxy@sha256:" + "a" * 64, REG + "migrate@sha256:" + "b" * 64,
                                 REG + "postgres@sha256:" + "c" * 64, "db-installer@example-project.iam.gserviceaccount.com",
                                 "agentarium", commit, self.migrations, previous=None)
        self.configmap, self.job = result["items"][1], result["items"][2]
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for name, body in self.configmap["data"].items():
            (self.dir / name).write_text(body)
        self.latest = int(self.configmap["metadata"]["annotations"]["agentarium.io/migrations-latest"])

    def admin(self, *statements, db="postgres"):
        for s in statements:
            docker("exec", self.name, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", db, "-c", s)

    def query(self, sql, user="postgres"):
        return docker("exec", self.name, "psql", "-X", "-At", "-U", user, "-d", "agentarium", "-c", sql).stdout.strip()

    def run_container(self, c, image):
        cmd = ["run", "--rm", "--network", f"container:{self.name}", "-u", "65532:65532", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
        for e in c.get("env", []):
            cmd += ["-e", f"{e['name']}={e['value']}"]
        for m in c.get("volumeMounts", []):
            cmd += ["-v", f"{self.dir}:{m['mountPath']}:ro"]
        if c.get("command"):
            cmd += ["--entrypoint", c["command"][0]]
        return docker(*cmd, image, *c.get("command", [])[1:], *c["args"], check=False)

    def run_job(self):
        """Run init containers in order then the main container, like the kubelet."""
        pod = self.job["spec"]["template"]["spec"]
        images = {"bootstrap": SERVER_IMAGE, "migrate": MIGRATE_IMAGE, "verify": SERVER_IMAGE}
        outputs = []
        for c in pod["initContainers"][1:] + pod["containers"]:
            out = self.run_container(c, images[c["name"]])
            outputs.append((c["name"], out))
            if out.returncode != 0:
                break
        return outputs

    def test_fresh_install_then_idempotent_rerun(self):
        first = self.run_job()
        for name, out in first:
            self.assertEqual(out.returncode, 0, f"{name}: {out.stdout}\n{out.stderr}")
        self.assertEqual([n for n, _ in first], ["bootstrap", "migrate", "verify"])
        self.assertEqual(self.query("SELECT version, dirty FROM public.schema_migrations"), f"{self.latest}|f")
        self.assertIn(f"{self.latest} | f", first[-1][1].stdout)
        schemas = set(self.query("SELECT nspname FROM pg_namespace").split())
        self.assertTrue({"identity", "audit", "health"} <= schemas, schemas)
        # Objects are owned by the installer login or roles it created, never a runtime login.
        owners = set(self.query("SELECT DISTINCT pg_get_userbyid(nspowner) FROM pg_namespace "
                                "WHERE nspname NOT LIKE 'pg_%' AND nspname NOT IN ('public','information_schema')").split("\n"))
        self.assertNotIn("workload-identity-db@example-project.iam", owners)
        self.assertEqual(self.query("SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles "
                                    "WHERE rolname = 'workload-identity-db@example-project.iam'"), "f")
        self.assertEqual(self.query("SELECT pg_has_role('workload-identity-db@example-project.iam', 'identity_app', 'MEMBER')"), "f")

        second = self.run_job()
        for name, out in second:
            self.assertEqual(out.returncode, 0, f"{name}: {out.stdout}\n{out.stderr}")
        self.assertIn("no change", second[1][1].stderr)
        self.assertEqual(self.query("SELECT version, dirty FROM public.schema_migrations"), f"{self.latest}|f")

    def test_refuses_inherited_but_not_direct_createrole(self):
        self.admin(f'ALTER ROLE "{INSTALLER}" NOCREATEROLE')
        outputs = self.run_job()
        self.assertEqual([n for n, _ in outputs], ["bootstrap"])
        self.assertNotEqual(outputs[0][1].returncode, 0)
        self.assertIn("lacks direct CREATEROLE", outputs[0][1].stderr)
        self.assertEqual(self.query("SELECT to_regclass('public.schema_migrations') IS NULL"), "t")

    def test_refuses_login_without_cloudsqlsuperuser(self):
        self.admin(f'REVOKE cloudsqlsuperuser FROM "{INSTALLER}"')
        outputs = self.run_job()
        self.assertEqual([n for n, _ in outputs], ["bootstrap"])
        self.assertNotEqual(outputs[0][1].returncode, 0)
        self.assertIn("lacks cloudsqlsuperuser", outputs[0][1].stderr)
        self.assertEqual(self.query("SELECT to_regclass('public.schema_migrations') IS NULL"), "t")


if __name__ == "__main__":
    unittest.main()
