#!/usr/bin/env python3
"""Render the one-shot migration installer Job (TASK-01, issue #123).

The Job applies merged golang-migrate files through a private Cloud SQL Proxy
sidecar that logs in with automatic IAM DB authentication as the dedicated
installer GSA. This only renders JSON. It does not create IAM bindings, DB
users or grants, apply manifests, relax admission/network policy, or start
billable compute.
"""

import argparse
import copy
import hashlib
import importlib.util
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
NAME = "db-installer"
MIGRATION_FILE = re.compile(r"([0-9]{14})_[a-z][a-z0-9_]*\.up\.sql")
# ConfigMaps are limited to 1 MiB; leave room for metadata.
MAX_MIGRATION_BYTES = 900 * 1024
# TASK-10 owns control_health_writer, but the older identity migration grants
# to it and fails when it is missing (contact-services README, step 2).
BOOTSTRAP_SQL = ("DO $installer$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'control_health_writer') "
                 "THEN CREATE ROLE control_health_writer NOLOGIN; END IF; END $installer$;")


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True).stdout


def load_migrations(ref, main_ref):
    """Read *.up.sql from a commit already merged into main_ref (not the worktree)."""
    try:
        commit = git("rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
        git("rev-parse", "--verify", f"{main_ref}^{{commit}}")
    except subprocess.CalledProcessError as exc:
        raise ValueError("unknown migrations or main ref") from exc
    if subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", commit, main_ref]).returncode != 0:
        raise ValueError(f"migrations commit {commit} is not merged into {main_ref}")
    names = git("ls-tree", "--name-only", f"{commit}:migrations").decode().split("\n")
    return commit, {n: git("show", f"{commit}:migrations/{n}").decode() for n in names if n.endswith(".up.sql")}


def check_append_only(previous, migrations):
    """Fail unless migrations only appends files newer than the last install.

    golang-migrate `up` skips files at or below the ledger version, so a new
    file older than the installed latest would be silently ignored.
    """
    previous_commit, previous_migrations = previous
    if not re.fullmatch(r"[0-9a-f]{40}", previous_commit):
        raise ValueError("previous migrations commit must be a full commit id")
    versions = []
    for name in previous_migrations:
        match = MIGRATION_FILE.fullmatch(name)
        if not match:
            raise ValueError(f"unexpected previous migration file name {name!r}")
        versions.append(match.group(1))
    if not versions:
        raise ValueError("previous commit has no migrations; use --first-install")
    for name, body in previous_migrations.items():
        if migrations.get(name) != body:
            raise ValueError(f"installed migration {name} is missing or changed")
    installed_latest = max(versions)
    for name in sorted(set(migrations) - set(previous_migrations)):
        match = MIGRATION_FILE.fullmatch(name)
        if match and match.group(1) <= installed_latest:
            raise ValueError(f"new migration {name} is not newer than installed latest {installed_latest}; "
                             "migrate up would skip it")


def render(lock, proxy_image, migrate_image, psql_image, db_gsa, db_name, commit, migrations, *, previous):
    """previous is (commit, migrations) of the last install, or None for the first install."""
    spec = importlib.util.spec_from_file_location("base_render", ROOT / "deploy/gcp/base/render.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pattern = module.image_pattern(lock)
    for image in (proxy_image, migrate_image, psql_image):
        try:
            module.check_value("SQL_PROXY_IMAGE", image, pattern)
        except module.RenderError as exc:
            raise ValueError(str(exc)) from exc
    project = lock["project"]["id"]
    connection = lock["storage"]["cloudsql_instance"]
    parts = connection.split(":")
    region = re.sub(r"-[a-z]$", "", lock["project"]["location"])
    if len(parts) != 3 or parts[:2] != [project, region] or not re.fullmatch(r"[a-z][a-z0-9-]{0,96}[a-z0-9]", parts[2]):
        raise ValueError("Cloud SQL connection must belong to the lock project")
    # Only the dedicated installer GSA; never a runtime contact/workload GSA.
    if db_gsa != f"{NAME}@{project}.iam.gserviceaccount.com":
        raise ValueError("expected the dedicated db-installer GSA of the lock project")
    db_user = db_gsa.removesuffix(".gserviceaccount.com")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", db_name):
        raise ValueError("database name must be a lowercase PostgreSQL identifier")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("migrations commit must be a full commit id")
    versions = {}
    for name in migrations:
        match = MIGRATION_FILE.fullmatch(name)
        if not match:
            raise ValueError(f"unexpected migration file name {name!r}")
        if match.group(1) in versions:
            raise ValueError(f"duplicate migration version {match.group(1)}")
        versions[match.group(1)] = name
    if not versions:
        raise ValueError("no migrations to apply")
    if sum(len(v.encode()) for v in migrations.values()) > MAX_MIGRATION_BYTES:
        raise ValueError("migrations exceed the ConfigMap size budget")
    if previous is not None:
        check_append_only(previous, migrations)
    latest = max(versions)
    digest = hashlib.sha256("".join(f"{n}\0{migrations[n]}\0" for n in sorted(migrations)).encode()).hexdigest()

    source = json.loads((ROOT / "deploy/gcp/base/contact-services/contacts.yaml").read_text())
    deployment = next(x for x in source["items"] if x["kind"] == "Deployment" and x["metadata"]["name"] == "workload-identity")
    base = deployment["spec"]["template"]["spec"]
    proxy = copy.deepcopy(next(c for c in base["initContainers"] if c["name"] == "cloud-sql-proxy"))
    proxy["image"] = proxy_image
    # The connector and the DB login both use the installer GSA.
    proxy["args"] = [a.replace("${IDENTITY_DB_GSA}", db_gsa).replace("${CLOUDSQL_CONNECTION_NAME}", connection)
                     for a in proxy["args"]]
    hardened = copy.deepcopy(proxy["securityContext"])
    small = {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}}
    env = [{"name": k, "value": v} for k, v in [
        ("PGHOST", "127.0.0.1"), ("PGPORT", "5432"), ("PGUSER", db_user), ("PGDATABASE", db_name),
        ("PGSSLMODE", "disable"), ("PGCONNECT_TIMEOUT", "10")]]
    precheck = (f"DO $installer$ BEGIN IF session_user <> '{db_user}' OR current_user <> session_user "
                "THEN RAISE EXCEPTION 'unexpected installer login %', session_user; END IF; "
                "IF NOT pg_has_role(current_user, 'cloudsqlsuperuser', 'MEMBER') "
                "THEN RAISE EXCEPTION 'installer login lacks cloudsqlsuperuser'; END IF; IF NOT (SELECT rolcreaterole FROM pg_roles WHERE rolname=current_user) THEN RAISE EXCEPTION 'installer login lacks direct CREATEROLE'; END IF; END $installer$;")
    verify = (f"DO $installer$ DECLARE v bigint; d boolean; BEGIN SELECT version, dirty INTO STRICT v, d FROM public.schema_migrations; "
              f"IF v <> {int(latest)} OR d THEN RAISE EXCEPTION 'ledger version % dirty % expected {latest}', v, d; END IF; END $installer$;")
    url = f"postgres://{db_user.replace('@', '%40')}@127.0.0.1:5432/{db_name}?sslmode=disable"
    labels = {"app.kubernetes.io/name": NAME, "agentarium.io/installation": "true"}
    annotations = {"agentarium.io/migrations-commit": commit, "agentarium.io/migrations-sha256": digest,
                   "agentarium.io/migrations-latest": latest,
                   "agentarium.io/migrations-previous-commit": "first-install" if previous is None else previous[0]}
    pod_spec = {
        "serviceAccountName": NAME,
        "automountServiceAccountToken": False,
        "nodeSelector": copy.deepcopy(base["nodeSelector"]),
        "schedulerName": base["schedulerName"],
        "securityContext": copy.deepcopy(base["securityContext"]),
        "tolerations": copy.deepcopy(base["tolerations"]),
        "terminationGracePeriodSeconds": 30,
        "restartPolicy": "Never",
        "initContainers": [
            proxy,
            {"name": "bootstrap", "image": psql_image, "command": ["psql"],
             "args": ["-X", "-v", "ON_ERROR_STOP=1", "-c", precheck, "-c", BOOTSTRAP_SQL],
             "env": env, "securityContext": copy.deepcopy(hardened), "resources": copy.deepcopy(small)},
            {"name": "migrate", "image": migrate_image,
             "args": ["-path=/migrations", f"-database={url}", "up"],
             "volumeMounts": [{"name": "migrations", "mountPath": "/migrations", "readOnly": True}],
             "securityContext": copy.deepcopy(hardened), "resources": copy.deepcopy(small)},
        ],
        "containers": [
            {"name": "verify", "image": psql_image, "command": ["psql"],
             "args": ["-X", "-v", "ON_ERROR_STOP=1", "-c", precheck, "-c", verify,
                      "-c", "SELECT version, dirty FROM public.schema_migrations;"],
             "env": env, "securityContext": copy.deepcopy(hardened), "resources": copy.deepcopy(small)},
        ],
        "volumes": [{"name": "migrations", "configMap": {"name": f"{NAME}-migrations", "defaultMode": 0o444}}],
    }
    namespace = "agent-control"
    items = [
        {"apiVersion": "v1", "kind": "ServiceAccount",
         "metadata": {"name": NAME, "namespace": namespace, "labels": dict(labels)},
         "automountServiceAccountToken": False},
        {"apiVersion": "v1", "kind": "ConfigMap",
         "metadata": {"name": f"{NAME}-migrations", "namespace": namespace, "labels": dict(labels),
                      "annotations": dict(annotations)},
         "immutable": True, "data": {n: migrations[n] for n in sorted(migrations)}},
        {"apiVersion": "batch/v1", "kind": "Job",
         "metadata": {"name": NAME, "namespace": namespace, "labels": dict(labels), "annotations": dict(annotations)},
         "spec": {"backoffLimit": 0, "completions": 1, "parallelism": 1, "activeDeadlineSeconds": 1800,
                  "ttlSecondsAfterFinished": 3600,
                  "template": {"metadata": {"labels": dict(labels), "annotations": dict(annotations)}, "spec": pod_spec}}},
    ]
    result = {"apiVersion": "v1", "kind": "List", "items": items}
    if "${" in json.dumps(items[2]):
        raise ValueError("unresolved template input")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--migrate-image", required=True)
    parser.add_argument("--psql-image", required=True)
    parser.add_argument("--db-gsa", required=True)
    parser.add_argument("--db-name", required=True)
    parser.add_argument("--migrations-ref", required=True, help="merged commit whose migrations/ is applied")
    parser.add_argument("--main-ref", default="origin/main")
    history = parser.add_mutually_exclusive_group(required=True)
    history.add_argument("--previous-commit",
                         help="migrations commit of the last successful install (its migrations-commit annotation)")
    history.add_argument("--first-install", action="store_true",
                         help="no migration has ever been installed on this database")
    args = parser.parse_args()
    try:
        commit, migrations = load_migrations(args.migrations_ref, args.main_ref)
        # The previous install must be an ancestor of the commit being installed.
        previous = None if args.first_install else load_migrations(args.previous_commit, commit)
        result = render(json.loads(args.lock.read_text()), args.proxy_image, args.migrate_image, args.psql_image,
                        args.db_gsa, args.db_name, commit, migrations, previous=previous)
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
