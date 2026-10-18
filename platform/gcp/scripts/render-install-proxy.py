#!/usr/bin/env python3
"""Render a temporary private Cloud SQL Proxy Pod for operator DB installation.

This only renders JSON. It does not create an IAM DB login, grant privileges,
apply manifests, relax admission/network policies, or start billable compute.
The operator authenticates to PostgreSQL separately using their own IAM token.
"""

import argparse
import copy
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]


def render(lock, image, db_gsa):
    spec = importlib.util.spec_from_file_location("base_render", ROOT / "deploy/gcp/base/render.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        module.check_value("SQL_PROXY_IMAGE", image, module.image_pattern(lock))
    except module.RenderError as exc:
        raise ValueError(str(exc)) from exc
    project = lock["project"]["id"]
    connection = lock["storage"]["cloudsql_instance"]
    parts = connection.split(":")
    region = re.sub(r"-[a-z]$", "", lock["project"]["location"])
    if len(parts) != 3 or parts[:2] != [project, region] or not re.fullmatch(r"[a-z][a-z0-9-]{0,96}[a-z0-9]", parts[2]):
        raise ValueError("Cloud SQL connection must belong to the lock project")
    # Reuse the already specified contact-service impersonation relation. This
    # renderer must not grant that KSA another GSA or give its DB user admin.
    if db_gsa != f"workload-identity-db@{project}.iam.gserviceaccount.com":
        raise ValueError("expected the existing workload-identity database GSA")
    source = json.loads((ROOT / "deploy/gcp/base/contact-services/contacts.yaml").read_text())
    sa = next(x for x in source["items"] if x["kind"] == "ServiceAccount" and x["metadata"]["name"] == "workload-identity")
    deployment = next(x for x in source["items"] if x["kind"] == "Deployment" and x["metadata"]["name"] == "workload-identity")
    template = deployment["spec"]["template"]
    pod_spec = copy.deepcopy(template["spec"])
    proxy = next(c for c in pod_spec["initContainers"] if c["name"] == "cloud-sql-proxy")
    proxy.pop("restartPolicy")
    proxy["image"] = image
    # The proxy's GSA authorizes the connector. The operator's IAM token supplies
    # DB authentication, so auto-iam-authn must not replace it with the app login.
    proxy["args"] = [a.replace("${IDENTITY_DB_GSA}", db_gsa).replace("${CLOUDSQL_CONNECTION_NAME}", connection)
                     for a in proxy["args"] if a != "--auto-iam-authn"]
    pod_spec["containers"] = [proxy]
    pod_spec.pop("initContainers")
    pod_spec.pop("volumes", None)
    proxy.pop("volumeMounts", None)
    pod_spec["restartPolicy"] = "Never"
    pod_spec["activeDeadlineSeconds"] = 1800
    metadata = copy.deepcopy(template["metadata"])
    metadata.update(name="agentarium-install-proxy", namespace=sa["metadata"]["namespace"])
    metadata["labels"]["agentarium.io/installation"] = "true"
    pod = {"apiVersion": "v1", "kind": "Pod", "metadata": metadata, "spec": pod_spec}
    result = {"apiVersion": "v1", "kind": "List", "items": [sa, pod]}
    if "${" in json.dumps(result):
        raise ValueError("unresolved template input")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--proxy-image", required=True)
    parser.add_argument("--db-gsa", required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(render(json.loads(args.lock.read_text()), args.proxy_image, args.db_gsa), indent=2))
    except (ValueError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
