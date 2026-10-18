# Operator database installation connection

`render-install-proxy.py` renders a temporary private Cloud SQL Auth Proxy Pod
and the existing workload-identity ServiceAccount from the contact-service
manifest. It does not create DB users, grant roles, apply manifests, start nodes,
or change admission/network policy. The normal application Deployments need not
start before this connection is available.

```sh
python3 platform/gcp/scripts/render-install-proxy.py \
  --lock /path/to/environment.lock.json \
  --proxy-image "$PINNED_PROXY_IMAGE" \
  --db-gsa "$IDENTITY_DB_GSA" > /tmp/install-proxy.json
```

Use a digest-pinned Proxy image mirrored into this environment's Artifact
Registry. `--db-gsa` must name the already configured workload-identity database
GSA. The KSA must have its existing impersonation relation; this renderer creates
no IAM binding. Only the Proxy uses the GSA. The operator supplies their own
approved DB login and short-lived IAM token to the local PostgreSQL client.
`--auto-iam-authn` is deliberately absent: the Proxy must not substitute the
application's DB identity for the installer's identity. Keep tokens in memory;
never add them to arguments, the manifest, a ConfigMap or logs.

Before applying the Pod, install the reviewed contact-service ServiceAccount,
rendered TASK-06 NetworkPolicies and the admission image allowlist. The Pod uses
the same protected control-node placement, non-root context and observation
bootstrap toleration as the contact-service Proxy. Do not bypass a missing KSA,
image allowlist, taint or egress rule by making the Pod privileged, using
hostNetwork, changing the SQL public IP, or weakening connector enforcement.
A server dry-run cannot create the KSA for subsequent objects in the same List;
validate the Pod only after the KSA exists.

Create the Pod only for an authorized installation window. It has no Service,
no projected application token/secret volumes, listens for DB connections on
127.0.0.1:5432, and terminates after 30 minutes. An operator can port-forward it
with `--address=127.0.0.1`; runtime callers receive no port-forward permission.
Check the actual Proxy readiness and DB current_user/privileges before invoking
migrations. The health probe confirms Proxy startup, not DB administrator access.

Apply merged migrations in version order using golang-migrate. A human IAM
DB login is blocked by Context-Aware Access (#123); migrations run from the
installer Job in `db-installer-job.md` instead. Register each
runtime login with only its specified application roles. Do not grant an
application IAM user CREATEROLE, CREATEDB, schema ownership or installer access.
DB admin registration, database ownership, initial grants and credential delivery
are separate installation inputs; this renderer does not invent those values.

Remove the temporary Pod and stop port-forwarding after installation. Keep the
workload-identity ServiceAccount, since the regular contact service uses it.
Revoke any explicitly temporary installer privileges without dropping owned
objects. Restore the prior compute state when the installation window ends.
No credential rotation or destructive rollback is part of this renderer.

Local validation:

```sh
python3 -m unittest discover -s tests/platform -p 'test_install_proxy.py' -v
```

These checks cover immutable image origin, matching project/region/GSA, private
loopback transport, absent automatic application DB authentication, bounded Pod
lifetime, and absence of secret mounts or cluster grants. They do not prove live
Proxy connectivity, Cloud SQL login, migrations, or application startup.
