# Migration installer Job (issue #123)

A human IAM DB login cannot be used for installation: the operator's inherited
Context-Aware Access policy cannot be combined with Cloud SQL connector IAM DB
authentication. The owner decision (2026-10-17) is a dedicated installer
identity:

```text
Job agent-control/db-installer (KSA db-installer, one shot)
  -> native Cloud SQL Proxy sidecar, --auto-iam-authn, impersonates db-installer GSA
  -> private Cloud SQL (connector enforcement REQUIRED, IAM auth on)
  -> login db-installer@PROJECT.iam, member of cloudsqlsuperuser
```

Context policy, connector enforcement, the postgres user and every runtime GSA
stay unchanged. Runtime identities gain no role, binding or DB privilege.

## Pieces

- Terraform `platform/gcp/iam/db-installer` (wired in `envs/prod` as
  `module.db_installer`): GSA `db-installer`, Cloud SQL user of type
  `CLOUD_IAM_SERVICE_ACCOUNT` with `database_roles = ["cloudsqlsuperuser"]`,
  instance-scoped `roles/cloudsql.client` and `roles/cloudsql.instanceUser`,
  and `roles/serviceusage.serviceUsageConsumer` (required for Proxy
  impersonation, same as the contact DB GSAs). The KSA binding
  `roles/iam.workloadIdentityUser` for exactly
  `ns/agent-control/sa/db-installer` exists only while
  `db_installer_workload_binding = true` (default `false`).
- `render-db-installer-job.py` renders KSA `db-installer`, an immutable
  ConfigMap with the `*.up.sql` files of a commit already merged into
  `origin/main` (read from git objects, not the worktree), and the Job. It
  requires exactly one of `--previous-commit` or `--first-install` (see
  [Append-only check](#append-only-check)).
- `deploy/gcp/base/network/allow-matrix.yaml` workload
  `agent-control/db-installer` with egress to kube-dns, Cloud SQL (TCP/3307),
  Private Google Access and the metadata server only; no ingress.

The Job runs, in order: the Proxy sidecar; `bootstrap` (psql) which refuses to
continue unless `session_user` is the installer login, it is a member of
`cloudsqlsuperuser`, and the login itself has the CREATEROLE attribute
(`pg_roles.rolcreaterole`; membership does not inherit it), then creates NOLOGIN `control_health_writer` if missing
(required before the identity migration, see contact-services README step 2);
`migrate` (golang-migrate `up`, ledger `public.schema_migrations`); and
`verify`, which fails unless the ledger is at the rendered latest version and
not dirty, then prints it. `backoffLimit: 0`: a failed migration leaves a dirty
ledger for a human decision, never an automatic retry or `force`.

## cloudsqlsuperuser grant

The membership is a PostgreSQL grant that only Cloud SQL can make for this
login: no existing cloudsqlsuperuser member can log in (the human installer is
blocked by #123 and postgres must not be reset). Cloud SQL applies it from the
user's `databaseRoles`:

- Terraform sends `database_roles` on create. The attribute is write-only in
  provider 8.6.0, so drift is invisible to plan.
- The operator re-asserts it once after the apply. It is idempotent and does
  not remove other roles (no `--revoke-existing-roles`). The caller needs
  `cloudsql.users.update` (Cloud SQL Admin):

  ```sh
  gcloud sql users assign-roles "db-installer@${PROJECT}.iam" \
    --project "$PROJECT" --instance "$INSTANCE" \
    --type CLOUD_IAM_SERVICE_ACCOUNT --database-roles cloudsqlsuperuser
  ```

- The Job checks the result in SQL before any migration (exact statement in
  the rendered `bootstrap` container):

  ```sql
  SELECT session_user, pg_has_role(current_user, 'cloudsqlsuperuser', 'MEMBER'),
         (SELECT rolcreaterole FROM pg_roles WHERE rolname = current_user);
  ```

- The check assumes Cloud SQL gives the IAM service account user the
  CREATEROLE attribute directly along with `cloudsqlsuperuser`. This has not
  been confirmed on the real instance. If it does not, `bootstrap` fails closed
  with `installer login lacks direct CREATEROLE` (or `lacks cloudsqlsuperuser`)
  before any migration, and the ledger is untouched. Then:
  1. Disable the workload binding (step 9 below) and delete the Job.
  2. Re-run the `gcloud sql users assign-roles` command above, read the user
     back with `gcloud sql users describe`, and render and run a new Job once.
  3. If `bootstrap` fails the same way, stop the window. Do not log in as
     `postgres`, reset its password, or grant the attribute by hand. Escalate
     to the owner with the `bootstrap` log and the `describe` output; the
     installer design (#123) needs a decision before any migration runs.

## Operator sequence

Do this only in an authorized installation window. Values come from the ignored
environment lock and local render inputs; never commit them.

```sh
cd /path/to/Agentarium   # clean checkout of origin/main that contains this change
LOCK=deploy/gcp/environment.lock.json
PROJECT=$(jq -r .project.id "$LOCK")
INSTANCE=$(jq -r '.storage.cloudsql_instance | split(":")[2]' "$LOCK")
AR="$(jq -r '.project.location | sub("-[a-z]$"; "")' "$LOCK")-docker.pkg.dev/${PROJECT}/agentarium"

# 1. Power on (nodes + Cloud SQL).
platform/gcp/scripts/power.sh on --lock "$LOCK"

# 2. Targeted apply: GSA, IAM, SQL user. Binding stays off. Review the plan:
#    it must add only module.db_installer resources.
cd platform/gcp/envs/prod
terraform init -backend-config=backend.hcl
terraform plan  -var lock_path="../../../$LOCK" -target=module.db_installer -out=installer.tfplan
terraform apply installer.tfplan
cd -

# 3. Grant step (idempotent re-assert of cloudsqlsuperuser) and read back.
gcloud sql users assign-roles "db-installer@${PROJECT}.iam" --project "$PROJECT" \
  --instance "$INSTANCE" --type CLOUD_IAM_SERVICE_ACCOUNT --database-roles cloudsqlsuperuser
gcloud sql users describe "db-installer@${PROJECT}.iam" --project "$PROJECT" --instance "$INSTANCE"

# 4. Mirror the two Job images (linux/amd64) and read the destination digests
#    back from Artifact Registry. Sources verified locally with this change:
#    migrate/migrate:v4.19.0  sha256:d5c978181e3bfa55cc50e3bd8d7da3d87418a87693453250a8804b81ee6494db
#    postgres:16-alpine       PostgreSQL 16.15 (pin the digest you mirror)
crane copy --platform linux/amd64 \
  docker.io/migrate/migrate@sha256:d5c978181e3bfa55cc50e3bd8d7da3d87418a87693453250a8804b81ee6494db "$AR/migrate:v4.19.0"
crane copy --platform linux/amd64 "docker.io/library/postgres@$POSTGRES_16_DIGEST" "$AR/postgres:16-alpine"
gcloud artifacts docker images describe "$AR/migrate:v4.19.0"  --format='value(image_summary.digest)'
gcloud artifacts docker images describe "$AR/postgres:16-alpine" --format='value(image_summary.digest)'
MIGRATE_IMAGE="$AR/migrate@sha256:..."; PSQL_IMAGE="$AR/postgres@sha256:..."
PROXY_IMAGE="$AR/cloud-sql-proxy@sha256:..."   # the digest already allowlisted by #121

# 5. Admission allowlist and NetworkPolicy. Append MIGRATE_IMAGE and PSQL_IMAGE
#    to AGENT_CONTROL_IMAGES in the local values file, render, and apply only
#    the constraints ConfigMap and the rendered policies (adds db-installer-allow).
python3 deploy/gcp/base/render.py --lock "$LOCK" --values /path/to/values.json --out /tmp/base-install
kubectl apply -f /tmp/base-install/admission/constraints.yaml
kubectl apply -f /tmp/base-install/network/rendered/policies.yaml

# 6. Enable the KSA -> GSA binding for the window only.
cd platform/gcp/envs/prod
terraform plan -var lock_path="../../../$LOCK" -var db_installer_workload_binding=true \
  -target=module.db_installer -out=window-on.tfplan    # must add exactly one IAM member
terraform apply window-on.tfplan
cd -

# 7. Render and run the Job. `create`, not client-side `apply`: the ConfigMap
#    is too large for the last-applied annotation and is immutable.
#    HISTORY is `--previous-commit <migrations-commit of the last successful
#    install>` (recorded in step 8), or `--first-install` only when no
#    migration has ever been applied to this database. Rendering fails if the
#    new commit changes or drops an installed file or adds a file whose version
#    is not newer than the installed latest; see Append-only check.
HISTORY=(--previous-commit "$PREVIOUS_MIGRATIONS_COMMIT")   # or: HISTORY=(--first-install)
python3 platform/gcp/scripts/render-db-installer-job.py --lock "$LOCK" \
  --proxy-image "$PROXY_IMAGE" --migrate-image "$MIGRATE_IMAGE" --psql-image "$PSQL_IMAGE" \
  --db-gsa "db-installer@${PROJECT}.iam.gserviceaccount.com" --db-name "$DB_NAME" \
  --migrations-ref origin/main "${HISTORY[@]}" > /tmp/db-installer.json
jq '.items[0]' /tmp/db-installer.json | kubectl create -f -                  # KSA first
jq '.items |= .[1:]' /tmp/db-installer.json > /tmp/db-installer-rest.json
kubectl create --dry-run=server -f /tmp/db-installer-rest.json
# Pod admission policies match Pods, not Jobs: dry-run the Job's Pod template too.
jq '.items[2] | {apiVersion: "v1", kind: "Pod", spec: .spec.template.spec,
    metadata: (.spec.template.metadata + {name: "db-installer-dryrun", namespace: .metadata.namespace})}' \
  /tmp/db-installer.json | kubectl create --dry-run=server -f -
kubectl create -f /tmp/db-installer-rest.json
kubectl -n agent-control wait job/db-installer --for=condition=Complete --timeout=30m

# 8. Verify the ledger (Job TTL removes Pods after 1 hour; capture now).
kubectl -n agent-control logs job/db-installer -c bootstrap
kubectl -n agent-control logs job/db-installer -c migrate
kubectl -n agent-control logs job/db-installer -c verify   # version = migrations-latest annotation, dirty = f
kubectl -n agent-control get configmap db-installer-migrations \
  -o jsonpath='{.metadata.annotations}'
#    Record agentarium.io/migrations-commit with the install record: it is the
#    --previous-commit of the next install.

# 9. Disable the binding (also on failure), then remove the window objects and
#    restore the previous AGENT_CONTROL_IMAGES value.
cd platform/gcp/envs/prod
terraform plan -var lock_path="../../../$LOCK" -target=module.db_installer -out=window-off.tfplan  # must destroy exactly the one IAM member
terraform apply window-off.tfplan
cd -
kubectl -n agent-control delete job/db-installer configmap/db-installer-migrations serviceaccount/db-installer --ignore-not-found
python3 deploy/gcp/base/render.py --lock "$LOCK" --values /path/to/values-previous.json --out /tmp/base-restore
kubectl apply -f /tmp/base-restore/admission/constraints.yaml

# 10. Power off.
platform/gcp/scripts/power.sh off --lock "$LOCK"
```

Server dry-run cannot see a KSA created in the same List, so step 7 creates
the KSA before dry-running the ConfigMap and Job. If the Job fails, keep the binding off, read
the `migrate` log and the ledger, and decide manually; never `migrate force`
without review. `--db-name` must be the database used by the contact-service
render values; the Job does not create a database.

The installer login keeps cloudsqlsuperuser and owns the migrated objects, so
it is not dropped (`deletion_policy = "ABANDON"`). With the binding removed, no
workload can impersonate the GSA. The objects it owns include SECURITY DEFINER
functions that run with its privileges until their migrations move them to a
dedicated owner role: `identity.revoke_approvals_for_policy_change`,
`identity.audit_source_certificate`, `coordinator.bind_activation_probe_action`,
`coordinator.resolve_unknown_attempt` and `release.lock_active_policy`. Runtime logins still need their install-time
role memberships (contact-services README step 3), which this Job does not
grant.

## Failure recovery and migration order

The IAM-login quoting fix from #162 is merged. The installer now also checks
that the login itself has CREATEROLE; cloudsqlsuperuser membership does not
inherit that role attribute.

For a failed migration, keep the workload binding disabled and inspect the
failed migration, logs and schema_migrations row. Confirm whether its transaction
rolled back and record the actual schema state before choosing a recovery
version. Only after that review may an operator use `migrate force <verified
version>` and rerun. `force` changes the ledger; it never reverses partial DDL.
Do not automatically force the previous version or erase a dirty ledger.

### Append-only check

`migrate up` applies only files newer than the ledger version. A file whose
version is at or below the installed latest is skipped, and `verify` still
passes because the ledger reaches the new latest (reproduced in the #156
review: installed `20261018110000`, then a new `20261018100000` was never
applied). The repository migration CI rejects such versions against the base
branch, but a PR merged on a stale CI result can still introduce one.

The renderer therefore needs the last installed commit:

- `--previous-commit <sha>` must be an ancestor of `--migrations-ref`. Every
  `*.up.sql` present at that commit must exist unchanged in the new commit,
  and every added file must have a version greater than the previous commit's
  latest. Otherwise rendering fails and nothing is created. Fix the migration
  (renumber it above the installed latest in a new PR); do not bypass the check
  with `--first-install`.
- `--first-install` is only for a database with no `public.schema_migrations`
  ledger. It records `first-install` in the
  `agentarium.io/migrations-previous-commit` annotation.

The check compares git history only. The operator is responsible for passing
the commit that was actually installed (the `migrations-commit` annotation from
the last successful Job). The Job's verify step checks the exact latest version
and dirty flag, not every historical schema object.

## Local checks

```sh
python3 -m unittest discover -s tests/platform -p 'test_db_installer_job.py' -v
go test ./tests/platform/admission -run TestDBInstallerJobAdmission -v
(cd platform/gcp/iam/db-installer && terraform init -backend=false && terraform validate && terraform test)
(cd platform/gcp/envs/prod && terraform init -backend=false && terraform validate && terraform test)
DB_INSTALLER_DOCKER=1 python3 -m unittest discover -s tests/platform -p 'test_db_installer_job_pg.py' -v
```

The PostgreSQL 16 test runs the rendered `bootstrap`/`migrate`/`verify`
commands as uid 65532 with a read-only root against a disposable container,
as a non-superuser `cloudsqlsuperuser` member, twice (fresh install, then
no-change rerun). It does not emulate the Proxy, IAM, Cloud SQL or GKE.
