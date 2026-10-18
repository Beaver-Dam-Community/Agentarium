# migrations

Shared `golang-migrate` directory for every Task (TASK-03 3.2 and TASK-07 decide one shared directory).

- File name: `{version}_{prefix}_{title}.up.sql` and `.down.sql`.
- `version` is a UTC timestamp `YYYYMMDDHHMMSS`.
- `prefix` is the owning Task's schema prefix, for example `identity_`, `coordinator_`, `audit_`, `receiver_`, `discovery_`.
- golang-migrate does not apply files whose version is lower than the current version. Before opening a PR, rebase onto `main` and make sure every new version is greater than the latest version on `main`.
- Never edit a merged migration. Add a new one instead.
- A GRANT on another Task's schema goes in the migration of the Task that owns the granted object.
