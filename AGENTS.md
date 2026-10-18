# Agent rules for Agentarium

Two people (`rina`, `siu`) build this repository in parallel, each with their own AI agents. These rules keep their work from colliding. Documentation rules in [docs/AGENTS.md](docs/AGENTS.md) still apply to `docs/` and README.

## Before you start

- Know whose agent you are. Read the ownership table in [docs/implementation-plan.md](docs/implementation-plan.md) section 2 and work only on that person's Tasks and paths.
- Implement what the tech specs say. The scope is the full tech spec in `docs/tech-specs/`; COMMON.md is the source of truth for fields, enums, APIs, and event names. Do not invent APIs, fields, or enum values that the specs do not define.
- Follow the build order in the plan: MVP-required contracts first, then AI assist features, `startup_guard_gate`, `measurement` scope, and optional features.

## Ownership

- Do not modify files owned by the other person. This includes their service directories, their Task documents, and the deploy manifests generated for their services.
- If you need a change in someone else's path or in a shared document (COMMON.md, plan.md, architecture.md, tech-specs README), stop and open a separate PR that contains only that change. Name the branch `<owner>/change-<topic>`, explain why, and list the affected Tasks. Do not bundle it into your feature PR.
- Do not merge code that depends on that change until the separate PR is merged. Until then, keep going with a stub or adapter inside your own paths.
- If the spec is ambiguous or contradicts itself, do not silently pick an interpretation or edit the spec. Record the question in your PR description and ask your owner.

## Shared files

- `go.mod` / `go.sum`: on conflict, rebase onto `main` and regenerate with `go mod tidy`. Do not hand-merge.
- `migrations/`: one shared directory in `golang-migrate` format with the Task's file prefix (`identity_`, `audit_`, ...). Use a UTC timestamp (`YYYYMMDDHHMMSS`) as the version. Before opening a PR, rebase and make sure every new version is greater than the latest version on `main`; golang-migrate skips versions lower than the current one. Never edit a merged migration; add a new one.
- `packages/canonical/`: change only through a separate PR.
- Copy the existing Dockerfile, Makefile, and CI patterns instead of creating new ones.

## Branches and PRs

- Branch names start with the owner: `rina/...` or `siu/...`. Never push to `main` directly and never push to the other person's branches.
- Keep PRs small: one Task section per PR. Merge as soon as its unit tests pass instead of batching work for a final merge.
- Rebase onto `main` before opening a PR and resolve conflicts only in your own paths.

## Reporting status honestly

- Do not change `implementation_status` or `functional_verification` in a Task document without evidence. Mock or stub results do not count as functional completion.
- In PR descriptions, separate what was implemented, what was tested (and how), and what was not run.
- Never commit secrets, credentials, or tokens. Real resource identifiers belong in `deploy/gcp/environment.lock.json` only as the specs allow.

Claude Code reads `CLAUDE.md`, not this file. If you use Claude Code, add `@AGENTS.md` to your local `CLAUDE.md` (not committed) so these rules load.
