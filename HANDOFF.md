# Agent handoff — Fleet Manager

**Read first:** `AGENTS.md`, `docs/PLAN.md`, `docs/planning/initial-issues.md` (the authoritative ledger — every milestone's status, issues, and findings are recorded there).

## Where things stand (2026-09-18)

- **M0–M3 complete.** All issues closed, epics #50–#53 and #76 closed.
- **M4 in progress.** Epics #5–#8; implementation issues #89 (FM-400, DONE via PR #93), #90 (FM-401 next), #91 (FM-402), #92 (FM-403). The approach comments on each issue describe the planned implementation.
- **Repo is PUBLIC** since 2026-09-17 — no secrets in history (verified), private infra redacted.

## Workflow (established over M2–M3)

1. Read the issue, post an implementation-approach comment on it.
2. Branch `fm-XXX-<slug>`, implement narrowly within the issue's owned paths.
3. `cargo xtask verify` must pass (fmt, clippy -D warnings, all tests, web, policy, Compose smoke).
4. PR → cubic AI review (`cubic-dev-ai`) → fix findings → re-review until clean → merge with `gh pr merge --merge --delete-branch`.
5. Close the issue with a summary comment, tick the epic checklist, update `docs/planning/initial-issues.md`.
6. Never push `refs/t3/checkpoints` (session data) — never `git push --mirror`.

## Established patterns (follow them)

- **External CLI providers**: `CliTransport` port in the provider crate, fixed binary name, bounded output, deadline kills reported honestly, per-kind version gates, argument arrays via the base64 metadata blob (never shell interpolation), structural redaction via `fleet-core::redact` shared helpers (`redact_url_credentials`, `redact_schemeless_credentials`, `flatten_control_characters`).
- **Executor kinds**: registered in `CREATABLE_KINDS` (fleet-application/src/operation.rs), machine-scoped authz via `machine_scoped_kind_permission` (enforced on BOTH the dedicated endpoint and the generic /operations surface), executor + `*Dispatch` wrapper in fleet-controller, wired into main.rs's chain.
- **Authz catalog**: `Permission` enum in fleet-application/src/authz.rs; count pinned in fleet-auth/tests/authz_adapter.rs (currently 33).
- **Blocked/manual approval**: `blocked_manual_approval` is a first-class terminal OperationState.
- **Migrations**: STRICT tables; a CHECK-constraint change requires a table rebuild (documented decision — cubic flags it every time; respond with the PR #86 rationale).
- **ssh e2e tests**: shared harness in `crates/fleet-controller/tests/common/mod.rs` with a cross-process startup file lock (uid-scoped, 0600, `OpenOptionsExt::mode`).
- **Desired state (FM-400)**: schemas crate with per-kind if/then schema generation (hoisted $defs); composition in fleet-application/src/composition.rs (deny-through-traversal, escaped identity keys, provenance). Semantic gates: `FM_SCHEMA_SEMANTIC_*` diagnostics refuse credentials before activation.

## Known flakiness

- sshd e2e tests were flaky in CI under parallel load; the startup lock fixed it (see commit "test: make the sshd startup lock cross-process"). If `Rust full checks` fails on an exec/checkout/skills/frogenv test, suspect a regression there first.

## Environment

- Self-hosted GitHub Actions runner "dev-box" runs all Linux CI (installed at ~/actions-runner, run via nohup; svc.sh needs sudo). Windows job is informational/out-of-gate.
- GitHub Actions billing is broken for hosted runners (account payment issue) — maintainer action needed.
- Integration VM fleet-test-01 (192.168.68.223 PVE host) — credentials in ~/.config/fleet/proxmox.env. FM-305's live e2e run is still pending on the maintainer.
- cubic free plan: ~13 reviews/month; if a review is stuck pending, comment @cubic-dev-ai; if it reviews a stale commit, push an empty commit to retrigger.

## Next up

FM-401 (#90): observed-state normalization, the difference model (missing/extra/changed/unknown/unsupported), and the dependency-ordered planner with dry-run parity across API/web/CLI. See the issue and its approach comment.
