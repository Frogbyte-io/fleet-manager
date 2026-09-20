# Agent handoff — Fleet Manager

**Read first:** `AGENTS.md`, `docs/PLAN.md`, `docs/planning/initial-issues.md` (the authoritative ledger — every milestone's status, issues, and findings are recorded there).

## Where things stand (2026-09-20)

- **M0–M4 complete.** All issues closed, epics #50–#53, #76, and #5–#8 closed. The authz catalog is at 38 entries. The exit gate for M4: an invalid revision cannot become active; a reviewed plan converges a test machine; restart/resume and partial-failure tests preserve truth and audit history — the unit/contract portions are covered; a live end-to-end run remains for the maintainer's environment.
- **M6 started.** FM-S08 (spike #97, PR #98) resolved: the Proxmox client is a small reqwest transport with a pinned-fingerprint rustls verifier — the typed crate's TLS surface cannot pin against PVE's cluster CA without disabling verification; the 8.x leg is a recorded deviation moving to the real-cluster suite. FM-600 (#99, PR #100) landed: Proxmox accounts, TLS trust, and discovery — multi-account records over the encrypted secret store, the explicit observe→confirm trust gate, honest failure taxonomy, `/api/v1/proxmox/*` + `fleetctl proxmox`, STRICT migrations 0017/0018, live-verified against the integration PVE 9.2.2 host. Epics #10–#12 (associations/guest-agent, lifecycle, destructive ops) are next.
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

FM-601 (epic #10): Proxmox guest associations and QEMU Guest Agent data — stable association between a Proxmox guest and a Fleet machine identity, guest-agent readiness/IP with explicit unavailable states, per-resource failure isolation. FM-600's discovery and trust flow are the foundation; the provider's normalized `PveResource` shapes and the observed-state model from FM-401 are the vocabulary. Create the issue, post the approach, branch `fm-601-*`.

## Established patterns (M6 additions)

- **Proxmox transport**: `PveTransport` port in `fleet-provider-proxmox`, `PinningVerifier` (SHA-256 leaf pinning, TLS 12+13, `ring`), observe-only probes capture the fingerprint and refuse before any credential is sent; the body bound is enforced while streaming; `ProxmoxSource` normalizes at the provider boundary.
- **Trust flow**: `observe` persists `observed_fingerprint`; `confirm` pins only what the probe saw (BEGIN IMMEDIATE update+readback); discovery is locked until confirmed; a changed certificate reports both fingerprints as evidence.
- **Proxmox accounts**: secrets live as `proxmox/<account-id>` records in the encrypted store; two-phase audit intents (`*_creating`/`*_created`, `*_confirming`/`*_confirmed`, `*_deleting`/`*_deleted`) with the completion event after success.
