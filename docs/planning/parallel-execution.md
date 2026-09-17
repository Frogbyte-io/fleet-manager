# Parallel execution

Fleet Manager issues are written so several agents or contributors can work at once. Concurrency is limited by two things: the dependency graph, and which files an issue is allowed to write. This document defines both.

An issue is safe to start when every issue in its **Depends on** list is merged, and no other in-flight issue owns the paths it needs to write.

## M0 execution waves (historical)

M0 is front-loaded and serial: FM-001 and the workspace scaffolds gate everything else. Maximum useful concurrency is three agents, reached in waves 3 and 4.

```text
wave 1   FM-001 toolchains/CI          FM-S01 OpenAPI spike
             |                              |
wave 2   FM-002 Cargo ---- FM-002B pnpm/Vue |
             |     \            |     \      |
wave 3   FM-003   FM-004      FM-002C  |    |
          legacy   core          verify |    |
                     |                  |    |
wave 4   FM-005 schemas   FM-007 proto   FM-006 API <-+
                                            |
wave 5                                   FM-008 image/Compose
```

| Wave | Issues | Concurrency | Notes |
|---|---|---|---|
| 1 | FM-001, FM-S01 | 2 | FM-S01 needs nothing; it can run from a throwaway project |
| 2 | FM-002, FM-002B | 2 | Disjoint file sets; the split exists to make this wave parallel |
| 3 | FM-003, FM-004, FM-002C | 3 | FM-002C needs both scaffolds; FM-003 and FM-004 need only FM-002 |
| 4 | FM-005, FM-006, FM-007 | 3 | All need FM-004; FM-006 additionally needs FM-S01 and FM-002B |
| 5 | FM-008 | 1 | Needs FM-006 and a host with Docker |

FM-002 was split from a single issue precisely because five issues waited on it and its two halves share no files.

## M2 execution waves and current status

**Checkpoint 2026-09-09 (session handoff).** Waves 1–6 are closed and **M2 is complete except the optional FM-213 follow-through**: FM-210 (#64, PR #69) delivered the SSH Add Machine workflow; FM-211 (#65, PR #70) the fleetd service package and bootstrap; FM-212 (#66, PR #71) the orchestrated one-command upgrade with inventory verification; FM-213 (#67, PR #74) the optional read-only Tailscale discovery with correlation-evidence-only listing and import through the FM-210 flow (two cubic review rounds addressed in-PR; a real-tailnet smoke awaits an OAuth client from the maintainer). Epics #50/#51/#52 are closed; #53 remains open only for FM-213's optional follow-through. The next agent plans **M3 — Projects and developer tooling**. Operating notes for the handoff:

- **What FM-211 delivered (see the close-out on #65):** `cargo xtask package-fleetd` → `target/dist/fleetd-<version>-linux-x86_64.tar.gz` (binary, hardened systemd unit, install/uninstall scripts, README, SHA256SUMS); the controller serves artifacts from `Settings.artifacts_dir` at `GET /downloads/fleetd/<file>`; the `machine.install-fleetd` operation kind (executor in `fleet-controller::install`) mints the single-use enrollment token itself (never in argv, payload, or files — `fleetd --token-stdin`), installs, enrolls, and waits for a connected gateway session; `fleetctl machines install-node … --wait`. fleetd grew `--token-stdin`.
- **What FM-212 can rely on:** the install operation is idempotent (upgrade over a live identity mints no token, replaces the binary atomically, keeps the enrollment), failure cleanup leaves the agentless endpoint usable, revocation + reinstall re-enrolls with a fresh key, and reboot re-connects (proven on a real Ubuntu 24.04 VM: ACPI reboot → connected again in ~15 s). The machine stays the same Fleet machine throughout — the upgrade workflow's identity-association work is mostly done by these guarantees.
- **Real-VM environment:** the integration VM (`fleet-test-01`, Ubuntu 24.04, PVE host <pve-host-ip>) is documented on #65; its cloud-init seed must configure **`ens18`** (the actual NIC name — a seed saying `eth0` produces a boot with no network), and the PVE `sshkeys` API parameter rejects values through the API-token path, so seeds travel as a NoCloud ISO.
- **What FM-212 added (see the close-out on #66):** the orchestrated auto mode of `machine.install-fleetd` — no artifact fields; the executor selects the package from `Settings.artifacts_dir` against the machine's own facts (os.family linux, case-insensitive; x86_64/aarch64), computes the digest server-side, and after connect verifies the node's inventory by dispatching `node.inventory` through the live session registry and ingesting the report (shared `ingest_inventory_report` helper). The connect wait now polls the **live registry**, not the persisted `gateway_state` (stale after controller restarts). `fleetctl machines install-node` needs no artifact flags (controller URL defaults to `--url`); the web machine detail has the Install Fleet Node flow.
- **Remaining:** wave 7 (`FM-213`, optional). FM-214 stays deferred past the first Lab release.

M2 started 2026-09-04 after M1 closed. The dependency chain differs from M0: the SSH track (waves 1–2) is serial through the trust/execution/probe stack, and the fleetd track (wave 3) opens a new connection surface.

```text
wave 1   FM-S05 spike (resolved)  FM-200 model/storage
            |                          |
wave 2   FM-201 trust  FM-202 execution
            |               |
wave 3   FM-203 probes
            |
wave 4   FM-204 enrollment -> FM-205 gateway -> FM-207 journal
            |                   |
wave 5   FM-206 fleetd     FM-208 socket    FM-209 machine surfaces
            inventory          API             (API/web/CLI)
            |
wave 6   FM-210 Add Machine -> FM-211 install -> FM-212 upgrade
            |
wave 7   FM-213 Tailscale (optional)
```

| Wave | Issues | Status |
|---|---|---|
| 1 | FM-S05, FM-200 | **Done** (2026-09-04) |
| 2 | FM-201, FM-202 | **Done** (2026-09-04) |
| 3 | FM-203 | **Done** (2026-09-04) |
| 4 | FM-204 → FM-205 → FM-207 | **Done** (2026-09-04) |
| 5 | FM-206, FM-208, FM-209 | **Done** (2026-09-05) |
| 6 | FM-210 → FM-211 → FM-212 | **Done** (2026-09-07: #69, #70, #71) |
| 7 | FM-213 | **Done** (2026-09-09, PR #74); real-tailnet smoke pending maintainer OAuth client |

Handoff guarantees a fresh agent can rely on:

- **FM-200** (#54): the machine aggregate, endpoints, capability facts, tags/groups behind `machine.read/create/update/delete` — hostname/IP are never identity; snapshots and capability upsert are authorized, audited mutations.
- **FM-201** (#55): the system-OpenSSH provider (`fleet-provider-ssh`) with the isolated config dir, the probe→decide(new/known/changed)→pin→connect trust flow, per-endpoint verified fingerprints, and a real-sshd integration harness reused by FM-202/FM-203's tests. **FM-S05 resolved: direct OpenSSH invocation; Purple is reference only.**
- **FM-202** (#56): `execute_script` with the metadata-blob transport (caller data never hits a remote shell), 64 KiB stream caps, deadline kills, a permit-pool limiter, the bounded `payload_json` on operations, the `ssh.exec` kind, and the controller's kind-dispatching executor enforcing the trust gate.
- **FM-203** (#57): the probe script + parser (`fleet-provider-ssh::inventory`), the honest status vocabulary, fixture tests, and the `agentless.inventory` operation kind proven end-to-end. **Note:** capability facts are stored but not yet hydrated into the `Machine` read model — FM-209 owns that surface.
- **FM-204** (#58): node enrollment and identity (see FM-204's handoff below and FM-204's close-out comment on #58). **Guarantees:** the `Nodes` use cases over the `NodePort` (`fleet-application::node`), the `node.enroll`/`node.read`/`node.revoke` permissions, the enrollment tables (`fleet-storage-sqlite` migration `0009`), the pinned token/credential/proof formats (`fleet-auth::node`, RFC 8032/known-vector pinned), the HMAC signing key auto-provisioned in the secret store (`fleet-controller::node_crypto`), machine-facing endpoints at `/api/node/v1/{enroll,challenge,session,rotate}` (contract in `proto/README.md#enrollment-over-http-fm-204`), and the operator surface `machines/{id}/node{,/enrollments,/revoke}` in the public OpenAPI (client regenerated). **What FM-205 can rely on:** `Nodes::enroll`, `challenge`, `prove_session`, `rotate`, and `validate_session` are ready to serve a gateway; `validate_session(credential-token)` answers `SessionValidity::Valid/Invalid` for a presented session. **What it owns next:** the WSS loop, session presentation, revocation-driven disconnect, and the `fleetd` client.
- **FM-205** (#59): the node gateway (see FM-205's close-out on #59). **Guarantees:** `GET /api/node/v1/connect` with session-header admission and `fleet.node.v1` subprotocol, Hello/Welcome negotiation over the FM-007 frames, a one-session-per-node registry with supersede (`SESSION_REJECTED` to the old loop), heartbeats that never touch SQLite (transitions persist `node_identities.gateway_state` via migration `0010`), connect/disconnect/superseded audit events, the parameterized staleness sweeper (`run_staleness_sweeper_with`), and a real-WS test harness (`fleet-controller/tests/gateway.rs`). The `fleetd` client proves, upgrades, heartbeats, and reconnects with ±25% jitter (500 ms → 30 s); `fleetd enroll/run --controller <url>` work against a controller with a master key. **What FM-207 can rely on:** the registry's `session_of(machine_id)` exposes `journal_position` and `heartbeat_sequence`, and the gateway rejects non-Hello/Heartbeat payloads with `UNKNOWN_PAYLOAD` — command frames are still refused, which is exactly the hole FM-207 fills. **What it owns next:** Command dispatch to connected sessions, the node-side journal, and reconnect reconciliation.
- **FM-207** (#61): command dispatch and the node journal (see the close-out on #61). **Guarantees:** `CREATABLE_KINDS` gains `node.noop`/`node.diagnostic` (payload `{"machineId": …}`); `GatewayService::dispatch(machine_id, command)` routes through the live session with the in-flight bound (`DispatchError::{Offline,Backpressure,Duplicate,Disconnected,Timeout}`); `NodeCommandExecutor` (composed over the SSH executor in the binary) maps node result statuses onto operation terminal states; the fleetd library (`fleetd` is now lib + bin) ships the NDJSON journal (`NodeJournal`: acceptance-before-execution, result-before-report, torn-tail recovery, atomic compaction), the two command kinds, and a real end-to-end path exercised by `fleet-controller/tests/gateway.rs` (`start_real_node` runs the actual `fleetd::run_gateway_connected` loop against a real controller). **What FM-206/FM-208 can rely on:** the journal is a standalone `Arc<NodeJournal>` the daemon owns; commands execute off the journal contract, so a new kind only extends `commands::SUPPORTED_KINDS`; the gateway loop's outbound channel accepts any `wire::Frame` a future kind needs to send. **What it owns next (FM-206):** pluggable local probes, baseline snapshots, revisioned deltas.
- **FM-206** (#60): fleetd local inventory (see the close-out on #60). **Guarantees:** `ProbeRunner` with per-probe isolation (2 s timeout, panic-safe, bounded facts), the standard probe set (`os`, `host`, `agent.fleetd`, bounded `tool.{git,docker,tailscale,mise}`), `InventoryState` (node-local baseline, atomic persist, revision gap → full snapshot), the `node.inventory` command kind with ingestion in `NodeCommandExecutor` (`record_capabilities` + `record_snapshot` with `fleetd/<version>` provenance, `MachinePort::latest_inventory_revision` driving delta-vs-full), and end-to-end tests through the real node loop. **What FM-209 can rely on:** capability facts and inventory snapshots for fleetd machines are durable in the same tables FM-203's agentless path uses, so the machine read surface hydrates both sources identically. **What FM-208 owns next:** the constrained local socket API.
- **FM-208** (#62): the constrained local surface (see the close-out on #62). **Guarantees:** `fleetd::local::LocalServer` on `local.sock` (mode `0660`; the packaged unit sets the group), kernel-gated admission plus `SO_PEERCRED` defense in depth (same-user default, `--local-group <gid>` strict mode), `GET /local/status` only (node facts + the controller's public system view, unreachable controllers reported honestly), `404`/`405`/`403` for everything else, and `fleetctl status` with local-preferred routing (`--url` is the explicit direct-controller override; the used route is in the JSON). **What FM-211 can rely on:** the socket path and group handoff are documented in `proto/README.md`; the service unit owns the chgrp. **What FM-209 owns next:** the machine list/detail/status surfaces in API, web, and CLI.
- **FM-209** (#63): the machine read surface (see the close-out on #63). **Guarantees:** `GET /api/v1/machines` (Page envelope; `tag`/`group`/`capability=ns:name`/`status`/`limit` filters) and `GET /api/v1/machines/{machineId}` (Resource envelope) over `Machines::get/list`, which take the read time and answer `MachineView` — the derived `machineStatus` (`connected|stale|offline|agentless`, revoked identities fold to offline), capability facts with the staleness rule applied at that time (`CAPABILITY_FRESHNESS_MS`, 24 h; stale ≠ unknown ≠ unavailable ≠ missing), the newest `lastObservation`, and `lastSeenAt`. Endpoint references are redacted (`***@host`) unless the caller passes the new `machine.read.sensitive` question (risky, per-resource; `Permission::ALL` grew to 17, `fleet-auth`'s pinned count test updated). Hydration lives in `MachineRepository::hydrate` (capabilities + newest snapshot + `node_identities` row), the status filter is implemented in the list SQL, and `fleetctl machines list/get` render human text and `--output json` from the same envelopes (the machine renderer is command-aware so an empty page says "no machines"). The web `MachinesPanel.vue` consumes the regenerated orval client, with component tests via the new dev-only vitest harness (xtask runs `pnpm -r test`; e2e stays deferred). **What FM-210 can rely on:** the machine detail view is the review surface; endpoint references arrive redacted by default and full under the sensitive permission. **What FM-211/FM-212 can rely on:** `machineStatus` is derived from `node_identities` alone, so install/upgrade flows only need to persist gateway state to update every surface.

- **FM-210** (#64): the SSH Add Machine workflow (see the close-out on #64). **Guarantees:** the `Onboarding` use cases over `OnboardingPort` (durable `onboarding_drafts`, migration `0011`) and `OnboardTrustPort` (pin/unpin over the controller's one SSH trust store) in `fleet-application::onboarding`; the staged flow — draft → `machine.onboard.test` (probe/decide/connect-check, **no machine side effect**) → explicit `confirm-host-key` (pin + `confirmed`; a later changed key marks the draft `changed` and blocks discover/add until re-confirmed) → `machine.onboard.discover` (the FM-203 probe into the draft, partial/zero facts are honest) → review (facts, OS/profile hint, **duplicate candidates by host:port, warned never merged**) → `add` (composes `Machines::register` + `confirm_fingerprint` + fact/snapshot ingestion, deletes the draft). **Cleanup contract:** drafts hold no secret values (auth is `agent` or an identity-file *path*); cancel/complete deletes the row, and cancel unpins the host **only when no machine endpoint shares that host** (host-scoped, because `unpin` strips every port). Surfaces: `/api/v1/machines/onboarding/drafts{,/{draftId}{,/test,/discover,/confirm-host-key,/add,/cancel}}` in the OpenAPI doc (client regenerated), `fleetctl machines onboard {create,list,get,test,discover,confirm,add,cancel}` with `--wait`, and the web `OnboardingPanel.vue`. Permissions reuse the vocabulary (`machine.create` lifecycle+add, `machine.read` reads); endpoint userinfo is redacted unless `machine.read.sensitive`. **What FM-212 can rely on:** add already confirms the endpoint's `verified_fingerprint` and ingests `agentless/1` facts, so an upgrade flow starts from a fingerprint-verified agentless machine whose `machineStatus` flips through `node_identities` alone. **What FM-213 can rely on:** `NewDraft` is a plain struct — a Tailscale import can hand an address straight to `Onboarding::create_draft` and inherit the whole trust/test/review flow.
- **FM-211** (#65): the fleetd service package and the SSH bootstrap (see the close-out on #65). **Guarantees:** `cargo xtask package-fleetd` builds `target/dist/fleetd-<version>-linux-x86_64.tar.gz` (release binary, hardened systemd unit, idempotent `install.sh`/`uninstall.sh`, README, `SHA256SUMS`) from `deploy/fleetd/`; the controller serves `GET /downloads/fleetd/<file>` from `Settings.artifacts_dir` (path-contained, off by default in tests); the `machine.install-fleetd` operation kind runs through `InstallExecutor` (`fleet-controller::install`, composed in the dispatch chain) which resolves the verified endpoint, decides the enrollment mode from the node's identity (fresh → mint a 10-min single-use token; revoked → forced re-enroll with a wiped local state; live → upgrade, no token), builds the install script with the token **in the script text only** (ssh stdin; `fleetd enroll --token-stdin`; never argv, payload, result, or disk), verifies the archive digest on the node, installs, and waits bounded for `GatewayState::Connected` before completing succeeded. `fleetctl machines install-node … --wait` drives it. **Proven on a real Ubuntu 24.04 VM** (fresh install → connected; revoke → reinstall with a fresh key; ACPI reboot → auto-reconnect ~15 s; upgrade → no new token, same key). **What FM-212 can rely on:** the machine keeps its Fleet id and endpoint across the whole upgrade — the install/upgrade/re-enroll paths are already audited operations; the upgrade workflow is orchestration and UI on top. **What the packaging team should know:** `install.sh` needs root or passwordless sudo on the target; the state dir is `/var/lib/fleetd` (0700 fleet:fleet, socket 0660); the console login is key-only by design (no password is ever set).

M0's waves below are historical evidence of that milestone's execution, kept because the path-ownership rules are still the operating rules.

## Path ownership

Every issue declares the paths it owns. Only the owning issue creates or edits files under them while it is in flight.

| Owned path | Owner |
|---|---|
| `.github/`, `rust-toolchain.toml`, `deny.toml`, lockfile policy | FM-001 |
| `Cargo.toml` (root), `crates/**` skeletons | FM-002 |
| `pnpm-workspace.yaml`, `apps/web/**`, `packages/ui/**` | FM-002B |
| `xtask/**`, the root verification command | FM-002C |
| `legacy/**`, and the move of `src/`, `bin/`, `test/` | FM-003 |
| `crates/fleet-core/**` | FM-004 |
| `schemas/**` | FM-005 |
| `crates/fleet-api/**`, `packages/api-client/**` | FM-006 |
| `proto/**`, `crates/fleet-protocol/**` | FM-007 |
| `deploy/**`, controller `Dockerfile` | FM-008 |

Paths not listed are unowned. Claim one in the issue before writing to it.

## Shared files

Three files are edited by many issues and cannot be exclusively owned:

- Root `Cargo.toml` `[workspace] members`
- `pnpm-workspace.yaml` package globs
- `package.json` `scripts`

The protocol for all three: **append your own line, change nothing else.** A one-line addition merges cleanly. Reordering, reformatting, or "tidying while I'm here" turns every concurrent branch into a conflict. If an issue needs to restructure one of these files, it says so explicitly and runs alone.

## Handoff contracts

An issue that unblocks others states what it guarantees on completion, so downstream work can be written against the guarantee rather than against the implementation:

- **FM-001** guarantees pinned toolchain versions and a CI entry point that later jobs extend.
- **FM-002** guarantees every crate in the layout exists, compiles, and has its dependency direction declared.
- **FM-002B** guarantees the Vue workspace builds and emits a static shell to a documented output directory.
- **FM-004** guarantees the ID, time, error, and secret-reference types that every later crate imports.
- **FM-S01** guarantees a named OpenAPI toolchain and TypeScript generator, with the rejected options recorded.

## Rules for concurrent agents

- Work on one issue per branch. Branch from current `main`, not from another agent's branch.
- Do not fix problems you notice outside your owned paths. Open an issue or leave a note on the relevant one. An unrelated drive-by fix in a shared file is the most common cause of a conflicted merge.
- If your issue turns out to need a file another in-flight issue owns, stop and coordinate rather than editing it. Overlapping ownership is a planning error worth surfacing.
- Re-read `AGENTS.md` before implementing. It constrains every issue and is not repeated in issue bodies.
- A blocked issue reports as blocked. Do not substitute adjacent work to appear productive; that produces changes nobody reviewed against an acceptance criterion.
