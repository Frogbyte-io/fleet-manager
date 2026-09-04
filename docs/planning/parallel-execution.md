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
| 5 | FM-206, FM-208, FM-209 | FM-206 **Done** (2026-09-04); FM-208/FM-209 next |
| 6 | FM-210 → FM-211 → FM-212 | after FM-209 |
| 7 | FM-213 | after FM-210; optional |

Handoff guarantees a fresh agent can rely on:

- **FM-200** (#54): the machine aggregate, endpoints, capability facts, tags/groups behind `machine.read/create/update/delete` — hostname/IP are never identity; snapshots and capability upsert are authorized, audited mutations.
- **FM-201** (#55): the system-OpenSSH provider (`fleet-provider-ssh`) with the isolated config dir, the probe→decide(new/known/changed)→pin→connect trust flow, per-endpoint verified fingerprints, and a real-sshd integration harness reused by FM-202/FM-203's tests. **FM-S05 resolved: direct OpenSSH invocation; Purple is reference only.**
- **FM-202** (#56): `execute_script` with the metadata-blob transport (caller data never hits a remote shell), 64 KiB stream caps, deadline kills, a permit-pool limiter, the bounded `payload_json` on operations, the `ssh.exec` kind, and the controller's kind-dispatching executor enforcing the trust gate.
- **FM-203** (#57): the probe script + parser (`fleet-provider-ssh::inventory`), the honest status vocabulary, fixture tests, and the `agentless.inventory` operation kind proven end-to-end. **Note:** capability facts are stored but not yet hydrated into the `Machine` read model — FM-209 owns that surface.
- **FM-204** (#58): node enrollment and identity (see FM-204's handoff below and FM-204's close-out comment on #58). **Guarantees:** the `Nodes` use cases over the `NodePort` (`fleet-application::node`), the `node.enroll`/`node.read`/`node.revoke` permissions, the enrollment tables (`fleet-storage-sqlite` migration `0009`), the pinned token/credential/proof formats (`fleet-auth::node`, RFC 8032/known-vector pinned), the HMAC signing key auto-provisioned in the secret store (`fleet-controller::node_crypto`), machine-facing endpoints at `/api/node/v1/{enroll,challenge,session,rotate}` (contract in `proto/README.md#enrollment-over-http-fm-204`), and the operator surface `machines/{id}/node{,/enrollments,/revoke}` in the public OpenAPI (client regenerated). **What FM-205 can rely on:** `Nodes::enroll`, `challenge`, `prove_session`, `rotate`, and `validate_session` are ready to serve a gateway; `validate_session(credential-token)` answers `SessionValidity::Valid/Invalid` for a presented session. **What it owns next:** the WSS loop, session presentation, revocation-driven disconnect, and the `fleetd` client.
- **FM-205** (#59): the node gateway (see FM-205's close-out on #59). **Guarantees:** `GET /api/node/v1/connect` with session-header admission and `fleet.node.v1` subprotocol, Hello/Welcome negotiation over the FM-007 frames, a one-session-per-node registry with supersede (`SESSION_REJECTED` to the old loop), heartbeats that never touch SQLite (transitions persist `node_identities.gateway_state` via migration `0010`), connect/disconnect/superseded audit events, the parameterized staleness sweeper (`run_staleness_sweeper_with`), and a real-WS test harness (`fleet-controller/tests/gateway.rs`). The `fleetd` client proves, upgrades, heartbeats, and reconnects with ±25% jitter (500 ms → 30 s); `fleetd enroll/run --controller <url>` work against a controller with a master key. **What FM-207 can rely on:** the registry's `session_of(machine_id)` exposes `journal_position` and `heartbeat_sequence`, and the gateway rejects non-Hello/Heartbeat payloads with `UNKNOWN_PAYLOAD` — command frames are still refused, which is exactly the hole FM-207 fills. **What it owns next:** Command dispatch to connected sessions, the node-side journal, and reconnect reconciliation.
- **FM-207** (#61): command dispatch and the node journal (see the close-out on #61). **Guarantees:** `CREATABLE_KINDS` gains `node.noop`/`node.diagnostic` (payload `{"machineId": …}`); `GatewayService::dispatch(machine_id, command)` routes through the live session with the in-flight bound (`DispatchError::{Offline,Backpressure,Duplicate,Disconnected,Timeout}`); `NodeCommandExecutor` (composed over the SSH executor in the binary) maps node result statuses onto operation terminal states; the fleetd library (`fleetd` is now lib + bin) ships the NDJSON journal (`NodeJournal`: acceptance-before-execution, result-before-report, torn-tail recovery, atomic compaction), the two command kinds, and a real end-to-end path exercised by `fleet-controller/tests/gateway.rs` (`start_real_node` runs the actual `fleetd::run_gateway_connected` loop against a real controller). **What FM-206/FM-208 can rely on:** the journal is a standalone `Arc<NodeJournal>` the daemon owns; commands execute off the journal contract, so a new kind only extends `commands::SUPPORTED_KINDS`; the gateway loop's outbound channel accepts any `wire::Frame` a future kind needs to send. **What it owns next (FM-206):** pluggable local probes, baseline snapshots, revisioned deltas.
- **FM-206** (#60): fleetd local inventory (see the close-out on #60). **Guarantees:** `ProbeRunner` with per-probe isolation (2 s timeout, panic-safe, bounded facts), the standard probe set (`os`, `host`, `agent.fleetd`, bounded `tool.{git,docker,tailscale,mise}`), `InventoryState` (node-local baseline, atomic persist, revision gap → full snapshot), the `node.inventory` command kind with ingestion in `NodeCommandExecutor` (`record_capabilities` + `record_snapshot` with `fleetd/<version>` provenance, `MachinePort::latest_inventory_revision` driving delta-vs-full), and end-to-end tests through the real node loop. **What FM-209 can rely on:** capability facts and inventory snapshots for fleetd machines are durable in the same tables FM-203's agentless path uses, so the machine read surface hydrates both sources identically. **What FM-208 owns next:** the constrained local socket API.

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
