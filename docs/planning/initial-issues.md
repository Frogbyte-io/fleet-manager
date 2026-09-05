# Initial implementation issues

These are issue-ready proposals for M0–M2. They are not created on GitHub by this planning change. Create the milestone epics first, then copy each item into a small linked issue. IDs express dependency order, not permanent GitHub issue numbers.

## Issue template

```markdown
## Context
Why this outcome is needed and what exists now.

## Goal
One independently verifiable outcome.

## Architecture reference
Links to PLAN/architecture/ADR sections that constrain the work.

## Dependencies
Blocking issue IDs and external prerequisites, or “None.”

## Research required
Upstream APIs/libraries/projects to inspect before choosing implementation.

## Acceptance criteria
- Observable behavior, compatibility, failure behavior, and documentation.

## Non-goals
- Adjacent work deliberately excluded.

## Tests
- Unit/contract/integration/e2e evidence required.
```

An implementation issue should normally fit one focused pull request. A spike ends with evidence and a decision/ADR update, not production code hidden inside “research.”

## M0 — Architecture and migration foundation

Created on GitHub 2026-08-25. Planning IDs are stable; GitHub numbers are not, so they are mapped here rather than renaming anything.

**Status: Done 2026-09-04.** FM-000 through FM-008 and FM-002B/002C all closed; the epics (#17, #18, #19) and the milestone are closed. The M0 exit gate — `cargo xtask verify` plus the Compose smoke — runs continuously in CI (`deploy/smoke.sh`).

Execution order, path ownership, and the rules for concurrent agents are in [parallel-execution.md](parallel-execution.md).

| Planning ID | Issue | Epic |
|---|---|---|
| FM-000 | [#20](https://github.com/Frogbyte-io/fleet-manager/issues/20) (closed) | — precedes the epics |
| FM-001 | [#21](https://github.com/Frogbyte-io/fleet-manager/issues/21) | [#19](https://github.com/Frogbyte-io/fleet-manager/issues/19) Build, CI, and deployment foundation |
| FM-002 | [#22](https://github.com/Frogbyte-io/fleet-manager/issues/22) | [#17](https://github.com/Frogbyte-io/fleet-manager/issues/17) Monorepo and legacy migration |
| FM-002B | [#30](https://github.com/Frogbyte-io/fleet-manager/issues/30) | [#17](https://github.com/Frogbyte-io/fleet-manager/issues/17) Monorepo and legacy migration |
| FM-002C | [#31](https://github.com/Frogbyte-io/fleet-manager/issues/31) | [#19](https://github.com/Frogbyte-io/fleet-manager/issues/19) Build, CI, and deployment foundation |
| FM-003 | [#23](https://github.com/Frogbyte-io/fleet-manager/issues/23) | [#17](https://github.com/Frogbyte-io/fleet-manager/issues/17) Monorepo and legacy migration |
| FM-004 | [#24](https://github.com/Frogbyte-io/fleet-manager/issues/24) | [#18](https://github.com/Frogbyte-io/fleet-manager/issues/18) API, schema, and protocol contracts |
| FM-005 | [#25](https://github.com/Frogbyte-io/fleet-manager/issues/25) | [#18](https://github.com/Frogbyte-io/fleet-manager/issues/18) API, schema, and protocol contracts |
| FM-006 | [#26](https://github.com/Frogbyte-io/fleet-manager/issues/26) | [#18](https://github.com/Frogbyte-io/fleet-manager/issues/18) API, schema, and protocol contracts |
| FM-007 | [#27](https://github.com/Frogbyte-io/fleet-manager/issues/27) | [#18](https://github.com/Frogbyte-io/fleet-manager/issues/18) API, schema, and protocol contracts |
| FM-008 | [#28](https://github.com/Frogbyte-io/fleet-manager/issues/28) | [#19](https://github.com/Frogbyte-io/fleet-manager/issues/19) Build, CI, and deployment foundation |
| FM-S01 | [#29](https://github.com/Frogbyte-io/fleet-manager/issues/29) | [#18](https://github.com/Frogbyte-io/fleet-manager/issues/18) API, schema, and protocol contracts |

### FM-000 — Review and accept the master plan and ADR set

**Context:** The target architecture materially supersedes the current issues #2/#3 and local-CLI assumptions.  
**Goal:** Resolve comments, set accepted ADR statuses, and agree milestone/epic ownership.  
**Architecture reference:** `docs/PLAN.md`; `docs/adr/`.  
**Dependencies:** None.  
**Research required:** Confirm product/operator constraints and supported initial OS/PVE versions.  
**Acceptance criteria:** Maintainer decisions are recorded; ADR statuses match decisions; a root project license is selected/added; unresolved choices have named spike issues; #2/#3 are closed as superseded only after replacement epics link back.  
**Non-goals:** Implementing code or deleting legacy functionality.  
**Tests:** Documentation links and Markdown checks.  
**Status:** Done 2026-08-25. Decisions are in [fm-000-acceptance.md](fm-000-acceptance.md); spikes are in [spikes.md](spikes.md). Milestones M0–M8, the replacement epics, and the closure of #2/#3 all landed.

### FM-001 — Establish pinned toolchains and cross-workspace CI

**Context:** The repository has Node tests only; the target has Rust, Vue/TypeScript, schemas, generated artifacts, and cross-platform binaries.  
**Goal:** Add pinned Rust/Node/pnpm toolchain policy and CI jobs that can grow without hidden local steps.  
**Architecture reference:** ADR-0006; `AGENTS.md`.  
**Dependencies:** FM-000.  
**Research required:** Current stable Rust MSRV, pnpm/Corepack behavior, GitHub runner OS coverage, cargo-deny/license tooling.  
**Acceptance criteria:** Linux runs full checks; Windows runs binary/library compatibility checks; lockfiles are enforced; the dependency/license/secret scanning policy is documented and fails on a license outside the Apache-2.0-compatible inbound set; CI has no deployment credentials.  
**Non-goals:** Release publishing/signing or product code.  
**Tests:** A deliberately stale generated/format artifact fails its dedicated check in a fixture or script test.

### FM-002 — Scaffold Cargo workspace and crate skeletons

Split on 2026-08-25 into FM-002, FM-002B, and FM-002C. Five issues depended on the original, and its halves share no files, so bundling them serialised work for no reason.

**Context:** Target component boundaries need compilable roots before parallel work.  
**Goal:** Create the Cargo workspace and empty/skeletal crates matching the approved layout, without moving legacy code.  
**Architecture reference:** `docs/PLAN.md#recommended-monorepo-layout`; ADR-0001/0006.  
**Dependencies:** FM-001.  
**Owned paths:** root `Cargo.toml`, `crates/**`.  
**Research required:** Axum supported versions and crate dependency-direction enforcement options.  
**Acceptance criteria:** Every crate has its documented dependency direction; binaries print version/help only; no product provider behavior.  
**Non-goals:** API routes, database, authentication, machine registration; the Vue workspace and the joint verification command.  
**Tests:** Workspace dependency graph check, Rust unit smoke.

### FM-002B — Scaffold pnpm workspace and Vue shell

**Context:** The Vue workspace has a disjoint file set from the Cargo workspace and can be built concurrently.  
**Goal:** Create the pnpm workspace and a Vue 3/TypeScript/Tailwind static shell.  
**Architecture reference:** `docs/PLAN.md#recommended-monorepo-layout`; ADR-0001/0006.  
**Dependencies:** FM-001.  
**Owned paths:** `pnpm-workspace.yaml`, `apps/web/**`, `packages/ui/**`.  
**Research required:** Vue/Vite supported versions and the static asset output layout the controller embeds.  
**Acceptance criteria:** Vue renders a static shell; the build emits to a documented output directory FM-008 can embed; type-check and build pass; pnpm resolves from the FM-001 pin.  
**Non-goals:** API client code, visual feature design, routing beyond a shell.  
**Tests:** Vue type/build smoke.

### FM-002C — Add the root verification command

**Context:** Something must verify both workspaces with one command, and leaving that to whichever scaffold lands second gives it no owner.  
**Goal:** One root command that builds and tests the Cargo and pnpm workspaces together.  
**Architecture reference:** `docs/PLAN.md#recommended-monorepo-layout`; ADR-0006.  
**Dependencies:** FM-002, FM-002B.  
**Owned paths:** `xtask/**` and the root verification entry point.  
**Research required:** None beyond the two scaffolds.  
**Acceptance criteria:** One command builds/tests both workspaces; identical in CI and locally with no hidden local steps; either workspace failing fails the command legibly; wired into the FM-001 CI entry point; documented in the README.  
**Non-goals:** Checks for artifacts that do not exist yet; Nx or Turborepo.  
**Tests:** The command fails when either workspace is deliberately broken.

### FM-003 — Move the Node proof of concept under `legacy/`

**Context:** The current package must remain testable while new roots occupy the repository.  
**Goal:** Mechanically relocate the Node package and update paths/documentation without behavior changes.  
**Architecture reference:** ADR-0006; current-codebase assessment.  
**Dependencies:** FM-002.  
**Research required:** npm binary/path behavior and any actual external installation references.  
**Acceptance criteria:** All 50 baseline tests pass repeatedly from the new path; the timing-dependent Proxmox timeout test uses a fake clock or another deterministic boundary without changing product behavior; package/bin behavior and fixtures are otherwise unchanged; root README labels it legacy and links the plan; deletion parity checklist exists.  
**Non-goals:** Porting, renaming the executable, fixing schemas, or changing Proxmox/skills commands.  
**Tests:** Exact legacy suite plus a package/bin invocation smoke test.

### FM-004 — Define shared IDs, time, errors, and sensitive-value primitives

**Context:** Stable resource identity and safe errors are prerequisites for every API/storage/provider.  
**Goal:** Add small domain types for opaque IDs, mutable slugs, revisions, timestamps/deadlines, correlation IDs, public error codes, and secret references.  
**Architecture reference:** `architecture/overview.md`; `architecture/security.md`.  
**Dependencies:** FM-002.  
**Research required:** UUIDv7 ecosystem/support and Rust secret wrapper/redaction patterns.  
**Acceptance criteria:** IDs serialize canonically and never derive from hostname/IP; public errors separate safe message/details from internal source; secret references cannot accidentally format as a value; clock/ID generation are injectable.  
**Non-goals:** Database rows, HTTP envelope, encryption, or machine model.  
**Tests:** Round-trip/property tests, invalid parsing, redaction/Debug snapshot, fake-clock behavior.

### FM-005 — Define desired-resource envelope and schema workflow

**Context:** Legacy YAML has no version envelope or machine-checkable published schema.  
**Goal:** Define only the generic `apiVersion`/`kind`/metadata/spec envelope, schema generation/validation workflow, and fixture conventions.  
**Architecture reference:** `architecture/desired-state.md`; ADR-0004.  
**Dependencies:** FM-002, FM-004.  
**Research required:** JSON Schema draft/tooling and YAML-to-JSON validation diagnostics.  
**Acceptance criteria:** A minimal example validates; unknown version/kind and duplicate identity fail with stable diagnostics; schemas are generated/checked in CI; no observed/status/secret value fields are allowed in the generic envelope.  
**Non-goals:** Full machine/profile/project/Lab v1 specs or legacy auto-migration.  
**Tests:** Positive/negative golden schema fixtures on Rust and any published CLI validator path.

### FM-006 — Define public API conventions and OpenAPI generation

**Context:** Web, CLI, and Fleet skills need one stable client contract before endpoints proliferate.
**Goal:** Establish `/api/v1`, resource/error/operation envelopes, pagination/filter/idempotency/correlation conventions, and generated OpenAPI/TypeScript checks with one inert endpoint.  
**Architecture reference:** ADR-0002; `architecture/overview.md#api-and-client-contract`.  
**Dependencies:** FM-002, FM-004.  
**Research required:** Rust OpenAPI tooling compatibility with Axum and selected TypeScript generator.  
**Acceptance criteria:** OpenAPI is reproducible; TypeScript client is generated rather than hand-authored; correlation ID appears in success/error paths; compatibility policy is documented; one endpoint is exercised end to end.  
**Non-goals:** Authentication, machines, operations worker, or realtime resources.  
**Tests:** Spec snapshot/diff guard, generated client compile, HTTP contract test.

### FM-007 — Define node protocol v1 envelope and compatibility fixtures

**Context:** Controller and `fleetd` will release independently and reconnect across upgrades.  
**Goal:** Define protobuf/envelope source, version negotiation, message IDs, feature flags, typed protocol errors, and golden encoded fixtures for `Hello`, `Welcome`, heartbeat, and generic command/result.  
**Architecture reference:** ADR-0002/0003; `architecture/controller-node-protocol.md`.  
**Dependencies:** FM-002, FM-004.  
**Research required:** Prost/protobuf compatibility and Axum WebSocket binary framing/subprotocol support.  
**Acceptance criteria:** Unknown additive fields survive/ignore safely; incompatible ranges produce stable error; fixtures are consumable from controller and node crates; message/frame size limits are explicit.  
**Non-goals:** Network connection, enrollment crypto, inventory schema, or command execution.  
**Tests:** Encode/decode golden fixtures, compatibility matrix, fuzz/property test for bounded invalid frames.

### FM-008 — Build minimal controller image and Compose smoke deployment

**Context:** Controller-first deployment must be continuously real, not postponed until features.  
**Goal:** Build a minimal non-privileged controller image serving the Vue shell and health/readiness endpoints with documented volumes/config placeholders.  
**Architecture reference:** ADR-0001/0007; `architecture/overview.md#runtime-and-deployment`.  
**Dependencies:** FM-002B, FM-006. Blocked on a host with Docker.  
**Research required:** Reproducible multi-stage Rust/Vue image builds, container health checks, non-root file ownership.  
**Acceptance criteria:** `docker compose up -d` reaches healthy; web shell is served by controller; container has no Docker socket/host network/privileged mode; persistent and secret mount locations are documented; graceful SIGTERM passes.  
**Non-goals:** TLS termination, database migrations, login, or production reverse-proxy templates.  
**Tests:** Compose e2e smoke, read-only root filesystem feasibility check, signal shutdown test.

## M1 — Controller, API, and trusted-LAN control kernel

**Status: Done 2026-09-04.** FM-100 through FM-110 (FM-105 deferred to M8 with FM-S02 by design) are closed; the four epics (#36–#39) and the milestone are closed. All M1 issues were created as #40–#49. The controller serves typed config, migrated SQLite with the single-controller lock, AEAD secret records with key rotation, the trusted-LAN principal, the authorization catalog, the append-only audit ledger, durable operations with a spike-resolved worker (FM-S03), browser mutation guards, and the system/operations vertical slice in API, web, and `fleetctl`.

### FM-100 — Implement typed controller configuration and startup validation

**Context:** Controller configuration will include paths, URLs, limits, and secret-key source; unsafe defaults must fail early.  
**Goal:** Load file/environment/CLI configuration with documented precedence, validation, redacted diagnostics, and effective non-secret config output.  
**Architecture reference:** `architecture/overview.md#runtime-and-deployment`; `architecture/security.md`.  
**Dependencies:** FM-004, FM-008.  
**Research required:** Serde/config crates and platform path conventions.  
**Acceptance criteria:** Missing/unsafe key/path/listen settings fail before readiness; secret values never render; config version is explicit; Compose uses a file/Docker-secret key source.  
**Non-goals:** Secret encryption or provider account configuration.  
**Tests:** Precedence table, invalid configs, redaction snapshots, Unix permissions where applicable.

### FM-101 — Add SQLite migration and transaction foundation

**Context:** Runtime truth must survive restart with a single-controller constraint.  
**Goal:** Initialize SQLx SQLite, WAL/foreign keys/busy timeout, embedded migrations, metadata, and transaction/repository test helpers.  
**Architecture reference:** ADR-0004/0007; data ownership in `docs/PLAN.md`.  
**Dependencies:** FM-002, FM-004, FM-100.  
**Research required:** SQLx/SQLite WAL, online backup API, migration locking, container filesystem behavior.  
**Acceptance criteria:** One controller lock is enforced; migrations are atomic/idempotent; readiness waits for success; unsupported schema downgrade fails safely; backup/restore procedure and local-filesystem constraint are documented.  
**Non-goals:** Domain tables beyond metadata/migration lock or PostgreSQL abstractions.  
**Tests:** Fresh/upgrade/restart/downgrade/lock/contention integration tests and restore smoke.

### FM-102 — Implement encrypted controller secret records

**Context:** Provider credentials cannot live in Git or plaintext SQLite.  
**Goal:** Implement opaque secret CRUD/use with versioned AEAD envelope, separately mounted master key, rotation design, and redaction.  
**Architecture reference:** ADR-0004; `architecture/security.md#secret-handling`.  
**Dependencies:** FM-100, FM-101.  
**Research required:** Rust AEAD/KDF/zeroization crates, nonce/key rotation, Docker secrets, backup threat model.  
**Acceptance criteria:** Ciphertext is authenticated and context-bound; plaintext never appears in DB/log/Debug/audit; key version is recorded; wrong/missing key fails closed; rotation can rewrap records without external provider calls.  
**Non-goals:** General secrets UI, Frogenv values, Vault integration, or provider-specific forms.  
**Tests:** Known-vector/tamper/wrong-key/rotation/redaction tests and DB inspection assertion.

### FM-103 — Implement trusted-LAN caller resolution and deployment guardrails

**Context:** The first release deliberately has no accounts or login; every client that can reach the local-network listener has full control.
**Goal:** Resolve browser/CLI/skill requests to an explicit `anonymous-lan-admin` principal, make the trust mode visible in configuration/system status/UI, and prevent documentation or defaults from implying safe Internet exposure.
**Architecture reference:** `architecture/security.md#initial-trusted-lan-principal`.
**Dependencies:** FM-100, FM-101.
**Research required:** Axum client-address/trusted-proxy handling and safe container listen defaults.
**Acceptance criteria:** Every request has the stable LAN principal and correlation metadata; startup/UI warn that all reachable clients can mutate; request IP/proxy data is treated as evidence rather than identity; unsupported public exposure is documented.
**Non-goals:** Accounts, passwords, sessions, CLI tokens, OIDC, or per-agent identity.
**Tests:** Caller-resolution, proxy-header rejection/allowlist, warning/status, and audit-metadata integration tests.

### FM-104 — Protect browser mutations in trusted-LAN mode

**Context:** An open LAN API is still vulnerable to a malicious public webpage driving a user's browser against local services.
**Goal:** Enforce same-origin browser use, strict CORS/Host/Origin handling, appropriate anti-CSRF state for mutations, and safe content/security headers without introducing user accounts.
**Architecture reference:** `architecture/security.md#initial-trusted-lan-principal`; ADR-0002.
**Dependencies:** FM-103, FM-106.
**Research required:** Browser private-network request behavior, Axum CORS/CSRF patterns, and reverse-proxy header trust.
**Acceptance criteria:** Cross-site mutation attempts fail; supported same-origin web/API use works; CLI calls remain possible; proxy trust is explicit; protection does not claim to authenticate individual LAN callers.
**Non-goals:** Login, identity, per-user sessions, revocable API tokens, or Internet exposure.
**Tests:** Origin/CORS/CSRF/Host/proxy integration matrix and CLI regression tests.

### FM-105 — Deferred authenticated authorization-engine spike

FM-105 moves to M8 with FM-S02. It evaluates Cedar only when authenticated human/agent/CI identities and scoped policies enter the roadmap. It is not a dependency of the trusted-LAN release.

### FM-106 — Add centralized authorization port and permission catalog

**Context:** Every later mutation/read needs one decision point even if the final policy engine remains swappable.  
**Goal:** Define principal/action/resource/context request, decision/diagnostics, permission catalog, an explicit allow-all `anonymous-lan-admin` adapter, and application middleware/helper. Preserve the port for a later deny-by-default authenticated adapter.
**Architecture reference:** `architecture/security.md#authorization`; ADR-0001.  
**Dependencies:** FM-004, FM-103.
**Research required:** Map HTTP hiding versus domain denial and model a stable decision record that survives later authentication.
**Acceptance criteria:** No handler/provider directly decides permission; the LAN adapter explicitly permits the catalog rather than bypassing it; resource context is included; decisions carry stable reason/policy IDs without secret data; catalog documents read/write risk.
**Non-goals:** Complete end-user policy editor or every future permission.  
**Tests:** LAN-principal permit, unknown-principal denial, missing context, handler/provider bypass checks, and decision diagnostics.

### FM-107 — Add append-only audit event service

**Context:** Autonomous and infrastructure actions require intent/decision/outcome traceability.  
**Goal:** Persist/query audit events with actor/action/resource/decision/correlation/operation/outcome and mandatory redaction.  
**Architecture reference:** `architecture/security.md#audit`.  
**Dependencies:** FM-101, FM-106.  
**Research required:** Transactional outbox/event pattern and retention/indexing for SQLite.  
**Acceptance criteria:** Accepted mutations write intent in the state transaction where possible; terminal outcomes append separately; query is paginated/authorized; metadata schema rejects raw headers/env/secret fields.  
**Non-goals:** SIEM forwarding, tamper-evident external ledger, or arbitrary full request logging.  
**Tests:** Transaction rollback, ordered pagination, correlation, redaction corpus, unauthorized query.

### FM-108 — Implement durable Operation state and API

**Context:** Remote work cannot be a request-scoped task.  
**Goal:** Persist operation creation, state transitions, idempotency, progress, deadlines, cancellation request, terminal result/error, and correlation API.  
**Architecture reference:** ADR-0008; `architecture/overview.md`.  
**Dependencies:** FM-101, FM-106, FM-107.  
**Research required:** Operation transition model and idempotency key scoping/retention.  
**Acceptance criteria:** Duplicate accepted requests return the same operation; invalid transitions fail; cancellation/deadline are explicit states; public result is redacted and bounded; restart preserves truth.  
**Non-goals:** Generic worker execution, node dispatch, or provider-specific progress.  
**Tests:** Transition/property, concurrent idempotency, restart, auth scope, truncation/redaction.

### FM-109 — Spike and implement the persistent operation worker

**Context:** A durable operation record still needs safe claim/retry/recovery execution. Effectum may help but cannot own Fleet semantics.  
**Goal:** Evaluate Effectum against the existing SQLite/transaction model, then implement the smallest worker adapter that claims operation steps, heartbeats, retries classified-safe work, and recovers abandoned claims.  
**Architecture reference:** ADR-0007/0008.  
**Dependencies:** FM-108.  
**Research required:** Effectum database ownership/transactions/cancellation/recovery; compare a constrained SQL claim/outbox loop.  
**Acceptance criteria:** Decision is documented; only one worker owns a claim; crash/restart recovers; unsafe steps do not auto-retry; shutdown drains/checkpoints; queue saturation/backpressure is visible.  
**Non-goals:** Distributed workers, cron platform, provider/node calls, or Lab scheduler.  
**Tests:** Kill/restart, double worker, lease expiry, safe/unsafe retry, graceful shutdown integration tests.

### FM-110 — Deliver trusted-LAN system/operation vertical slice in API, web, and CLI

**Context:** The API-first rule needs one complete path before machine features.  
**Goal:** Expose system info and operation list/detail/cancel consistently in generated client, Vue shell, and `fleetctl`.  
**Architecture reference:** ADR-0001/0002; `architecture/overview.md#api-and-client-contract`.  
**Dependencies:** FM-006, FM-103, FM-104, FM-108, FM-109.
**Research required:** SSE reconnect/cursor behavior and CLI JSON/stdout conventions.  
**Acceptance criteria:** Web uses generated client; CLI supports human and JSON output; SSE resumes progress after reconnect and gap triggers refetch; authorization and correlation behave identically; no business rule in UI/CLI.  
**Non-goals:** Machine screens, design-system expansion, accounts/login, MCP, or desktop shell.
**Tests:** API-client contract, CLI stdout/stderr snapshots, web component/e2e, SSE reconnect/gap e2e.

## M2 — Machines, connectivity, and onboarding

**Status: In progress (as of 2026-09-04, checkpoint at `main` `f309163`).** Created as epics #50–#53 with issues #54–#68. Resolved and closed: FM-S05 (spike #68 — SSH transport fallback confirmed), FM-200 (#54 machine model/storage), FM-201 (#55 SSH trust workflow), FM-202 (#56 bounded SSH execution), FM-203 (#57 agentless inventory probes), FM-204 (#58 single-use enrollment tokens, key binding, nonce proof, node credential/session issuance, rotation/revocation — machine-facing endpoints at `/api/node/v1` and the operator surface under `machines/{id}/node`), FM-205 (#59 controller WSS gateway + fleetd client — session-by-proof admission at `GET /api/node/v1/connect`, Hello/Welcome negotiation, one-session-per-node supersede, sparse heartbeat state, bounded-jitter reconnect; revocation now both prevents renewal and disconnects via supersede/close), FM-207 (#61 command dispatch + node journal — `node.noop`/`node.diagnostic`/`node.inventory` operations dispatch through the gateway, the fleetd NDJSON journal dedupes replays and survives torn tails, redelivery replays journaled results, flow control bounds in-flight commands), FM-206 (#60 fleetd inventory — pluggable isolated probes, `node.inventory` as a command kind, node-local baseline/delta with the gap rule, controller ingestion with provenance; no per-snapshot audit churn), FM-208 (#62 constrained local socket API — a `0660` Unix socket at `local.sock` with `SO_PEERCRED` defense in depth, one read (`GET /local/status`: node facts + the controller's public system view), no mutations or forwarding, and `fleetctl status` with local-preferred routing and an explicit `--url` override). Next: **FM-209 (#63 machine API/web/CLI — also the read surface for the capability facts FM-203/FM-206 store); all of its dependencies are merged.** Then FM-210 (#64 Add Machine), FM-211 (#65 service install; needs a real Linux VM), FM-212 (#66 upgrade workflow), FM-213 (#67 Tailscale, optional). FM-214 stays deferred past the first Lab release.

### FM-200 — Add machine, endpoint, observation, tag, and capability model/storage

**Context:** Machine identity must be stable while hostnames/IPs/endpoints and observations change.  
**Goal:** Implement machine aggregate/storage plus connection endpoints, inventory snapshot metadata, namespaced capability facts, tags, and groups.  
**Architecture reference:** `architecture/overview.md#stable-identity-and-association`; `provider-model.md#capability-facts`.  
**Dependencies:** FM-101, FM-108.  
**Research required:** UUID/name normalization, JSON payload retention versus normalized columns, staleness indexing.  
**Acceptance criteria:** Hostname/IP are never identity; endpoints can coexist; observations retain provenance/time/version; capability unknown/stale differs from unavailable; tag/group filtering is paginated.  
**Non-goals:** SSH connection, fleetd, desired profiles, Proxmox association.  
**Tests:** Repository/constraint, endpoint update, staleness clock, filter/pagination, serialization.

### FM-201 — Implement SSH endpoint and known-host trust workflow

**Context:** Agentless onboarding must not normalize insecure host-key bypass.  
**Goal:** Store an SSH endpoint and implement connect test with strict known-host verification, explicit first fingerprint confirmation, and host-key-change block.  
**Architecture reference:** `provider-model.md`; `security.md#remote-execution-and-providers`.  
**Dependencies:** FM-102, FM-200.  
**Research required:** OpenSSH isolated config/known_hosts, ProxyJump, key/agent auth, Linux targets, and Purple SSH patterns.
**Acceptance criteria:** Password/key/agent secret references do not leak; TOFU requires authorized confirmation; changed key blocks; controller uses isolated files and bounded timeout; useful diagnostics are redacted.  
**Non-goals:** Remote commands, inventory, SSH config editor/import, or certificate authority.  
**Tests:** Ephemeral SSH servers for new/known/changed key, timeout/auth failure, secret/log redaction.

### FM-202 — Implement bounded SSH command execution

**Context:** Inventory and bootstrap need a common agentless executor with cancellation and audit.  
**Goal:** Implement argument/script dispatch over verified SSH with working directory, environment allowlist, deadline, output bounds, exit result, and operation integration.  
**Architecture reference:** `controller-node-protocol.md#commands-and-privilege`; `provider-model.md`.  
**Dependencies:** FM-109, FM-201.  
**Research required:** OpenSSH process cancellation/control socket behavior, shell quoting across POSIX/PowerShell, sudo policy.  
**Acceptance criteria:** Structured script payload avoids interpolating user data; timeout/cancel kills local SSH and reports remote uncertainty; stdout/stderr truncate safely; concurrency is limited; every execution is authorized/audited.  
**Non-goals:** Interactive terminal, file browser, unrestricted sudo, or bulk fan-out.  
**Tests:** Linux SSH integration for exit/output/timeout/cancel/disconnect and quoting-injection fixtures. Windows command execution is a later support claim.

### FM-203 — Implement agentless OS/hardware/tool inventory probe

**Context:** SSH-managed machines need limited onboarding inventory before `fleetd`.  
**Goal:** Detect OS/architecture/hostname/CPU/RAM/storage/IP plus presence/version of Git, Docker, Tailscale, major agents, Skills Manager, Frogenv, and mise through versioned probes.  
**Architecture reference:** `provider-model.md#capability-facts`; `desired-state.md#observed-state`.  
**Dependencies:** FM-200, FM-202.  
**Research required:** Stable native commands on the supported Linux baseline and least-privilege behavior.
**Acceptance criteria:** Partial failures preserve other facts; each fact has source/time/version/status; probes are bounded/read-only; unsupported OS returns raw baseline plus explicit gaps; no project-recursive scan yet.  
**Non-goals:** Install/update, project discovery, Docker containers, or hardware benchmark.  
**Tests:** Sanitized fixtures per OS, locale/spacing/null variance, partial command failure, real Linux integration.

### FM-204 — Implement single-use node enrollment records and key proof

**Context:** Fully managed nodes need identity independent of endpoint/network.  
**Goal:** Create enrollment token API, node public-key binding, nonce proof, short-lived node credential/session issuance, rotation/revocation storage, and audit.  
**Architecture reference:** ADR-0003; `controller-node-protocol.md#enrollment-and-node-identity`; `security.md`.  
**Dependencies:** FM-102, FM-106, FM-200.  
**Research required:** Ed25519 challenge protocols, token hashing, replay/race prevention, OS key storage.  
**Acceptance criteria:** Token is scoped/hashed/single-use/expiring; private key never leaves node; replay and concurrent claim fail; node session cannot access user API; revocation disconnects/prevents renewal.  
**Non-goals:** WSS message loop, automatic machine merge, Tailscale auth, or binary update signing.  
**Tests:** Crypto vectors, replay/race/expiry/wrong-key/revocation, authorization boundary.

### FM-205 — Implement outbound node gateway hello/heartbeat/reconnect

**Context:** Enrolled nodes need a persistent, version-negotiated channel before commands.  
**Goal:** Implement controller WSS gateway and fleetd client for proof/session, `Hello/Welcome`, heartbeat, backoff, drain/shutdown, and online/stale/offline state.  
**Architecture reference:** ADR-0002/0003; `controller-node-protocol.md`.  
**Dependencies:** FM-007, FM-204.  
**Research required:** Axum/rustls WebSocket limits, reverse-proxy idle timeouts, jittered reconnect.  
**Acceptance criteria:** Only one active session per node/boot policy; protocol mismatch is actionable; reconnect uses bounded jitter; heartbeat does not flood SQLite; state transitions are observable/audited where meaningful.  
**Non-goals:** Inventory, commands, Tailscale, or multi-controller gateway.  
**Tests:** Real WSS, idle proxy simulation, duplicate session, protocol ranges, clock/staleness, reconnect storm limits.

### FM-206 — Implement fleetd local inventory snapshots and deltas

**Context:** Fully managed inventory must be richer and periodic without rescanning everything every heartbeat.  
**Goal:** Add pluggable local probes, baseline snapshot, revisioned delta, periodic/event-triggered collection, and controller ingestion.  
**Architecture reference:** `controller-node-protocol.md#delivery-and-recovery`; `desired-state.md#observed-state`.  
**Dependencies:** FM-203 probe schemas, FM-205.  
**Research required:** Cross-platform disk/network/tool APIs and filesystem-watch cost.  
**Acceptance criteria:** Delta references known baseline; gap requests full snapshot; slow/failed probe is isolated; payload/output limits hold; controller records provenance/version/staleness; no volatile churn overwhelms audit.  
**Non-goals:** Recursive project discovery, container list, desired apply, or realtime performance telemetry.  
**Tests:** Probe unit fixtures, baseline/delta/gap, partial timeout, payload bounds, cross-platform CI smoke.

### FM-207 — Implement node command journal and at-least-once dispatch

**Context:** Disconnect/retry must not execute the same install/command twice.  
**Goal:** Dispatch a typed no-op/diagnostic command from durable Operation to node, persist acceptance/result journal locally, deduplicate command ID/idempotency key, stream bounded progress, cancel, and reconcile after reconnect.  
**Architecture reference:** ADR-0008; `controller-node-protocol.md#delivery-and-recovery`.  
**Dependencies:** FM-108, FM-109, FM-205.  
**Research required:** Node-local SQLite or atomic journal choice, process cancellation semantics, result retention.  
**Acceptance criteria:** Duplicate delivery does not duplicate execution; restart returns/resumes terminal result; deadline/cancel state distinguishes confirmed versus uncertain; flow-control bounds in-flight work/log bytes.  
**Non-goals:** General shell, provider commands, privileged helper, or exactly-once claim.  
**Tests:** Disconnect before/after ack/result, controller/node kill/restart, duplicate frames, journal corruption/recovery, backpressure.

### FM-208 — Implement constrained fleetd local Unix-socket API

**Context:** Local agents should use fleetd without controller admin credentials.  
**Goal:** Expose local status and forwarded read request using Unix-socket peer permissions/credentials and a smaller allowlisted contract; add fleetctl route selection.
**Architecture reference:** ADR-0003; `controller-node-protocol.md#local-agent-path`.  
**Dependencies:** FM-110, FM-205.  
**Research required:** Unix peer credentials and systemd socket permissions.
**Acceptance criteria:** Non-member local user is denied; allowed caller can get node/Fleet read status; no controller/provider secret or admin endpoint is reachable; direct-controller override is explicit; route appears in diagnostics/JSON.  
**Non-goals:** Agent delegation tokens, mutation forwarding, MCP, interactive terminal, or Windows named pipes.
**Tests:** Unix permissions/peer identity, surface allowlist, and unavailable fallback.

### FM-209 — Add machine list/detail/status to API, web, and fleetctl

**Context:** M2 needs one consistent operational view of SSH and fleetd machines.  
**Goal:** Expose identity, endpoints (redacted), inventory summary, capabilities, tags/groups, connected/stale/offline/agentless state, and last observation.  
**Architecture reference:** ADR-0001/0002; `overview.md`.  
**Dependencies:** FM-110, FM-200, FM-203, FM-205, FM-206.  
**Research required:** Accessible data-density patterns in existing `DESIGN.md`; no new external dependency.  
**Acceptance criteria:** API is canonical; web uses generated client; CLI human/JSON parity; stale/unknown differs from missing; filters cover tag/group/capability/status; secrets/usernames are permission-aware.  
**Non-goals:** Desired drift/apply, bulk actions, charts, or command palette.  
**Tests:** API/filter/pagination authorization, CLI snapshots, web component/e2e, stale clock.

### FM-210 — Implement SSH Add Machine onboarding workflow

**Context:** Users need a staged, reviewable path from address to registered agentless machine.  
**Goal:** Create draft/test/discover/review/add operation across API, web, and CLI with OS/profile hint and explicit SSH fingerprint confirmation.  
**Architecture reference:** `security.md`; M2 in `PLAN.md`.  
**Dependencies:** FM-201, FM-203, FM-209.  
**Research required:** Safe password/key UX and temporary credential lifecycle.  
**Acceptance criteria:** Test has no persistent machine side effect; draft secret cleanup is defined; discovered facts are reviewable; add assigns Fleet ID and endpoint; duplicate candidates are warned, not auto-merged; unsupported facts do not block basic agentless add.  
**Non-goals:** Install fleetd, apply profile, tool installation, or Tailscale import.  
**Tests:** Happy path, host-key confirm/change, duplicate, partial inventory, cancel/secret cleanup, web e2e.

### FM-211 — Package/install fleetd as a system service on the first Linux target

**Context:** “Install Fleet Node” needs a reproducible, signed/checksummed service deployment before multi-OS breadth.  
**Goal:** Produce package/archive and an audited SSH bootstrap operation for one approved Linux distribution, service account, protected key storage, enrollment, health, upgrade/rollback layout.  
**Architecture reference:** `controller-node-protocol.md#commands-and-privilege`; `security.md`.  
**Dependencies:** FM-202, FM-204, FM-205, FM-207, release artifact from FM-001.  
**Research required:** systemd hardening, deb/rpm or portable archive choice, signature/update framework, package repository later path.  
**Acceptance criteria:** No reusable enrollment secret in process list/files after use; service is non-root unless a reviewed helper is necessary; restart/reboot reconnects; failed install leaves agentless endpoint usable; uninstall/re-enroll behavior documented.  
**Non-goals:** Windows/macOS services, self-update service, or tool/profile application.
**Tests:** Fresh VM install/reboot/reconnect, failure rollback, permissions, token cleanup, upgrade/downgrade compatibility.

### FM-212 — Add “Install Fleet Node” upgrade workflow

**Context:** Onboarding promises a one-click transition from agentless SSH to fully managed.  
**Goal:** Orchestrate artifact selection, one-time enrollment, service install, session wait, identity association, inventory verification, and operation UI/CLI.  
**Architecture reference:** M2 exit gate; ADR-0003/0008.  
**Dependencies:** FM-210, FM-211.  
**Research required:** Identity match rules and safe timeout/manual recovery UX.  
**Acceptance criteria:** Existing Fleet machine ID is retained after confirmed association; timeout leaves explicit recoverable state; accidental second node cannot claim it; operation progress/rollback/audit are visible; supported-platform limitation is clear.  
**Non-goals:** Assign/apply Developer profile or multi-machine bulk install.  
**Tests:** End-to-end agentless-to-managed, wrong node proof, timeout/retry, controller restart midway.

### FM-213 — Add optional Tailscale device discovery/import

**Context:** Tailnet discovery can simplify onboarding but is not a prerequisite.  
**Goal:** Configure scoped OAuth credentials, list normalized devices, correlate cautiously with Fleet machines, and import a device address as an SSH onboarding draft.  
**Architecture reference:** ADR-0003/0005; research Tailscale section.  
**Dependencies:** FM-102, FM-210.  
**Research required:** Current Tailscale device API/scopes/pagination/rate limits and OAuth app versus client use.  
**Acceptance criteria:** Read-only minimum scope is documented; token refresh works; correlation evidence is displayed and never silently merges; import proceeds through SSH trust/test; integration can be disabled/removed without affecting Fleet identity.  
**Non-goals:** Mandatory Tailscale install, ACL editor, Headscale, or automatic auth-key distribution.  
**Tests:** Recorded API fixtures, pagination/rate/auth failure, secret redaction, duplicate/correlation cases, import handoff.

### FM-214 — Deferred Windows in-guest management slice

FM-214 moves after the first Lab release. Initial Windows support in M6 is Proxmox lifecycle plus QEMU Guest Agent health/IP observations. The later issue retains the Windows service, protected node key, named-pipe broker, inventory/exec, project readiness, upgrade/rollback, and real-host test requirements described by FM-S04.

## Creation and dependency hygiene

- Put every issue under exactly one milestone and one epic.
- Add `type:spike` only when the acceptance criterion is a decision/evidence package.
- Link blocking issues rather than copying their scope.
- Add provider labels only to adapter issues; domain/application work should stay provider-neutral.
- Do not open M3+ implementation issues until the relevant upstream CLI/API is refreshed and the M0/M1 contracts have landed.
- Create every spike in [spikes.md](spikes.md) as a `type:spike` issue under its owning milestone before the issues in its **Consumed by** column start.
