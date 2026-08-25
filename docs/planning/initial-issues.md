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

| Planning ID | Issue | Epic |
|---|---|---|
| FM-000 | [#20](https://github.com/Frogbyte-io/fleet-manager/issues/20) (closed) | — precedes the epics |
| FM-001 | [#21](https://github.com/Frogbyte-io/fleet-manager/issues/21) | [#19](https://github.com/Frogbyte-io/fleet-manager/issues/19) Build, CI, and deployment foundation |
| FM-002 | [#22](https://github.com/Frogbyte-io/fleet-manager/issues/22) | [#17](https://github.com/Frogbyte-io/fleet-manager/issues/17) Monorepo and legacy migration |
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

### FM-002 — Scaffold Cargo and pnpm workspaces

**Context:** Target component boundaries need compilable roots before parallel work.  
**Goal:** Create empty/skeletal crates and Vue workspace matching the approved layout, without moving legacy code.  
**Architecture reference:** `docs/PLAN.md#recommended-monorepo-layout`; ADR-0001/0006.  
**Dependencies:** FM-001.  
**Research required:** Axum/Vue/Vite supported versions and controller static asset embedding options.  
**Acceptance criteria:** Every crate has its documented dependency direction; binaries print version/help only; Vue renders a static shell; one root verification command builds/tests both workspaces; no product provider behavior.  
**Non-goals:** API routes, database, authentication, machine registration, or visual feature design.  
**Tests:** Workspace dependency graph check, Rust unit smoke, Vue type/build smoke.

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

**Context:** Web, CLI, and MCP need one stable client contract before endpoints proliferate.  
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
**Dependencies:** FM-002, FM-006.  
**Research required:** Reproducible multi-stage Rust/Vue image builds, container health checks, non-root file ownership.  
**Acceptance criteria:** `docker compose up -d` reaches healthy; web shell is served by controller; container has no Docker socket/host network/privileged mode; persistent and secret mount locations are documented; graceful SIGTERM passes.  
**Non-goals:** TLS termination, database migrations, login, or production reverse-proxy templates.  
**Tests:** Compose e2e smoke, read-only root filesystem feasibility check, signal shutdown test.

## M1 — Controller, API, and security kernel

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

### FM-103 — Implement one-time administrator bootstrap

**Context:** A fresh remote controller must not ship default credentials or an open admin API.  
**Goal:** Create one expiring single-use bootstrap path that establishes the first admin credential/session and then disables itself.  
**Architecture reference:** `architecture/security.md#identities`.  
**Dependencies:** FM-101, FM-102, FM-106.  
**Research required:** Password hashing versus passkey/OIDC first slice and secure console/file delivery.  
**Acceptance criteria:** Bootstrap is required only when no admin exists; replay/expiry/race loses safely; secret is emitted once without access-log leakage; successful setup creates audited admin identity and invalidates bootstrap.  
**Non-goals:** Multi-user invitations, OIDC, recovery, or GitHub login.  
**Tests:** Concurrent claim, expiry, restart, replay, log-redaction integration tests.

### FM-104 — Implement web sessions and revocable CLI tokens

**Context:** Web and CLI need different safe credential storage/transport.  
**Goal:** Add authenticated sessions, logout/revocation, CSRF controls, and named expiring CLI tokens with hashed storage.  
**Architecture reference:** `architecture/security.md#identities`; ADR-0002.  
**Dependencies:** FM-101, FM-102, FM-103, FM-106.  
**Research required:** Axum session/cookie/CSRF libraries and OS credential-store follow-up for `fleetctl`.  
**Acceptance criteria:** Secure cookie attributes and CSRF protection; API token shown once and stored hashed; expiry/revocation checked centrally; auth failures use stable API errors and do not reveal identity existence.  
**Non-goals:** Agent/node credentials, OIDC, scopes beyond user role bindings.  
**Tests:** Cookie/CSRF/revocation/expiry/token hash/timing-safe comparison tests.

### FM-105 — Spike Cedar with Fleet authorization scenarios

**Context:** Fleet needs RBAC/ABAC-like resource scopes but must not invent a policy language.  
**Goal:** Model at least admin, read-only user, development operator, restricted Codex, and CI Lab policies in Cedar; measure integration and authoring costs.  
**Architecture reference:** `architecture/security.md#authorization`.  
**Dependencies:** FM-004; can run before FM-106.  
**Research required:** Current Cedar Rust API/schema/validator, forbid/default-deny diagnostics, policy storage/versioning.  
**Acceptance criteria:** Executable matrix covers machine/project/tag/production/Lab TTL/resource constraints; deny/forbid and malformed policy behavior are proven; report recommends adopt/defer/reject and updates ADR/security doc.  
**Non-goals:** Production UI, OpenFGA service, or permission enforcement rollout.  
**Tests:** Policy matrix as data-driven tests and evaluation benchmark.

### FM-106 — Add centralized authorization port and permission catalog

**Context:** Every later mutation/read needs one decision point even if the final policy engine remains swappable.  
**Goal:** Define principal/action/resource/context request, decision/diagnostics, permission catalog, default-deny adapter, and application middleware/helper.  
**Architecture reference:** `architecture/security.md#authorization`; ADR-0001.  
**Dependencies:** FM-004, FM-105 decision.  
**Research required:** Incorporate Cedar spike; map HTTP hiding versus domain denial.  
**Acceptance criteria:** No handler/provider directly decides permission; explicit forbid wins; resource scope is included; decisions carry stable reason/policy IDs without secret data; catalog documents read/write risk.  
**Non-goals:** Complete end-user policy editor or every future permission.  
**Tests:** Default deny, permit/forbid, scope/tag/project, missing context, decision diagnostics.

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

### FM-110 — Deliver authenticated system/operation vertical slice in API, web, and CLI

**Context:** The API-first rule needs one complete path before machine features.  
**Goal:** Expose system info and operation list/detail/cancel consistently in generated client, Vue shell, and `fleetctl`.  
**Architecture reference:** ADR-0001/0002; `architecture/overview.md#api-and-client-contract`.  
**Dependencies:** FM-006, FM-104, FM-108, FM-109.  
**Research required:** SSE reconnect/cursor behavior and CLI JSON/stdout conventions.  
**Acceptance criteria:** Web uses generated client; CLI supports human and JSON output; SSE resumes progress after reconnect and gap triggers refetch; authorization and correlation behave identically; no business rule in UI/CLI.  
**Non-goals:** Machine screens, design-system expansion, MCP, or desktop shell.  
**Tests:** API-client contract, CLI stdout/stderr snapshots, web component/e2e, SSE reconnect/gap e2e.

## M2 — Machines, connectivity, and onboarding

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
**Research required:** OpenSSH isolated config/known_hosts, ProxyJump, key/agent auth, Windows targets, Purple SSH patterns.  
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
**Tests:** Linux SSH integration for exit/output/timeout/cancel/disconnect; quoting injection fixtures; Windows contract marked required before support claim.

### FM-203 — Implement agentless OS/hardware/tool inventory probe

**Context:** SSH-managed machines need limited onboarding inventory before `fleetd`.  
**Goal:** Detect OS/architecture/hostname/CPU/RAM/storage/IP plus presence/version of Git, Docker, Tailscale, major agents, Skills Manager, Frogenv, and mise through versioned probes.  
**Architecture reference:** `provider-model.md#capability-facts`; `desired-state.md#observed-state`.  
**Dependencies:** FM-200, FM-202.  
**Research required:** Stable native commands on supported Linux and Windows targets and least-privilege behavior.  
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

### FM-208 — Implement constrained fleetd local socket/named-pipe API

**Context:** Local agents should use fleetd without controller admin credentials.  
**Goal:** Expose local status and forwarded read request using OS peer permissions/credentials and a smaller allowlisted contract; add fleetctl route selection.  
**Architecture reference:** ADR-0003; `controller-node-protocol.md#local-agent-path`.  
**Dependencies:** FM-110, FM-205.  
**Research required:** Unix peer credentials/systemd socket permissions and Windows named-pipe ACL/client identity.  
**Acceptance criteria:** Non-member local user is denied; allowed caller can get node/Fleet read status; no controller/provider secret or admin endpoint is reachable; direct-controller override is explicit; route appears in diagnostics/JSON.  
**Non-goals:** Agent delegation tokens, mutation forwarding, MCP, or interactive terminal.  
**Tests:** Unix permissions/peer identity, mocked Windows ACL contract plus Windows CI, surface allowlist, unavailable fallback.

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
**Non-goals:** The Windows service (FM-214), macOS installers, self-update service, tool/profile application.  
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

### FM-214 — Package/install fleetd as a Windows service

**Context:** FM-000 committed Windows to the initial supported platform baseline, so the M2 exit gate cannot be met by the Linux packaging in FM-211 alone.  
**Goal:** Produce a Windows service package and an audited bootstrap operation covering service account, protected key storage, named-pipe broker permissions, enrollment, health, and upgrade/rollback layout.  
**Architecture reference:** ADR-0003; `controller-node-protocol.md#commands-and-privilege`; `security.md`; [fm-000-acceptance.md](fm-000-acceptance.md).  
**Dependencies:** FM-S04, FM-208, FM-211.  
**Research required:** Windows service installation and recovery settings, DPAPI or equivalent for node key storage, named-pipe ACLs and peer identification, code-signing requirements, process-tree termination for cancelled commands.  
**Acceptance criteria:** No reusable enrollment secret survives in process arguments or on disk after use; the service runs with the least privilege the broker allows; reboot reconnects; failed install leaves the agentless SSH endpoint usable; named-pipe ACLs deny non-authorized local users; uninstall and re-enroll behavior is documented.  
**Non-goals:** macOS installers, self-update service, tool/profile application, Windows-specific inventory breadth beyond FM-203.  
**Tests:** Fresh Windows host install/reboot/reconnect, failure rollback, pipe ACL denial case, token cleanup, cancellation process-tree test, upgrade/downgrade compatibility.

## Creation and dependency hygiene

- Put every issue under exactly one milestone and one epic.
- Add `type:spike` only when the acceptance criterion is a decision/evidence package.
- Link blocking issues rather than copying their scope.
- Add provider labels only to adapter issues; domain/application work should stay provider-neutral.
- Do not open M3+ implementation issues until the relevant upstream CLI/API is refreshed and the M0/M1 contracts have landed.
- Create every spike in [spikes.md](spikes.md) as a `type:spike` issue under its owning milestone before the issues in its **Consumed by** column start.
