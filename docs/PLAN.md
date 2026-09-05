# Fleet Manager master plan

Status: accepted baseline; product-scope revision in progress
Prepared: 2026-08-25  
Accepted: 2026-08-25 — see [planning/fm-000-acceptance.md](planning/fm-000-acceptance.md)  
Revised: 2026-08-27 — confirmed product decisions from the maintainer planning review below  
Scope: architecture and development planning only; no product features are implemented by this plan  
Execution: M0 and M1 are complete and their epics are closed; M2 is in progress — waves 1–5 closed as of 2026-09-05 and FM-210 is implemented (PR #69), FM-211 is next. Live per-issue status: [planning/parallel-execution.md](planning/parallel-execution.md)

## Confirmed 2026-08-27 product-scope revision

This section records decisions confirmed during the maintainer's current plan review. It supersedes conflicting roadmap and acceptance-scope text below; the detailed milestone text has also been aligned where the consequences are already known. The review is still in progress, so unanswered design branches remain open rather than being guessed.

- **One product ladder:** ship Developer Fleet as a complete first release, then build Fleet Lab on the proven controller, machine, project, provider, and operation foundations. Do not run them as competing product tracks.
- **Initial deployment and trust:** the controller is hosted on Linux and exposed only on a trusted local network. The dashboard has no accounts or login initially; every LAN client can read and mutate. Application-layer authorization and audit remain mandatory, initially using a clearly identified `anonymous-lan-admin` principal so later authentication does not require handler rewrites.
- **Human usage:** several people may view or operate the same web dashboard, but the product is optimized for one human controller at a time rather than concurrent multi-user collaboration.
- **Windows scope:** Fleet need not run its controller on Windows. Initial Windows support is Proxmox VM lifecycle plus QEMU Guest Agent health/IP visibility. A Windows `fleetd`, in-guest inventory/exec, local broker, and project readiness are later work after the first Lab release.
- **First Lab promise:** request a disposable Linux environment, prepare a project, execute commands, and guarantee TTL-driven cleanup. Rich scheduling, hardware passthrough, Windows guest readiness, and broad artifact workflows follow later.
- **GitOps sequencing:** full desired-state/Git activation is not a prerequisite for the first Lab release. Lab takes only the minimal versioned bootstrap-profile and Lab-template contracts it needs; the broader M4 product proceeds independently afterward.
- **Image production:** Fleet creates and maintains Proxmox VM templates through an image-build provider, with Packer as the first external CLI integration. Modern `.pkr.json` is the portable recipe format. Fleet offers a structured editor for supported Proxmox fields plus an advanced raw-JSON editor.
- **Image versioning:** editing creates a draft; saving an edit of an existing recipe produces a new version. Build inputs and outputs are immutable snapshots. Promotion of a successfully built image version is manual. Automatic rebuild/update policy is out of scope for the first release; the exact pre-promotion validation gate remains under review.
- **Future recipe catalog:** a future test-VM marketplace distributes Packer recipes, metadata, provisioning assets, compatibility constraints, and integrity/provenance data—not VM disk images. Licensed installation media remains operator-supplied.
- **Agent access:** humans and agents use the same public API through `fleetctl --output json`; official Fleet skills are thin workflows over that CLI. Agents may use the available operations autonomously in the initial trusted-LAN deployment. A dedicated MCP server is not planned.

## Product direction

Fleet Manager will be a persistent, controller-first and web-first control plane for developer infrastructure: machines, source checkouts, AI coding tools and skills, development environments, containers, Proxmox resources, and disposable Lab environments. It coordinates specialized systems; it does not replace them.

The recommended first product is a self-hosted modular monolith:

```text
Browser        fleetctl <---- Fleet skills/agents
   \              |
    +--------- Fleet HTTP API
                  |
          application services
        authz / audit / operations
                  |
    SQLite runtime state + secret references
          /                 \
 controller providers     node connections
 SSH GitHub Tailscale      outbound WSS
 Proxmox                   fleetd -> local providers
```

The controller is the only always-on control plane. The Vue web app is static content served by the controller and contains no independent business logic. `fleetctl`, the web app, agent-facing Fleet skills, and any future desktop shell invoke the same application services through the same public API contracts. Skills call `fleetctl`; they do not create a parallel authority or business-logic surface.

## Current-codebase assessment

The repository at commit `913944e` is a coherent proof of concept, not an incremental base for the final runtime.

| Area | Current state | Planning consequence |
|---|---|---|
| Runtime | Private Node 18 ESM package, about 1,649 lines across source and tests | Freeze feature growth, retain characterization tests, and migrate capability-by-capability into the Rust workspace. Avoid a line-by-line port. |
| Declarative state | Loads YAML from a separate registry repo; resolves machines, inherited roles, skill packs, projects, test profiles, capabilities, and device references | Preserve the useful resolution semantics as migration fixtures, but replace the informal schema with versioned JSON Schema and explicit desired-state resources. |
| CLI | `agents-registry` supports `init`, `validate`, `resolve`, `status`, `capabilities`, and a limited local `sync` | Rename the future user-facing CLI to `fleetctl`. Keep a temporary compatibility wrapper only if real installations require it. |
| Skills | `skillsBackend.js` probes a generic `skills` binary and constructs shell templates such as `skills install`; it does not integrate Skills Manager's documented CLI | Replace with a `skills-manager-cli --json` provider and contract tests. Never parse its SQLite database. The skills.sh `skills` CLI is a distinct tool whose documented install verb is `add`. |
| Proxmox | Handwritten HTTPS client with API token auth, certificate fingerprint checks, UPID polling, and a few QEMU actions | Preserve TLS and task-polling tests as requirements. Replace the environment-variable singleton with a multi-account provider, typed domain mapping, least-privilege credentials, discovery, and a library compatibility spike. |
| Persistence | Local config file only; no controller database | Add controller-owned runtime persistence, migrations, backup/restore, durable operations, and audit before remote mutation. |
| Connectivity | No controller, node daemon, SSH inventory, enrollment, protocol, or realtime channel | Build a thin vertical slice before feature providers. |
| User/API surfaces | No web app, HTTP API, stable JSON envelope, or generated client | Define OpenAPI first, generate the TypeScript client, and require JSON output from `fleetctl`. |
| Security | Proxmox token handling and TLS pinning exist, but there are no identities, sessions, authorization, secret store, or audit trail | Security is a foundation milestone, not an Agent Automation afterthought. |
| Licensing | Resolved by FM-000: the repository is Apache-2.0 with a root `LICENSE` and `NOTICE` | Third-party source copied in must be attributed in `NOTICE` under its own terms; CI must enforce the inbound license policy from FM-001 onward. |
| Tests | There are 50 Node tests. Repeated Node 24 runs exposed an intermittent failure in `waitForTask rejects on timeout`: its 2 ms wall-clock threshold can exhaust three canned responses before `Date.now()` advances far enough (reconfirmed on 2026-08-25: only one of five isolated reruns passed, so it now fails more often than it succeeds) | Make this test deterministic with an injected/fake clock or bounded polling as migration characterization work, then keep the legacy suite green until superseded. The earlier missing-dependency failure was an uninstalled workspace, not a source defect. |

The open issues also need triage. Issues #2 and #3 are too broad for implementation and should be closed as superseded after this plan is approved and replacement epics exist. Closed issue #1 describes the correct Skills Manager boundary, but the implementation never reached its current public CLI contract.

## Architecture recommendations that change the brief

1. **Use a modular monolith, not services.** One controller process, one database, and in-process application modules minimize deployment and consistency costs. Provider and storage ports preserve boundaries without pretending distributed deployment is already needed.
2. **Split public and node protocols.** Public clients use versioned HTTP/JSON described by OpenAPI plus SSE for resumable notifications and log/progress streams. `fleetd` uses an outbound authenticated WebSocket with a separately versioned binary protocol. These lifecycles and compatibility needs are different.
3. **Do not make Tailscale the node transport.** Tailscale is a preferred endpoint/discovery provider. Node identity and authorization remain Fleet-owned so direct LAN, VPN, reverse-proxy, and future transports work identically.
4. **Introduce control boundaries before mutation.** Centralized authorization, audit, durable operations, secret references, and remote-command guardrails land before machine apply, Docker actions, Proxmox lifecycle, or Lab writes. The initial trusted-LAN mode authorizes an explicit anonymous LAN principal; named identity and login flows are deferred until Fleet leaves that trust boundary.
5. **Move minimum Skills Manager and Frogenv work earlier.** The primary “clone project to another machine and make it ready” workflow depends on both. Rich administration remains later, but detection, status, setup, and execution contracts belong in Developer Fleet.
6. **Do not make Fleet a package or configuration manager.** Profiles express outcomes. Tool providers delegate to Skills Manager, Frogenv, mise, OS package managers, Docker, and narrowly scoped recipes. Fleet plans, authorizes, invokes, verifies, and audits.
7. **Treat recipes as privileged code.** A recipe is declarative metadata around commands, not a safe plugin format. Sources require trust policy, pinned revisions/checksums where possible, explicit shell use, timeouts, output redaction, and review before apply.
8. **Keep desired resources independent of observed records.** A Git machine declaration must not contain volatile IP, last-seen, current branch, lease, container, or provider status. Stable references associate desired resources with runtime identities.
9. **Start with one controller and SQLite deliberately.** WAL mode, migrations, backups, bounded write transactions, and a single active controller are explicit constraints. PostgreSQL is a later scale/HA migration, not a nominal checkbox in every repository interface.
10. **Use subprocess integrations when that is the public boundary.** Skills Manager, Frogenv, mise, Git, DevPod, and chezmoi should be invoked through documented CLI contracts. Sharing their internal databases or source modules would create tighter and less stable coupling.

## Target component boundaries

| Component | Owns | Must not own |
|---|---|---|
| `fleet-core` | Domain types, invariants, reconciliation plans, lease and reservation state machines, permission/action vocabulary | HTTP, SQL, subprocesses, provider DTOs, UI state |
| `fleet-application` | Use cases, transactions, authorization gates, operation orchestration, provider ports | Framework handlers, concrete databases, provider-specific logic |
| `fleet-controller` | Process composition, HTTP/SSE/WSS hosting, background workers, configuration, web asset serving | Duplicated domain rules |
| `fleet-storage-sqlite` | SQLx repositories, migrations, transaction/outbox mechanics, backups | Desired-state interpretation or authorization policy |
| `fleetd` | Local discovery, provider execution, health, command journal, controller connection, local privileged broker | Fleet-wide scheduling, canonical desired state, administrator credentials |
| `fleetctl` | Human/agent CLI UX, direct-controller mode, local-daemon mode, JSON rendering | Alternate business logic or direct provider access |
| Web app | Views, forms, optimistic UX, API client, accessible realtime presentation | Direct SQL/provider access or reconciliation logic |
| Providers | External protocol/CLI adaptation, capability probes, normalized observations/actions | Cross-provider workflow orchestration or policy decisions |
| Agent skills | Documented workflows over `fleetctl --output json` | Separate authority, direct provider access, or business logic hidden in prompts |

Detailed boundaries are in [architecture/overview.md](architecture/overview.md), [architecture/provider-model.md](architecture/provider-model.md), and [architecture/controller-node-protocol.md](architecture/controller-node-protocol.md).

## Recommended monorepo layout

```text
fleet-manager/
├── apps/
│   └── web/                       # Vue 3, TypeScript, Tailwind
├── crates/
│   ├── fleet-controller/          # controller binary/composition root
│   ├── fleetd/                    # node daemon binary
│   ├── fleetctl/                  # CLI binary
│   ├── fleet-core/                # domain model and pure rules
│   ├── fleet-application/         # use cases and ports
│   ├── fleet-api/                 # public DTOs/OpenAPI adapters
│   ├── fleet-protocol/            # node protocol and compatibility fixtures
│   ├── fleet-config/              # controller/node/CLI config parsing
│   ├── fleet-auth/                # identity, sessions, authorization adapter
│   ├── fleet-secrets/             # encrypted secret-reference implementation
│   ├── fleet-storage-sqlite/      # SQLx repositories and migrations
│   └── providers/
│       ├── fleet-provider-ssh/
│       ├── fleet-provider-tailscale/
│       ├── fleet-provider-docker/
│       ├── fleet-provider-proxmox/
│       ├── fleet-provider-github/
│       ├── fleet-provider-skills-manager/
│       ├── fleet-provider-frogenv/
│       └── fleet-provider-mise/
├── packages/
│   ├── api-client/                # generated from OpenAPI; do not hand-copy DTOs
│   └── ui/                        # shared web-only components when justified
├── proto/                         # node protocol source
├── schemas/                       # desired-state JSON Schemas and examples
├── recipes/                       # reviewed built-in recipe data
├── deploy/
│   └── compose.yaml
├── docs/
│   ├── PLAN.md
│   ├── architecture/
│   ├── adr/
│   ├── planning/
│   └── research/
├── legacy/
│   └── agents-registry/           # temporary, removed after parity/migration
├── xtask/                         # repeatable repository build/generation tasks
├── Cargo.toml
├── package.json
├── pnpm-workspace.yaml
├── mise.toml                      # optional contributor tool/task convenience
└── AGENTS.md
```

Use a Cargo workspace and pnpm workspace. The controller build embeds the web distribution. Do not add Nx or Turborepo initially. Move the current JavaScript package under `legacy/` only after its fixtures can run from the new location; do not combine that move with behavior changes.

## Data ownership summary

| Data | System of record | Fleet behavior |
|---|---|---|
| Optional declarative fleet spec | Fleet Git repository | Clone/fetch, validate, record revision, plan, and apply; never write observed state or secrets there |
| Runtime/observed state | Controller SQLite | Machines, connections, inventory, checkouts, operations, leases, reservations, audit, provider cache, imported desired revision |
| Controller credentials | Encrypted secret records, with master key mounted separately | Resolve just-in-time by secret reference; redact from logs/jobs/audit |
| Node private identity | Node-local protected storage | Never uploaded; used to prove node identity and authenticate sessions |
| Project source | Git host and node checkout | Fleet records remote identity and observed checkout metadata only |
| Skills | Skills Manager library/database and agent directories | Fleet declares requested presets/deployments and caches public CLI observations |
| Project environment secrets | Frogenv/SOPS/age repository and local machine key | Fleet invokes Frogenv and records status; never decrypts values for display or storage |
| Docker/Proxmox/Tailscale resources | Their owning systems | Fleet caches observations and submits authorized lifecycle actions |
| Lab artifacts | Configured artifact store/volume | SQLite stores metadata, digest, owner, retention, and location |

See [architecture/desired-state.md](architecture/desired-state.md) for reconciliation rules.

## Supported platform baseline

FM-000 recorded the original Linux-and-Windows baseline. The 2026-08-27 product-scope revision narrows the initial release gate as follows; the FM-000 record remains historical evidence of the earlier decision.

| Target | Scope | Meaning |
|---|---|---|
| Linux x86_64 (Debian/Ubuntu) | Primary | Agentless SSH, `fleetd` service, Docker, real integration tests, and the controller image |
| Windows guests | Limited initially | Proxmox lifecycle plus QEMU Guest Agent health/IP observations; no Windows controller or in-guest `fleetd` release gate |
| Linux aarch64 | Deferred | Revisit with FM-S06, which flags Skills Manager release coverage on non-x86 Linux |
| macOS | Deferred | Still a design goal in the architecture documents; not an M2 acceptance requirement |
| Proxmox VE 8.x and 9.x | Supported | The M6 compatibility matrix and real-cluster suite must pass on both majors |

Deferred is not rejected. Cross-platform assumptions stay in the protocol, configuration, and filesystem layers so Windows in-guest management, Linux aarch64, or macOS can be added later by testing and packaging work rather than by redesign.

## Milestone roadmap

Milestones are outcome gates, not fixed time boxes. Security, testing, documentation, API contracts, and migration are acceptance work in every milestone.

### M0 — Architecture and migration foundation

Status: complete (2026-09-04 — epics and milestone closed; recorded in [planning/initial-issues.md](planning/initial-issues.md)).

Outcome: the approved architecture is executable as a repository structure without changing product behavior.

- Approve this plan and proposed ADRs.
- Establish Cargo/pnpm workspaces, linting, cross-platform CI, generation checks, and dependency/license policy.
- Move the Node proof of concept to `legacy/` with all characterization fixtures preserved.
- Define public API conventions, node protocol compatibility rules, desired-state schema versioning, stable IDs, error envelopes, and operation semantics.
- Create Rust binary/library shells and Vue shell; no provider features.

Exit gate: one command verifies Rust, TypeScript, schemas, generated API artifacts, legacy tests, and a minimal Compose build.

### M1 — Controller, API, and trusted-LAN control kernel

Status: complete (2026-09-04 — epics and milestone closed; recorded in [planning/initial-issues.md](planning/initial-issues.md)).

Outcome: a persistent trusted-LAN controller can be deployed, inspected, and trusted to record work before it controls a machine.

- Controller configuration, health/readiness, graceful shutdown, static web hosting, and Compose volume layout.
- SQLite migrations/WAL, backup/restore procedure, repository transactions, and runtime metadata.
- Trusted-LAN deployment mode with no accounts or login, an explicit `anonymous-lan-admin` principal, centralized permission vocabulary/authorization boundary, and a documented warning that every LAN client can mutate.
- Encrypted secret-reference store with Docker-secret/file master-key input.
- Append-only audit events and correlation IDs.
- Durable operation model with progress, cancellation, deadlines, idempotency, retries, and restart recovery; evaluate Effectum rather than silently inventing a generic job queue.
- OpenAPI publication, generated TypeScript client, `fleetctl --output json`, and web system/operations shell.

Exit gate: Compose starts a controller bound to its configured local-network interface, API/CLI/web report the same system and operation data, every mutation passes the centralized authorization and audit path, and restart does not lose an accepted operation. Authenticated or Internet-exposed deployment is not supported by this gate.

### M2 — Machines, connectivity, and onboarding

Status: in progress (2026-09-05 — waves 1–5 closed, FM-210 implemented (PR #69); next is FM-211 (#65). Live wave status: [planning/parallel-execution.md](planning/parallel-execution.md)).

Outcome: users can add agentless SSH machines or enroll `fleetd`, see reliable inventory/health, and upgrade an SSH machine to fully managed mode.

- Machine identity, endpoints, tags/groups, namespaced discovered capabilities, inventory snapshots, and staleness rules.
- Strict-known-host SSH connection provider with test, remote exec, cancellation, bounded output, OS probe, and agentless inventory.
- Linux `fleetd` enrollment, key-bound node identity, outbound WSS protocol, heartbeat, inventory delta, operation journal, and signed update design.
- Unix-socket local API so `fleetctl` and local agents can use `fleetd` as a constrained broker.
- Onboarding API/UI/CLI, bootstrap package/service installation, and online/offline/drift-free machine views.
- Tailscale OAuth device discovery and one-click endpoint import as an optional sub-epic; Fleet identity remains independent.

Exit gate: Linux compatibility tests cover protocol and inventory; a supported Linux target passes real SSH-to-fleetd upgrade; offline/reconnect and duplicate-delivery tests pass. Windows guests are managed through Proxmox lifecycle/guest-agent observations in M6 until later in-guest support lands.

### M3 — Projects and developer tooling

Outcome: Fleet can discover a project, clone it to a standard root, and run provider-backed setup to reach a verifiable ready state.

- Project identity by normalized Git remote, node checkout discovery, roots, branch/dirty status, and clone/pull/status actions.
- Guarded project file operations for `AGENTS.md`, `CLAUDE.md`, and discovered agent configuration; editor/shell launch is a best-effort client handoff rather than a server-side business rule.
- Tool/coding-agent inventory with version observations and reviewed install/update recipes.
- Optional mise provider for project runtime/tool convergence; native project files remain authoritative.
- Skills Manager provider using the public `skills-manager-cli --json` contract for agents, skills, presets, deploy/undeploy, and update status.
- Global/project skill browse and Markdown editing only through an explicit provider/content contract with path containment, atomic writes, and provider reindex/adopt. Contribute the contract upstream if the public CLI cannot support it; do not edit Skills Manager's database.
- Frogenv provider for status/detection/setup/login/request and `env run`; contribute upstream JSON/non-interactive gaps instead of reading private files.
- Ready-project workflow with an explicit plan: clone, inspect project declarations, install missing prerequisites, configure Frogenv, deploy project skills, verify.

Exit gate and first product release: the clone-to-ready workflow is idempotent on the supported Linux baseline and clearly reports blocked/manual Frogenv approval rather than exposing secrets. The web UI and `fleetctl --output json` are complete, documented surfaces for this workflow.

### M4 — Profiles, desired state, and GitOps (independent follow-on)

Outcome: Fleet can validate a declarative revision, compare desired with observed state, explain drift, and apply an authorized plan safely.

M4 is not on the critical path to the first Lab release. M7 may reuse a minimal versioned bootstrap-profile/Lab-template contract without waiting for Git source activation, general drift composition, or GitHub bootstrap. Milestone numbers remain stable planning IDs rather than a requirement to execute every milestone serially.

- Versioned desired resources for machines, profiles, projects, tool requirements, skill presets, recipes/actions, Lab templates, and policy bindings.
- Deterministic composition and provenance; migrate legacy role/pack fixtures without preserving accidental schema constraints.
- Difference model (`missing`, `extra`, `changed`, `unknown`, `unsupported`) and apply planner with dependency ordering, dry run, approvals, compensation, and post-verification.
- Declarative custom actions using the same reviewed recipe runner, permission checks, durable operations, and audit path; no separate plugin SDK.
- Git source adapter with isolated clone/worktree, validation before activation, revision history, conflict reporting, and manual rollback.
- GitHub App web flow for one-click private repository creation and initialization with least permissions and expiring tokens.

Exit gate: an invalid revision cannot become active; a reviewed plan converges a test machine; restart/resume and partial-failure tests preserve truth and audit history.

### M5 — Docker visibility and basic actions

Outcome: Fleet exposes useful container operations without becoming Portainer.

- Local Docker Engine API access through `fleetd` using a maintained Rust client such as Bollard and API negotiation.
- Agentless Docker-over-SSH fallback using an isolated Docker context/host.
- Container list/inspect/log stream/start/stop/restart/exec with explicit Docker-root-equivalent permission warnings.
- Stable mapping between node, engine, and container observations; Compose project awareness is a later read/action slice, with no Compose editor or image-build platform.

Exit gate: local and SSH-backed contract suites pass against supported Docker versions; authorization and output redaction tests cover every action.

This milestone may execute in parallel with M3/M4 after M2 provider and operation contracts stabilize.

### M6 — Proxmox infrastructure provider

Outcome: Fleet discovers Proxmox clusters and safely performs bounded QEMU/LXC lifecycle operations.

- Multi-account authentication, TLS trust/pinning, health, privilege diagnostics, and an API compatibility matrix covering PVE 8.x and 9.x.
- Cluster/node/storage/template/QEMU/LXC discovery and normalized resource associations.
- QEMU Guest Agent readiness/IP data with explicit unavailable states.
- Start/stop/shutdown/reboot and task progress first; clone/snapshot/revert/delete only after idempotency and destructive-operation review.
- Initial Windows support stops at provider lifecycle plus QEMU Guest Agent health/IP observations; it does not require a Windows controller, `fleetd`, local broker, inventory, or project-readiness implementation.
- Spike the young/experimental typed `proxmox-client` crate and Purple's provider patterns; retain a raw-endpoint escape hatch behind the provider if coverage or TLS requirements fail.

Exit gate: recorded/simulated API tests plus a dedicated real-cluster suite validate task polling, privilege failures, TLS mismatch, partial-node failure, and resource association.

M6 can start after M2 and the M1 operation/security kernel, but Lab waits for M3/M4 readiness and reconciliation.

### M7 — Fleet Lab

Outcome: humans and agents can obtain, use, and release disposable Linux development/test environments without leaked VMs.

- Packer image-build provider using its documented CLI, with version probing, bounded/redacted output, contract fixtures, and a license/distribution review before Fleet bundles any Packer binary.
- Image recipes stored as modern `.pkr.json` plus versioned provisioning assets and Fleet metadata. The web app provides a structured editor for the supported Proxmox subset and an advanced raw-JSON editor that preserves unknown fields.
- Editable drafts and immutable recipe/image versions. Editing any existing recipe creates a new draft/version; a successful build never replaces an existing image version or becomes the default automatically.
- Manual promotion of built image versions. The exact mandatory smoke-test gate is unresolved in the current planning review and must be decided before implementation.
- Versioned Proxmox-backed Lab templates that pin promoted image versions, readiness probes, minimal bootstrap profiles, and project setup. Full M4 GitOps is not required.
- Durable lease and VM lifecycle state machines; TTL begins at ready, with separate provisioning and maximum-lifetime deadlines.
- Minimal safe placement and transactional capacity reservation, cancellation, and recovery. Rich fairness, quotas, preemption, and exclusive hardware scheduling are follow-on work.
- Destroy by default; revert for explicitly pooled guests; keep requires elevated permission and transfers the VM out of automatic cleanup.
- `fleetctl lab create/status/exec/destroy --output json`, artifacts/log metadata, expiry sweeper, and cleanup reconciliation.
- Fleet-provided skills that drive the JSON CLI for autonomous agent use; no MCP dependency or separate skill authority.
- Later sub-epics: Windows in-guest management/readiness, rich artifact workflows, stable physical USB/GPU inventory, IOMMU/host validation, exclusive reservation, attach/detach compensation, and hardware-in-the-loop workflows.

Exit gate: a human or agent can request a disposable Linux environment from a manually promoted image version, prepare a project, execute commands, and release it or allow TTL expiry. Failure-injection tests at every lifecycle transition leave no unowned VM or capacity reservation, and expired leases clean up after controller restart.

### M8 — Authentication and agent/CI hardening

Outcome: when Fleet must operate outside the initial fully trusted LAN, anonymous administration can be replaced by authenticated, least-privileged human, agent, and CI identities without changing application use cases.

- First-run controller bootstrap, web session and CLI credential flows, plus delegated short-lived agent/CI credentials scoped by project, node/tag, action, resource limits, TTL, and owner.
- Preserve `fleetctl --output json` and official Fleet skills as the agent interface; do not add an MCP server without a new demonstrated need and plan revision.
- Read/write command separation, high-impact confirmation policy, rate/concurrency limits, and prompt-injection threat tests.
- CI integration and autonomous Lab workflows with owner/purpose linkage and artifact handoff.
- Richer audit query/export and policy simulation.

Exit gate: authenticated deployment no longer relies on LAN trust; a restricted agent identity can create and destroy an allowed Lab lease but cannot execute on production, administer Fleet, read secrets, or retain a VM.

### Later — scale, convenience, and additional providers

- Optional native desktop shell that consumes the public API and offers local editor/terminal handoff; no core logic.
- Command palette over discoverable authorized API actions.
- Bulk plans/actions across tags/groups with blast-radius preview, concurrency limits, partial-result reporting, and per-target authorization/audit.
- Rich Frogenv machine/group/status administration after its public machine-readable contract supports it; key private material remains outside Fleet.
- Compose-aware container grouping/actions, never a full Compose authoring platform.
- Hosted Fleet Controller/Fleet Cloud, team/multi-user administration, OIDC/SSO, policy administration, and external audit export.
- PostgreSQL and multi-controller/high-availability architecture only after measured need and a new ADR.
- Advanced Lab fairness/quotas/preemption/pools, more artifact stores, and additional virtualization/cloud providers.
- Community image-recipe catalog/marketplace only after trust, signatures, review, licensing, and compatibility policy exist. It distributes recipes and metadata, never VM disks or licensed installation media.

## Dependency map

```text
M0 Foundation
  -> M1 Controller + trusted-LAN control kernel
       -> M2 Machines + connectivity
            -> M3 Projects + tool providers (Developer Fleet release)
            -> M4 Desired state/GitOps (independent follow-on)
            -> M5 Docker
            -> M6 Proxmox -------------------------+
       M1 operations/audit -------------------------+-> M7 image builds + Lab -> M8 auth hardening
       M3 project readiness ------------------------+
       minimal profile/template contracts ----------+
```

The critical path is M0 → M1 → M2 → M3 for the complete Developer Fleet release, then M6 plus the Packer/image-version slice of M7 for the first Lab release. Full M4 GitOps and Docker are not Lab prerequisites. Tailscale discovery is optional. Agents use skills and `fleetctl`; MCP is not on the roadmap.

## Recommended GitHub milestones and epic issues

Use the milestone names M0–M8 above. Each epic should be a tracking issue containing only dependency/status checklists; implementation work remains in narrow linked issues.

| Milestone | Recommended epics |
|---|---|
| M0 | Monorepo and legacy migration; API/schema/protocol contracts; build/CI/deployment foundation |
| M1 | Controller runtime and storage; trusted-LAN authorization/secrets/audit; durable operations; API/web/CLI vertical slice |
| M2 | Linux SSH agentless management; Linux fleetd enrollment and protocol; inventory/capabilities/health; onboarding and service install; Tailscale discovery |
| M3 | Project roots/checkouts/actions and guarded context editing; tool recipes and mise; Skills Manager provider/editing; Frogenv provider; clone-to-ready workflow |
| M4 | Desired resource schema and composition; observed/difference/planner; apply engine; Git source and GitHub bootstrap |
| M5 | Docker discovery; Docker lifecycle/log/exec actions |
| M6 | Proxmox accounts and discovery; VM/LXC associations and guest data; lifecycle/task operations; template/clone/snapshot operations |
| M7 | Packer recipe editor/build/version/promotion; minimal Lab templates/readiness; leases and cleanup; Lab CLI/skills/project workflow; later Windows guest and hardware slices |
| M8 | Optional authenticated deployment; agent/CI identity hardening and delegation; autonomous Lab/CI workflows; policy/audit administration |

Issue-ready work for M0–M2 is in [planning/initial-issues.md](planning/initial-issues.md). Use its issue template for later milestones.

## Success measures by workflow

| Workflow | First milestone that completes it | Evidence |
|---|---|---|
| Add and inspect an SSH machine | M2 | Connection/host-key test, inventory provenance, offline handling |
| Upgrade SSH machine to `fleetd` | M2 | Package/service install, one-time enrollment, reconnect and version negotiation |
| Clone project to another machine and make ready | M3 | Idempotent operation plan and provider verification |
| Detect and repair profile drift | M4 | Deterministic diff, reviewed apply, post-apply observation |
| Inspect/manage a container | M5 | Negotiated Docker API and authorization/audit evidence |
| Inspect/manage Proxmox VM/LXC | M6 | Cluster compatibility and UPID/failure handling |
| Human or agent requests disposable Linux test VM | M7 API/CLI/skills, identity-hardened in M8 | Lease ownership, readiness, TTL, execution, cleanup |
| Build and promote a Proxmox image | M7 | Versioned `.pkr.json` recipe, immutable build record, validation evidence, manual promotion |
| Inspect/manage a Windows VM | M6 | Proxmox lifecycle plus QEMU Guest Agent health/IP; in-guest management is later |
| Hardware-in-the-loop Lab | M7 later sub-epic | Exclusive reservation and cleanup under failure |

## Risks and research gates

- **Migration scope:** do not combine the Rust rewrite, schema redesign, and new behavior in one issue. Port fixtures first and maintain a written parity/deletion checklist.
- **Remote privilege:** Docker socket access is effectively root; SSH `sudo`, node service permissions, and recipe execution need explicit per-action policy and platform tests.
- **Windows service behavior:** service installation, named pipes, filesystem permissions, process trees, and update/rollback require real-host CI or a documented test matrix. This is the highest per-platform cost in the supported baseline and is gated by spike FM-S04. macOS is deferred but must not be designed out of the protocol, config, or filesystem layers.
- **Skills supply chain and portability:** Skills Manager is fast-moving and release-platform coverage may not include every Linux architecture. Pin a tested CLI range, verify checksums, contract-test JSON, and degrade explicitly rather than forking its data model.
- **Frogenv automation/distribution contract:** only `status` is JSON today; setup and approvals include interactive/security ceremonies, and npm still serves v0.1.0 while the inspected repository is v0.2.0. Coordinate upstream flags/release artifacts and never bypass approval by editing its repository.
- **Proxmox clients:** the broad Rust client found during research labels itself experimental. A compatibility/TLS/task spike is a gate, not a blind dependency choice.
- **Git concurrency:** validate in an isolated worktree, serialize activation, never auto-resolve semantic conflicts, and retain the last valid active revision.
- **SQLite and HA:** a single active controller is a documented constraint. Measure write contention, operation volume, and backup recovery before proposing PostgreSQL or multi-controller support.
- **Scheduler correctness:** VM IDs, storage, GPUs, and USB devices require transactional reservations plus external-state reconciliation because the database and Proxmox cannot share a transaction.
- **Agent threat model:** project files, skills, provider output, and test logs can all contain hostile instructions. Authorization cannot rely on model intent or UI confirmation alone.
- **Trusted-LAN administration:** the first deployment deliberately grants all LAN callers full control. The controller must warn prominently, avoid Internet-facing defaults, audit the anonymous LAN principal and request origin, and preserve a centralized authorization boundary so authentication can replace the allow-all policy later.
- **Packer boundary and licensing:** Packer is an external image-build provider, not Fleet's embedded configuration engine. Pin the CLI/plugin range, validate modern `.pkr.json`, record checksums and provenance, and complete a Business Source License/distribution review before bundling Packer. Marketplace recipes are privileged, potentially hostile build inputs.
- **Schema overreach:** capability names and provider observations must be extensible, while desired resources stay small and outcome-oriented. Avoid a generic configuration-management language.
- **Desktop automation:** no single framework is selected. Research Appium/WinAppDriver or FlaUI for Windows and technology-specific runners when a concrete application workflow exists; Fleet only provisions, invokes, and collects.

## Explicitly outside Fleet Manager

- Generic enterprise RMM, endpoint surveillance, patch compliance, helpdesk, or asset/license management
- A Proxmox replacement, hypervisor console, storage/network configuration suite, or full backup UI
- A Portainer replacement, Compose authoring platform, image registry, or build service
- Browser automation; use Playwright or a project-selected runner
- Desktop automation; use a project-selected external runner
- A test framework or CI system; Fleet provisions and invokes them
- A new skills package manager or marketplace; use Skills Manager and skills.sh
- A dedicated MCP server in the initial roadmap; agents use Fleet skills over `fleetctl --output json`
- Distribution of VM disk images or licensed operating-system media; a future catalog distributes build recipes and metadata
- A dotfile manager; use chezmoi if dotfile convergence is requested
- A secrets-management platform; Fleet stores only the credentials it must use and delegates project secrets to Frogenv or another provider
- A general package/configuration manager such as Ansible, Nix, or Chef
- A generic dynamic plugin SDK in the early product
- A native desktop application containing core logic

## Architecture decisions

The ADRs in [adr/README.md](adr/README.md) record the architecture boundaries accepted on 2026-08-25. The 2026-08-27 product-scope revision changes release scope and sequencing without rewriting that historical acceptance record. Any confirmed revision that reverses an ADR boundary still requires a superseding ADR before implementation.

Accepting an ADR fixed a boundary, not every library or upstream contract inside it. The eight open choices are named spikes in [planning/spikes.md](planning/spikes.md). A spike that fails its preferred option takes the recorded fallback; it does not reopen its parent ADR.

## Research basis

The research log, source links, versions/commits, integration choices, and rejected duplications are in [research/ecosystem.md](research/ecosystem.md). It should be refreshed at the start of the milestone that consumes each external interface.
