# Architecture overview

Status: proposed

## System shape

Fleet Manager is a self-hosted modular monolith with remote adapters. The controller process hosts the public API, realtime feeds, node gateway, background operation workers, web assets, and concrete provider adapters. Domain/application crates retain boundaries inside that process.

```text
                               controller host
  +----------+       +---------------------------------------------+
  | Vue web  |------>| public API adapter: HTTP/JSON + SSE         |
  +----------+       |                                             |
  | fleetctl |------>| application services                       |
  +----------+       | caller -> authz -> transaction -> audit     |
  | skills   |->CLI  |       |                    |                |
  +----------+       |    fleet-core          operations worker   |
                     |       |                    |                |
                     | SQLite/secret refs   controller providers   |
                     |                    SSH/Tailscale/GitHub/PVE |
                     +--------------------------|------------------+
                                                | outbound WSS
                                      +---------v---------+
                                      | fleetd            |
                                      | local providers   |
                                      | inventory/exec    |
                                      +----|-----------|--+
                                           |           |
                                     local socket   Docker/Git/
                                     fleetctl/agent Skills/Frogenv
```

The controller is available without any developer laptop. A future native app is an API client and optional local integration shell only.

## Architectural layers

### Domain (`fleet-core`)

Pure or deterministic concepts:

- Stable IDs and resource references
- Machine, project, checkout, capability, desired resource, difference, plan, lease, reservation, and artifact metadata
- Lease, reservation, and operation transition validation
- Desired-state composition/provenance and dependency graphs
- Permission/action vocabulary shared by authorization adapters

Domain code does not import Axum, SQLx, subprocess, Docker, Proxmox, or web types.

### Application (`fleet-application`)

Use cases and ports:

- Register machine, record observation, compute availability, plan/apply desired state
- Create/cancel/retry operations
- Discover/clone/prepare projects
- Create/release Lab leases
- Invoke providers through narrow domain-specific ports
- Authorize before opening a transaction or dispatching an action
- Emit audit drafts and domain events as part of the state change

Handlers, CLI commands, skill-driven CLI calls, and workers invoke this layer. None reimplement it.

### Adapters

- Public API and node gateway translate network messages.
- SQLite repositories translate persisted rows.
- Providers translate external APIs/CLIs into observations, actions, progress, and typed errors.
- Web and CLI translate user intent and render application results.

## Primary domain aggregates

| Aggregate | Key invariants |
|---|---|
| Machine | Stable Fleet ID is distinct from hostname, IP, provider ID, or Tailscale identity; connections and observations may change independently. |
| Checkout | A project can have at most one tracked checkout at a normalized path on a node; Git remote identity is normalized without embedding credentials. |
| Desired revision | Only a fully parsed and validated immutable revision can be active; invalid fetches do not replace the last valid revision. |
| Operation | Accepted work has an ID, actor, permission decision, idempotency key, deadline, progress, result, and audit correlation. |
| Lab lease | Exactly one owner and cleanup policy; a ready TTL, provisioning deadline, and maximum lifetime are independent. |
| Reservation | Exclusive resources have at most one active holder; consumable allocations cannot exceed the scheduler's current safe capacity. |
| Secret reference | Domain and job records contain an opaque reference, never secret bytes. |

## Stable identity and association

- Fleet-generated UUIDv7 (or another approved sortable opaque ID) identifies controller resources.
- User-readable slugs/names are mutable and are never foreign keys.
- A machine may have SSH, Tailscale, direct network, node-session, and provider-resource endpoints simultaneously.
- A Proxmox guest association uses provider account + cluster/node/resource type/provider ID and can be confirmed by node identity. IP address alone is never sufficient.
- A project identity uses normalized host/owner/repository plus provider, while checkouts retain their exact fetch URL separately and never expose embedded credentials.

## API and client contract

- `/api/v1/...` HTTP JSON is the public control API.
- OpenAPI is generated from or checked against Rust DTO definitions and is the source for `packages/api-client`.
- Mutations return or reference an `Operation`; they do not hold an HTTP request for a long infrastructure workflow.
- Errors use a stable code, message, retry classification, correlation ID, and optional field violations. Internal/provider secrets never enter the envelope.
- List endpoints use stable cursor pagination and explicit filters.
- SSE carries ordered, resumable operation/audit/resource notifications. Clients recover gaps by refetching canonical resources.
- Logs use bounded/resumable streams; bulk artifacts use separate upload/download endpoints.
- `fleetctl` offers human output by default and `--output json` with the API schema. JSON goes to stdout; diagnostics/progress go to stderr.
- Official Fleet skills orchestrate the JSON CLI contract. They do not call providers directly or define another authorization surface.

## Runtime and deployment

Initial Compose deployment contains one controller container and persistent mounts for controller data, Git worktrees, and artifacts. The web distribution is embedded or copied into the controller image. A master-key file is mounted separately as a Docker secret/file. No Docker socket is mounted into the controller by default.

Initial constraints:

- One active controller instance per data directory
- Linux-hosted controller reachable only on a trusted local network; all reachable callers initially map to the fully authorized `anonymous-lan-admin` principal
- SQLite WAL on a local filesystem, not an arbitrary network share
- Graceful shutdown stops intake, checkpoints workers, and leaves accepted operations resumable
- Health means process/aliveness; readiness includes database migrations and master-key availability
- Backups cover SQLite, active desired-state metadata, artifact metadata, and required configuration; secret key backup is an operator responsibility documented separately

## Cross-cutting rules

- Every mutation passes through caller resolution, centralized authorization, operation creation, and audit in the application layer. Initial caller resolution yields `anonymous-lan-admin`; later authenticated deployment can replace it without changing use cases.
- Every remote/provider call has a deadline, cancellation path, bounded/redacted output, correlation ID, and typed retry semantics.
- Inventory carries source, observed time, confidence/status, and schema version. Absence can mean unknown/stale, not automatically false.
- Providers may add namespaced capability facts without changing a global enum.
- Provider and CLI versions are recorded with observations and operation results.
- New dynamic extension mechanisms require an ADR. Compiled adapters and documented subprocess providers are sufficient initially.

## Test boundaries

- Domain: pure unit/property tests for composition, transitions, scheduling, and permissions.
- Application: use-case tests with fake clock, provider, authorization, and repository ports.
- Adapter contracts: recorded external responses and CLI JSON fixtures with redaction checks.
- Integration: real SQLite migrations/recovery, HTTP/OpenAPI compatibility, WSS reconnect, SSH containers/VMs, Docker engine, and opt-in Proxmox lab.
- End-to-end: Compose controller + web + fleetctl + test fleetd.
- Cross-platform: keep protocol, config, service, filesystem permission, process cancellation, local socket/pipe, and inventory abstractions portable. The initial controller and in-guest node baseline is Linux; initial Windows coverage is Proxmox lifecycle and QEMU Guest Agent observation. Windows `fleetd`/broker/project readiness and macOS remain designed-for follow-ons.
