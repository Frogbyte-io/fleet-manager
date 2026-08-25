# Security architecture

Status: proposed; a dedicated threat model is an M1 deliverable

## Trust boundaries

- Browser/CLI/MCP caller to controller
- Controller to agentless SSH host
- Controller to third-party APIs (GitHub, Tailscale, Proxmox)
- Controller to enrolled `fleetd`
- `fleetd` service to local users/agents and privileged OS facilities
- `fleetd` to Docker socket, Git checkout, skills, Frogenv, and project commands
- Desired Git, recipes, skills, repositories, provider output, logs, and artifacts as potentially hostile input

Tailscale provides private reachability and network identity but is not Fleet authentication or authorization.

## Identities

First-class principals are user, node, agent, CI job, and service. Sessions/API credentials are separate records with expiry and revocation. An agent/CI identity has an owner, purpose, optional project/node/tag scope, issue/PR reference, and maximum lifetime.

- Web users use secure, HttpOnly, SameSite cookies with CSRF protection.
- CLI users use device/login flow or explicitly created revocable tokens stored in an OS credential store where available.
- Nodes use enrolled asymmetric keys and short-lived sessions; node credentials cannot call user/admin APIs.
- Agents receive short-lived delegated credentials or go through the constrained local `fleetd` broker; they do not inherit a user's indefinite admin token.
- Provider credentials authenticate Fleet to a provider and are never treated as Fleet identities.

The initial local administrator is created through a one-time, expiring bootstrap secret emitted to the controller console/file. First login must establish the durable credential and invalidates bootstrap. Remote default credentials are prohibited.

## Authorization

Authorization is centralized in the application layer and answers principal/action/resource/context. Default is deny; explicit forbids override permits. HTTP route checks, hidden UI controls, or MCP tool lists are defense-in-depth, not the decision point.

Initial permission vocabulary includes:

- `machines.read`, `machines.enroll`, `machines.exec`, `machines.apply`, `machines.admin`
- `projects.read`, `projects.clone`, `projects.modify`
- `skills.read`, `skills.deploy`, `skills.modify`
- `containers.read`, `containers.logs`, `containers.exec`, `containers.lifecycle`
- `proxmox.read`, `proxmox.lifecycle`, `proxmox.clone`, `proxmox.destroy`
- `labs.read`, `labs.create`, `labs.exec`, `labs.destroy`, `labs.keep`, `hardware.reserve`
- `desired.read`, `desired.plan`, `desired.apply`, `desired.admin`
- `secrets.use` (provider- and purpose-scoped), never a general `secrets.read` for agents
- `fleet.audit.read`, `fleet.policy.admin`, `fleet.admin`

Bindings can scope resources by ID, project, provider account, machine group/tag, environment classification, owner, TTL, and resource ceilings. Do not build an ad-hoc expression language. M1 should spike embedded Cedar against concrete policies; retain a small authorization port so the choice can be reviewed before multi-user release.

Authentication, authorization, human approval, and provider privilege are separate. A permitted action may still require risk confirmation; confirmation never grants a denied permission.

## Secret handling

- Desired Git, source repositories, logs, audit metadata, operation payloads, URLs, and error messages contain references, not secret values.
- Controller secrets are individually encrypted with an authenticated cipher. A versioned master key is mounted from a protected file/Docker secret outside the database and supports planned rotation.
- Secrets are decrypted just in time at the adapter boundary, held for the shortest practical duration, zeroized where supported, and redacted by value/pattern before persistence or streaming.
- SSH private keys should preferably remain in an agent/credential helper or use short-lived certificates. Stored keys are encrypted secret records with strict provider scope.
- Project environment values stay in Frogenv/SOPS/age. Fleet invokes `frogenv env run`; it does not list values or become a decryption UI.
- Backups require both encrypted data and separately protected master-key recovery instructions. Losing either has an explicit failure mode.

## Remote execution and providers

- SSH onboarding requires explicit host-key verification or a clearly labeled trust-on-first-use fingerprint confirmation. Host-key change blocks connection until reviewed.
- Commands use argument arrays, controlled working directories/environment, output/time limits, process-tree cancellation, and a run-as policy. Shell mode is a distinct high-risk path.
- `sudo`/Administrator helpers expose an allowlisted protocol. Avoid a root `fleetd` general shell.
- Docker access is labeled root-equivalent on typical hosts; container exec/lifecycle permissions are separate.
- Proxmox tokens use dedicated users/tokens and the minimum roles/path ACLs. TLS verification/pinning cannot be disabled silently.
- Git hooks are disabled for controller-managed desired clones. Project setup does not execute repository scripts until an authorized plan names them.
- Downloads and binaries use TLS, pinned version, checksum/signature where upstream supplies one, and atomic install/rollback.

## Agent and MCP protections

- Tool discovery is filtered by permission and resource scope.
- Read and write tools are distinct; no overloaded “do anything” exec tool in the default set.
- Tool parameters are structured and validated. Project text cannot add scopes or approvals.
- Agent identities have TTL, concurrency/rate/resource limits, and a kill/revoke path.
- Every call links owner, agent, project/purpose, input digest, authorization decision, operation, provider result, and lease/artifact IDs.
- High-impact actions (production exec, keep Lab, delete VM, change policy, reveal secret) are absent or denied by default.
- MCP HTTP transport follows the current MCP OAuth-based authorization specification. STDIO/local adapters obtain credentials from the local Fleet broker, not environment-wide administrator tokens.

## Audit

Audit events are append-only application records with timestamp, actor and credential/session IDs, action, resource, decision, request/correlation/operation IDs, outcome, provider external task/reference, and redacted metadata. The application writes intent/decision in the same database transaction as accepted state where possible and records terminal outcome later.

Audit is not a dump of commands or provider bodies. Redaction tests cover URLs, headers, environment, stdout/stderr, Git remotes, SSH errors, and serialized job payloads. Retention/export and tamper-evident external forwarding are later administration features.

## Required threat-model scenarios

- Compromised node attempts to impersonate another node or call admin APIs
- Stolen enrollment token replay
- Malicious project/skill/recipe exfiltrates controller or Frogenv secrets
- Prompt injection requests production exec or retained Lab resources
- SSH host-key change and Proxmox certificate mismatch
- Docker output/log contains token-like data
- Git desired repository compromised or force-pushed
- Controller/database/artifact backup stolen without master key, and master key stolen without database
- Duplicate/replayed destructive operation after disconnect
- USB/VM cleanup fails midway and leaves a device accessible
