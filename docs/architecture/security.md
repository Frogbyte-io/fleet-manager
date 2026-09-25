# Security architecture

Status: proposed; a dedicated threat model is an M1 deliverable

## Trust boundaries

- Browser/CLI/Fleet-skill caller to controller
- Controller to agentless SSH host
- Controller to third-party APIs (GitHub, Tailscale, Proxmox)
- Controller to enrolled `fleetd`
- `fleetd` service to local users/agents and privileged OS facilities
- `fleetd` to Docker socket, Git checkout, skills, Frogenv, and project commands
- Desired Git, recipes, skills, repositories, provider output, logs, and artifacts as potentially hostile input

The first release is deliberately limited to a trusted local network and has no accounts or login. Every LAN caller can mutate. Network placement is therefore the initial authentication boundary, but requests still cross Fleet's centralized authorization and audit path as `anonymous-lan-admin`. Tailscale or a local network provides reachability, not durable Fleet identity; Internet exposure is unsupported in this mode.

An optional Tailscale Serve identity mode is a separate, explicit listener. It accepts only requests whose TCP peer is IPv4 loopback and that carry exactly one bounded `Tailscale-User-Login`; absent, duplicate, malformed, or missing identity claims fail with 401. Tagged devices have no user identity and therefore cannot use this listener. The regular listener must also remain loopback-only when identity mode is enabled, preventing a remote anonymous-admin bypass. The Tailscale principal still has the full current admin permission set; this mode identifies a human for audit and does not implement per-user authorization. The host itself remains trusted: local processes can connect to either loopback listener and forge headers.

Tailscale Serve must proxy to the identity listener at `http://127.0.0.1:<port>`. The default bridged Docker Compose deployment is incompatible: Serve connections arrive through a container bridge rather than from loopback, and identity mode intentionally rejects them. The opt-in Linux host-network Compose override or a host process shares Serve's network namespace; bind both controller listeners to loopback and configure Serve to target the dedicated port. Do not trust Docker gateway addresses or forwarded-address headers as a substitute for the loopback peer check.

Because identity mode requires the regular controller listener to be loopback-only, its node enrollment and gateway routes are also host-local. Remote `fleetd` clients cannot reach those routes in this mode; keep identity mode disabled when the controller must accept remote node sessions until a separately scoped node listener is available. The dedicated Serve listener additionally requires a human Tailscale identity before serving its UI, downloads, health routes, or node routes; node protocol credentials remain an additional check for node operations.

## Initial trusted-LAN principal

The initial controller recognizes one application principal, `anonymous-lan-admin`, for browser, CLI, and skill-driven requests received on the configured LAN listener. It grants the full initial permission vocabulary. Audit records include this principal plus correlation ID and available request-origin/client metadata; an IP address is evidence, not identity.

The fleet-wide SSE stream separately requires the centralized `events.read` permission. It carries only event names and opaque cursors, never resource data; clients refetch through the normal authorized read endpoints after notifications or a `gap`.

Nodes retain Fleet-owned asymmetric identity because controller-to-node replay and impersonation risks exist even on a trusted LAN. Provider credentials remain encrypted secrets. Centralized authorization is not removed: the initial policy is an explicit allow-all policy for the LAN principal that authenticated deployment can replace later.

The dashboard must prominently state that anyone who can reach it can control the fleet. The controller must not default to an Internet-facing deployment, and documentation must not present reverse-proxy publication as supported before authenticated mode exists.

## Deferred authenticated identities

When authenticated deployment is added, first-class principals are user, node, agent, CI job, and service. Sessions/API credentials are separate records with expiry and revocation. An agent/CI identity has an owner, purpose, optional project/node/tag scope, issue/PR reference, and maximum lifetime.

- Web users use secure, HttpOnly, SameSite cookies with CSRF protection.
- CLI users use device/login flow or explicitly created revocable tokens stored in an OS credential store where available.
- Nodes use enrolled asymmetric keys and short-lived sessions; node credentials cannot call user/admin APIs.
- Agents receive short-lived delegated credentials or go through the constrained local `fleetd` broker; they do not inherit a user's indefinite admin token.
- Provider credentials authenticate Fleet to a provider and are never treated as Fleet identities.

Bootstrap credentials and durable human/agent sessions belong to the later authenticated-deployment milestone, not the trusted-LAN release.

## Authorization

Authorization is centralized in the application layer and answers principal/action/resource/context. The trusted-LAN policy explicitly permits the full vocabulary to `anonymous-lan-admin`; authenticated mode later becomes deny-by-default with explicit forbids overriding permits. HTTP route checks and hidden UI controls are defense-in-depth, not the decision point.

Initial permission vocabulary includes:

- `machines.read`, `machines.enroll`, `machines.exec`, `machines.apply`, `machines.admin`
- `projects.read`, `projects.clone`, `projects.modify`
- `skills.read`, `skills.deploy`, `skills.modify`
- `containers.read`, `containers.logs`, `containers.exec`, `containers.lifecycle`
- `proxmox.read`, `proxmox.lifecycle`, `proxmox.clone`, `proxmox.destroy`
- `labs.read`, `labs.create`, `labs.exec`, `labs.destroy`, `labs.keep`, `hardware.reserve`
- `desired.read`, `desired.plan`, `desired.apply`, `desired.admin`
- `secrets.use` (provider- and purpose-scoped), never a general `secrets.read` for agents
- `audit.read`, `fleet.policy.admin`, `fleet.admin`

Future bindings can scope resources by ID, project, provider account, machine group/tag, environment classification, owner, TTL, and resource ceilings. Do not build an ad-hoc expression language. M1 implements the authorization port and explicit trusted-LAN policy; evaluate an embedded engine only when authenticated or multi-user deployment requires concrete policies.

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

## Agent and CLI-skill protections

- Official Fleet skills call `fleetctl --output json`; they do not receive a second API, bypass application authorization, or confer authority through prompt text.
- Read and write commands are distinct; no overloaded “do anything” command is the default agent surface.
- Command parameters are structured and validated. Project text cannot add capabilities or approvals.
- In trusted-LAN mode agents have the same full authority as every other LAN caller. This is an explicit risk, not least privilege; per-agent identity, limits, and revocation are deferred to authenticated mode.
- Every call links the anonymous LAN principal, available client/origin metadata, project/purpose, input digest, authorization decision, operation, provider result, and lease/artifact IDs. Authenticated mode adds durable owner/agent identity.
- The initial skill catalog should expose the intended autonomous workflows while making destructive effects explicit. There is no dedicated MCP server in the planned product.

## Audit

Audit events are append-only application records with timestamp, actor and credential/session IDs, action, resource, decision, request/correlation/operation IDs, outcome, provider external task/reference, and redacted metadata. The application writes intent/decision in the same database transaction as accepted state where possible and records terminal outcome later.

Audit reads use the `audit.read` permission and a filtered, cursor-paginated API. The response exposes only fixed-format event identifiers, digests, enum values, and numeric facts from metadata. Free-form values such as names, purposes, notes, hostnames, and remotes are omitted because caller text can contain credentials under otherwise harmless keys. Lab lease purposes are not written to audit metadata.

Pending status is tracked from the audit-query migration boundary forward. Earlier outcome rows did not retain a reliable intent link, so the migration does not infer one from similar historical event fields or report unmatched historical intents as pending.

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
