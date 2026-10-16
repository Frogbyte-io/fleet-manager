# Security architecture

Status: proposed; a dedicated threat model is an M1 deliverable

## Trust boundaries

- Browser/CLI/Fleet-skill caller to controller
- Controller to agentless SSH host
- Controller to third-party APIs (GitHub, Tailscale, Proxmox, Coolify, Cloudflare)
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

## Delegated Lab credentials (proposed, ADR 0011)

A delegated credential is an opaque bearer token with an owner, a TTL of at most 24 hours, and an allow-list of Lab templates or template versions. An operator issues, lists, and revokes it (`fleetctl credentials issue|list|revoke`; `credential.issue`, `credential.read`, `credential.revoke`, administrators only). The token (`fmdc1.<64 hex>`, 32 CSPRNG bytes) is shown once at issue time and stored only as its SHA-256; it is never logged, audited, put in a payload, or listed. Setting `FLEET_TOKEN` makes `fleetctl` present it as `Authorization: Bearer`; `fleetctl` never prints it.

A presented token is checked against the store on every request, so expiry and revocation apply to the next request. It resolves to the principal `credential:<owner>:<credentialId>` beside the LAN and Tailscale principals; an unknown, expired, or revoked token is a 401 and never falls back to administrator. Every use appends a `credential.use` audit event under that principal.

The `fleet-auth` authorizer decides a credential principal from a deny-by-default catalog table, `DELEGATED_LAB_LOOP`: `lab.template.use` (the allow-list), `lab.lease` (create, release), `lab.lease.read`, `lab.lease.provision`, `lab.extend`, `lab.exec`, `lab.exec.read`, `lab.artifacts`, `lab.artifacts.read`, and `operation.create` / `operation.read` for the Lab kinds only. Everything else, including `lab.keep`, standalone `lab.provision`, template, image, pool, Proxmox, secret, machine, audit, and settings actions, is refused with `policy.action_not_delegated`. Adding an action is one table row and one test. Leases record the owner `credential:<owner>`, artifacts copy it, and the Lab use cases report another owner's lease, artifact, or operation as not found.

The credential narrows a caller that presents it; it is not a perimeter. Anonymous callers of the trusted-LAN listener stay administrators until the rest of M8 (sessions, bootstrap, refusing anonymous administration) lands.

## Brokered provider actions (proposed, ADR 0016)

API-token providers (Coolify and Cloudflare in M10) are provider accounts whose tokens are encrypted secret records. No API, CLI output, log, audit event, operation payload, or result returns a token, and agents never receive one. An agent asks for a change by creating an `ActionRequest`: a typed provider action with structured, validated parameters. Each action type has a risk class, `auto`, `approve`, or `deny`, configurable per type. An approved request runs as a durable operation through the same authorization and audit path as any other mutation. Requests, decisions, and approvers are audited; parameters are validated, not interpreted as text.

Until authenticated identities are in use, the requester and approver are both `anonymous-lan-admin` (or a Tailscale admin), so the policy is a guardrail against agent mistakes, not a boundary against a hostile LAN caller. Delegated credentials (ADR 0011) are the path to per-agent scoping: a delegated principal may request and never approve.

Registry resources in Fleet Git (ADR 0016) have no secret value type. Validation runs the credential scrubber over every value and rejects matches; a field may say where a login lives, never what it is.

## Action broker (ADR 0016)

Agents do not hold provider credentials. They `POST /requests` to ask the controller to run a typed provider action (`action.request`, resource = action id), and Fleet runs it with credentials only it holds. A request is a durable SQLite record (`action_requests`) with its requester, origin, target, scrubbed parameters, risk class, reason, decider, and linked operation. Its states are `pending -> approved | denied | expired -> executing -> succeeded | failed`; the transitions are a pure rule in `fleet-core`, and each one is a compare-and-set committed with its audit event, so of concurrent approvals exactly one executes.

- **Policy.** Each provider action declares a risk class: `auto` (runs on request), `approve` (waits for a person), or `deny`. `FLEET_ACTION_POLICY=action.id=class,...` raises or lowers a class per action id; a malformed value stops startup. `FLEET_ACTION_REQUEST_TTL_SECONDS` (default 86400, 60 to 604800) bounds how long a request waits for a decision. A `deny`-class request is refused at creation with 403 `policy_denied`: no row is stored and only an audit event is kept. If policy changes to `deny` after a request was made, approving it ends the request `denied` by policy (audited) with the same code.
- **Approve and deny are separate permissions** from request and from each other (`action.approve`, `action.deny`, both authorized against the request's action id; `action.read` lists and reads). A delegated principal can be granted request and never approve.
- **Brokered operation kinds are not creatable any other way.** Each provider action declares the operation kind it runs. The generic `POST /operations` refuses those kinds ("use `/requests`"), and refuses idempotency keys beginning `action-request:`, which the broker owns. The broker creates the operation on a separate brokered route authorized by the decision itself: `action.request` under `auto` policy, or `action.approve` for an approved request. That route does not require `operation.create`, so an agent that can request cannot bypass approval through `/operations`. Kinds that have their own dedicated routes (the Lab kinds) stay refused, and a kind's machine-scoped permission still applies. The operation runs as the approver, or as the requester when policy approved it.
- **Execution is an ordinary durable operation** (ADR 0008) whose idempotency key is `action-request:<id>`; the returned operation's kind and payload are checked against what the action built. The request follows the operation to `succeeded` or `failed`. An approved request whose operation was never linked (the controller stopped between the two) is recovered by creating the operation again under the same key, which returns the existing operation or makes it; it fails only when that cannot be done. An executing request whose operation record cannot be found fails after a one-minute grace.
- **Idempotent creation.** `POST /requests` accepts an `idempotencyKey` scoped to the requester; a retry returns the request already made, and a different request under the same key is a 409.
- **Expiry is lazy.** It is evaluated when a request is read or decided, not by a sweeper. It is a pure function of the stored deadline, so a restart cannot leave a request approvable past it, and the approve and deny statements re-check the deadline themselves. The `expired` transition is audited when first observed.
- **No secrets, pattern-based.** Parameters are structured. A request whose parameters (or target, or reason) the shared redaction helpers would change, or that has a secret-named key, is refused with a 400 that does not echo the value. Parameters are stored and served, and never audited. This detection is pattern-based: it catches the credential shapes the scrubber knows, not every secret. An action that must carry a secret value (a future environment-variable change, for example) must take a secret reference and have Fleet resolve it, never a raw value in its parameters.
- **Errors do not echo caller input** (action id, request id, state filter, idempotency key).
- **Approval inbox (FM-1041).** The console's Approvals page (`/requests`) and `fleetctl requests list|get|approve|deny` are adapters over the same `/api/v1/requests` routes; neither holds a rule. The console shows the action, target, parameters, reason, requester, age, and risk of each pending request, approves or denies it (the note is a denial's only; the approve route takes none), and lists decided requests with their outcome, decider, note, failure, and linked operation. Every committed request change (a new request or a won transition) publishes a payload-free `request.changed` on the fleet event stream, so the inbox and the Overview's needs-attention queue update live; an operation's `operation.changed` also refreshes them, because an executing request follows its operation lazily. `fleetctl requests get <id> --wait[=<duration>]` polls with backoff (250 ms doubling to 5 s) for at most the duration (1 s to 1 h, default 5 m) and answers `{ "outcome": "executed" | "denied" | "expired" | "failed" | "still_pending", "request": ... }` with exit code 0 for `executed`, 2 for `still_pending`, and 1 otherwise. `still_pending` also covers an approved request still running at the bound; the request stays durable. The helper (`fleetctl::requests::wait_for_outcome`, flag parser `parse_wait_approval`) is what provider action commands call for `--wait-approval[=<duration>]`. No provider action command exists yet, so `--wait-approval` itself is deferred: the first action commands wire the shared helper. Each read of the wait is capped at the time left (and 30 s); up to three consecutive transient read failures (no answer, or a 5xx) are retried on the same backoff, the fourth ends the wait with the error, and a refusal (4xx) ends it at once. `fleetctl requests deny --note` trims the note and omits it when blank. The console lists pending requests from a `state=pending` query and the history from a separate query, and its fleetctl command box shows a typed note only as a `"<note>"` placeholder.

**Before M8 this policy is a guardrail keyed on risk class, not a security boundary.** Every caller of the trusted-LAN listener is `anonymous-lan-admin` and holds `action.approve` as well as `action.request`, so it can approve its own request. The policy protects against an agent's mistakes (a mistyped redeploy, a DNS change made without a person looking), not against a hostile caller on the network. Per-agent scoping arrives with delegated credentials (ADR 0011): a delegated principal will be allowed to request and never to approve, which the deny-by-default delegated catalog already enforces for every action it does not list.

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
- `events.read` (payload-free fleet change notifications)
- `action.request`, `action.approve`, `action.deny`, `action.read` (the action broker)

Future bindings can scope resources by ID, project, provider account, machine group/tag, environment classification, owner, TTL, and resource ceilings. Do not build an ad-hoc expression language. M1 implements the authorization port and explicit trusted-LAN policy; evaluate an embedded engine only when authenticated or multi-user deployment requires concrete policies.

Authentication, authorization, human approval, and provider privilege are separate. A permitted action may still require risk confirmation; confirmation never grants a denied permission.

## Secret handling

- Desired Git, source repositories, logs, audit metadata, operation payloads, URLs, and error messages contain references, not secret values.
- Controller secrets are individually encrypted with an authenticated cipher. A versioned master key is mounted from a protected file/Docker secret outside the database and supports planned rotation.
- Secrets are decrypted just in time at the adapter boundary, held for the shortest practical duration, zeroized where supported, and redacted by value/pattern before persistence or streaming.
- SSH private keys should preferably remain in an agent/credential helper or use short-lived certificates. Stored keys are encrypted secret records with strict provider scope.
- External provider account tokens (Coolify, Cloudflare) are encrypted secret records named `external/<account-id>`, write-only through the API and `fleetctl`, and used only by the probe at the provider boundary. See `provider-model.md`.
- Project environment values stay in Frogenv/SOPS/age. Fleet invokes `frogenv env run`; it does not list values or become a decryption UI.
- Backups require both encrypted data and separately protected master-key recovery instructions. Losing either has an explicit failure mode.

## Remote execution and providers

- SSH onboarding requires explicit host-key verification or a clearly labeled trust-on-first-use fingerprint confirmation. Host-key change blocks connection until reviewed.
- Commands use argument arrays, controlled working directories/environment, output/time limits, process-tree cancellation, and a run-as policy. Shell mode is a distinct high-risk path.
- `sudo`/Administrator helpers expose an allowlisted protocol. Avoid a root `fleetd` general shell.
- Docker access is labeled root-equivalent on typical hosts; container exec/lifecycle permissions are separate.
- Proxmox tokens use dedicated users/tokens and the minimum roles/path ACLs. TLS verification/pinning cannot be disabled silently.
- Operator guide for the per-tier Proxmox roles, ACL paths, and token rotation: [operations/proxmox-token.md](../operations/proxmox-token.md).
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
