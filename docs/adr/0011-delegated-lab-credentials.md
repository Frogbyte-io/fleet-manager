# ADR 0011: Delegated, scoped credentials for the Lab lease loop

Status: Proposed

Proposed: 2026-10-09 (issue #392)

This is the first slice of FM-S02 (authenticated authorization). It is scoped to what the M8 CI/agent identity needs and no more. It does not choose a general policy engine.

## Context

Every caller of the controller is `anonymous-lan-admin` (ADR 0001/0008 trusted-LAN mode) or, when enabled, `tailscale:<login>` (ADR 0010). Both are mapped by the same allow-all adapter. The M8 exit gate requires that "a restricted agent identity can create and destroy an allowed Lab lease but cannot execute on production, administer Fleet, read secrets, or retain a VM". The reference consumer, Release QA, needs to lease a Linux guest, run in it, collect evidence, download it, and release the lease, and nothing else.

The existing pieces this must fit into:

- The `Authorizer` port and the `Permission` catalog in `fleet-application::authz`. Every use case calls `authorize` with `(principal id, action, resource)`; the adapter in `fleet-auth` answers.
- The request principal is an `ActingPrincipal { id }` produced by one resolution middleware per listener (`fleet-auth`).
- Leases already record the creating principal id as `owner`; artifacts copy the lease owner.
- Audit events carry the acting principal id; metadata keys that look like credentials are structurally refused.
- Node enrollment tokens already show the accepted pattern for a bearer secret: 32 CSPRNG bytes via `ring`, shown once, stored only as a SHA-256 hash.

## Decision

### 1. The credential

A delegated credential is an opaque bearer token `fmdc1.<64 lowercase hex>` (32 bytes from `ring::rand::SystemRandom`).

- Fleet stores only the SHA-256 hash of the token. The token is returned exactly once, in the response to the issue request, and is never logged, never audited, never placed in a job payload, and never echoed again by any API or CLI listing.
- A credential record has an id, an **owner** label (`[a-z0-9][a-z0-9._-]{0,62}`), the issuing principal, an issue time, an **expiry** (required; at most 24 hours after issue), an **allow-list** of one or more template ids or template version ids (at least one entry, bounded), an optional free-text label, and `revoked_at`.
- Presented tokens are hashed and looked up by hash; the stored hash is then compared in constant time. The token itself is never compared and never used as a lookup key in logs.
- Operators issue, list, and revoke credentials through the public API and `fleetctl credentials`. The three actions are catalog entries (`credential.issue`, `credential.read`, `credential.revoke`), allowed to the LAN and Tailscale administrators and to no credential principal. Issue and revoke are audited; the audit metadata carries the credential id, owner, expiry, and allow-list, never the token or its hash.
- Several credentials may share an owner (token rotation). The owner, not the credential id, is the ownership identity for leases and artifacts.

### 2. Becoming a request principal

A resolver runs before the listener's existing caller resolver on both listeners:

- No `Authorization` header, or a scheme or token that is not `Bearer fmdc1.…`: untouched. The listener's own principal (`anonymous-lan-admin`, or the Tailscale identity) applies exactly as before.
- A `Bearer fmdc1.…` token: looked up on every request, so expiry and revocation take effect on the next request. A valid token resolves to the principal `credential:<owner>:<credentialId>` and wins over any other identity on the request. An unknown, expired, or revoked token is HTTP 401 `authentication_required`. **A presented credential never falls back to administrator**: a request can only be narrowed by presenting a token, never widened.
- On the Tailscale identity listener the TCP peer must still be the trusted loopback peer; a valid bearer then replaces the need for a user login header (tagged devices have none). On the regular listener the bearer is accepted as is.
- The node surface (`/api/node/v1/*`) does not use principals: it keeps its own node credentials. A delegated credential has no effect there.
- Every authenticated request appends a `credential.use` audit intent under the credential principal (method and path, no query, no headers). If the ledger refuses the append, the request is refused.

### 3. How the authz catalog decides

The `Authorizer` stays the single decision point. The adapter is composed: LAN and Tailscale principals keep the existing allow-all behavior; a principal whose id starts with `credential:` is decided by a deny-by-default table in `fleet-auth` (one row per allowed catalog action and resource rule). An action with no row is refused with the stable reason `policy.action_not_delegated`; a row whose resource rule does not match is refused with `policy.out_of_scope`. The table is data, so adding a Lab action (for example `lab.put`, detached exec) is one row and one test.

Two things the table cannot know on its own are provided by the grant of the presented credential, which the resolver registers with the authorizer for the request: the template allow-list (decided as the catalog action `lab.template.use` on `<templateId>/<versionId>`), and the credential's validity.

Allowed for a credential principal:

| Action | Rule |
|---|---|
| `lab.template.use` | Resource `<templateId>/<versionId>` matches the allow-list (template id or version id) |
| `lab.lease` | With a resource: create from an allowed version (also with an `Idempotency-Key`, whose scope is the owner, so a retry with a rotated token of the same owner replays and no other owner can), release (destroy) and cleanup retry of the caller's own lease. Without a resource (sweep): refused |
| `lab.lease.read` | A lease, its guest details and reservation, and the lease search with its filters (#395); own leases only: the owner scope is forced to the credential's owner, so an `owner` filter can only narrow it |
| `lab.lease.provision` | Provision of the caller's own requested lease |
| `lab.extend` | Own lease, within the lease's maximum lifetime (existing use-case rule) |
| `lab.exec` | Own lease |
| `lab.artifacts` | Collect from own lease; download of own artifacts |
| `lab.artifacts.read` | List and read metadata of own artifacts |
| `operation.create` | Only for the kinds a Lab route queues for the caller: `lab.provision`, `lab.exec`, `lab.collect`, `lab.cleanup` |
| `operation.read` | One operation, only when it belongs to the caller's own lease. Listing is refused |

Everything else is refused, notably: `lab.keep`, standalone `lab.provision`, template, image, pool, Proxmox, tailnet, machine, project, skills, desired-state, settings, secret, node, audit, events, and system actions, `operation.cancel`, generic operation creation, and the credential actions. In addition the use cases refuse, for a credential principal, an explicit project on lease creation and a template whose cleanup strategy is `keep`, so the credential cannot retain a VM.

### 4. Owner scoping of leases and artifacts

A lease created by a credential principal records the owner identity `credential:<owner>`; its artifacts copy it. Ownership is lease data, so owner scoping is applied in the Lab, artifact, and operation use cases, after the catalog allows the action: a lease, artifact, or operation of another owner is reported as not found, and lease and artifact lists are filtered to the owner. Leases created by administrators are never visible to a credential principal.

### 5. Out of scope

Web sessions, first-run bootstrap, user accounts, roles, OIDC, rate and concurrency limits, high-impact confirmation, policy administration, a policy engine, and refusing anonymous administration on a listener. The credential narrows a caller that presents it; it is not a perimeter. Anonymous callers that reach the trusted-LAN listener remain administrators until the rest of M8 lands, so a deployment that must not rely on LAN trust still needs that work. No new secrets manager, policy engine, or database is introduced; the credential table is a SQLite table next to the others.

## Known limits

- Credentials of one owner share its leases, so a newer credential with a narrower allow-list can still exec on, extend, and release leases an older one created from other templates. Issue a distinct owner label to separate them.
- A credential names no Proxmox account (placement chooses), no project, and cannot lease a template whose cleanup is `keep`.
- A response already streaming (an operation event stream, an artifact download) is not cut off at revocation; the next request is refused.
- Unknown or malformed tokens identify no principal and are not audited.

## Consequences

- A CI job gets a credential that is useless outside its owner's leases and the allowed templates, expires on its own, and can be revoked at once. A leaked token cannot administer Fleet, read secrets, exec outside Lab, or keep a VM.
- Hash-only storage means a lost token cannot be recovered; issue a new one.
- The credential adds one database read per authenticated request. This is acceptable for the single-controller design (ADR 0007).
- The catalog grows by seven entries (`credential.issue`, `credential.read`, `credential.revoke`, `lab.template.use`, `lab.lease.read`, `lab.artifacts.read`, `lab.lease.provision`) so decisions are made per action and not per route. The allow-all adapter permits them for administrators.
- Because ownership is applied in use cases, a future listener or adapter that calls a use case with a credential principal gets the same scoping.

## References

- Issue [#392](https://github.com/Frogbyte-io/fleet-manager/issues/392); PLAN M8
- [ADR 0010](0010-tailscale-serve-identity.md), [ADR 0008](0008-durable-operations-and-lab-leases.md)
