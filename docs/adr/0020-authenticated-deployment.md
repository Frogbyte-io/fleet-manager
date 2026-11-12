# ADR 0020: Authenticated deployment: accounts, sessions, tokens, and no anonymous administration

Status: Accepted

Proposed: 2026-11-06 (issue [#602](https://github.com/Frogbyte-io/fleet-manager/issues/602))

Accepted: 2026-11-07 by maintainer review, with the changes recorded under [Maintainer decisions](#maintainer-decisions-2026-11-07). It completes FM-S02 beside [ADR 0011](0011-delegated-lab-credentials.md), narrows [ADR 0010](0010-tailscale-serve-identity.md) in authenticated mode, and turns the [ADR 0016](0016-descriptive-registry-and-action-broker.md) approval policy into a boundary. It keeps [ADR 0003](0003-node-identity-and-local-broker.md) node identity unchanged and stores everything in SQLite ([ADR 0007](0007-sqlite-single-controller.md)).

## Context

Fleet is to be installed on every developer device (Linux now, Windows next, epic [#606](https://github.com/Frogbyte-io/fleet-manager/issues/606)) so agents share skills and machine knowledge through the built-in `fleet` skill and `fleetctl --output json`. Today that hands full administration to every agent and every reachable tailnet device.

What the code does today (`dev`, 2026-11-06):

- `fleet-auth::TrustMode` has one variant, `TrustedLan`, and its warning is printed on every start. There are no users, passwords, sessions, cookies, or roles.
- The regular listener (`FLEET_LISTEN`) resolves every request, including static files, `/downloads`, and the node surface, to `anonymous-lan-admin` (`resolve_lan_caller`). The optional Serve listener (`FLEET_TAILSCALE_SERVE_LISTEN`) resolves `tailscale:<login>` from a loopback peer or answers 401, and forces the regular listener to loopback.
- `resolve_delegated_caller` runs first on both listeners: a `Bearer fmdc1.…` token narrows the caller to `credential:<owner>:<id>` or is a 401; it never widens. `ScopedAuthorizer` allows the whole catalog (86 permissions) to the LAN and Tailscale principals and decides delegated principals from `DELEGATED_LAB_LOOP`.
- `/api/node/v1` is mounted on the same listener and authenticates with signed node credentials and sessions (`fmnc1`, `fmns1`) that the operator API never accepts. `fleetd`'s local socket is a read-only status surface.
- Browser protection is an `Origin`-equals-`Host` check on mutations (`browser_mutation_guard`), no CORS, and security headers. `fleetctl` reads only `FLEET_TOKEN`; #614 adds `FLEET_URL` and `$XDG_CONFIG_HOME/fleet/config.toml` (`%APPDATA%\fleet\config.toml`).
- The broker keeps `action.approve` separate from `action.request` but does not compare requester and approver.
- The permanent controller (bergen) runs in Coolify's bridged Compose: the container listens on `0.0.0.0:8080`, published on host loopback, and host Tailscale Serve proxies HTTPS 443 (browsers) and HTTP 8080 (`fleetd`, which speaks HTTP only). Identity mode is off there, because a bridged peer is never loopback.

## Options for human authentication

| Option | Works on bergen as deployed | Cost | Verdict |
|---|---|---|---|
| (a) Local password, argon2id | Yes | Password storage and reset in Fleet | **Baseline** |
| (b) Tailscale Serve identity (ADR 0010) | No: needs host networking; tagged devices have no login | Already built; the host stays trusted | **Optional sign-in, mapped to an account** |
| (c) OIDC | Needs an identity provider the homelab does not run | Redirect, discovery, key rotation, client secret | **Deferred** |
| (d) Passkeys (WebAuthn) | Yes, over the HTTPS Serve origin | Ceremony state, credential storage, recovery path | **Later addition, not the M8 gate** |

Researched crates (crates.io, 2026-11-06): `argon2` 0.6.0 (RustCrypto password-hashes, MIT OR Apache-2.0; defaults are argon2id m=19 MiB, t=2, p=1, the OWASP minimum); `webauthn-rs` 0.6.2 (kanidm, MPL-2.0); `openidconnect` 4.1.0 (MIT); `keyring-core` 1.0.1 with `windows-native-keyring-store` 1.1.0 and `zbus-secret-service-keyring-store` 1.0.1 (MIT OR Apache-2.0; `keyring` 4.2.0 is now a wrapper and sample CLI over these); `tower-sessions` 0.15.0 and `axum-login` 0.18.0 (MIT). All licenses are on the `deny.toml` allow-list.

## Decision

### 1. Two modes, chosen by configuration

`FLEET_AUTH_MODE` (and `auth_mode` in the config file) is `trusted-lan` (default, today's behavior unchanged) or `authenticated`. A malformed value stops startup. `TrustMode` gains `Authenticated`; the startup warning and `/api/v1/meta` report the mode. In authenticated mode **no listener has an anonymous principal**: `anonymous-lan-admin` is not resolved anywhere, and an unauthenticated request gets 401 except on an explicit allow-list: `/healthz`, `/readyz`, `/api/v1/meta`, the static console shell, sign-in, bootstrap, the device-login endpoints, `/downloads/fleetd/*` (checksummed public binaries a fresh machine must fetch), and `/api/node/v1/*` (node credentials). A route-table test fails when a new route is neither authenticated nor on that list. There is no read-only anonymous view: inventory, hostnames, and skills are exactly what the mode protects.

### 2. Accounts and human sign-in

- Users are SQLite records (id, unique username, role, disabled flag, timestamps). Principal id: `user:<username>`. Usernames are `[a-z0-9][a-z0-9._-]{0,62}`.
- **Password (a) is the baseline.** argon2id through the `argon2` crate with its default parameters, stored as a PHC string; parameters can rise later and old hashes upgrade on sign-in. Minimum 15 characters, no composition rules (NIST SP 800-63B-4). Sign-in failures answer one generic message and are audited with the user id when the username exists and nothing typed otherwise (a password typed into the username field must not reach the ledger).
- **Throttling never locks an account.** Two independent limits apply. Per username, each consecutive failure doubles the delay before that username's next attempt is evaluated, from 1 second to a **maximum of 30 seconds**; a success resets it, and there is no lockout, so an attacker can slow a user's sign-in by at most 30 seconds, never block it. Per source (the TCP peer), failures above a fixed rate (default 60 a minute) answer 429 until the window passes; this bound limits floods and does not touch any username's counter. Behind bergen's bridged proxy every caller shares one peer address, so the source limit is a flood bound, not a per-user one, and the per-username cap is what protects each account.
- **Tailscale identity (b) maps to an account, never creates one.** On the identity listener, `tailscale:<login>` resolves to the user an administrator linked it to (`fleetctl users link-tailscale`), with that user's role; an unlinked login is 401. Because the regular listener no longer has an anonymous administrator, authenticated mode lifts ADR 0010's rule that it must be loopback-only, so remote `fleetd` and the identity listener can coexist.
- **OIDC (c) is deferred** until an identity provider is in use; the account model keeps an external-identity link table so it, or (d), adds a sign-in method without changing principals. **Passkeys (d)** through `webauthn-rs` are a follow-up for phishing-resistant sign-in and are not needed for the exit gate.
- Users are created by an administrator. The new user receives a single-use setup token (the same mechanism as bootstrap, valid 24 hours) and sets a password; an administrator can reset a user the same way. There is no self-registration and no email.

### 3. First-run bootstrap

An authenticated controller with no enabled administrator accepts only the bootstrap route. The secret is created on the host, not in the service log or the environment:

- `fleet-controller bootstrap` (run on the host or through `docker exec` / the Coolify terminal) writes a bootstrap token `fmbt1.<64 hex>` (32 CSPRNG bytes) and prints it once to that command's terminal. SQLite stores only its SHA-256 and an expiry of one hour; a new token replaces the old one.
- The console's bootstrap page takes the token, a username, and a password. Creating the first administrator and consuming the token are one transaction, so the token is single-use under concurrent attempts. The command refuses while an enabled administrator exists, unless given `--recover`, which is the documented lost-administrator path: host access already implies database access, so it is not a new trust.
- The token is never logged, audited, or placed in a payload. The audit ledger records `auth.bootstrap_issued` and `auth.bootstrap_completed` with the new user id.
- Rejected: printing the token in the service log (Coolify keeps and shows logs), `FLEET_BOOTSTRAP_TOKEN` in the environment (persists in Compose and Coolify settings), and "first visitor becomes administrator" (a race any tailnet device wins).

### 4. Web sessions

- A session is an opaque 32-byte token in the cookie `__Host-fleet_session` (`Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`). SQLite stores its SHA-256, the user, created, last-seen, and absolute expiry, and `revoked_at`, and looks it up on every request, so revocation and expiry apply to the next request (the ADR 0011 pattern; one read per request is acceptable under ADR 0007).
- Idle timeout 24 hours (last-seen is written at most once a minute), absolute lifetime 30 days, both configurable within bounds. Sign-in issues a fresh session id. Sign-out, password reset, role change, and disabling a user revoke that user's sessions; a user can list and revoke their own sessions, an administrator anyone's.
- CSRF: every unsafe method on a cookie-authenticated request must carry `X-Fleet-CSRF` equal to a per-session token (stored hashed beside the session and served to the console after sign-in), in addition to the existing `Origin` check and `SameSite=Strict` ([OWASP CSRF cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)). Bearer-token requests carry no ambient credential and are exempt. The WebSocket console and terminal routes keep their single-use session tokens, created by an authorized caller.
- `Secure` cookies require the HTTPS origin: on bergen, browsers use the HTTPS Serve endpoint. The HTTP endpoint stays for `fleetd` and tailnet CLI use, where WireGuard encrypts the transport.
- Fleet keeps its own session table rather than `tower-sessions`/`axum-login`: it needs hash-at-rest, per-request revocation, per-user listing, and the existing resolver chain, which those crates would duplicate as a second session abstraction.

### 5. Roles

Roles are fixed, data-driven permission tables in `fleet-auth`, like `DELEGATED_LAB_LOOP`, and the `Authorizer` stays the single decision point. Authenticated mode is deny-by-default: an action with no row is refused.

| Role | Grants |
|---|---|
| `admin` | The whole catalog, including user, role, token, and credential administration, secret writes, provider and source settings, and `hardware.override-release` |
| `operator` | Everything except the administration set above, with one exception: it may issue ADR 0011 delegated credentials for CI, and list and revoke **the credentials it issued** (`credential.issue`, `credential.read`, `credential.revoke`, scoped to the issuer in the credential use case). Only `admin` sees and revokes every credential |
| `viewer` | An explicit allow-list of safe reads: `system.read`, `events.read`, `operation.read`, `machine.read`, `projects.read`, `skills.read`, `tools.read`, `images.read`, `lab.read`, `lab.lease.read`, `lab.artifacts.read`, `hardware.read`, `registry.read`, `action.read`. Not derived from `Permission::is_risky()`: that set also holds `secret.list`, `audit.read`, and `node.read`, which `viewer` does not get |
| agent (agent tokens, section 6) | The `viewer` list, plus `action.request`, plus `skills.catalog.draft` (new; split from `skills.modify`, see below) |
| `delegated` | ADR 0011 `credential:` principals, unchanged |

An **agent token** (section 6) is `viewer` plus `action.request` plus skill catalog **draft** write: an agent can read the fleet, ask for changes, and create and edit catalog drafts to share a skill, and every `approve`-class change waits for a person (or for bounds an operator set on auto approval, ADR 0016). Publishing a catalog version and rolling it out stay human-only. In the current catalog (`crates/fleet-application/src/authz.rs`) one permission, `skills.modify`, authorizes catalog `create`, `update` and `publish` (`skill_catalog.rs`) as well as Skills Manager library and preset changes on machines, so the implementation **must split it**: a new draft permission (suggested id `skills.catalog.draft`) authorizes only creating and editing drafts and is the one the agent grant holds; `publish` and machine library changes keep `skills.modify`; a rollout keeps `apply.execute` and `skills.deploy`. The agent grant holds none of `skills.modify`, `skills.deploy`, `apply.execute` or `action.approve`.

Adding a role or moving a permission is one table row and one test. A new catalog permission is **denied to `viewer`** until it is added to that list, and a catalog test fails until it is classified as administration-only or operator, so no permission reaches a role by default. Resource-scoped roles (per project, machine, or tag) are not part of this decision.

### 6. CLI and agent credentials

- **API tokens** `fmpt1.<64 hex>` are a SQLite table (SHA-256 at rest, constant-time compare, shown once) with an owner user, a kind (`personal` or `agent`), a role ceiling no higher than the owner's role (effective permissions are the intersection with the owner's current role, so a demoted or disabled owner narrows every token at once), a label, an optional machine binding, an expiry, and `revoked_at`. Personal CLI tokens default to 90 days, agent tokens to 1 year; both are renewable and revocable from `fleetctl tokens` and the console. Every request looks the token up, so **revocation (and owner demotion or disabling) applies on the next request**; that, not expiry, is the response to a leaked or lost token, and the long agent lifetime makes it the one to rehearse. Principals: `user:<username>` for personal tokens and `agent:<username>/<tokenId>` for agent tokens; the token id is immutable and unique, so two agent tokens never share an identity, and the label is display only. Every audit event records the credential id that authenticated the request (session id, personal or agent token id, or delegated credential id) beside the principal, never the token or its hash.
- **`fleetctl login` uses a device authorization flow** shaped on [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628): `fleetctl` asks the controller for a device code, prints the verification URL and an 8-character user code, and polls; the user approves in a signed-in browser session, choosing the role ceiling (default `viewer`, at most their own) and lifetime; the controller then returns a personal token. Codes expire after 10 minutes and are single-use. It works over SSH to a remote device, and no token passes through a clipboard or scrollback. `fleetctl login --with-token` reads a token from stdin for headless use. `fleetctl logout` revokes the token on the controller and deletes it locally.
- **Storage**, keyed by controller origin: the OS credential store through `keyring-core` with the Windows Credential Manager and Secret Service stores; where no store is available (headless Linux, SSH sessions without a D-Bus session), `credentials.toml` beside #614's `config.toml`, mode 0600 in a 0700 directory (owner-only ACL on Windows). `fleetctl` never prints a token, and `fleetctl --output json system` reports only which source supplied one. Precedence: `FLEET_TOKEN` (any token kind, including ADR 0011 `fmdc1`), then the credential store, then the file.
- **Agents get a scoped identity by default.** Machine setup (the #614 follow-up that writes `config.toml` for the SSH login) also issues an agent token bound to that machine, owned by the operator who set it up, and writes it into the 0600 file through the brokered SSH session (ADR 0017). The `fleet` skill therefore works immediately as a `viewer` that can file requests and write catalog drafts. A human who wants more runs `fleetctl login` deliberately.
- **Honest limit.** An agent runs as the same OS user as the human. Keyrings and 0600 files do not isolate processes of one user, so an agent can use any token that user stored. The mitigations are structural: tokens default to `viewer`, `fleetctl login` asks for the ceiling, and approving `approve`-class requests and Fleet administration need a browser session (section 8).
- The `fleetd` local socket stays read-only status. Forwarding agent requests through it (ADR 0003's broker) is not chosen now, because Windows workstations will not run `fleetd` (#606) and a token works on both platforms.

### 7. Nodes and delegated credentials

Node credentials, sessions, enrollment, and the node surface are unchanged and remain invalid on `/api/v1`. ADR 0011 delegated credentials keep their format, 24-hour cap, table, and catalog, work in both modes, and can still be issued by `operator`. In authenticated mode their issuer is a user principal.

### 8. Approver separation (ADR 0016)

In authenticated mode `action.approve` and `action.deny` additionally require:

- the approver is a `user:` principal authenticated by a **web session** (not an API token, an agent token, or a delegated credential), and
- the approver is not the requester, **unless exactly one active administrator exists**. With two or more active administrators, a user's own request (session or personal token) needs another user; an agent token's request may be approved by its owner, which is the intended loop. With exactly one active (enabled) administrator, that administrator may approve their own requests, including requests filed by their own agent tokens, and the decision is audited distinctly as self-approval (`action.self_approved`, with the requester and approver principals and credential ids). Disabling or adding an administrator changes the rule for the next decision, not for decisions already made.

Both are checked in the broker use case, not the route, and again when the operation starts. `fleetctl requests approve` in authenticated mode prints the console URL of the request instead of approving. `auto`-class actions still run on request; operators who want a person on every change raise those classes with `FLEET_ACTION_POLICY`.

### 9. Switching an existing controller to authenticated mode

1. Upgrade, then run `fleet-controller bootstrap` and keep the token for the next step. Nothing changes while `FLEET_AUTH_MODE` is unset.
2. Set `FLEET_AUTH_MODE=authenticated` and redeploy. The start records `auth.mode_changed` in the audit ledger. Anonymous callers now receive 401, so CLIs, agents, and the console must sign in.
3. Create the administrator on the bootstrap page, then users, then run machine setup (or `fleetctl tokens issue --kind agent --machine <id>`) to place agent tokens on each device.
4. Data stays as it is. Audit rows, leases, artifacts, operations, and requests keep `anonymous-lan-admin` as their recorded actor and are never rewritten. Pending requests made anonymously can be approved by any administrator session. Delegated credentials and node enrollments keep working. Existing `tailscale:` audit history stays as recorded.
5. Rolling back is setting the mode back to `trusted-lan`, which is audited; sessions and tokens are then ignored (not deleted) and anonymous administration returns with its warning.

## Consequences

- An unauthenticated tailnet device and an agent on a developer machine can no longer administer Fleet; the M8 exit gate becomes testable.
- Every human must sign in, and every device needs a token before the `fleet` skill works. Machine setup issues the agent token so that rollout is one step.
- Approvals need a second person for human-made `approve` requests once two administrators are active. A single-administrator deployment approves its own requests and its agents' requests, and the ledger marks each as self-approval, so separation of duties starts when a second administrator is added.
- Fleet now stores password hashes and must document reset, `--recover`, and the session and token tables in backups. Loss of the master key does not affect these hashes.
- The Serve identity listener becomes compatible with remote nodes in authenticated mode.
- New dependencies: `argon2` (controller) and `keyring-core` with two platform stores (`fleetctl`). `webauthn-rs` and `openidconnect` only if their follow-ups are approved.
- Risks: a same-user agent can use a human's stored token (bounded by role ceilings and session-only approval); a stolen session cookie is valid until idle (24 h) or absolute (30 days) expiry unless revoked; a leaked agent token is valid for up to 1 year and a personal token for up to 90 days unless revoked, so revocation on the next request, machine binding, the agent grant's narrow permissions, and the credential id in every audit event are the controls that bound a leak; a single administrator's self-approval removes the second-person check until another administrator exists; device-code phishing (mitigated by short code lifetime and showing the request's origin and requested ceiling on the approval page); account lockout is avoided by backoff instead of hard lockout, which slows but does not stop online guessing of weak passwords.

## Maintainer decisions (2026-11-07)

The review questions raised in #602 / PR #617 were answered by the maintainer on 2026-11-07, and the decision text above already reflects them:

1. **Self-approval.** With exactly one active administrator, that administrator may approve their own action requests, including those filed by their own agent tokens, audited distinctly as self-approval. With two or more active administrators, approver ≠ requester holds (section 8). This replaces the proposed refusal.
2. **Agent tokens hold `action.request`.** Approval still needs a person, or operator-set auto-approve bounds (section 5).
3. **Agents may create and edit skill catalog drafts.** Publishing a version and rolling it out stay human-only. The agent grant is `viewer` + `action.request` + catalog draft write; `skills.modify` must be split so drafts have their own permission (section 5, issue [#628](https://github.com/Frogbyte-io/fleet-manager/issues/628)).
4. **Longer lifetimes than proposed.** Web sessions 24 h idle / 30 days absolute (was 12 h / 7 days); personal CLI tokens 90 days (was 30); agent tokens 1 year (was 90 days). Revocation applies on the next request and is the primary control for a leaked token (sections 4 and 6, Consequences).
5. **`fleetctl requests approve` prints the console link only;** approval needs a signed-in browser session, as proposed (section 8).
6. **`viewer` includes `skills.read` and `tools.read`,** as proposed (section 5).
7. **The four additional implementation issues are opened now** (below).

## Implementation issues

| Issue | Scope | Depends on |
|---|---|---|
| [#628](https://github.com/Frogbyte-io/fleet-manager/issues/628) auth mode, users, and role tables | `FLEET_AUTH_MODE`, `TrustMode::Authenticated`, users table, `admin`/`operator`/`viewer`/agent tables in `ScopedAuthorizer`, deny-by-default in authenticated mode, `user.*`/`token.*` catalog entries, the catalog draft permission split from `skills.modify` | this ADR |
| [#603](https://github.com/Frogbyte-io/fleet-manager/issues/603) bootstrap and web sessions | `fleet-controller bootstrap [--recover]`, bootstrap page, password sign-in with argon2id and backoff, sessions (24 h idle / 30 days absolute), CSRF token, user setup tokens, console sign-in and Users page | #628 |
| [#604](https://github.com/Frogbyte-io/fleet-manager/issues/604) `fleetctl login` and API tokens | Device flow, `--with-token`, `logout`, personal (90 days) and agent (1 year) tokens with role ceilings, keyring and 0600 file storage beside #614, `tokens list/issue/revoke`, `fleet` skill login step | #603, #614 |
| [#605](https://github.com/Frogbyte-io/fleet-manager/issues/605) refuse anonymous administration | Anonymous allow-list and route-table test, node credentials refused on user APIs, approver separation with single-administrator self-approval (section 8), exit-gate evidence | #603, #604 |
| [#629](https://github.com/Frogbyte-io/fleet-manager/issues/629) agent tokens placed by machine setup | Issue an agent token for the SSH login during machine setup and write it with the #614 config | #604, #614 |
| [#630](https://github.com/Frogbyte-io/fleet-manager/issues/630) Tailscale identity in authenticated mode | Link logins to users, unlinked is 401, lift the loopback-only rule for the regular listener | #603, #605 |
| [#631](https://github.com/Frogbyte-io/fleet-manager/issues/631) migrate bergen | Operations runbook (section 9), Coolify Compose and env example, pilot runbook update (#601) | #605, #629 |
| Later, not M8: passkeys | `webauthn-rs` registration and sign-in beside passwords | #603 |

## References

- Issue [#602](https://github.com/Frogbyte-io/fleet-manager/issues/602); [security.md](../architecture/security.md); PLAN M8
- [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) (device authorization grant); [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2); [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html); OWASP [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) and [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) cheat sheets; [cookie prefixes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes)
- Crates: [argon2](https://crates.io/crates/argon2), [webauthn-rs](https://crates.io/crates/webauthn-rs), [openidconnect](https://crates.io/crates/openidconnect), [keyring-core](https://crates.io/crates/keyring-core), [tower-sessions](https://crates.io/crates/tower-sessions)
