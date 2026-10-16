# Provider model

Status: proposed

## Principle

A provider is an adapter for a specialized system. Fleet owns cross-provider orchestration, desired/observed comparison, authorization, durable operations, audit, and user-facing resource identity. The provider owns protocol/CLI details and translates them into Fleet concepts.

Do not create one universal `Provider` trait. Use narrow ports that match domain behavior:

| Port | Examples |
|---|---|
| `ConnectionProvider` | SSH connectivity/test/exec, node session dispatch |
| `MachineDiscoveryProvider` | Tailscale devices, Proxmox guests, SSH imports |
| `InventoryProvider` | OS/hardware/tool/Git facts |
| `ContainerProvider` | Docker list/inspect/log/lifecycle/exec |
| `InfrastructureProvider` | Proxmox nodes, storage, guests, templates, task/lifecycle |
| `ImageBuildProvider` | Packer validation/build of versioned Proxmox image recipes |
| `SourceControlProvider` | GitHub repositories/auth and Git desired source |
| `SkillsProvider` | Skills Manager inventory/presets/deployment |
| `EnvironmentProvider` | Frogenv status/setup/command environment, optional DevPod workspace |
| `ToolProvider` | mise and reviewed tool/agent recipes |

A crate implements only the ports it can honor. Read and write capabilities are declared separately.

## Execution location

- Controller-side: SSH, Tailscale API, GitHub API, Git desired source, Proxmox API.
- Node-side through `fleetd`: local Docker socket, Git checkouts, installed tools/agents, Skills Manager, Frogenv, mise, editors, local files.
- Agentless fallback: selected node ports can execute over SSH with reduced guarantees.

The application chooses a route from machine endpoints and observed provider capabilities. A provider never selects another provider or bypasses authorization.

Proxmox guest discovery reports evidence-only Fleet machine candidates. The runtime association is a separate, explicitly confirmed one-to-one link between a Fleet machine and an account/kind/VMID guest identity. Confirmation rediscovers that guest and requires current evidence for the selected machine; conflicts are refused by the runtime store. A machine's displayed kind comes from its confirmed guest link first, then its observed `host.virtualization` fact. Names never create links automatically.

Windows guests (FM-608) get the same Proxmox observation as Linux guests. Nothing more is promised.
- **Source.** Everything comes from the PVE API and the QEMU Guest Agent.
- **OS facts.** The application classifies the agent's `get-osinfo` answer. `id: mswindows` becomes `os.family = windows`. Fleet also records `os.name`, `os.version` and `os.variant` when the answer carries them; every `get-osinfo` member is optional. An unrecognized id and a missing answer record no `os.family`, so they never overwrite what an in-guest observer reported.
- **`ostype` hint.** The config `ostype` (`win10`, `win11`, …) is a separate `pve.ostype_hint` fact. It is never treated as the guest's OS.
- **Addresses.** Association and the displayed `pve.addressN` facts use only usable addresses. Loopback, unspecified, multicast, `169.254.0.0/16` and `fe80::/10` addresses are excluded, after any `%zone` suffix is stripped. The raw interface list is kept, bounded.
- **Agent states.** Agent not running, agent not configured and guest off are all `unavailable`, the same as for Linux guests.
- **Not covered.** Windows `fleetd`, WinRM or SSH into the guest, in-guest inventory or exec, and Windows Lab templates. Those are FM-S04 and FM-214.

## Provider contract requirements

Each call receives operation context containing correlation/operation ID, deadline, cancellation, actor decision digest, target, and redaction policy. It returns:

- Normalized observation or action result
- Source provider/account/resource IDs and provider version
- Progress events for long work
- Typed error category: invalid input, unauthenticated, unauthorized, unavailable, conflict/locked, rate limited, unsupported, timed out, cancelled, or internal
- Retry safety and optional external task ID
- Verification data proving the requested outcome when practical

Mutation methods declare idempotency behavior. “Accepted by provider” and “verified complete” are different states.

## Capability facts

Capabilities are observations, not a hardcoded boolean list. A fact contains a namespaced name, availability (`available`, `degraded`, `unavailable`, `unknown`), optional version/attributes, source, observed time, and schema version.

Examples:

- `runtime.docker` with engine/API versions
- `infra.proxmox-host` with node/cluster association
- `tool.git`, `runtime.node`, `agent.codex`, `agent.claude-code`
- `skills.manager`, `env.frogenv`, `network.tailscale`
- `hardware.usb-passthrough`

Desired state references provider-neutral outcomes where possible and can require a specific provider only when the workflow truly depends on it.

## External CLI providers

CLI integration rules:

1. Use documented commands and `--json`/equivalent output.
2. Pin and record a tested version range; probe version before use.
3. Parse into versioned provider DTOs and maintain golden contract fixtures.
4. Pass argument arrays, a controlled environment, deadline/cancellation, and bounded output.
5. Never scrape a TUI, edit an internal database, or import undocumented source modules.
6. Never put secret values on a command line when stdin/file descriptor/environment injection is available; redact process descriptions and output.
7. Return `unsupported` with an actionable requirement if the installed version lacks the contract.

Skills Manager and Frogenv remain standalone products under these rules.

### Packer image-build provider

Packer is the first `ImageBuildProvider` and runs as an external CLI behind the same operation, authorization, audit, cancellation, redaction, version-probe, and contract-test rules. Fleet must not depend on Packer's internal packages or plugin storage. Before distributing or bundling a Packer binary, record an explicit review of Packer's then-current license and the Proxmox plugin's license; the initial integration may require the operator to install a compatible version.

The portable source is modern HCL2 JSON named `*.pkr.json`, not legacy Packer JSON. Fleet stores it with a separate manifest and versioned provisioning assets. The web adapter provides:

- A structured editor for the supported Proxmox builder subset
- An advanced raw-JSON editor for the complete recipe
- Preservation of unknown fields during structured edits
- JSON/schema checks followed by `packer validate`

Packer recipes and provisioners are privileged code. Saving changes produces an editable draft/new version; a build snapshots immutable inputs, installed Packer/plugin versions, checksums, logs, and resulting Proxmox template identity. A successful build requires manual promotion before Lab uses it by default. The exact promotion validation checks remain an open planning decision.

A future catalog distributes signed/versioned recipes, manifests, provisioning assets, compatibility constraints, and integrity/provenance metadata. It does not distribute VM disks or licensed operating-system installation media.

## External provider accounts (Coolify, Cloudflare)

API-token providers outside Proxmox share one account registry (FM-1001; `crates/fleet-application/src/external_accounts.rs`). It generalizes the Proxmox account shape where it fits and does not migrate Proxmox accounts.

- **Account:** provider kind (a closed enum, `coolify` or `cloudflare`), label (unique within a kind; several accounts per kind are allowed), base URL, an optional provider account id (Cloudflare account-owned tokens), notes, and the latest probe result. The token is an encrypted secret record named `external/<account-id>`; only that namespace resolves for these accounts.
- **Surfaces:** `GET|POST /api/v1/external-accounts`, `GET|PATCH|DELETE /api/v1/external-accounts/{id}`, `POST .../probe`; `fleetctl accounts list|get|create|update|delete|probe`; Settings > Provider accounts. All three are adapters over the same use cases.
- **Authorization and audit:** `external_account.read` lists and reads; `external_account.config` creates, updates, probes, and deletes (a probe sends the token off-host, so it is privileged). Both are administrator-only and refused for delegated credentials. Every mutation records a two-phase audit intent (`external_account_creating` then `external_account_created`, likewise `updating`, `probing`, `deleting`). Metadata carries the kind, label, and probe status only.
- **Write-only token:** it arrives on create or on update, is stored encrypted, and is never returned by the API, printed by `fleetctl` (it is read from stdin), logged, or placed in audit metadata or operation payloads. Replacing the token or changing the endpoint clears the stored probe.
- **Probe classification:** `ok`, `unreachable` (transport or TLS failure, a redirect, or an answer that is not the provider's API), `unauthorized` (token refused, expired, or disabled), and `insufficient_permission` (token valid, permissions missing). A failing service is a successful probe with that status, not an API error. A report lists `granted`, `missing` (seen to lack), and `unverified` (deliberately not checked) permissions.
- **No mutating probe requests:** a probe only sends `GET` requests to safe read endpoints, on every provider version, never following redirects (a redirect stops the probe and names only the target host).
- **Provider crates:** `fleet-provider-cloudflare` calls `GET /user/tokens/verify`, or `GET /accounts/{id}/tokens/verify` when an account id is set, and reads `result.status`; Fleet does not evaluate `expires_on` or `not_before`. `fleet-provider-coolify` sends exactly one request, `GET /api/v1/version`, which Coolify gates behind the `read` ability: a version string verifies `read`, `401` is unauthorized, a `403` with the "Missing required permissions" body is a missing ability, and any other `403` (API disabled, caller IP not allowed) is unauthorized with Coolify's message. A `404` or a non-version answer is "not a Coolify API". Coolify documents no endpoint that returns a token's abilities, and before v4.2.0 `GET /api/v1/enable` and `GET /api/v1/deploy` reach handlers that re-enable the API or start a deployment, so `write` and `deploy` are reported as `unverified`, never guessed; `read:sensitive` and `root` are not probed. Both crates return fleet-core `ProbeReport`s, so provider DTOs stay in the provider crates.
- **Endpoint safety:** Cloudflare base URLs must use https (a loopback address is allowed for local stubs). Changing an account's base URL scheme, host, or port requires a new token in the same request, so a stored token is never sent to an origin it was not given for. Labels and notes the credential scrubber would change are refused.
- **Out of scope here:** Coolify resource discovery (FM-1030). Cloudflare DNS is the next section.

## Cloudflare DNS (FM-1042)

Fleet reads DNS through a Cloudflare external account and changes it only through the action broker (ADR 0016). Code: `crates/fleet-application/src/dns.rs` (rules, use cases, actions), `crates/providers/fleet-provider-cloudflare` (the API v4 client and the `DnsGateway` implementation), `crates/fleet-api/src/dns.rs`, `crates/fleetctl/src/dns.rs`.

- **Reads:** `GET /api/v1/dns/zones` and `GET /api/v1/dns/records?name=<fqdn>[&type=][&account=]`, `fleetctl dns zones|records <fqdn>`; permission `dns.read` (risky: it sends the account's token off-host). The zone is resolved from the name as the longest zone the Cloudflare accounts can see; a zone visible to two accounts is a conflict until `--account` names one. A records read is recorded as an observation in `dns_record_observations` (migration 0059), replaced per account, zone, and name, and removed with the account. When the active Registry has a matching `domain/<fqdn or apex>` entry the observation names it; the entry itself is never changed, and the storage is separate from other enrichers'.
- **Changes:** `POST /api/v1/dns/changes` computes the preview and files an action request for `dns.record.upsert` or `dns.record.delete` (default risk class `approve`, configurable through `FLEET_ACTION_POLICY` like any action). The preview (current record, proposed record, and the changed fields) is stored in the request's parameters with the resolved account and zone ids, so approver, executor, and requester share one view. The action's `validate` rejects parameters that carry no consistent preview, so the generic `POST /requests` cannot skip it. `fleetctl dns set|delete ... [--wait-approval[=<duration>]]` files the request and, with the flag, waits through the shared `requests` wait helper and answers `{ outcome, request, result }`.
- **Safe record set:** `A`, `AAAA`, `CNAME`, `TXT`, `MX`. `CAA` (certificate issuance), `NS` (delegation), `SRV`, `SOA`, and the rest are not changed through Fleet. Names must be inside the zone; labels are letters, digits, `-`, `_`, and `*` only as the leftmost label. TTL is `1` (automatic) or 60 to 86400; a proxied record (A, AAAA, CNAME) has TTL 1. `TXT` is limited to 1024 bytes so the parameters stay under the broker's 8 KiB bound.
- **Identity and idempotency:** a record is identified by zone, name, and type, plus its content for the multi-value types (`A`, `AAAA`, `TXT`, `MX`). An upsert whose content already exists updates that record; `replaces` names the existing value a new content replaces; otherwise a new value is added. `CNAME` has one value, so an upsert replaces it. A request that would change nothing is refused at request time.
- **Execution:** the operation re-reads the records at the name and recomputes the plan. If the zone no longer holds what the preview said, the operation fails with a stale-preview reason and writes nothing. A state that already matches (an upsert whose record now exists as asked, a delete whose record is gone) succeeds as `unchanged` or `already_absent`, so a replay after a crash is harmless. A write that the provider refuses as a duplicate is re-read and accepted only if the record is as wanted. Every successful write is verified by a read.
- **Provider failures** are classified at the boundary: `auth`, `permission`, `not_found`, `conflict`, `rate_limited`, `invalid`, `unavailable`. Cloudflare allows 1200 requests per five minutes; a `429` is retried at most twice within the advertised `Retry-After` (at most 30 s) and then reported. A refused token or an outage is a 502 from the API, not the caller's error.
- **Secrets:** no token is in any request, parameter, payload, result, audit event, or log. `TXT` content passes the broker's credential refusal like every parameter: API-key-shaped values are refused. SPF, DKIM public keys, and most DMARC policies pass; a DMARC `rua=mailto:user@host` is refused because `mailto:user@host` has the shape of URL credentials (a known limitation of the shared scrubber, not worked around here).
- **Fixtures:** the contract tests use payloads adapted from Cloudflare's documented examples, not a live account. An ignored capture test (`tests/capture.rs`) records scrubbed fixtures from a real account with a read-only token.

## Recipes and custom actions

Recipes are data interpreted by a built-in node runner, not providers and not a plugin SDK. A proposed schema includes:

- ID/version/source/trust metadata
- Supported OS/architecture and prerequisites
- Detection command and structured parser
- Install/update/uninstall/verify actions
- Explicit `argv` or `shell` mode, run-as requirement, working-directory policy
- Timeout, acceptable exit codes, environment names (never embedded secret values)
- Download URL plus digest/signature where applicable
- Reboot/reconnect expectation and rollback/compensation notes

Built-ins are reviewed with Fleet releases. Custom/community recipe sources are opt-in and pinned. Recipe changes appear in desired-state plans. Shell recipes and remote URLs display heightened risk and may require approval.

Custom command buttons use the same runner, authorization, operation, and audit machinery. There is no early marketplace, in-process code loading, or arbitrary server-side extension.

## Provider selection decisions

- Skills: `skills-manager-cli --json` is primary. The skills.sh CLI is a source/install fallback only where the richer provider is unavailable; Fleet does not emulate presets.
- Skills library and preset mutations are durable, machine-scoped operations dispatched through the pinned v1.40.0 CLI contract. `skills.modify` protects library changes and preset CRUD/membership; preset deployment uses `skills.deploy`. Destructive remove/delete calls require explicit confirmation, and CLI conflicts remain structured operation output.
- Project secrets: Frogenv CLI provider; Fleet does not read Frogenv policy/key files or decrypted values.
- Docker: Docker Engine API on fully managed nodes; Docker-over-SSH for agentless nodes; never expose unauthenticated TCP Docker.
- Git: system Git CLI in a controlled environment to retain credential-helper/SSH behavior; isolate controller desired-state worktrees.
- SSH: system OpenSSH initially for strict host-key and familiar proxy/jump behavior; inspect Purple patterns and libraries before extracting code.
- Proxmox: maintained typed client if the compatibility/TLS spike passes, with a narrow raw endpoint escape hatch inside the provider.
- Image builds: external Packer CLI with modern `.pkr.json` and the Proxmox plugin; no Fleet-native ISO automation engine.
- mise/DevPod/chezmoi: optional providers invoked only when project/profile declarations request them.

## Provider testing

- Contract fixtures from sanitized real output for every supported version family.
- Fake/recorded tests for error and partial-data mapping.
- Real opt-in integration suites labeled by provider and destructive risk.
- No production secret in a fixture or recording.
- Compatibility matrix documented in provider code and UI.
- Provider conformance tests for deadline, cancellation, redaction, correlation, idempotency classification, and extra/unknown fields.
