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
- **Endpoint and token move together:** an account's endpoint and token are two stores. Update and delete hold a per-account async lock (`AccountLocks`) across the record change and the credential write, restore-on-failure included, and a probe or discovery takes the same lock while it reads the endpoint and the token. A reader therefore never pairs a new endpoint with the old token, and the old token never reaches a new origin. The lock is released before the network call, so a run that started before an update finishes with the consistent old pair (its discovery result is then discarded, see below).
- **Write-only token:** it arrives on create or on update, is stored encrypted, and is never returned by the API, printed by `fleetctl` (it is read from stdin), logged, or placed in audit metadata or operation payloads. Replacing the token or changing the endpoint clears the stored probe.
- **Probe classification:** `ok`, `unreachable` (transport or TLS failure, a redirect, or an answer that is not the provider's API), `unauthorized` (token refused, expired, or disabled), and `insufficient_permission` (token valid, permissions missing). A failing service is a successful probe with that status, not an API error. A report lists `granted`, `missing` (seen to lack), and `unverified` (deliberately not checked) permissions.
- **No mutating probe requests:** a probe only sends `GET` requests to safe read endpoints, on every provider version, never following redirects (a redirect stops the probe and names only the target host).
- **Provider crates:** `fleet-provider-cloudflare` calls `GET /user/tokens/verify`, or `GET /accounts/{id}/tokens/verify` when an account id is set, and reads `result.status`; Fleet does not evaluate `expires_on` or `not_before`. `fleet-provider-coolify` sends exactly one request, `GET /api/v1/version`, which Coolify gates behind the `read` ability: a version string verifies `read`, `401` is unauthorized, a `403` with the "Missing required permissions" body is a missing ability, and any other `403` (API disabled, caller IP not allowed) is unauthorized with Coolify's message. A `404` or a non-version answer is "not a Coolify API". Coolify documents no endpoint that returns a token's abilities, and before v4.2.0 `GET /api/v1/enable` and `GET /api/v1/deploy` reach handlers that re-enable the API or start a deployment, so `write` and `deploy` are reported as `unverified`, never guessed; `read:sensitive` and `root` are not probed. Both crates return fleet-core `ProbeReport`s, so provider DTOs stay in the provider crates.
- **Endpoint safety:** Cloudflare and Coolify base URLs must use https (a literal loopback address is allowed for local stubs). An account stored before this rule with another http URL is flagged `policyViolation: "https_required"` on the account (API and `fleetctl accounts get --output json`), and it is neither probed nor discovered, so its token is never sent in clear. It stays listed and deletable. Because any other edit re-validates the whole record, the way out is one update that sets an https base URL together with a new token (the scheme is part of the origin, so the token must be replaced anyway); the violation clears with it. Changing an account's base URL scheme, host, or port requires a new token in the same request, so a stored token is never sent to an origin it was not given for. Labels and notes the credential scrubber would change are refused.
- **Coolify discovery (FM-1030):** `POST /api/v1/external-accounts/{id}/coolify/discover` runs a read-only discovery and stores the snapshot; `GET .../coolify/observations` reads the cache. Running it needs `external_account.config` on the account (it resolves the token and writes the cache) and records `coolify_discovering` then `coolify_discovered` audit intents whose metadata carries only the label and per-class counts and states; reading needs `external_account.read`. `CoolifyDiscovery` and the `CoolifySource` port live in `crates/fleet-application/src/coolify.rs`; `fleet-provider-coolify` implements the port.
  - **Classes and translation:** servers, projects with environments, applications, services (with their hostnames), databases, and recent deployments (active ones plus the latest five per application, bounded to 50 applications). The provider translates with an explicit field allow-list, so environment variable values, database passwords and URLs, raw Compose files, webhook secrets, basic-auth credentials, and deployment logs never leave the provider crate, even for a token that holds `read:sensitive`. Discovery never calls the `/envs` routes and never requests anything but `GET` on a closed route set.
  - **Bounds and partial failure:** 10 s per request, 90 s per run, 8 MiB per response, and at most 120 requests per run (Coolify allows 200 per minute per user by default), plus per-class item and follow-up caps. The first HTTP 429 stops every later request (`rate_limited`, with `Retry-After` in the detail; the run never sleeps). A failed `/version` (unreachable, refused, not Coolify) fails every class after one request. Otherwise each class reports `complete`, `partial` (with reasons such as a failed environment fetch), or `failed` (`unauthorized`, including HTTP 400 "Invalid token.", `insufficient_permission`, `not_found`, `unreachable`, `timeout`, `rate_limited`, `invalid_response`) independently. All top-level lists are fetched before any follow-up (environments per project, hostnames per service, deployments per application), and a follow-up route that answers 404 once is not asked again. List answers may be arrays or Laravel-style objects keyed by position (`/deployments`); both are read. The list routes are not paginated by Coolify; only the per-application deployment history takes `skip` and `take`. A token that can read sensitive values (deployment `logs`, database passwords present) produces a `warnings` entry: use a read-only token.
  - **Stamped and stale-aware:** each class carries `attemptedAt` and `observedAt` (last success). A class that fails keeps its previous items and last success time, and is `stale` until a run succeeds; a successful class turns stale 15 minutes after its last success. Items whose follow-up failed (environments, hostnames) keep the previous run's detail flagged `detailsStale`. A run that finishes after the account changed (endpoint or token) is discarded, not stored (the save is conditional on the account's `updated_at` from before the run), and audited as `coolify_discovery_discarded`; a failed save is audited as `coolify_discovery_failed`. Changing an account's endpoint or token clears the cache. The snapshot is bounded to 4 MiB by cutting the largest classes (flagged `truncated`) rather than failing the save. It is one row per account (`coolify_observations`, migration 0057) that goes with the account.
  - **Fixtures:** `tests/fixtures/v4.4.6/` is synthetic (from the upstream v4.4.6 schemas and controllers) with a `read:sensitive` variant whose secret fields carry sentinels that must not come out. An operator records real fixtures with the ignored `capture` test and a read token; the scrubber is default-deny (object keys, image names, hostnames, and addresses included) and refuses output containing the token, the instance host, a hostname outside `.example.test`, or an address outside 192.0.2.0/24; capture writes the files under the names the contract tests read, and a test applies the same check to every committed fixture directory. Real-instance fixtures are pending.
- **Out of scope here:** Cloudflare resource discovery (FM-1042) and the unified service view (FM-1031).

## Public lookups: RDAP and DNS (FM-1020)

`fleet-provider-rdap` and `fleet-provider-dns` are credential-free providers for the Registry domain enricher (see [desired-state.md](desired-state.md)). RDAP uses the IANA bootstrap registry and HTTPS only, with bounded bodies and redirects; DNS uses hickory-resolver (MIT OR Apache-2.0) over the system resolver. Failures are fixed, credential-free categories. Provider types are translated in the controller adapters (`registry_enrich.rs`), not leaked into the application.

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
