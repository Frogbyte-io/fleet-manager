# Ecosystem research and integration recommendations

Research date: 2026-08-25; FM-S01 refreshed 2026-08-26. Prefer linked upstream documentation/repositories over this summary when implementing. Re-run the relevant spike at milestone start because versions and public contracts will change.

## Direct integrations

### Skills Manager

Sources: [project](https://github.com/xingkongliang/skills-manager), [CLI documentation](https://github.com/xingkongliang/skills-manager#cli), [product site](https://skillsmanager.dev/). Inspected `1aa2c3c` / v1.34.2. License: MIT.

Findings:

- The desktop app and `skills-manager-cli` use the same Rust core, central library, SQLite database, tool adapters, and sync engine.
- The CLI exposes global `--json` and groups for repository status, agents, skills, presets, and Git operations.
- Relevant operations already include list/show/install/update/check/remove, deploy/undeploy/status, preset CRUD/membership/deployment/status, existing-skill adoption, tags, Git backup, and an external `--skills-root` mode.
- It detects many coding agents and models actual deployment separately from preset membership.
- Official standalone binaries are published, but platform/architecture coverage must be checked; source compilation may be needed for unsupported ARM Linux nodes.

Decision: use `skills-manager-cli --json` as Fleet's primary skills provider. Pin a tested version range, verify release checksums, record its version, and keep JSON contract fixtures. Do not read its SQLite database, invoke Tauri internals, or recreate its library, updater, agent adapters, presets, or Git merge engine.

Desired ownership needs to be explicit:

- An external Skills Manager preset is referenced and owned entirely by Skills Manager.
- A Fleet-managed preset has membership canonical in Fleet desired Git and is reconciled through documented preset CLI operations. It must be visibly marked managed; manual divergence is drift, not two-way merge.
- Skills Manager Git backup can mirror its store but does not silently become a second authority for a Fleet-managed preset.

The current `legacy/agents-registry/src/skillsBackend.js` is not this integration. Its default `skills install` command matches neither Skills Manager (`skills-manager-cli skills install`) nor the separate skills.sh CLI (`npx skills add`). Preserve its tests only as migration evidence and replace it in M3.

### skills.sh CLI

Sources: [official CLI docs](https://www.skills.sh/docs/cli), [open-source CLI](https://github.com/vercel-labs/skills).

Findings: the `skills` CLI installs sources/packs with `npx skills add`, supports many agents, and supplies the skills.sh ecosystem. It does not replace Skills Manager's central library, preset, backup, and deployment-state model.

Decision: Skills Manager should normally mediate skills.sh sources. A direct skills.sh provider may be a reduced fallback on a platform where Skills Manager is unavailable, but Fleet must report the missing preset/update semantics rather than implement them.

### Frogenv

Sources: [repository](https://github.com/Frogbyte-io/frogenv), [README/security model](https://github.com/Frogbyte-io/frogenv#security-model). Inspected `06bbd71` / v0.2.0. License: MIT.

Findings:

- Frogenv is a TypeScript CLI orchestrating SOPS + age with a private Git repository as transport.
- It owns one local age key per machine, group/path recipient policy, pending/approved machine records, encrypted project environment files, and approval/re-encryption flows.
- `frogenv status` already emits JSON with configuration and machine registration fields.
- `setup --yes` is non-interactive, but `check` and `machine list` are human text; setup/login/request/approve/sync perform security-sensitive local or Git mutations. `env run` injects decrypted values only into a child process.
- Frogenv's machine ID is derived from hostname and age public key and is not Fleet's machine ID.
- The npm registry still reports v0.1.0 while the repository/package is v0.2.0, so Fleet cannot assume `npx frogenv` provides the inspected commands until the release gap is closed.

Decision: keep Frogenv standalone and invoke its public CLI on a node through the environment provider. Fleet maps, but never equates, the two machine IDs. Minimum M3 capabilities are detect/version/status, `setup --yes`, login, machine request/status, check/sync, and `env run` for a project action. Approval remains an explicit Frogenv ceremony unless Frogenv's documented CI policy is configured.

Distribution gate: publish and checksum v0.2.x (or install a pinned release/source artifact through a reviewed recipe) before declaring the provider generally available. Do not silently fall back to the older npm package.

Upstream collaboration needed before rich UI:

- `--json` for `check`, `machine list`, request/approval/sync results
- Consistent non-interactive/error codes and idempotent “already configured” outcomes
- A safe command that lists project/environment names without values, if required
- An explicit way to correlate a Fleet machine ID as metadata without changing key identity

Fleet must not edit `frogenv.yaml`, `.sops.yaml`, `keys/`, its local config, or encrypted files directly and must never capture/display `env get` values.

### Docker

Sources: [Docker Engine API](https://docs.docker.com/reference/api/engine/), [secure daemon access over SSH](https://docs.docker.com/engine/security/protect-access/), [Docker contexts](https://docs.docker.com/engine/manage-resources/contexts/), [Bollard Rust client](https://docs.rs/bollard/latest/bollard/). Bollard is Apache-2.0.

Findings: Docker already exposes a versioned REST API with negotiation; its CLI forwards an SSH endpoint to the remote Unix socket. Bollard is async, generates models from upstream schemas, supports Unix sockets, Windows named pipes, TLS, Podman, and SSH.

Decision: on fully managed nodes, `fleetd` talks to the local engine using Bollard with API negotiation. On agentless nodes, the controller invokes a one-shot isolated Docker-over-SSH route/context rather than exposing TCP port 2375. Keep initial scope to list/inspect/logs/start/stop/restart/exec. Docker socket access is root-equivalent on typical systems and receives separate permissions.

### Tailscale

Sources: [OAuth clients](https://tailscale.com/kb/1215/oauth-clients), [auth keys](https://tailscale.com/docs/features/access-control/auth-keys), [device provisioning with OAuth apps](https://tailscale.com/docs/features/oauth-apps/device-provisioning).

Findings: OAuth clients support scoped API access and one-hour access tokens; the API can list devices and generate tagged auth keys. User OAuth app provisioning can preserve individual user identity but is one-time per device.

Decision: use a least-privilege OAuth integration for tailnet device discovery and optional ephemeral/tagged Lab onboarding. Store the client secret as a Fleet secret. Do not use long-lived API keys, reusable auth keys by default, Tailscale identity as Fleet node auth, or assume all users have a tailnet.

### GitHub

Sources: [GitHub App authentication](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app), [user access tokens and web/device flows](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app), [create repository API](https://docs.github.com/en/rest/repos/repos#create-a-repository-for-the-authenticated-user), [contents API](https://docs.github.com/en/rest/repos/contents#create-or-update-file-contents).

Findings: GitHub recommends Apps for organization/on-behalf-of-user API access. User access tokens can be expiring and refreshed. Creating a private user repository requires administration-write permission; initializing contents requires contents-write permission.

Decision: the web controller uses GitHub App web authorization; the headless CLI may use device flow. Ask for the least permissions, use expiring tokens, encrypt refresh/access tokens, and initialize one serialized commit. Organization repository creation/installation is a distinct approval path. Do not start with a broad classic PAT.

## Tools to integrate optionally

### mise

Sources: [configuration](https://mise.jdx.dev/configuration.html), [environments](https://mise.jdx.dev/environments/), [tasks](https://mise.jdx.dev/tasks/toml-tasks.html), [monorepo tasks](https://mise.jdx.dev/tasks/monorepo.html). License: MIT.

Mise manages tool/runtime versions, environment, and tasks in project configuration. Fleet should detect and optionally install/invoke it for projects that use it, then observe `mise` status/install results. It is not mandatory, and Fleet recipes remain necessary for system services/tools outside mise. Project `mise.toml` stays authoritative; Fleet must not translate it into a second tool-version model.

### DevPod and Dev Containers

Sources: [what DevPod is](https://devpod.sh/docs/what-is-devpod), [architecture](https://devpod.sh/docs/how-it-works/overview), [provider model](https://devpod.sh/docs/developing-providers/quickstart), [first-party providers](https://devpod.sh/docs/managing-providers/add-provider). License: MPL-2.0.

DevPod is client-only, uses `devcontainer.json`, deploys its agent/SSH over provider tunnels, and already supports Docker, SSH, Kubernetes, and cloud machine providers. Its client-owned lifecycle does not replace a persistent Fleet controller, durable Lab leases, hardware scheduling, or audit.

Decision: do not integrate DevPod into Lab initially. In M3, spike a node-side provider for repositories with Dev Container configuration: Fleet allocates/selects the machine, DevPod creates the reproducible workspace, and Fleet records the workspace operation. Avoid writing a Fleet DevPod provider or copying its agent until an actual gap is demonstrated.

### chezmoi

Source: [chezmoi concepts](https://www.chezmoi.io/reference/concepts/). License: MIT.

Chezmoi already separates source, destination, machine configuration, and computed target state for dotfiles. Dotfile synchronization is outside initial Fleet scope. If profiles later request dotfiles, Fleet should invoke chezmoi and report its plan/apply status rather than add file templates/sync to Fleet.

### Playwright and desktop automation

Sources: [Playwright browsers/projects](https://playwright.dev/docs/browsers), [Microsoft Windows app testing guidance](https://learn.microsoft.com/en-us/windows/apps/develop/testing/), [FlaUI](https://github.com/FlaUI/FlaUI), [Appium Windows driver](https://github.com/appium/appium-windows-driver).

Playwright already owns multi-browser testing and browser binary compatibility. Fleet provisions an environment and invokes a project Playwright command.

Microsoft now states that WinAppDriver is no longer actively developed and points Windows App SDK testing toward Appium's Windows driver; FlaUI is a mature MIT .NET wrapper around Windows UI Automation. No universal desktop choice is justified. Select a project/technology-specific external runner in a later research issue; Fleet only provisions, attaches hardware, invokes, and collects.

## Libraries and reference projects to spike

### Purple

Source: [repository](https://github.com/erickochen/purple). Inspected `3b4ca5f` / v3.26.1. License: MIT.

Relevant implementation evidence:

- Rust library modules for round-trip OpenSSH config parsing/writing, provider sync, Tailscale and Proxmox discovery, remote Docker/Podman actions, command fan-out, and MCP.
- Uses system OpenSSH for remote execution, preserving familiar SSH behavior.
- Proxmox parsing handles loose/null Perl JSON shapes, cluster resources, QEMU Guest Agent network/OS data, LXC interfaces, and per-resource failure isolation.
- MCP has read-only tool filtering, structured JSON-RPC, audit redaction, and tests.

Decision: Purple is the highest-value architecture/reference and potential Rust reuse candidate. Before depending on `purple_ssh`, open a bounded spike that assesses public module stability, transitive/TUI weight, config ownership assumptions, error/cancellation behavior, test extraction, and upstream willingness to split reusable crates. Reuse MIT code with attribution or contribute extraction upstream if justified. Do not embed its TUI/application state or make `~/.ssh/config` Fleet's database.

### Proxmox Rust clients

Sources: [official Proxmox API viewer](https://pve.proxmox.com/pve-docs/api-viewer/), [Proxmox common Rust crates](https://github.com/proxmox/proxmox-rs), [`proxmox-client` crate](https://docs.rs/proxmox-client/latest/proxmox_client/), [Purple Proxmox provider](https://github.com/erickochen/purple/blob/main/src/providers/proxmox.rs).

Findings:

- Proxmox exposes the authoritative REST API and asynchronous UPID task model. QEMU Guest Agent data is optional and shape/version tolerant code is necessary.
- The official `proxmox-rs` workspace contains a crate named `proxmox-client`, but it is part of Proxmox's broad internal/common workspace and is not clearly a complete PVE automation SDK for Fleet's use.
- The crates.io `proxmox-client` v0.9.2 from `landrzejewski/proxmox-client-rust` advertises broad typed coverage but explicitly labels itself experimental and was very young/low-adoption at review.
- The current Fleet client has valuable certificate-fingerprint and UPID tests but uses `rejectUnauthorized: false` plus manual pinning and one environment-configured account.

Decision: M6 begins with a compatibility spike against required endpoints and PVE versions. Prefer the typed crate only if authentication, task polling, TLS custom trust/pinning, unknown-field tolerance, cancellation, and endpoint coverage pass. Otherwise keep a small `reqwest` transport plus typed provider DTOs, borrowing Purple's tested parsing patterns. Never accept invalid certificates as the production answer.

### Rust controller/node stack

Candidate primary sources: [Axum](https://docs.rs/axum/latest/axum/) for HTTP/SSE/WebSocket, [SQLx](https://github.com/launchbadge/sqlx) for compile-checked SQLite/migrations, [Bollard](https://docs.rs/bollard/latest/bollard/) for Docker, [Effectum](https://docs.rs/effectum/latest/effectum/) for an embedded SQLite task queue, and [Cedar](https://github.com/cedar-policy/cedar) for embedded authorization.

#### FM-S01: OpenAPI and TypeScript client generation

Decision (2026-08-26): use [`utoipa` 5.5.0](https://crates.io/crates/utoipa/5.5.0) with [`utoipa-axum` 0.2.0](https://crates.io/crates/utoipa-axum/0.2.0) to register real Axum handlers and generate OpenAPI 3.1 JSON. Use [`orval` 8.26.0](https://www.npmjs.com/package/orval/v/8.26.0) with its Fetch client to generate the TypeScript client. Pin these versions and their Cargo/npm dependency graphs; an upgrade reruns this evidence before changing the pins. This chooses tooling within ADR-0002 and does not change its API/protocol split.

The FM-006 generation contract is:

1. Build a small repository-owned export binary/task that constructs the same `utoipa_axum::OpenApiRouter` used by the controller, splits out its `OpenApi`, and serializes pretty JSON with `serde_json` to a checked-in file.
2. Generate into a temporary location during the check and byte-compare it with the checked-in OpenAPI file. Any difference exits nonzero and prints the diff. Do not normalize, sort, or rewrite the document in a separate tool that could hide nondeterminism.
3. Run pinned Orval against that checked-in document with `client: "fetch"`, then run TypeScript with `strict: true` and `noEmit: true`. Check the generated artifacts by regenerating to a temporary directory and diffing them; never hand-edit the client.
4. Keep an HTTP contract test for each endpoint's material status/body behavior. Utoipa ties route registration and DTO schemas to handlers, but explicitly annotated response statuses can still be written incorrectly; OpenAPI snapshot checking is not a substitute for exercising the handler.

Evidence was produced in disposable projects outside this repository using Rust/Cargo 1.98.0, Node 24.19.0, and TypeScript 5.9.3. The Rust proof used two actual Axum handlers registered through `OpenApiRouter`: `GET /api/v1/machines/{id}` and `POST /api/v1/machines`, with path, request, and response DTOs. No proof code or generated client is production code.

| Required evidence | Observed result |
|---|---|
| Reproducible generated OpenAPI | Twenty separate `cargo run --quiet` invocations of the pinned utoipa proof produced 2,201-byte files with the identical SHA-256 `9fd8b510f9a9601cee4e40bb999d8e1914afd64122bf25b197a1c963b29537db`; `cmp` of runs 1 and 20 exited 0. A parallel aide proof also produced one identical SHA-256 across 20 runs. |
| Compiling generated TypeScript client | `npx orval --input openapi.json --output generated/orval/client.ts --client fetch` generated typed `createMachine` and `getMachine` Fetch functions; `npx tsc --noEmit` under strict settings exited 0. A second generation diffed byte-for-byte equal. Hey API's generated SDK and openapi-typescript's generated declarations also compiled in the same project. |
| Loud drift failure | After the checked baseline, adding `serial_number: Option<String>` to the Rust `Machine` response DTO changed the generated schema. `cmp checked-openapi.json regenerated-openapi.json` exited 1, reporting the first difference at byte 2,171/line 98, and the diff showed the new nullable property. FM-006 should implement this as a temporary regeneration plus diff, so a stale checked document fails CI. |
| Fallback exercised | The hand-maintained-document fallback was assessed and rejected because handler-driven generation passed reproducibility, client compilation, and drift detection. Maintaining the same DTO contract twice would add drift risk without solving a failure observed by the spike. |

Maintenance snapshot, verified from the projects' release histories, manifests, registries, and GitHub issue search on 2026-08-26 (open counts exclude pull requests):

| Candidate | Release cadence and open issues | Current Axum tracking | Result |
|---|---|---|---|
| [`utoipa`](https://github.com/juhaku/utoipa) / [`utoipa-axum`](https://github.com/juhaku/utoipa/tree/master/utoipa-axum) | utoipa 5.5.0 on 2026-05-04, 5.4.0 on 2025-06-16, and 5.3.1 on 2025-01-06; [162 open issues](https://github.com/juhaku/utoipa/issues?q=is%3Aissue%20state%3Aopen). The repository was active through 2026-08-24. | The [binding manifest](https://github.com/juhaku/utoipa/blob/master/utoipa-axum/Cargo.toml) requires Axum `0.8.4`, whose compatible range resolved and compiled with current [Axum 0.8.9](https://crates.io/crates/axum/0.8.9). | **Chosen.** It passed 20-run determinism and its `routes!` plus `OpenApiRouter` path registers the handler and documentation together. Explicit operation metadata is straightforward and the stable release is current. |
| [`aide`](https://github.com/tamasfe/aide) | Stable 0.15.1/0.15.0 on 2025-08-19 and 0.14.0 on 2025-01-12; 0.16 remains alpha, with alpha.4 published 2026-04-14; [35 open issues](https://github.com/tamasfe/aide/issues?q=is%3Aissue%20state%3Aopen). | Both the [0.15.1 manifest](https://github.com/tamasfe/aide/blob/release-aide-0.15.1/crates/aide/Cargo.toml) and current alpha accept Axum `0.8.1+`; the stable proof resolved and compiled Axum 0.8.9. | Rejected, not failed. Its real `ApiRouter` proof was also byte-stable across 20 runs, but its last stable line is a year old while the next line remains alpha, and the equivalent operation/status detail needs additional transforms. Utoipa has the stronger current stable integration signal. |
| [`openapi-typescript`](https://github.com/openapi-ts/openapi-typescript) | 7.13.0 on 2026-02-11, 7.12.0 on 2026-02-08, and 7.10.1 on 2025-10-15; [208 open issues](https://github.com/openapi-ts/openapi-typescript/issues?q=is%3Aissue%20state%3Aopen). | Not applicable. | Rejected as the sole generator. Its output was deterministic and compiled, but the package generates TypeScript declarations, not callable client functions. Pairing it with a generic `openapi-fetch` runtime is viable later, but does not satisfy the spike's clearest generated-client outcome as directly as Orval. |
| [`@hey-api/openapi-ts`](https://github.com/hey-api/hey-api/tree/main/packages/openapi-ts) | Stable 0.99.0 on 2026-06-22, 0.98.x on 2026-06-01, 0.97.2 on 2026-05-18, and frequent next builds through 2026-08-24; [493 open issues](https://github.com/hey-api/hey-api/issues?q=is%3Aissue%20state%3Aopen) across the monorepo. | Not applicable. | Rejected, not failed. Its generated Fetch SDK was deterministic and compiled, but the latest stable tool remains pre-1.0 and the exact installed graph produced four high `npm audit` findings through `js-yaml` with no non-breaking fix offered. Re-evaluate after 1.0 and a clean pinned audit rather than selecting that snapshot. |
| [`orval`](https://github.com/orval-labs/orval) | 8.26.0 on 2026-08-23, 8.25.0 on 2026-08-21, and six more stable releases from 2026-06-24 through 2026-08-08; [56 open issues](https://github.com/orval-labs/orval/issues?q=is%3Aissue%20state%3Aopen). | Not applicable. | **Chosen.** The pinned stable release generated a compact, dependency-free Fetch client whose strict TypeScript compilation and repeated-output diff both passed. The separately tested pinned graph did not contribute an npm audit finding. |

Primary-source commands used for the snapshot were GitHub's repository/releases and `type:issue state:open` search APIs, `cargo info` plus the candidates' published Cargo manifests, and npm package metadata. Counts and advisories are point-in-time maintenance signals, not quality scores; refresh them when FM-006 updates a pin.

Recommendations:

- Axum/Tokio/Tower fit the shared HTTP/SSE/WSS runtime.
- SQLx with SQLite fits the declared initial deployment and keeps SQL visible/testable.
- Evaluate Effectum for worker scheduling/retry, but keep Fleet Operation/Lab records as domain state and prove database/transaction/recovery behavior before adoption.
- Spike Cedar using the real permission/resource/tag/project policies. Cedar is default-deny and supports permit/forbid plus RBAC/ABAC, but policy management complexity should be measured before commitment. OpenFGA is a later multi-tenant/relationship option and would add another service too early.
- Use `secrecy`/`zeroize`-style secret wrappers and a reviewed AEAD/key-rotation design; crate selection belongs to the M1 threat-model issue.

### MCP

Source: [current Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization).

Decision: use the maintained Rust MCP SDK/server stack available during M8, not a handwritten JSON-RPC implementation copied from Purple. HTTP MCP must use protected-resource metadata and OAuth discovery/PKCE requirements current at implementation. Fleet authorization still decides each tool/resource; MCP authorization is transport authentication/delegation, not the domain policy.

## Approaches explicitly rejected

- Portainer-like Docker management or direct unauthenticated Docker TCP
- Rebuilding Skills Manager presets/agent adapters/update/Git sync
- Direct edits to Frogenv config, recipient, key, or encrypted-env internals
- A DevPod fork or Fleet-specific devcontainer implementation
- Fleet dotfile templating instead of chezmoi
- Browser/desktop testing engines inside Fleet
- A full Ansible/Nix replacement expressed through Fleet recipes
- A generic plugin SDK before internal provider contracts stabilize
- A young Proxmox crate adopted without a real compatibility/TLS spike
