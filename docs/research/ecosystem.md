# Ecosystem research and integration recommendations

Research date: 2026-08-25. Prefer linked upstream documentation/repositories over this summary when implementing. Re-run the relevant spike at milestone start because versions and public contracts will change.

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

The current `src/skillsBackend.js` is not this integration. Its default `skills install` command matches neither Skills Manager (`skills-manager-cli skills install`) nor the separate skills.sh CLI (`npx skills add`). Preserve its tests only as migration evidence and replace it in M3.

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
