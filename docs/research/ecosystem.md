# Ecosystem research and integration recommendations

Research date: 2026-08-25; FM-S01 refreshed 2026-08-26; FM-S10 refreshed 2026-09-25. Prefer linked upstream documentation/repositories over this summary when implementing. Re-run the relevant spike at milestone start because versions and public contracts will change.

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

#### FM-S10: Skills Manager v1.40 contract refresh

Research date: 2026-09-25. Compared the released [v1.34.2](https://github.com/xingkongliang/skills-manager/releases/tag/v1.34.2) baseline with [v1.40.0](https://github.com/xingkongliang/skills-manager/releases/tag/v1.40.0), published 2026-09-17. Inspected the versioned [README](https://github.com/xingkongliang/skills-manager/blob/v1.40.0/README.md), [CLI implementation](https://github.com/xingkongliang/skills-manager/blob/v1.40.0/src-tauri/src/bin/skills-manager-cli.rs), [skills command implementation](https://github.com/xingkongliang/skills-manager/blob/v1.40.0/src-tauri/src/commands/skills.rs), [agent instructions](https://github.com/xingkongliang/skills-manager/blob/v1.40.0/skills/manage-skills/SKILL.md), [changelog](https://github.com/xingkongliang/skills-manager/blob/v1.40.0/CHANGELOG.md), and release API assets. Both releases identify the project as MIT in its upstream license metadata.

Evidence:

- Downloaded both Linux x64 release binaries and verified their SHA-256 digests against the release asset metadata. `--version`, command help, and a malformed JSON-mode `skills deploy` invocation were executed on both. The command help matched for the relevant `skills` and `presets` operations; error JSON had the same `{ ok: false, code, message, error }` envelope and exit code 2. Captures are in [`docs/research/fixtures`](fixtures/).
- The relevant CLI surface is already present at v1.34.2: `skills install`, `update`, `check`, `show`, `export`, `deploy`, `undeploy`, `status`, `set-source`, and preset operations. v1.40.0 preserves it. Later release changes relevant to an adapter include publishing a desktop-managed CLI copy with a version stamp (v1.36), structured target-conflict details, local source re-import/update safety, and expanded Linux ARM64 release builds. The upstream agent skill resolves the desktop-published copy for that desktop user's environment; Fleet's service provider should use an explicitly configured binary and verify its `--version`, since a service account may not share that desktop installation. Server-only deployments can use the standalone release binary.
- Local updates are a documented contract: `skills install <local-directory> --local` copies the source into the central library and records the source path; `skills update <ref>` re-imports `local`/`import` skills from that recorded path. The implementation leaves source reference, id, tags, preset membership, and deployment records in place, then refreshes deployed copies. `skills update --all` is also supported. Missing source directories return an error.
- Update replacement stages a new directory before swap. If the source no longer contains paths present in the current library/deployments, the command leaves state unchanged and returns `held_back_removals`; there is no CLI approval flag. Files that still exist at the same relative path can be overwritten, including local edits. The `manage-skills` instructions document both cases. Fleet therefore must keep the staging tree canonical and treat catalog versions as authoritative; it must surface held-back removals as a blocked rollout for human resolution instead of retrying.
- `skills show --json` includes `markdown` (the central `SKILL.md` text), `skill_file`, a file list, and absolute central/target paths. `skills export --dest` can write a full skill directory to an explicit destination. The CLI can read content, though it does not provide a stable generic JSON bundle for every file. These fields are unnecessary for FM-920 (which explicitly excludes reading machine-local skill content) or FM-922 (whose authored source lives in Fleet). Do not add an upstream content API request for those scopes; if Fleet later needs source browsing, specify a bounded, path-neutral contract first.
- v1.40.0 publishes `skills-manager-cli-Linux-x64` and `skills-manager-cli-Linux-arm64`; its release notes report Linux x64 and Linux ARM64 builds. The v1.34.2 release had only a Linux x64 CLI asset. Fleet's stated primary node baseline is Linux x86_64; ARM64 availability is verified as a release artifact, but this spike did not execute the ARM64 binary and does not move Fleet's platform-support gate.

Decision: the existing documented CLI supports FM-922's staged local-source rollout; Fleet does not need to write the Skills Manager library or database. Keep Fleet-authored content and immutable version digests in Fleet's own catalog. Install once from a stable Fleet-owned staging directory; for later versions, atomically replace that staged version and call `skills update` on the existing skill, then verify with `skills show`/`skills status`. Handle `held_back_removals` explicitly. Do not consume `show`'s machine-local content or absolute paths in the read model. Start the provider at exact version `=1.40.0`, verify the published SHA-256, and refresh fixtures before broadening the accepted range. The older v1.34.2 binary is comparison evidence, not the supported minimum.

The captures are candidate provider fixtures, not a promise that every upstream version shares byte-identical output: [v1.34.2 help](fixtures/skills-manager-cli-v1.34.2-help.txt), [v1.34.2 argument error JSON](fixtures/skills-manager-cli-v1.34.2-invalid-argument.json), [v1.40.0 help](fixtures/skills-manager-cli-v1.40.0-help.txt), and [v1.40.0 argument error JSON](fixtures/skills-manager-cli-v1.40.0-invalid-argument.json). Versioned source and release metadata are the primary references when adapting the provider.

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

#### FM-S08: Proxmox client compatibility spike

Decision (2026-09-20): **fallback chosen — a small `reqwest` transport plus typed provider DTOs with a custom rustls fingerprint-pinning verifier.** The spike tested the leading typed crate against the live PVE 9.2 integration host (`fleet-test-01`'s PVE node, `pve.localdomain`, PVE 9.2.2/repo `b9984c6d90a4bd80`) and inspected its source; the decisive failure is TLS, which is a security gate, not a feature gap.

Evidence from a disposable probe project (outside this repository), Rust 1.98 toolchain:

| Required evidence | Observed result |
|---|---|
| Authentication | [`proxmox-client` 0.9.2](https://crates.io/crates/proxmox-client) API-token auth worked live (`PVEAPIToken` header) — version, cluster resources, node list, QEMU list/status, task list, task status, and a real `qmreboot` UPID round-trip all passed. Auth is a builder string; no secret-wrapper integration, but that is adapter work either way. |
| TLS trust and pinning | **Failed, decisively.** The builder's entire TLS surface is `accept_invalid_certs(bool)`, which maps to reqwest's `danger_accept_invalid_certs`. There is no fingerprint-pinning hook, no custom root store, no `use_preconfigured_tls` passthrough. The PVE host uses its own cluster CA (`PVE Cluster Manager CA`), so system-trust verification fails (`unable to get local issuer certificate`), meaning the only working configurations are "disable verification" — forbidden by the spike rules and the security policy — or nothing. |
| UPID task polling | Worked: `get_task_status` with `is_running()`/`is_ok()`, plus `stop_task` and `get_task_log`. Gaps: the caller receives a raw `String` UPID and must parse `node`/`type`/`id` out of it itself (the `Upid` newtype has no parsing helpers), and there is no built-in wait/poll helper — Fleet owns the deadline/timeout loop (which is what it wants anyway, to avoid the legacy `waitForTask` wall-clock flake). |
| Unknown-field tolerance | Good: zero `deny_unknown_fields` across the crate, all response fields `Option`-typed, the `{"data": ...}` envelope unwraps cleanly including `data: null`, and `VmConfig` preserves indexed params (`net0`, `scsi0`, …) in a flattened `extra` map. Live agent responses (loose QGA shapes) parsed fine. |
| Cancellation | Weak: per-request timeouts and an overall client timeout only; no request-cancellation surface (Fleet owns cancellation by dropping futures, as with any reqwest stack). |
| Endpoint coverage | Broad — QEMU/LXC lifecycle, snapshots, config, agent (26 agent methods), cluster resources/tasks, storage, tasks, access, pools. Everything M6's first three epics need is present or trivially reachable. |
| Maintenance and supply chain | Unhealthy for a dependency Fleet must trust: 3 commits ever (all 2026-03-17/18), **zero GitHub stars, 591 total downloads / 29 recent, 3 releases in one week**, one open issue, no README feature list beyond "experimental". MIT (inbound-compatible). Requires reqwest ^0.13.2 whose default TLS is aws-lc-rs — a second TLS backend (the workspace standardizes on reqwest 0.12 + ring) plus a second reqwest major in one graph. `cargo deny check licenses/bans` pass, but the crates.io weight is a single-maintainer zero-adoption snapshot. |
| Fallback exercised | A probe implemented the fallback's decisive risk — fingerprint pinning over plain reqwest — and passed it live: a custom `rustls::client::danger::ServerCertVerifier` that SHA-256-hashes the leaf certificate and compares it to the pinned fingerprint connected successfully to the real host, and a wrong fingerprint was refused at the TLS handshake (`is_connect() == true`). Verification is never disabled; an unpinned host is refused until an authorized trust step pins it, mirroring the FM-201 SSH TOFU flow. The whole fallback probe used reqwest 0.12 + rustls `ring` — the same TLS stack the tailscale provider already uses — so no new transport dependency class, no duplicated reqwest major, no aws-lc-rs. |

The second candidate inspected, [`proxmox-api` 0.2.0](https://github.com/datdenkikniet/proxmox-api) (schema-generated types, 4.5 MiB of generated code, 32-crate graph, Apache-2.0/MIT, 6 stars), was rejected faster: its default reqwest client hardcodes `danger_accept_invalid_certs(true)`, its Debug output prints the raw API token (no redaction), and its ergonomic surface (typed `VmId(i128)` wrappers, mandatory params structs even for empty GETs, `Option<Vec<_>>` unwrapping) adds friction without solving the same TLS gate. The official `proxmox-rs` workspace crates remain internal/build-time oriented and do not provide a usable PVE automation client.

Consequence for M6: build `fleet-provider-proxmox` on a small `reqwest` 0.12 transport with the pinned-fingerprint rustls verifier (shared trust workflow modeled on FM-201's SSH pin/decide/confirm), typed provider DTOs translating at the boundary, and Fleet-owned UPID parsing, polling loops, and deadlines. Recorded/simulated fixtures plus the dedicated real-cluster suite (epics #10–#12) carry the PVE 8.x/9.x compatibility matrix.

**Recorded deviation against the FM-000 acceptance criterion** ("FM-S08 must produce evidence against both majors; passing on one major is not a pass"): only PVE 9.2.2 was reachable live — the integration environment has a single PVE host and no 8.x node. The 8.x half of the evidence is static, not live: the [PVE 8.x API documentation archive](https://pve.proxmox.com/pve-docs-8/api-viewer/apidoc.js) (verified to be the 8.x generation — it lacks the 9.x-only `sdn/fabrics` endpoints) documents every endpoint the spike exercised, with the same `PVEAPIToken` authentication and `exitstatus` task-status shape. The spike's decisive evidence is TLS behavior, which is client-side and version-independent — the crate's `accept_invalid_certs(bool)` surface cannot pin fingerprints against any PVE major. The client choice is therefore recorded with the deviation named, and the live 8.x leg moves to the M6 real-cluster suite (epics #10–#12), which must validate a PVE 8.x host before Fleet claims 8.x support; that limitation is recorded on epic #9.

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

#### FM-007: protobuf compilation without `protoc`

Decision (2026-08-31): compile the node protocol source with [`protox` 0.9.1](https://crates.io/crates/protox/0.9.1), a pure-Rust protobuf compiler, and generate Rust types from its descriptor set with [`prost-build` 0.14.4](https://crates.io/crates/prost-build/0.14.4) using `skip_protoc_run()`, on the [`prost` 0.14.4](https://crates.io/crates/prost/0.14.4) runtime. Building Fleet Manager therefore requires no `protoc` binary anywhere. This chooses tooling inside ADR-0002 and ADR-0003 and changes neither.

FM-007 posed the choice as vendored `protoc` versus a documented toolchain prerequisite. Both were rejected in favour of the pure-Rust compiler:

| Option | Result |
|---|---|
| `protox` + `prost-build` with `skip_protoc_run()` | **Chosen.** Verified on a machine with no `protoc` installed: a disposable project outside this repository compiled a `.proto` file and round-tripped an encode/decode through the generated types. `cargo metadata --all-features` over that graph reported 59 dependency crates, every one declaring a license already in the allow table generated from `.github/dependency-policy.md`, so no per-crate exception is needed. |
| [`protoc-bin-vendored`](https://crates.io/crates/protoc-bin-vendored) | Rejected. It ships a prebuilt `protoc` per platform: a second supply chain outside the Cargo advisory and yank mechanisms, and a per-target artifact for both baseline targets in `deny.toml`. |
| [`protobuf-src`](https://crates.io/crates/protobuf-src) | Rejected. It builds `protoc` from C++ source, adding a C++ toolchain to CI, to the controller image, and to every contributor's machine, and slowing cold builds for one build-time step. |
| Documented `protoc` prerequisite | Rejected. A clean checkout would fail to build for a reason no lockfile can fix, and the failure would differ per platform and per installed `protoc` version — the class of problem pinned toolchains exist to remove. |

The consequence to keep in mind is that prost *ignores* unknown fields rather than preserving them across a decode/encode cycle. That is sufficient for peers that consume frames, which is all FM-007 defines; it would not be sufficient for a relay that re-encodes a frame it does not fully understand, and `proto/README.md` records that limit.

Recommendations:

- Axum/Tokio/Tower fit the shared HTTP/SSE/WSS runtime.
- SQLx with SQLite fits the declared initial deployment and keeps SQL visible/testable.
- Evaluate Effectum for worker scheduling/retry, but keep Fleet Operation/Lab records as domain state and prove database/transaction/recovery behavior before adoption.
- Spike Cedar using the real permission/resource/tag/project policies. Cedar is default-deny and supports permit/forbid plus RBAC/ABAC, but policy management complexity should be measured before commitment. OpenFGA is a later multi-tenant/relationship option and would add another service too early.
- Use `secrecy`/`zeroize`-style secret wrappers and a reviewed AEAD/key-rotation design; crate selection belongs to the M1 threat-model issue.

### MCP

Source: [current Model Context Protocol authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization).

Decision: use the maintained Rust MCP SDK/server stack available during M8, not a handwritten JSON-RPC implementation copied from Purple. HTTP MCP must use protected-resource metadata and OAuth discovery/PKCE requirements current at implementation. Fleet authorization still decides each tool/resource; MCP authorization is transport authentication/delegation, not the domain policy.

### Image building: Packer and the Proxmox plugin

Sources: [Packer releases](https://github.com/hashicorp/packer/releases), [packer-plugin-proxmox](https://github.com/hashicorp/packer-plugin-proxmox), [the BUSL license text](https://www.hashicorp.com/bsl), the plugin's builder sources and cleanup step, and a live probe against the integration PVE 9.2 host (Packer 1.16.1, plugin 1.2.4).

Findings:

- Packer 1.16.1 (2026-09-18) is the current stable; releases are steady (1.16.0 2026-07, 1.15.4 2026-06). HCL2 `.pkr.json`/`.pkr.hcl` is the standard format; `packer validate` and `packer build -machine-readable` work as documented.
- The Proxmox plugin (`packer-plugin-proxmox` v1.2.4, MPL-2.0, actively maintained by HashiCorp — pushed 2026-09-07) covers both `proxmox-iso` and `proxmox-clone` builders with every field Fleet needs: node, VMID ranges, storage pools, network bridge, cloud-init (`ciuser`, `sshkeys` as URL-encoded key text — the FM-211 lesson holds: the API path for `sshkeys` rejects values, but Packer's builder injects them through the VM config where they work), additional ISO files, and template conversion.
- Machine-readable output is a line-oriented `timestamp,target,type,data…` format on stdout with `ui`/`artifact`/`version` message types and `%!(PACKER_COMMA)` escaping — stable, documented, and awk-friendly. Verified live: `packer -machine-readable version` emits the documented `version`/`version-prelease`/`version-commit` lines.
- **Cancellation and cleanup are the plugin's job and it does them**: `stepStartVM.Cleanup` stops and deletes the VM it created on any failure path (with an explicit "delete it manually" error if the delete itself fails). Verified live: a `proxmox-clone` build that timed out waiting for SSH stopped and deleted its VM; the host's resource list showed no orphan.
- **Licensing**: Packer is BUSL 1.1 with a four-year change date to MPL 2.0. The Additional Use Grant permits production use unless Fleet is offered to third parties as a hosted or embedded *competitive offering* — a self-hosted infrastructure controller invoking an operator-installed Packer binary is squarely inside the grant. Fleet must not bundle or redistribute the Packer binary (that would be embedding); the operator installs it, exactly as the recorded fallback says. The plugin is MPL-2.0 and enters the allowed inbound set.
- **One integration trap, found live**: `proxmox_url` must include `/api2/json` (the plugin does not append it). Without it the Telmate client requests `/cluster/resources` instead of `/api2/json/cluster/resources` and PVE answers `500 no such file '/cluster/resources'` — a confusing error that looks like a permission problem but is a path problem. Fleet's recipe editor must always render the full URL, and its probe must check this shape.
- The plugin's Telmate client is pinned to an Oct-2024 commit while upstream `proxmox-api-go` is active (Sept 2026) and carries open PVE-9 issues; the plugin works on PVE 9.2 for the paths it exercises (verified live through clone/create/start/cleanup), but the pin is a supply-chain fact to re-verify when PVE 10 arrives.

Decision (2026-09-22): **fallback confirmed — Fleet requires an operator-installed Packer CLI and never bundles it.** The image-build provider invokes `packer` through the documented CLI with `-machine-readable` output, pins `packer >= 1.15 < 2` and `proxmox >= 1.2.4 < 2` with checksum verification, and keeps the image-build port available for another implementation. The version range and the `/api2/json` URL contract are the pinned integration facts; the BUSL review is recorded with no bundling. Scope: like FM-S08, this spike exercised only PVE 9.2 live; PVE 8.x must be validated on a real host before Fleet claims 8.x support for the image-build provider.

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
