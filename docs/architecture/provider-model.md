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
