# fleet-manager

The engine behind a declarative fleet/machine/skill registry: machine manifests, role
inheritance, registry-owned skill packs, capability metadata, a Proxmox VM lifecycle
adapter, and the `agents-registry` CLI that resolves and reconciles all of it.

This repo is the **engine only** — no machine-specific data lives here. Your actual
fleet (machines, roles, packs, devices, projects, test profiles, and the
`AGENTS.md` SSH allowlist) lives in a separate data repo that you point this engine
at.

## How it's wired up

- **This repo (`fleet-manager`)** — the CLI and all resolution/validation/Proxmox logic.
  Published to npm as `@frogbyte-io/fleet-manager`; run it via `npx @frogbyte-io/fleet-manager <command>`
  with no local clone needed.
- **A data repo** (e.g. `Frogbyte-io/fleet`) — your `AGENTS.md`, `machines/`, `roles/`,
  `packs/`, `devices/`, `projects/`, `test-profiles/`, `context/`. This is the repo
  Codex CLI and Claude Code read machine/SSH-trust context from, and the one
  `agents-registry sync` reconciles each machine against.
- **A secrets repo** (e.g. `Frogbyte-io/fleet-secrets`) — encrypted, per-machine
  secret sharing via [frogenv](https://github.com/Frogbyte-io/frogenv) (Proxmox API
  tokens and similar credentials never live in either repo above in plaintext).

## First-time setup on a new machine

Until `@frogbyte-io/fleet-manager` is published to npm, clone this repo and run
`node bin/agents-registry.js <command>` in place of `npx @frogbyte-io/fleet-manager <command>`
everywhere below.

```bash
npx @frogbyte-io/fleet-manager init --repo-url <your-data-repo-url> [--path <dir>]
```

This clones (or pulls, if already cloned) your data repo and writes
`~/.config/fleet-manager/config.yaml` (`%APPDATA%\fleet-manager\config.yaml` on
Windows) so every later command knows where your registry lives, without needing
`--root` every time.

```bash
npx @frogbyte-io/fleet-manager status
npx @frogbyte-io/fleet-manager resolve <machine-id>
npx @frogbyte-io/fleet-manager sync
```

Registry root resolution order: `--root <dir>` flag > `FLEET_REGISTRY_PATH` env var
> the config file `init` wrote. If none are set, commands fail with a message
telling you to run `init`.

## Staying in sync automatically

Set up a recurring `git -C <data-repo-path> pull --ff-only && npx @frogbyte-io/fleet-manager sync`
on a timer (systemd user timer on Linux/macOS, Scheduled Task on Windows) so each
machine converges to your data repo's declared state without you having to log
back in. (The data repo itself may ship its own setup scripts for this — check its
README.)

## Fleet, roles, skill packs, and the Proxmox adapter

- Full schema and CLI reference: `docs/schema.md`
- Bootstrap rules for agents working with the registry: `bootstrap/fleet-bootstrap/SKILL.md`
- Design/implementation history: `docs/superpowers/specs/`, `docs/superpowers/plans/`

```bash
npm install
npm test
```

## Security notes

- This repo contains **no private keys, passwords, tokens, or machine-specific
  data** — that all lives in your separate data and secrets repos.
- Live Proxmox VM lifecycle (`src/proxmox/`) authenticates via `PROXMOX_HOST`,
  `PROXMOX_TOKEN_ID`, `PROXMOX_API_KEY`, `PROXMOX_FINGERPRINT` environment
  variables — never hardcode these; source them from your secrets repo (e.g. via
  `frogenv env run`).
