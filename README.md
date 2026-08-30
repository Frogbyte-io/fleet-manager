# fleet-manager

> **Architecture transition:** Fleet Manager is being redesigned as a persistent,
> controller-first developer fleet control plane. The canonical roadmap is
> [docs/PLAN.md](docs/PLAN.md), accepted on 2026-08-25 along with
> [the ADR set](docs/adr/README.md). The Node.js `agents-registry` described below is the
> **legacy** proof of concept and migration input; it is not the target controller/node/web
> architecture. No product features from the new plan have been implemented yet.

The legacy engine behind a declarative fleet/machine/skill registry: machine manifests, role
inheritance, registry-owned skill packs, capability metadata, a Proxmox VM lifecycle
adapter, and the `agents-registry` CLI that resolves and reconciles all of it.

Its preserved package now lives under
[`legacy/agents-registry/`](legacy/agents-registry/). See the
[deletion parity checklist](legacy/agents-registry/DELETION.md) for the conditions
that must be met before removing it.

This repo is the **engine only** — no machine-specific data lives here. Your actual
fleet (machines, roles, packs, devices, projects, test profiles, and the
`AGENTS.md` SSH allowlist) lives in a separate data repo that you point this engine
at.

## How it's wired up

- **The legacy package (`legacy/agents-registry/`)** — the CLI and all
  resolution/validation/Proxmox logic.
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
`node legacy/agents-registry/bin/agents-registry.js <command>` in place of
`npx @frogbyte-io/fleet-manager <command>`
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
- Master plan and architecture: `docs/PLAN.md` (accepted), `docs/adr/`, `docs/planning/`
- Bootstrap rules for agents working with the registry: `bootstrap/fleet-bootstrap/SKILL.md`
- Design/implementation history: `docs/superpowers/specs/`, `docs/superpowers/plans/`
- Web GUI design system: `DESIGN.md` (agent rules: `bootstrap/fleet-console-labs/SKILL.md`)

```bash
npm --prefix legacy/agents-registry ci
npm --prefix legacy/agents-registry test
npm run check:docs
```

## Repository verification

After installing the pinned tools described in
[`.github/toolchain-policy.md`](.github/toolchain-policy.md), run the same root
verification command used by CI:

```bash
cargo xtask verify
```

It checks Rust formatting, linting, and tests, then installs the pnpm workspace
from its lockfile and runs every package's lint, type-check, and build scripts.
The command stops at the first failed step and prints the exact failing command.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party source
copied into this repository must be attributed in `NOTICE` under its own terms.

## Security notes

- This repo contains **no private keys, passwords, tokens, or machine-specific
  data** — that all lives in your separate data and secrets repos.
- Live Proxmox VM lifecycle (`legacy/agents-registry/src/proxmox/`) authenticates via `PROXMOX_HOST`,
  `PROXMOX_TOKEN_ID`, `PROXMOX_API_KEY`, `PROXMOX_FINGERPRINT` environment
  variables — never hardcode these; source them from your secrets repo (e.g. via
  `frogenv env run`).
