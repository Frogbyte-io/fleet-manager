# Proxmox fleet + cross-machine skill/secret sharing — design

Status: approved by user 2026-08-22. Implements
[Andreas-Froyland/agents-registry#3](https://github.com/Andreas-Froyland/agents-registry/issues/3)
on top of the foundation from #2.

## Goals

- Stand up a real Proxmox host (`<pve-host-ip>`, PVE 9.2.2) as the fleet's
  VM host for the four machines already declared in `machines/`.
- Split the current single repo into a reusable engine + per-fleet data, so
  the tool works for fleets beyond this one homelab.
- Share secrets (starting with the Proxmox API token) across machines via
  frogenv instead of local `.env` files.
- Keep the existing pull-based sync model (machines converge to declared
  state on a timer); no new push/deploy mechanism.

## Repo topology

| Repo | Owner | Contents |
|---|---|---|
| `fleet-manager` | Frogbyte-io | Engine: CLI (`bin/agents-registry.js`), schema/resolve/validate (`src/`), Proxmox adapter, sync mechanics, tests, docs/schema.md, bootstrap skill. No machine-specific data. Published to npm as `@frogbyte-io/fleet-manager` (public). |
| `fleet` | Frogbyte-io | This homelab's data: `AGENTS.md`, `machines/`, `roles/`, `packs/`, `devices/`, `projects/`, `test-profiles/`, `context/`. |
| `fleet-secrets` | Frogbyte-io | frogenv-managed encrypted secret store. Nothing but `.enc.env` files, `frogenv.yaml`, `.sops.yaml`, `keys/`. |

`agents-registry` (`Andreas-Froyland/agents-registry`) is transferred to
`Frogbyte-io/fleet-manager`, preserving history/issues. The CLI verb stays
`agents-registry` (renaming it isn't in scope).

## Distribution model

`fleet-manager` is consumed via `npx @frogbyte-io/fleet-manager <command>` —
no local clone, no update timer for the engine itself; npx always resolves
the current published version. A new `fleet-manager init` command:

1. Clones (or updates) the `fleet` data repo to a local path.
2. Writes `~/.config/fleet-manager/config.yaml` (Windows:
   `%APPDATA%\fleet-manager\config.yaml`) with `registry_path: <path>`,
   which every subsequent command reads (overridable with `--registry` or
   `FLEET_REGISTRY_PATH`).
3. Registers the machine with frogenv (`frogenv machine request`).

Only the `fleet` repo needs a real local clone + the existing 30-minute
sync timer (`git pull` + `agents-registry sync`, now invoked as
`npx @frogbyte-io/fleet-manager sync`).

## Secrets (frogenv on `fleet-secrets`)

Groups, mapped to path globs in `frogenv.yaml`:

- `workstation` — the 3 physical boxes (`ananords-dev`, `bazzite-dotx-dev`→
  retired/re-provisioned, `windows-dev`). Gets everything.
- `vm-test` — ephemeral test VMs. No secrets by default; opt-in per-secret
  if a test ever needs one.
- `infra` — Proxmox API token and other infrastructure credentials.
  Workstation-only, since only workstations run the Proxmox adapter.

The Proxmox token moves from this repo's `.env` (which is deleted) to
`fleet-secrets` at `projects/proxmox/infra.enc.env`, consumed via
`frogenv env run fleet infra -- <command>`.

Bootstrapping frogenv (admin key ceremony, first machine approval) is a
manual, security-sensitive step the user performs directly — see
`docs/proxmox-fleet-manual-steps.md` §7.

## Proxmox adapter (`fleet-manager/src/proxmox/`)

- HTTPS client using `PVEAPIToken` auth (`<token-id>`), TLS pinned to
  the host's certificate fingerprint (`DC:2C:11:6E:...:64:98`).
- Wraps: clone, reset (snapshot rollback or re-clone), start, stop,
  snapshot, template conversion. Proxmox mutating calls return a UPID;
  the adapter polls `/nodes/<node>/tasks/<upid>/status` to completion
  rather than assuming synchronous completion.
- Wires `lifecycle.mode/reset_strategy/base_template` (already in the
  schema, see `docs/schema.md`) to these real calls. `agents-registry
  status` reports real power state instead of the current hardcoded
  `unmanaged`.
- `dev-01` (`lifecycle.mode: persistent`) is created directly as a normal
  VM — no template/clone/reset lifecycle applies to it.

## Golden-image workflow

ISOs uploaded to the `local` storage (94GB free, already has
`iso`/`vztmpl`/`backup` content types enabled). For each of `test-ubuntu`,
`test-bazzite`, `test-windows`: create VM → interactive install via
Proxmox console (user-driven, see manual-steps doc) → (Windows only)
sysprep generalize → shutdown → convert to template matching the
`base_template` name already declared in the manifest
(`ubuntu-desktop-24.04-v2`, `bazzite-test-v1`, `win11-test-v1`).

VM specs: `test-bazzite`/`test-ubuntu`/`dev-01` get 2 cores / 4GB / 40GB
(no existing override in their manifests). `test-windows` keeps its
existing manifest override (8 cores / 16GB / 100GB).

## USB device passthrough

`decker-controller` (`vendor_id: "2341"`, `product_id: "8036"`, an
Arduino) is wired through Proxmox's USB passthrough API once physically
connected to the host — it wasn't present in the last USB inventory scan.
Blocked on the user connecting it (manual-steps doc §6).

## Network prerequisite

The host has no `vmbr*` bridge — its only interface (`nic0`, altname
`enxa8a159157f99`) is a USB Ethernet dongle. A bridge must exist before any
VM gets LAN access. Given this is the host's only network path and it has
no IPMI/iKVM, this is called out as a manual, physical-console-standby step
rather than something automated remotely (manual-steps doc §3).

## Out of scope / risks carried forward

- frogenv's npm package has only `0.1.0` published while its repo is at
  `0.2.0` (missing `ci approve` and possibly other commands). Bootstrap
  will use a local/git build of frogenv rather than trusting `npx frogenv`
  if 0.2.0-only behavior is needed, until 0.2.0 is actually published.
- `bazzite-dotx-dev`'s registry entry in `AGENTS.md` is stale — the host at
  that IP was reimaged to Proxmox (confirmed via mismatched SSH host key
  fingerprint). Needs to be removed/updated as part of the `fleet` repo
  migration.
- No CI/CD or auto-approval workflow for frogenv is in scope here beyond
  what's needed to bootstrap the three workstations.
