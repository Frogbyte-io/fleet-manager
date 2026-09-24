# M9 — Fleet Console v2 and fleet-wide skills

Status: proposal — layout decisions confirmed 2026-09-24 (see "Decisions"); not yet folded into `PLAN.md`
Prepared: 2026-09-24
Mockups: [`docs/design/web-console/mockups/`](../design/web-console/mockups/index.html) (static HTML, open `index.html`)

## Goal

Replace the single-column M1–M3 panel shell in `apps/web` with a full web console for the whole fleet: Proxmox hosts, VMs/LXCs, physical devices (Raspberry Pis, desktops, laptops), tailnet devices, projects, Lab, and controller settings. It should feel like a fleet manager: at a glance you should see what exists, where it runs, how Fleet reaches it, and what needs attention.

The console stays an **adapter**. It has no business logic, and it shows only what the API (and so `fleetctl --output json`) can also report. Every mutation goes through the existing authorized, audited API.

## Relationship to existing plans and issues

Checked 2026-09-24: all M0–M5 issues are closed; the open issues are the M6 epics #9–#12 and M7 epics #13–#16 and #109 (backend Proxmox/Lab work, code-complete pending live acceptance). No open issue covers a web app or fleet-wide skills, so this is a **new milestone (M9) with new epics** rather than an expansion of existing issues. Existing items that change:

- **#15** (Lab CLI/project linkage/artifacts): its scope item "web presentation of active leases and their expiry" moves to FM-930.
- **#109** (image recipes): its remaining "web editor slice" moves to FM-932.
- **FM-302 (#79)**: its deferred Markdown-editing goal is superseded by FM-922 (Fleet-authored skills) and FM-S10 (upstream content contract).
- **`bootstrap/fleet-bootstrap`**: replaced by the official `fleet` skill (FM-924).
- **PLAN.md "Later"**: the command palette and bulk actions are pulled into M9 as FM-951/FM-952.

M9 depends only on landed work (M1 API/operations, M2 machines/tailnet, M3 skills provider, M4 planner/apply, M6 Proxmox, M7 Lab APIs). It may run in parallel with the M6/M7 real-host acceptance runs.

## Stack decision (proposed)

| Concern | Choice | Notes |
|---|---|---|
| Framework | Vue 3.5 + TypeScript (existing) | |
| Components | **shadcn-vue** (Reka UI primitives, copied into `apps/web/src/components/ui`) | Tailwind v4 is already in place. The components are source code we own, not a runtime theme dependency. |
| Theme | DESIGN.md tokens mapped onto shadcn CSS variables (`--background`←`--bg`, `--card`←`--panel`, `--border`←`--line`, `--primary`←gradient CTA, `--radius`←2px) | **Dark by default**; light is a full citizen; `localStorage["fleet-console-theme"]` + `?theme=`. |
| Routing | `vue-router` | One route per sidebar entry plus detail routes (`/fleet/:machineId`, `/lab/leases/:id`, …). |
| Server state | `@tanstack/vue-query` over the generated `@frogbyte-io/fleet-api-client` | Cache plus invalidation from SSE events; never hand-copy DTOs. |
| Tables | `@tanstack/vue-table` (the shadcn-vue data-table pattern) | |
| Icons | `lucide-vue-next` | |
| Utilities | `@vueuse/core` (color mode, keyboard, intervals) | |
| Code editor | CodeMirror 6 (`.pkr.json` raw editor, AGENTS.md editing) | Needed later, in the Images phase. |

All of these are MIT/ISC and must pass `.github/scripts/check-licenses.mjs`. None of them is a package, config, or secrets manager, so no ADR is needed under AGENTS.md. We should still record the stack in an `apps/web/README.md` update.

**DESIGN.md needs a revision pass** before implementation:
- Its vocabulary is the legacy `agents-registry` (Sync Queue, RESOLVE, roles/packs, RUNNING/STOPPED). Move it to controller terms: `connected/stale/offline/agentless` machine status, PVE guest status, lease states, operations/apply.
- Replace the 72px sticky nav and marketing-style hero with the app shell: sidebar + 56px topbar + page header.
- Decide the corner radius (sharp 2px per DESIGN.md vs soft Coolify-style; the mockups toggle between them).
- Map tokens to shadcn-vue variable names.

## App shell

- **Sidebar** (collapsible to icons, persisted), grouped:
  - Overview
  - *Infrastructure*: Fleet · Proxmox · Tailnet · Containers (M5)
  - *Work*: Projects · Skills · Lab · Images
  - *Control*: Operations (running/blocked count badge) · Audit log · Settings
  - Footer: controller readiness, version, **trusted-LAN warning**
- **Topbar**: breadcrumb, global search / **⌘K command palette** (already listed under "Later" in PLAN.md; pulled forward here), global **+ Add** button, live-connection indicator.
- **Activity tray**: running operations with progress. Every mutation returns an operation id, and a toast links to it.
- **"Copy as fleetctl"** on every form and action. This reinforces the "UI == CLI" rule and teaches agent workflows.

## Pages and features

### Overview (dashboard)
- KPI strip: connected / agentless / offline-stale / Lab leases / running operations.
- **Needs attention queue**: offline or stale machines, `cleanup_failed` leases, `blocked_manual_approval` operations, changed Proxmox TLS fingerprints, pending onboarding drafts, drift (M4), stale Lab template pins, expiring leases.
- Recent activity feed (operations + audit), live.
- Capacity snapshot per Proxmox node (CPU/mem/storage, Lab-reserved share).

### Fleet (machines, servers, VMs, devices) — decision 1
One inventory over three sources, joined by evidence:
1. **Fleet machines** (SSH/fleetd)
2. **Proxmox resources** (nodes, QEMU, LXC, templates)
3. **Tailnet devices**

Each item shows:
- **What it is**: kind = Proxmox node / VM / LXC / Lab VM / board / desktop / laptop / server.
- **Where it runs**: *runs on* pve-01 → QEMU 101.
- **How Fleet reaches it**: connection badges for SSH, fleetd+version, PVE guest agent, Tailscale online state.
- **Hardware**: CPU/mem/disk/arch, and board model when known.
- **Health**: status chip + last seen.

Features:
- Card / Topology / Table views of the same data, filters (kind, status, host, group, tag, connection), group-by, **saved views** ("Needs attention", "Lab").
- Unmanaged discoveries are shown in place: PVE guests with no linked machine → **Adopt**; tailnet devices not in Fleet → **Add**.
- Quick actions: power (start/shutdown/reboot for guests), probe inventory, install fleetd, copy SSH command, **open in VS Code Remote** (`vscode://vscode-remote/ssh-remote+host`), **open in Proxmox UI ↗** (console handoff; Fleet is not a hypervisor console).
- **Bulk actions** with a blast-radius preview (PLAN "Later": bulk plans across tags/groups): probe, install fleetd, tag, apply profile.
- **Machine detail page** tabs:
  - Overview
  - Inventory (facts with provenance + staleness)
  - Connections (endpoints, host key, node identity/enrollment, revoke)
  - Projects/checkouts
  - Tools & skills (mise/skills/frogenv operations)
  - Containers (M5)
  - Desired vs observed (M4 apply)
  - Operations
  - Audit
  - Guest (PVE: config, snapshots, clone/template via the review gate)
- **Wake-on-LAN** for offline physical devices (new; runs as an operation on a peer node on the same L2).

### Add flow (guided) — see `add-machine.html`
A single **+ Add** opens a dialog. Steps adapt to the source, and every path is a view over the existing **onboarding drafts**, so progress is durable and resumable.

| Source | Steps (existing API) |
|---|---|
| From Tailscale | pick device (`/tailnet/devices`, shows correlation candidates) → `import` creates a draft → test → confirm host key → discover → name/tags → agentless or install fleetd |
| Machine over SSH (incl. RPi/laptop) | host/user/auth → test → confirm host key → discover → name → management level |
| Proxmox server | URL + API token → `observe` → **confirm TLS fingerprint** → discovery preview → save account |
| Existing VM/LXC | pick discovered guest → association candidates → link to an existing machine or onboard as new |
| New persistent VM | pick promoted image → host/resources → reviewed clone (FM-603 gate) → onboard (**new use case**) |
| Lab environment | opens the Lab request drawer |

### Tailscale — how it fits
Today (FM-213): read-only OAuth (`devices:core:read`), device list, correlation candidates (address/name match), import → onboarding draft. Fleet identity stays independent; Tailscale is an endpoint/discovery provider (PLAN rec. #3).

What the console should do with it now (no plan change needed):
- **Add-flow source** with online/OS/tags, "already in Fleet" detection, and a *connect via* choice: MagicDNS name (survives re-IP), 100.x address, or LAN IP.
- **Tailscale badge on every machine**: tailnet online/last seen separate from Fleet reachability. This makes it easy to diagnose "tailnet says online, SSH fails".
- **"On your tailnet, not in Fleet"** section with Add / Hide.
- A Tailnet page: full device list, correlation, hidden devices, OAuth status in Settings.

Proposed additions (each needs a plan/ADR decision because they widen the read-only scope or trust boundary):
1. **Tailscale tags → Fleet groups** mapping (suggested on import; read-only, low risk).
2. **Auto-join new VMs and Lab leases.** With the `auth_keys` OAuth scope, Fleet mints a single-use, tagged, **ephemeral**, pre-authorized auth key per VM and passes it through cloud-init. Lab cleanup then also removes the device (`devices:core` write). This widens the scope from read-only, so it needs a decision and a spike against the Tailscale API docs.
3. **Tailnet identity as the M8 login.** When the controller sits behind `tailscale serve` (as it does here), serve adds identity headers (`Tailscale-User-Login`, …) on proxied requests. Only trusted from a loopback peer, these can replace `anonymous-lan-admin` with a real tailnet principal in the existing authz boundary. A cheap first step toward M8; verify the header contract in a spike.
4. Show **Tailscale SSH** and exit-node/subnet-router flags as device facts (read-only).

### Skills (fleet-wide Skills Manager) — see `skills.html`

**Why:** the M3 provider (FM-302) can probe `skills-manager-cli` and deploy/undeploy one skill on one machine. There is no fleet-wide view, no way to install, update or remove skills, no way to author a skill, and no notion of a skill that every machine should have. Content editing was in FM-302's goal but was deferred because the CLI has no content contract. Upstream v1.40.0 (2026-09-17) documents:
- `skills list/show/install/update/check/remove/deploy/undeploy/status/adopt/set-source/search`
- preset CRUD/deploy
- `git` backup
- `--json` with stable error codes

It still has **no command to read or write a skill's files**.

**Model.** Keep Skills Manager's three states separate: library membership, preset membership, and per-agent deployment. Fleet adds two things on top:
1. **Fleet skill catalog.** Skills Fleet authors or references:
   - *Fleet-authored*: SKILL.md + assets stored in the controller as editable drafts and immutable versions with digests. This follows the image-recipe pattern.
   - *Referenced*: a skills.sh ref or a Git URL/subpath, pinned to a revision where possible.
2. **Assignments.** Catalog skill → scope (all machines / group / tag / machine) × agents. **Global skills** are assignments with scope *all machines*, e.g. the official `fleet` skill that teaches agents to use `fleetctl --output json`.

**Rollout without touching another tool's internals:**
- *Fleet-authored skills:*
  1. Fleet writes the version into a **Fleet-owned staging directory** on the machine (e.g. `~/.local/share/fleet/skills/<name>/`) using the FM-301 guarded-write pattern: path containment, atomic rename.
  2. It calls `skills-manager-cli --json skills install <dir> --local` the first time. Later versions use `skills update <name>`, which the docs say re-imports a local source dir.
  3. Then it calls `skills deploy <name> --agent …`.
  4. It verifies with `skills show/status`.
- *Referenced skills:* `skills install <ref>` + `skills update`.
- It never writes Skills Manager's library, agent directories, or database directly.

**Reconciliation:**
- Assignments compose into desired state as a Fleet-managed skill set per machine. This is the "Fleet-managed preset" ownership rule already recorded in `docs/research/ecosystem.md`.
- The M4 planner/apply engine (which already orders and compensates `skills.deploy`) produces install/update/deploy steps. Missing or extra deployments are **drift**, shown in the matrix and on the overview attention queue.
- Stale or offline machines queue their steps. Machines without the CLI (e.g. aarch64, where no official build exists) report *unavailable* rather than guessing.

**Console:**
- **Fleet matrix**: skill × machine; cells show per-agent deployment, version, update-available and drift. Groups are *Global*, *assigned by group*, and *machine-local (not managed by Fleet)*.
- **Machine → Skills tab**: that machine's library, presets and per-agent deployments. Actions: install / update / remove (confirm; the CLI requires `--yes`) / deploy / undeploy / adopt unmanaged dirs (dry-run first) / set-source. `TARGET_CONFLICT` and `held_back_removals` are shown as data (paths), never auto-resolved.
- **Catalog**: Fleet-authored skills with a Markdown editor (frontmatter validated), version history with diffs, assignment editor, a **rollout plan preview**, then publish & roll out.
- **Presets**: list/CRUD Skills Manager presets per machine; Fleet-managed presets are marked as such.
- **Search skills.sh** via `skills search --json`, then install into catalog or machine.
- Reading or editing the content of *machine-local* skills (not authored by Fleet) waits for an upstream content contract (spike FM-S10). Until then, the UI offers "adopt into Fleet catalog" by re-authoring, never by reading library files.

**Official `fleet` skill:**
- Replaces the legacy `bootstrap/fleet-bootstrap` (which documents `agents-registry`).
- It ships with the controller as a built-in catalog entry versioned with the controller, assigned globally by default (removable).
- It documents only `fleetctl --output json` workflows. PLAN M7 already calls for "Fleet-provided skills"; this is the delivery mechanism.

### Proxmox page
Accounts, trust state (pinned / changed fingerprint with both fingerprints shown), nodes with capacity, storage, templates, guests, and a recent PVE task list. Lifecycle actions and the destructive-ops **review screen** show the exact reviewed payload and the review token flow.

### Lab — decision 2
Contents:
- **Environments** (leases): lifecycle stepper (requested → … → ready → released / failed / cleanup_failed), TTL bar, max lifetime, owner (human vs agent), purpose, project, cleanup decision.
  - Actions: exec, copy ssh, extend (**new API**), keep (elevated), release, retry cleanup.
  - Live provisioning log.
- **New environment** drawer: template, optional project to prepare, purpose, TTL, destroy/keep, placement preview ("fits on pve-02"), fleetctl equivalent.
- **Templates**: versions, pinned image version, **stale-pin warning**, readiness policy, TTL, cleanup strategy, publish.
- **Images**: recipes (structured Proxmox editor ⇄ raw `.pkr.json`, unknown fields preserved), versions, builds with a live Packer log, **manual promote** with evidence.
- **Capacity**: per-node Lab reservations vs free.
- **History**: released leases, durations, failure reasons; later artifacts (M7 follow-on).
- Exec console: run a command against a ready lease, streamed and bounded (existing exec semantics).

### Projects
- Projects list, plus a **checkout matrix** (project × machine) showing branch/dirty/ready.
- **"Make ready on…"** flow (clone-to-ready plan preview, blocked Frogenv approval surfaced clearly), and AGENTS.md/CLAUDE.md guarded editing.

### Operations & Audit
- Operations: filterable list, detail with SSE event stream/log, cancel, and blocked-approval handling.
- **Audit log viewer** (**new API**: query by actor/action/resource/time, export).

### Settings — see `settings.html`
- **General**: controller name/URL, default theme, time format.
- **Security & access**: trusted-LAN warning, principal, allowed origins; later tailnet-identity login (M8).
- **Integrations**: Proxmox accounts, Tailscale OAuth, Packer version probe, GitHub, Skills Manager / Frogenv / mise detection, Docker (M5).
- **Credentials**: names, scope, set/rotated date. Secrets are **write-only** and never displayed.
- **SSH & host keys**: controller public key, known-hosts review/revoke.
- **fleetd & enrollment**: enrollment tokens, node versions, update channel.
- **Lab defaults**: TTL, max lifetime, cleanup strategy, sweep interval.
- **Desired state**: Git source, active revision (M4).
- **Notifications** (new): webhook / ntfy for `cleanup_failed`, machine offline, blocked approvals.
- **Backups**: last SQLite backup, restore docs.
- **Diagnostics**: `/system`, `/meta`, readiness, versions.

## Backend gaps the console needs (new issues)

| Gap | Why | Owner layer |
|---|---|---|
| **Fleet-wide SSE event stream** (`/api/v1/events`: machine status, operation state, lease state) | Live cards without polling; only `/operations/{id}/events` exists today | application + api |
| **Machine kind & hosting relation** (`physical`/`vm`/`lxc` + `runsOn` guest link) | "What type of system, what it runs on" | core + application |
| **Confirm guest ↔ machine association** mutation | Associations are evidence-only candidates today; the UI needs "Link" / "Adopt" | application |
| **Inventory probe additions**: virtualization (`systemd-detect-virt`), board/DMI model (`/proc/device-tree/model`, `/sys/class/dmi/id/product_name`), CPU model, disk total | Hardware line on cards, RPi detection | provider-ssh + fleetd |
| **Proxmox node capacity** (CPU/mem/storage usage from the node status endpoints) | Host cards, Lab placement preview | provider-proxmox |
| **Overview/attention aggregate** endpoint (or client-side composition first) | Dashboard | application |
| **Audit query API** | Audit page | application + api |
| **Lease TTL extend** | Lab "Extend" | core lab state machine |
| **Persistent VM create** (clone promoted image → onboard) | "+ Add → New VM" | application saga |
| **Wake-on-LAN** operation | Offline devices | new executor kind |
| **Notifications** outbox + webhook | Attention outside the UI | application |
| **linux aarch64 fleetd** | RPi fleetd (agentless SSH works today) | PLAN marks aarch64 deferred; revisit |

## Epics and issues

IDs are planning IDs; GitHub numbers are mapped in `initial-issues.md`. Every issue owns `apps/web/**` only for its own routes/components, plus the crates it names.

**Epic A — Console foundation**
- **FM-900** DESIGN.md v2: controller vocabulary, app shell (sidebar/topbar), shadcn-vue token map, sharp 2px radius, dark default. Docs only.
- **FM-901** shadcn-vue + vue-router + TanStack Query + app shell. Port the existing five panels onto routes with no behavior change. License check for the new dependencies.
- **FM-902** Fleet-wide SSE event stream (`/api/v1/events`: machine status, operation, lease, onboarding transitions) with resume/gap semantics matching FM-110. The client invalidates queries from it.

**Epic B — Fleet inventory console**
- **FM-910** Fleet page: grouped card view (default) + table/drawer view, filters, group-by, saved views. Client-side join of machines, Proxmox discovery/guests and tailnet devices; tailnet devices not yet in Fleet are shown with an Add action.
- **FM-911** Machine detail page: overview, inventory with provenance, connections (endpoints/host key/node), projects, tools, operations, audit; PVE guest tab with lifecycle and reviewed destructive operations.
- **FM-912** Unified "+ Add" dialog over onboarding drafts, tailnet import, Proxmox account observe/confirm, and guest adoption.
- **FM-913** Machine kind (`physical`/`vm`/`lxc`) and `runsOn` hosting relation; **confirm guest↔machine association** mutation (today candidates are evidence only). Crates: core, application, storage, api.
- **FM-914** Inventory probe additions: virtualization, board/DMI model, CPU model, disk total (agentless probe + fleetd).
- **FM-915** Proxmox node capacity observations (CPU/mem/storage usage).
- **FM-916** Overview dashboard: KPIs, needs-attention queue, activity feed. Operations page.

**Epic C — Fleet-wide skills**
- **FM-S10** Spike: refresh the Skills Manager contract from v1.34.2 to v1.40.x (fixtures, version range); confirm `skills update` re-imports local sources; check whether `skills show --json` exposes content or paths; propose an upstream content read/write contract if needed; check aarch64 availability.
- **FM-920** Skills read model: per-machine library, presets and per-agent deployments from the CLI; `GET /machines/{id}/skills` and a fleet-wide matrix query; `fleetctl skills list/matrix`.
- **FM-921** Library operations: `skills.install/update/check/remove/adopt/set-source` and `presets.*` executor kinds with authz entries; confirmation for remove; `TARGET_CONFLICT`/`held_back_removals` surfaced as data.
- **FM-922** Fleet skill catalog: authored skills (drafts, immutable versions with digests) and referenced sources; rollout to a machine via the Fleet-owned staging dir + CLI install/update/deploy + verification.
- **FM-923** Skill assignments and global skills: scope × agents composed into desired state; planner/apply produce rollout plans; drift reported; offline machines queue.
- **FM-924** Official `fleet` skill: built-in catalog entry versioned with the controller, globally assigned by default. Retire `bootstrap/fleet-bootstrap`.
- **FM-925** Skills console: fleet matrix, machine Skills tab, catalog editor with version diff and rollout preview, presets, skills.sh search.

**Epic D — Lab and Images console**
- **FM-930** Lab environments page: lease cards with lifecycle/TTL, request drawer with placement preview and fleetctl equivalent, templates tab, history, capacity tab. Absorbs #15's web item.
- **FM-931** Lease TTL extend (bounded by max lifetime; audited) in core/application/api/CLI.
- **FM-932** Images/pipeline page: recipes (structured ⇄ raw `.pkr.json` editor), versions, builds with live log, promotion. Absorbs #109's web editor slice.

**Epic E — Settings, Proxmox, Projects, Audit, and access**
- **FM-940** Settings pages over existing integration/config/system surfaces (write-only secrets).
- **FM-941** Proxmox page: accounts, trust state, nodes, storage, templates, guests, tasks.
- **FM-942** Projects page: checkout matrix and "make ready on…" flow.
- **FM-943** Audit query API (actor/action/resource/time, cursor) + audit log page.
- **FM-944** ADR + implementation: tailnet identity (`tailscale serve` identity headers from a loopback peer) as the principal instead of `anonymous-lan-admin`.

**Later (not created yet):** FM-951 ⌘K command palette actions, FM-952 bulk actions with blast-radius preview, notifications outbox/webhooks, Wake-on-LAN, Containers (M5).

**Suggested waves:**
1. FM-900 → FM-901. FM-S10 in parallel.
2. FM-902, FM-910, FM-920, FM-930.
3. FM-911, FM-912, FM-916, FM-921, FM-922, FM-932.
4. FM-913, FM-914, FM-915, FM-923, FM-924, FM-925, FM-931.
5. FM-940–FM-944.

## Decisions (maintainer, 2026-09-24)

1. **Fleet overview:** grouped cards (option A) are the default view, with a table + detail-drawer view (option C) as a toggle for scale and bulk actions. The topology view (B) is not planned for now.
2. **Lab:** environments first (option A). The pipeline view (option B) becomes the Images / pipeline sub-page.
3. **Corners:** sharp 2px, as DESIGN.md prescribes. The shadcn-vue `--radius` maps to 2px.
4. **Tailscale:**
   - Console UX on the existing read-only API: yes.
   - Tailnet identity (`tailscale serve` identity headers) as the login that replaces `anonymous-lan-admin`: yes, pending an ADR, since it changes the trusted-LAN boundary and pulls part of M8 forward.
   - Auth-key auto-join for VMs and Lab: not now; stays read-only.
