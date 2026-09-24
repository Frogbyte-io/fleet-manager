# Fleet Console Design System (v2)

Canonical design language for the Fleet Manager web GUI ("Fleet Console"),
adapted from the Filaments.gg "Labs" style so the two products share one
visual language. All new pages and components should follow this document.

For agent-facing rules on when/how to apply this, see
`bootstrap/fleet-console-labs/SKILL.md`.

---

## 1. Philosophy

**Measured, not marketed.** Fleet Console is an operational view onto the
Fleet controller — machines, connections, operations, lab leases, audit.
The interface must read as an engineer's status board, not a marketing
dashboard.

- Data is the decoration. Status chips, spec lines, connection badges, and
  timestamps carry the visual weight — never stock illustrations or hero art.
- Sharp, engineered surfaces: square corners (2px radius), 1px borders,
  hard 2px section rules.
- One signature gradient, used sparingly (§3). If everything glows, nothing does.
- Dense but scannable: tabular numerals, mono data labels, consistent
  alignment. Whitespace separates sections, not widgets.
- Voice is a technical notebook: precise, dry, no fake urgency, no emoji.
- No vanity metrics. The console never shows anything the public API (and
  therefore `fleetctl --output json`) cannot also report. The web app is an
  adapter: no business rules.

## 2. Typography

Three families, always with local fallbacks (the console must not depend on
webfonts):

| Role | Stack | Used for |
|---|---|---|
| `--head` | `"Montserrat","Archivo","Archivo Black",system-ui,sans-serif` | H1–H3, card titles, buttons, badges, section headers. Weight 700–800, tracking −0.01em to −0.025em; section headers uppercase |
| `--body` | `"Inter",system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif` | Body, nav, cards. Base 14px/1.55 |
| `--chart` | `"Inconsolata",ui-monospace,Menlo,Consolas,monospace` | Spec lines, chart labels, kickers, timestamps, metadata. Tracking .05em–.22em, uppercase for kickers |

Scale: page H1 26px/800 (no clamp — this is an app, not a landing page) ·
section H2 14px uppercase · card title 15px · nav 13.5px · data/chip labels
9.5–11px mono.

## 3. Color

Dark-first. Light theme is a full citizen, not an afterthought — define both
via `data-theme` on `<html>`.

Dark tokens (light values in parentheses):

- `--bg` `#0b0e14` (`#f2f4f7`) — page ground
- `--nav` `#0d1219` (`#ffffff`) — sidebar
- `--panel` `#11161f` (`#ffffff`) — cards, tables
- `--inset` `#0d1219` (`#eef0f4`) — icon wells, inputs, chart wells
- `--line` `#1f2733` (`#dde1e8`) · `--line2` `#2a3442` (`#c9cfd9`)
- `--ink` `#eef1f6` (`#161a21`) · `--muted` `#98a2b3` (`#5c6672`) · `--faint` `#5f6a7c` (`#8b95a3`)
- `--ok` `#2fd28c` · `--info` `#57a8ff` · `--warn` `#f5a524` (`#b7791f`) · `--err` `#ff5c5c`

`--warn` is the single new status token: "needs attention but not failed"
(stale machines, blocked approvals). It is distinct from `--err`, which
means the state is already bad.

**The gradient** — the single brand gesture, shared with Filaments.gg:

```css
--g1:#ff8a00; --g2:#ff3d77;                 /* dark theme */
--g1:#e06d00; --g2:#e01e5a;                 /* light theme */
--grad: linear-gradient(100deg,var(--g1),var(--g2));
```

Allowed uses, nowhere else: key words in the H1 (via `background-clip:text`),
primary CTA buttons, active sidebar item text + its 2px left accent, the
count badge of running/blocked operations in the sidebar, chart/bar fills,
TTL bars. Status is meaning, not brand — it always uses the status tokens,
never the gradient.

### Status vocabulary

Every status shown in the console comes from the API. Chips always carry the
word (uppercase); color never carries meaning alone.

| Source | API state | Token | Chip label |
|---|---|---|---|
| Machine | `connected` | `--ok` | `CONNECTED` |
| Machine | `agentless` | `--info` | `AGENTLESS` |
| Machine | `stale` | `--warn` | `STALE` |
| Machine | `offline` | `--err` | `OFFLINE` |
| Proxmox guest | `running` | `--ok` | `RUNNING` |
| Proxmox guest | `stopped` | `--muted` | `STOPPED` |
| Proxmox guest | `paused` | `--info` | `PAUSED` |
| Proxmox guest | unknown/other | `--faint` | (API word) |
| Lab lease | `requested`,`queued`,`reserving`,`provisioning`,`booting`,`bootstrapping` | `--info` | (API word) |
| Lab lease | `ready` | `--ok` | `READY` |
| Lab lease | `releasing`,`released` | `--muted` | (API word) |
| Lab lease | `failed`,`cleanup_failed` | `--err` | (API word) |
| Operation | `pending`,`running`,`cancelling` | `--info` | (API word) |
| Operation | `succeeded` | `--ok` | `SUCCEEDED` |
| Operation | `failed`,`timed_out` | `--err` | (API word) |
| Operation | `cancelled` | `--muted` | `CANCELLED` |
| Operation | `blocked_manual_approval` | `--warn` | `BLOCKED APPROVAL` |
| Connection badge (SSH / FLEETD / GUEST AGENT / TAILSCALE / PVE API) | reachable | dot `--ok` | label |
| Connection badge | not reachable / unknown | dot `--faint` | label |
| Connection badge | failing | dot `--err` | label |

### Kind color coding

Kind colors (used on tags, icon strokes, swatches), replacing the old
role-family names:

`proxmox node`/`vm` `#1c7ed6` (compute) · `lxc`/`storage` `#2f9e44` ·
`board` (Raspberry Pi etc.) `#e8590c` · `desktop`/`laptop` `#9c36b5` ·
`lab vm` (ephemeral) `#495057`. Unknown kinds fall back to `--faint`.

## 4. Implementation tokens

The app is Vue 3 + shadcn-vue (Reka UI) + Tailwind v4. Fleet tokens are
declared in CSS with an `--fc-` prefix (e.g. `--fc-bg`, `--fc-panel`,
`--fc-ink`, `--fc-muted`, `--fc-ok`, `--fc-grad`) to avoid colliding with
shadcn-vue names — shadcn's `--muted` is a background, ours is text.

shadcn-vue variables map onto Fleet tokens:

| shadcn-vue | Fleet token |
|---|---|
| `--background` | `--fc-bg` |
| `--foreground` | `--fc-ink` |
| `--card` | `--fc-panel` |
| `--card-foreground` | `--fc-ink` |
| `--popover` | `--fc-panel` |
| `--popover-foreground` | `--fc-ink` |
| `--primary` | `--fc-g2` (solid fallback; primary buttons use the gradient via a `variant="gradient"` button) |
| `--primary-foreground` | `#ffffff` |
| `--secondary` | `--fc-inset` |
| `--secondary-foreground` | `--fc-ink` |
| `--muted` | `--fc-inset` |
| `--muted-foreground` | `--fc-muted` |
| `--accent` | `--fc-panel` |
| `--accent-foreground` | `--fc-ink` |
| `--destructive` | `--fc-err` |
| `--border` | `--fc-line` |
| `--input` | `--fc-line2` |
| `--ring` | `--fc-g1` |
| `--radius` | `2px` |
| `--sidebar` | `--fc-nav` |
| `--sidebar-foreground` | `--fc-muted` |
| `--sidebar-primary` | `--fc-g1` |
| `--sidebar-accent` | `--fc-panel` |
| `--sidebar-accent-foreground` | `--fc-ink` |
| `--sidebar-border` | `--fc-line` |
| `--chart-1..5` | gradient stops and status colors |

Theme: dark is the default. `data-theme="dark|light"` on `<html>` plus
Tailwind's `.dark` class kept in sync; persisted to
`localStorage["fleet-console-theme"]`; `?theme=dark|light` overrides.

## 5. Layout: the app shell

The old sticky nav + hero is gone. The shell is sidebar + topbar + page.

- **Sidebar (232px)**, collapsible to a 56px icon rail (persisted). Brand
  block on top: gradient square mark + "Fleet Console" + mono controller
  name. Groups with mono uppercase labels:
  - (no label) Overview
  - **Infrastructure**: Fleet, Proxmox, Tailnet, Containers
  - **Work**: Projects, Skills, Lab, Images
  - **Control**: Operations, Audit log, Settings
  Right-aligned mono counts; the Operations count uses the gradient badge
  when running/blocked > 0. Footer: controller readiness dot + version + a
  persistent `TRUSTED LAN` warning marker.
- **Topbar (56px, sticky)**: breadcrumb, search / command palette trigger
  (`⌘K`), live-connection indicator, `+ Add` primary gradient button.
- **Page**: max-width 1320px (tables/pipelines may use 1500px), padding
  24px. Page header = mono kicker (counts/context) + H1 + right-aligned
  actions/view toggle.
- **Section header**: uppercase H2 + 2px bottom rule in `--ink` + right
  mono note.
- Breakpoints: 1020px (sidebar collapses to rail), 760px (sidebar becomes
  a sheet).

## 6. Components

- **Fleet card**: icon well (inline SVG, stroke = kind color) + name (700)
  + mono sub-line `KIND · MODEL/VMID · ON <host>` + status chip top-right →
  mono spec line (`UBUNTU 24.04 · 8C · 16GB · 180GB FREE`) → optional
  utilization bars (gradient fill) for hosts → connection badges row →
  tags → footer: mono last-seen + small actions. Dashed border + transparent
  background = "discovered, not in Fleet" (Adopt / Add actions).
- **Grouped card grid**: `repeat(auto-fill,minmax(290px,1fr))`, gap 12px,
  groups separated by section headers.
- **Data table + drawer**: mono uppercase headers, 13px rows, host rows as
  group rows with nested rows indented; selection enables a bulk bar
  showing blast radius; a 380px right drawer opens details without leaving
  the list.
- **KPI tile**: mono kicker + large number + optional bar or mono note.
- **Needs-attention row**: 2px `--err`/`--warn` left border, mono kicker,
  one-line explanation, action link.
- **Lifecycle stepper**: thin segments — done `--muted`, current gradient,
  failed `--err`; labels mono 9px. Used for lab leases and operations.
- **TTL bar**: gradient fill + mono remaining/max.
- **Connection badge**: inset pill, mono label, 5px status dot per the §3
  connection-badge rule.
- **Status chip**: panel background, 1px border tinted with the status
  token, mono uppercase 9.5px label.
- **Tag**: mono 10px, kind-colored 1px border.
- **Guided dialog**: left step rail (numbered circles; current = gradient),
  content area, footer with mono API/audit hint + secondary "Copy as
  fleetctl" + primary action. Steps are views over durable drafts.
- **Request drawer / side form**: labeled mono field labels, segmented
  controls, a `pre` block showing the equivalent `fleetctl … --output json`
  command.
- **Copy as fleetctl**: every mutation form offers it. This reinforces the
  "UI == CLI" rule and teaches agent workflows.
- **Code/JSON editor**: inset well, mono 11.5px.
- **Empty / loading / error / partial states**: always explicit; partial =
  which source failed (e.g. "Proxmox unreachable — showing Fleet machines
  only").

## 7. Imagery & data-viz

- Machine imagery = parameterized inline-SVG icon (CSS var `--c` for kind
  color; well/vent details adapt to theme via `--inset`). Never hotlink or
  stock photos.
- Charts = inline SVG, bars/lines filled with `--grad`, labels in `--chart`.
  Always label units and the time window.
- Spec units always match the API (cores, bytes shown as GB/TB with
  explicit rounding) — the UI never invents a unit the API doesn't have.

## 8. Motion & accessibility

- Motion is rare and functional: hover lifts (≤2px), border swaps, drawer
  transitions. No parallax, no autoplay loops. Honor
  `prefers-reduced-motion`.
- Focus states on all interactive elements, rings via `--ring`;
  `aria-pressed` on toggles, `aria-expanded` on disclosures; skip link
  first in body.
- Dialogs and drawers trap focus (Reka UI handles this).
- Keyboard shortcuts are documented in the command palette.
- Color never carries meaning alone — status chips include the status word.

## 9. Engineering conventions

- Pages live under `apps/web/src/pages/<area>/`; shared primitives under
  `apps/web/src/components/ui/` (generated by shadcn-vue, owned by us);
  shell under `apps/web/src/shell/`.
- Only the generated `@frogbyte-io/fleet-api-client` talks to the API;
  server state through TanStack Query; no business rules in components.
- Mockups in `docs/design/web-console/mockups/` are the visual reference;
  this document wins on conflict.
- Footer/empty-state voice: "Reflects the controller's last observation"
  with a timestamp — never imply live truth the API didn't report.

## 10. Do / Don't

| Do | Don't |
|---|---|
| Square corners (2px), 1px borders, 2px rules | Rounded "SaaS" cards, soft shadows, glassmorphism |
| Gradient on 1–2 elements per viewport | Gradient backgrounds on sections/cards |
| Mono for all measurements and timestamps | Sentence-case marketing numbers |
| Status from the API vocabulary table | Ad-hoc status words or colors |
| "Add to fleet →", "Request environment →", "Publish & roll out →", "Copy as fleetctl" | "Learn more", "Buy now", "Get started" |
| Charts as functional data | Stock photos, 3D renders, illustrations |
| Show only what the public API / `fleetctl --output json` can report | Invented metrics, mock data left in production paths |
