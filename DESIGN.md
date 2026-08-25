# Fleet Console Design System

Canonical design language for the Fleet Manager web GUI ("Fleet Console"),
adapted from the Filaments.gg "Labs" style so the two products share one
visual language. All new pages and components should follow this document.

For agent-facing rules on when/how to apply this, see
`bootstrap/fleet-console-labs/SKILL.md`.

---

## 1. Philosophy

**Measured, not marketed.** Fleet Console is an operational view onto the
`agents-registry` — machines, roles, packs, capabilities, sync/drift state.
The interface must read as an engineer's status board, not a marketing
dashboard.

- Data is the decoration. Status chips, spec lines, role tags, and sync
  timestamps carry the visual weight — never stock illustrations or hero art.
- Sharp, engineered surfaces: square corners (0–3px radius), 1px borders,
  hard 2px section rules.
- One signature gradient, used sparingly (§3). If everything glows, nothing does.
- Dense but scannable: tabular numerals, mono data labels, consistent
  alignment. Whitespace separates sections, not widgets.
- Voice is a technical notebook: precise, dry, no fake urgency, no emoji.
- No vanity metrics. A machine's state shown here is exactly what
  `agents-registry status`/`resolve` would report — the UI never shows
  anything the CLI can't also tell you.

## 2. Typography

Three families, always with local fallbacks (the GUI must not depend on
webfonts):

| Role | Stack | Used for |
|---|---|---|
| `--head` | `"Montserrat","Archivo","Archivo Black",system-ui,sans-serif` | H1–H3, machine ids, buttons, badges, section headers. Weight 700–800, tracking −0.01em to −0.025em; section headers uppercase |
| `--body` | `"Inter",system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif` | Body, nav, cards. Base 15px/1.6 |
| `--chart` | `"Inconsolata",ui-monospace,Menlo,Consolas,monospace` | Spec lines, chart labels, kickers, timestamps, metadata. Tracking .05em–.22em, uppercase for kickers |

Scale: H1 `clamp(34px,4.8vw,56px)` · section H2 21px uppercase · machine card
title 16px · nav 13.5px · data/chip labels 9–11px mono.

## 3. Color

Dark-first. Light theme is a full citizen, not an afterthought — define both
via `data-theme` on `<html>`.

Dark tokens (light values in parentheses):

- `--bg` `#0b0e14` (`#f2f4f7`) — page ground
- `--nav` `#0d1219` (`#ffffff`) — sticky nav
- `--panel` `#11161f` (`#ffffff`) — cards, tables
- `--inset` `#0d1219` (`#eef0f4`) — icon wells, inputs, chart wells
- `--line` `#1f2733` (`#dde1e8`) · `--line2` `#2a3442` (`#c9cfd9`)
- `--ink` `#eef1f6` (`#161a21`) · `--muted` `#98a2b3` (`#5c6672`) · `--faint` `#5f6a7c` (`#8b95a3`)
- `--ok` `#2fd28c` (RUNNING) · `--info` `#57a8ff` (UNMANAGED) · `--err` `#ff5c5c` (ERROR/drift)

**The gradient** — the single brand gesture, shared with Filaments.gg:

```css
--g1:#ff8a00; --g2:#ff3d77;                 /* dark theme */
--g1:#e06d00; --g2:#e01e5a;                 /* light theme */
--grad: linear-gradient(100deg,var(--g1),var(--g2));
```

Allowed uses, nowhere else: key words in the H1 (via `background-clip:text`),
Sync Queue count chip, drift badges, chart/bar fills, primary CTA buttons,
nav active-link text, small tags/NEW chips, hover accents. Machine **status**
(RUNNING/STOPPED/UNMANAGED/ERROR) is meaning, not brand — it always uses
`--ok`/`--muted`/`--info`/`--err`, never the gradient.

Role-family color coding (used on role tags, swatches, rack-icon fills),
mirrored from the `roles/` registry:

`compute` (proxmox-host/vm) `#1c7ed6` · `storage` `#2f9e44` · `network`
`#e8590c` · `desktop`/workstation `#9c36b5` · `test-profile`/ephemeral
`#495057`. Unclassified roles fall back to `--faint`.

## 4. Layout & components

- Container: `max-width:1220px; padding:0 24px`. Breakpoints 1020px and 760px.
- Section header: uppercase H2 + 2px bottom rule in `--ink`, with a right-side
  mono note (`FULL REGISTRY →`, counts). No card-chrome around sections.
- **Sticky nav (72px)**: Fleet Console logo, primary links (active =
  gradient text), machine/role/capability search, square search input
  (rounded: 0), **Sync Queue** button with count chip, theme toggle.
- **Hero**: kicker (`--chart`, .22em tracking) → H1 with gradient phrase
  ("machines, resolved.") → 1-sentence sub → square finder input + gradient
  RESOLVE button → mono stat hints (machine count, drifted count, last sync
  time). Right column: inline-SVG bar chart of role distribution or sync
  history, never a stock image.
- **Sync Queue**: functional counter, batch sync (no fixed max). `+ QUEUE` on
  machine cards toggles membership (active state = gradient fill, label
  `✓ QUEUED`). Dropdown lists queued machines with remove buttons;
  `RUN SYNC →` enabled at ≥1.
- **Machine card**: icon well (`--inset`) with centered rack-unit SVG +
  status chip top-right (`RUNNING`/`STOPPED`/`UNMANAGED`/`ERROR`, colored per
  §3, over panel chip) → host mono line → 700-weight machine id → role tag
  (role-family color) → mono spec line (`CPU 8C · MEM 16GB · DISK 100GB`,
  matching `resources:` schema keys) → lifecycle hint icon
  (`persistent`/`ephemeral` + reset strategy) → footer: last-synced mono
  timestamp + `+ QUEUE` + gradient `RESOLVE →`.
- **Role/capability chips**: square buttons, mono count, gradient border on
  hover.
- **Drift cards**: `declared — [≠] — live` grid per machine; center badge is
  a gradient block when drifted, a neutral `--ok` check when clean; mono
  capability-diff count below.
- **Remediation rows**: "Fix drift on `<machine>`" blocks; rows with
  role-color swatch, machine id, mono capability/pack name, right-aligned
  `RESOLVE →` action (maps to `agents-registry sync --machine <id>`).
- **Recently synced**: flat row list — mono timestamp, machine id, bold
  role/pack delta description, status gradient chip for changed state, mono
  duration.
- **Registry digest cards**: inline-SVG chart cover (sync success rate,
  capability coverage — never photos), gradient category tag, 700 title
  (gradient on hover), mono meta line (run count, date range).
- **Footer**: 2px top rule in `--ink`; repo links; note that this engine repo
  holds no machine-specific data — state shown is whatever the connected
  fleet data repo + last sync resolved.

## 5. Imagery & data-viz

- Machine imagery = parameterized inline-SVG rack-unit/server icon (CSS var
  `--c` for role-family color; well/vent details adapt to theme via
  `--inset`). Never hotlink or stock photos.
- Charts = inline SVG, bars/lines filled with `--grad`, labels in `--chart`.
  Always label units and the time window.
- Resource specs always match `resources:` schema units 1:1 (CPU cores, GB
  memory, GB disk) — the UI never invents a unit the registry doesn't have.

## 6. Motion & accessibility

- Motion is rare and functional: queue dropdown, hover lifts (≤2px) or
  border swaps. No parallax, no autoplay loops. Honor
  `prefers-reduced-motion`.
- Focus states on all interactive elements; `aria-pressed` on toggles,
  `aria-expanded` on the queue; skip link first in body.
- Color never carries meaning alone — status chips include the status word,
  drift badges include a diff count.

## 7. Engineering conventions

- Standalone GUI pages: embedded `<style>` + `<script>` where practical, zero
  unnecessary external requests. Each concept carries a rationale comment at
  top.
- Theme: `data-theme` on `<html>`, persisted to `localStorage`
  (`fleet-console-theme`), overridable via `?theme=dark|light` URL param.
- Finder filter contract: `[data-finder]` input filters `[data-machine]`
  elements on text + `data-tags` (role ids); `[data-q]` chips set the query.
- Rationale HTML comment at the top of every page; footer note: "Reflects
  the registry as of the last sync — run `agents-registry sync` to
  reconcile drift."

## 8. Do / Don't

| Do | Don't |
|---|---|
| Square corners, 1px borders, 2px rules | Rounded "SaaS" cards, soft shadows, glassmorphism |
| Gradient on 1–2 elements per viewport | Gradient backgrounds on sections/cards |
| Mono for all measurements and timestamps | Sentence-case marketing numbers |
| Status chips, drift counts, sync timestamps | Star ratings, hearts, social proof |
| "RESOLVE →", "RUN SYNC →", "+ QUEUE" | "Learn more", "Buy now", "Get started" |
| Charts as hero art | Stock photos, 3D renders, illustrations |
| Show only what the CLI can also report | Invented metrics, mock data left in production paths |
