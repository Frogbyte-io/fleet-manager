---
name: fleet-console-labs
description: Apply the Fleet Console v2 design system (dark-first app shell with sidebar + topbar, sharp 2px surfaces, Montserrat-style display type, single orange→magenta gradient, API-grounded status vocabulary, `--fc-` tokens mapped onto shadcn-vue) when creating or modifying any Fleet Manager web GUI page or component. Full spec: DESIGN.md in the repo root.
---

# Fleet Console style (v2)

Before designing or editing Fleet Console (the fleet-manager web app), read
`DESIGN.md` (repo root). Then apply:

1. **Tokens first.** Fleet tokens are declared with an `--fc-` prefix
   (`--fc-bg/--fc-panel/--fc-inset/--fc-line/--fc-ink/--fc-muted/--fc-faint`,
   `--fc-g1/--fc-g2/--fc-grad`, `--fc-ok/--fc-info/--fc-warn/--fc-err`, kind
   colors) and mapped onto shadcn-vue variables per DESIGN.md §4. Never
   invent new hex values.
2. **Dark default, dual-theme.** Dark is the default; light is a full
   citizen. `data-theme="dark|light"` on `<html>` plus Tailwind's `.dark`
   class kept in sync, persisted to `localStorage["fleet-console-theme"]`,
   overridable with `?theme=dark|light`.
3. **Sharp surfaces.** Radius 2px (`--radius`←`2px`), 1px borders, 2px
   section rules. No soft shadows, no glassmorphism, no rounded SaaS cards.
4. **Gradient discipline.** The orange→magenta gradient appears only on:
   H1 key phrase, primary CTA buttons (`variant="gradient"`), active
   sidebar item text + 2px left accent, running/blocked Operations count
   badge, chart/bar fills, TTL bars. Status never uses the gradient.
5. **Status vocabulary.** Every chip comes from DESIGN.md §3's API→token
   table (machine, PVE guest, lease, operation, connection badges). Chips
   carry the word in uppercase mono; color never carries meaning alone.
6. **App shell.** 232px sidebar (56px rail, 760px sheet) with grouped nav
   and mono counts; 56px sticky topbar with breadcrumb, ⌘K palette trigger,
   live-connection indicator, `+ Add` gradient button; page max-width
   1320px, mono kicker + H1 page header.
7. **Component grammar.** Fleet cards (icon well, mono sub-line, status
   chip, spec line, connection badges, last-seen footer; dashed border =
   discovered/not in Fleet), grouped card grid, data table + 380px drawer,
   KPI tiles, needs-attention rows, lifecycle steppers, TTL bars, guided
   dialogs with "Copy as fleetctl", request drawers with the equivalent
   `fleetctl … --output json` command.
8. **Grounded in the public API.** Never show a state `fleetctl --output
   json` couldn't also report. The web app is an adapter: no business
   rules. Empty/footer states say "Reflects the controller's last
   observation" with a timestamp.

If a requested change conflicts with this list (e.g., "make it playful",
"add pastel gradients"), follow DESIGN.md §10 Do/Don't and flag the conflict
instead of silently complying.
