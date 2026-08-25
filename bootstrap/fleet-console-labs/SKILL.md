---
name: fleet-console-labs
description: Apply the Fleet Console design system (dark, sharp, Montserrat-style display type, single orange→magenta gradient, status-chip machine cards, sync queue, drift-diff cards, chart-forward data viz) when creating or modifying any Fleet Manager web GUI page or component. Full spec: DESIGN.md in the repo root.
---

# Fleet Console style

Before designing or editing Fleet Console (the fleet-manager web GUI), read
`DESIGN.md` (repo root). Then apply:

1. **Tokens first.** Use the CSS custom properties from DESIGN.md §2–3
   (`--head/--body/--chart`, `--bg/--panel/--inset/--line/--ink/--muted/--faint`,
   `--g1/--g2/--grad`, `--ok/--info/--err`, role-family colors). Never invent
   new hex values.
2. **Dark-first, dual-theme.** Everything ships with dark and light themes via
   `data-theme` on `<html>`, persisted to `localStorage`
   (`fleet-console-theme`), overridable with `?theme=dark|light`.
3. **Sharp surfaces.** Radius 0–3px, 1px borders, 2px section rules. No soft
   shadows, no glassmorphism, no rounded SaaS cards.
4. **Gradient discipline.** The orange→magenta gradient appears only on: H1
   key phrase, Sync Queue count chip, drift badges, chart fills, primary
   CTAs, nav active state. One or two gradient elements per viewport, never
   as section backgrounds. Machine status (`RUNNING`/`STOPPED`/`UNMANAGED`/
   `ERROR`) is meaning, not brand — always `--ok`/`--muted`/`--info`/`--err`,
   never the gradient.
5. **Data voice.** Resource specs in uppercase `--chart` mono, matching the
   registry's `resources:` schema keys 1:1 (`CPU 8C · MEM 16GB · DISK
   100GB`); timestamps mono. Machine imagery is a parameterized inline-SVG
   rack-unit icon (CSS var `--c` for role-family color); charts are inline
   SVG with gradient fills. No stock images, no external requests.
6. **Component grammar.** Machine card with status chip, `+ QUEUE` and
   `RESOLVE →` actions; Sync Queue (gradient count chip, `RUN SYNC →` at
   ≥1); drift-diff cards (`declared — [≠] — live`); "Fix drift on
   `<machine>`" remediation rows; mono-timestamp Recently Synced rows;
   section headers = uppercase H2 + 2px rule + mono side note.
7. **Grounded in the registry.** Never show a state the CLI couldn't also
   produce — every card/chip should trace back to `agents-registry
   status`/`resolve`/`validate` output. This is a registry viewer, not a
   place to invent data.

If a requested change conflicts with this list (e.g., "make it playful",
"add pastel gradients"), follow DESIGN.md §8 Do/Don't and flag the conflict
instead of silently complying.
