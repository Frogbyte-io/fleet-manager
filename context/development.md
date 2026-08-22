# Development context

- This repo is itself the `agents-registry` implementation: a Node.js CLI
  (`bin/agents-registry.js`) plus declarative YAML under `machines/`,
  `roles/`, `packs/`, `devices/`, `projects/`, `test-profiles/`.
- Schema reference: `docs/schema.md`.
- Run `npm test` before pushing changes to `src/` — it's the resolution
  engine and registry loader's only safety net.
- Run `agents-registry validate` after editing any YAML under those
  directories — it catches unknown role/pack/device references, id/filename
  mismatches, and duplicate ids before they reach `sync`.
- Don't hand-write skill installation logic here. `agents-registry` resolves
  *desired* state only; installing/updating skills is delegated to an
  external skills CLI (see `src/skillsBackend.js`) so this repo doesn't
  duplicate that tool's logic.
