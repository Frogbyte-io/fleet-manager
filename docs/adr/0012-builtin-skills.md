# ADR 0012: Built-in skills ship with the controller and are assigned by default

Status: Proposed

Proposed: 2026-09-27 (FM-924). The two design choices were made by the maintainer on the issue on 2026-09-27; this record states them for review.

## Context

FM-924 ships an official `fleet` skill that teaches agents to drive this controller through `fleetctl --output json`. It must be versioned with the controller release and assigned to every machine by default, and that default must be removable.

Two existing boundaries shape how this can work:

- The skill catalog (FM-922) is caller-driven. Entries get UUIDv7 identities, drafts are editable through the API, and published versions are immutable and content-addressed.
- Skill assignments are `SkillPreset` resources in Fleet Git (ADR 0004, FM-923). The controller reads desired state; it never writes Git.

## Decision

1. **Seed at startup into a reserved identity.** The skill's `SKILL.md` is embedded in the controller binary (`include_str!`). On every start, before the listener binds, the controller upserts it into the catalog under the reserved id `builtin-fleet`:
   - it creates the entry when it is missing;
   - it replaces the draft when the release's content differs;
   - it publishes the release's immutable version (`builtin-fleet@<sha256>`) when that version does not exist, and re-points the entry's `publishedFrom` at it.

   An unchanged restart writes nothing. Each change is audited under the actor `system:fleet-controller`. This is the controller acting for itself at startup, not a request, so it is not authorized for a principal.

   Seeding is best-effort by design. A failure (for example an unreadable store) is logged, and the controller still serves: the rest of the product does not depend on the built-in skill. The catalog then lacks the built-in entry, or keeps the previous release's version, until the next start retries. A name conflict (decision 3) is logged the same way and is not retried as an error.
2. **Built-in entries are controller-managed.** Identities with the `builtin-` prefix cannot come from the API (uploads get UUIDv7 ids). The API refuses to update or publish them, with `409 conflict`. So a restart never overwrites operator work, and operator edits never fork a release's skill. Operators who want a different skill author their own catalog entry and assign that instead.
3. **An operator entry that already owns the name wins.** Catalog names are unique. If an operator entry is already called `fleet`, seeding creates nothing, touches nothing, and logs why. There is then no implicit assignment.
4. **The default assignment is implicit, and Fleet Git can opt out.** Desired-state composition (`with_builtin_assignments`) adds a global assignment of the built-in version to the default agents (`claude_code`, `codex`), unless Fleet Git already has a `SkillPreset` for that skill (by skill id or catalog id). Once Git names the skill, Git owns it completely:
   - Presets that narrow the scope or agents replace the default.
   - A preset with an empty `deployTo` removes the skill everywhere. The schema's `deployTo` minimum drops from 1 to 0 for this reason; an empty list means "Fleet manages this skill but deploys it nowhere".

   Because the controller never writes Git, a later release cannot re-add a skill that Git removed.
5. **The skill's commands cannot rot.** Every `fleetctl` command in the skill's code blocks must parse with `--output json` placed before the command word. The request each one sends is pinned in a snapshot test in the `fleetctl` crate.

## Consequences

- A controller upgrade that changes the skill publishes a new version. A downgrade re-points the entry at the older version, which already exists.
- The implicit default is a composition rule. It takes effect wherever desired state is composed. Fleet Git activation (M4) is not wired into the controller yet, so until then the rule and its tests are the contract. The seeded catalog entry and its versions are real now, and can be rolled out through the catalog API and the Skills console.
- The default agent list is a fixed release default. Machines whose agents differ are served by a Git `SkillPreset`.
- `bootstrap/fleet-bootstrap`, which documented the legacy `agents-registry`, is removed.

## References

- Issue [FM-924](https://github.com/Frogbyte-io/fleet-manager/issues/138)
- [Skill catalog architecture](../architecture/skills-catalog.md)
- [Desired state architecture](../architecture/desired-state.md)
