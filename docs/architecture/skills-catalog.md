# Fleet skill catalog

Fleet's catalog is the source of truth for Fleet-authored skill content and
references to externally maintained skills. Drafts are mutable; published
versions are immutable and identified by a SHA-256 digest over canonical
catalog metadata and the sorted authored file set.

The API validates Agent Skills frontmatter, path containment, content bounds,
and credential-shaped content before a draft is stored. SQLite stores both
drafts and published versions. Audit metadata records catalog identifiers and
actions only; skill source text never enters audit events.

Rollouts must refer to one immutable version and one target machine. The
controller stages authored content under a Fleet-owned directory, verifies it,
and invokes only the documented Skills Manager CLI contract. Fleet never edits
the Skills Manager database, its library directory, or agent-specific skill
directories directly. Referenced skills keep their upstream source and pinned
revision where available. Separate GitHub subpath and revision pins must both
be present; Fleet maps them to the documented `/tree/<revision>/<subpath>`
install form and never guesses a repository's default branch.

When an existing non-Git skill is rolled out, Fleet updates it only if the
Skills Manager JSON `source_ref` exactly matches the catalog reference. This
check parses the JSON with `jq`; if `jq` is unavailable or the source differs,
the rollout fails closed without removing and reinstalling the skill.
