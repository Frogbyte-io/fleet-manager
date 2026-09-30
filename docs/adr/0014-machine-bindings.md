# ADR 0014: Machines bind to profiles and projects by name

Status: Proposed

Proposed: 2026-09-30 (FM-410). Proposed for maintainer review; it refines, and does not reverse, ADR 0013 decision 6.

## Context

ADR 0013 plans only skill assignments because a `Machine` resource declares identity, groups, and tags but has no link to a `Profile` or `Project`. Tool versions and checkouts therefore cannot be composed per machine, and `compose_profile` has no runtime caller.

## Decision

1. **Binding by name.** `Machine.spec.profiles` and `Machine.spec.projects` are optional lists (default empty, at most 16 each) of `metadata.name` values of `Profile` and `Project` resources in the same revision. Names, not ids, because desired resources already reference each other by name (`Profile.extends`) and names are what authors write. Selectors by group or tag are not added: `SkillPreset` scopes already do that for skills, and per-machine binding keeps a plan explainable from one resource.
2. **Matching the runtime machine.** A `Machine` resource applies to the registered Fleet machine whose name equals the resource's `metadata.name` (machine names are unique at registration). No explicit `machineId` field is added. A registered machine with no matching resource, or a resource with no registered machine, is not an error: that machine simply has no bound profiles or projects and plans as before.
3. **Validation at activation.** Semantic validation over the candidate revision refuses an unknown profile or project name in a binding or in `extends` (`FM_SCHEMA_SEMANTIC_UNRESOLVED_REFERENCE`), a profile `extends` cycle (`FM_SCHEMA_SEMANTIC_PROFILE_CYCLE`), and a duplicate name within `Machine`, `Profile`, or `Project` (`FM_SCHEMA_SEMANTIC_DUPLICATE_NAME`), since names are now reference keys. Such a revision cannot become active. Requirement conflicts depend on composition and are refused when planning (`PlanningError::Composition`), for the affected machine only.
4. **Composition.** The bound profiles compose as one synthetic profile extending them, so `extends`, deny-wins-over-include, and conflict refusal apply across the whole binding and the result is independent of binding order. A profile `deny` removes requirements only within profile composition; a project tool is added afterwards and is not removed by it.
5. **Projects.** Each bound project adds its tools and, when it declares a `root`, a checkout of its normalized remote at that root. A project tool that disagrees with a profile or another project is a conflict. Several projects may be bound: `DesiredState.checkout` becomes `checkouts`, and each is compared independently. One remote at two roots, or two remotes at one root, is a conflict. Project `skills` are not composed (project-scoped deployment is out of scope here).
6. **Skills precedence.** Profile skill requirements become machine-scoped assignments joined with `SkillPreset` assignments before the built-in default is considered, so a profile that names the built-in skill takes it over like a preset does. Assignments union; a `SkillPreset` `denyAgents` entry that removes a profile-required skill refuses the plan rather than dropping it silently. Skill assignment scoping is otherwise unchanged.
7. **Capabilities are report-only.** A capability requirement the machine does not report as a `known` fact is an `unsupported` difference with no action; Fleet has no bounded way to provision one.
8. **Plans stay deterministic.** Bound values are sorted, provenance is recorded per requirement, and the plan id remains the digest of machine, revision, and ordered actions. No migration and no API change: plans gain `mise.install` and `projects.clone` actions.

## Consequences

- Editing a `Machine` resource's bindings changes that machine's plan and drift with the next activation.
- Every plan reads the machine, profile, and project resources of the active revision, bounded at 5,000 each.
- A machine renamed at runtime loses its bindings until the Git resource is renamed; the drift view shows the resulting removal of desired state.
- Alternatives left for later: group or tag selectors for bindings, an explicit `machineId`, and project skills.
