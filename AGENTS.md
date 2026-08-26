# Fleet Manager agent guide

Fleet Manager is being redesigned as a controller-first developer fleet control plane. The current Node.js `agents-registry` package is legacy input to that redesign, not the target architecture.

Before implementing an issue:

1. Read `docs/PLAN.md`.
2. Read the architecture documents and proposed ADRs linked by the issue.
3. Inspect the code that exists at that time; do not assume the plan's suggested implementation is still optimal.
4. Search for existing domain abstractions and provider contracts before adding another one.
5. Research the relevant upstream API, CLI, library, and license using primary sources. Prefer a mature integration over recreating specialized behavior.
6. Write a short implementation approach in the issue or pull request before editing code.
7. Implement only the issue's goal and acceptance criteria. Preserve explicit non-goals.
8. Add or update unit, contract, integration, and documentation tests appropriate to the change.
9. Update architecture documentation or propose an ADR when a decision changes a documented boundary.

Rules:

- Issues define outcomes and constraints, not an infallible implementation recipe.
- Keep business rules in the application/core layers. The web UI, `fleetctl`, MCP server, providers, and HTTP handlers are adapters.
- Never store secrets in Fleet Git, logs, audit metadata, job payloads, fixtures, or command output.
- Treat remote execution, Docker access, Proxmox changes, recipes, skills, and project scripts as privileged or untrusted operations.
- All mutations require centralized authorization and an audit event. Do not authorize only in a UI or CLI.
- Provider-specific models must be translated at the provider boundary instead of leaking through the application.
- External CLI integrations use documented, versioned, machine-readable interfaces and contract tests. Do not read another tool's private database or internal files.
- Keep changes narrow enough to review and revert. Do not combine repository migration with unrelated product features.
- Write only inside the paths your issue owns. Other agents may be working concurrently; a drive-by fix in a shared file is the most common cause of a conflicted merge.
- Do not add Nx, Turborepo, microservices, PostgreSQL, a dynamic plugin SDK, or another package/configuration/secrets manager without an approved ADR and demonstrated need.

Canonical planning documents:

- `docs/PLAN.md` — product direction, milestones, dependencies, and epics
- `docs/architecture/` — subsystem boundaries and invariants
- `docs/adr/` — decisions that require explicit review before reversal
- `docs/planning/initial-issues.md` — issue-ready work for the first milestones
- `docs/planning/parallel-execution.md` — execution waves, path ownership, and rules for concurrent agents
- `docs/research/ecosystem.md` — researched integrations and evidence
