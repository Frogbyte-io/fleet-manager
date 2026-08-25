# ADR 0005: Narrow providers and public CLI boundaries

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

Fleet integrates many systems. Provider logic spread through UI/core would be untestable, while a universal plugin interface would erase useful domain semantics. Several preferred tools expose stable CLIs rather than libraries.

## Decision

Define narrow application ports by capability (connection, inventory, containers, infrastructure, skills, environment, source control, tools). Providers translate external types/errors and never orchestrate other providers. Use documented versioned JSON CLI contracts for Skills Manager, Frogenv, mise, Git, DevPod, and chezmoi; do not access their private databases or internal modules. Compile initial providers into controller/node binaries; no dynamic SDK initially.

## Consequences

- Contract fixtures and version probes are required for CLI adapters.
- Provider-specific fields do not leak into public core models unless deliberately namespaced metadata is needed.
- New external systems can be added without UI-specific business logic.
- A public/dynamic plugin model requires a later ADR.

## Rejected

- One `Provider` god trait.
- Hardcoding every tool installation in Fleet.
- Forking Skills Manager/Frogenv behavior or sharing their private state.
