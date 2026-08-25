# ADR 0006: Rust/Vue monorepo with staged migration

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

The current Node CLI is small and tested but has none of the target long-running/controller/node architecture. Separate repositories now would make protocols, releases, and cross-component changes harder. Frogenv has an independent product/security lifecycle.

## Decision

Use one Fleet Manager repository with a Cargo workspace for controller, `fleetd`, `fleetctl`, core/application/storage/auth/protocol/providers, and a pnpm workspace for Vue 3/TypeScript/Tailwind web and generated API client. Migrate the Node CLI under `legacy/` after preserving fixtures, then remove it only after explicit parity decisions. Frogenv remains external.

## Consequences

- One change can update protocol, binaries, web, generated clients, tests, and Compose.
- Rust supports shared typed core and cross-platform single-binary agents.
- Migration is outcome-by-outcome, not a big-bang line port.
- Nx/Turborepo and manually duplicated TypeScript DTO packages are unnecessary initially.

## Rejected

- Continue growing the local Node CLI into the controller architecture.
- Separate controller/node/CLI repositories before protocol stabilization.
- Absorb Frogenv into Fleet.
