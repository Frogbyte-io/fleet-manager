# ADR 0001: Controller-first modular monolith

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

Autonomous agents require machine and Lab control while developer laptops are offline. The current local CLI has no persistent control plane. The product also spans many domains, which creates pressure to split services prematurely.

## Decision

Run one persistent Fleet Controller as a self-hosted modular monolith. It serves the web app/API, node gateway, workers, and compiled controller providers. Domain/application/storage/provider boundaries exist as Rust crates and ports inside the process. Web, CLI, MCP, and a future desktop shell are API clients.

## Consequences

- `docker compose up -d` remains a viable default.
- Transactions, deployment, backup, and local development stay simple.
- Core logic cannot be placed in the desktop app or web UI.
- Independently deployed services require a future ADR supported by scale or isolation evidence.

## Rejected

- Desktop-first logic: unavailable when the laptop is off.
- Microservices: adds consistency/operations cost before scale evidence.
- Peer-to-peer nodes without controller authority: conflicts with leases, permissions, audit, and desired state.
