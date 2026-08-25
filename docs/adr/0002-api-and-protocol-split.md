# ADR 0002: Separate public API and node protocol

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

Web/CLI/MCP need stable resource-oriented requests, while `fleetd` needs bidirectional command delivery, reconnect, inventory deltas, and rolling upgrades. A single protocol would couple incompatible clients and lifecycles.

## Decision

Use versioned HTTP/JSON with OpenAPI for the public API and SSE for resumable progress/resource notifications. Use a separately versioned, outbound WebSocket binary protocol for controller–node sessions. Long mutations return durable operation IDs. Large artifacts use HTTP.

## Consequences

- TypeScript clients are generated; `fleetctl` JSON matches public DTOs.
- Node protocol compatibility can evolve independently.
- SSE is sufficient for public one-way updates; WebSocket complexity is limited to the bidirectional node channel.
- Domain/application types remain independent of both wire formats.

## Rejected

- Public clients talking directly to providers or nodes.
- One ad-hoc JSON WebSocket for every interface.
- Holding HTTP requests open for VM/Lab workflows.
