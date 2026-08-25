# ADR 0003: Fleet-owned node identity and local broker

Status: Accepted  
Proposed: 2026-08-25  
Accepted: 2026-08-25 (FM-000)

## Context

Tailscale is preferred but optional. Nodes often lack inbound routes. Agents should not hold powerful controller credentials, and a compromised node must not impersonate an administrator or another node.

## Decision

`fleetd` creates a node-local asymmetric key, enrolls with a short-lived single-use token, proves key possession, and opens an outbound authenticated WSS session. Tailscale and SSH endpoints are associations, not Fleet identity. A constrained Unix socket/named pipe lets local `fleetctl`/agents use the daemon as a least-privileged broker.

## Consequences

- Nodes need no Fleet inbound port.
- Reinstall/rotation/revocation and duplicate machine association require explicit workflows.
- The local broker surface and OS peer permissions require cross-platform security tests.
- Direct-controller CLI auth remains available for administrators.

## Rejected

- Tailscale IP/name as the primary Fleet ID.
- Shared bearer token copied to every node/agent.
- Root/Administrator general-purpose local Fleet socket.
