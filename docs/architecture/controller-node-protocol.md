# Controller–node communication

Status: proposed

## Goals

- Work when the node has no inbound route or open port.
- Keep controller administrator/provider credentials off managed nodes and agents.
- Resume safely after disconnects, duplicate delivery, controller restart, and node restart.
- Preserve a path to Linux, Windows, and macOS without requiring Tailscale. The initial controller and `fleetd` release baseline is Linux. Windows guests initially expose only Proxmox lifecycle and QEMU Guest Agent observations; Windows `fleetd`, named-pipe broker, in-guest inventory/exec, and project readiness follow after the first Lab release.
- Version independently from the public Fleet API.

## Transport split

`fleetd` opens an outbound `wss://<controller>/api/node/v1/connect` connection over ordinary TLS. The channel carries a versioned binary envelope (protobuf is the recommended initial encoding) with a WebSocket subprotocol identifying the Fleet node protocol version. A node never listens on a Fleet TCP administration port.

Browser, CLI, and skill-driven agent traffic does not use this protocol. Public realtime uses SSE. Large artifacts and long log bodies use HTTP transfers linked to an operation ID rather than unbounded WebSocket frames; authenticated deployment may add caller credentials later.

## Enrollment and node identity

1. An authorized user creates a short-lived, single-use enrollment token scoped to an expected machine/profile and optional endpoint facts.
2. `fleetd` creates a node-local Ed25519 keypair in OS-protected service storage.
3. Over normal TLS, it submits the token, public key, platform facts, and protocol range.
4. The controller consumes the token, creates or confirms a Fleet machine ID, and returns a short-lived controller-signed node credential bound to the public key.
5. On later connections, the server sends a nonce. The node proves key possession and exchanges its credential for a short-lived session.
6. Rotation/revocation changes the controller credential without moving the private key. Re-enrollment is an explicit audited action.

The exact credential format requires a security review. The invariant is asymmetric proof with no reusable controller secret stored on the node. Tailscale identity or IP may strengthen association but never substitutes for Fleet enrollment.

## Session negotiation

`Hello` includes:

- Fleet machine ID and node software version
- Minimum/maximum supported protocol and inventory schema versions
- Boot/session ID and monotonically increasing local journal position
- OS/architecture and feature flags
- Last controller operation acknowledgement retained locally

The controller either selects compatible versions or sends a typed upgrade-required rejection. Minor additive fields must be ignored safely. Breaking semantic changes require a new protocol version and fixture coverage for at least the supported rolling-upgrade window.

## Message families

| Direction | Messages | Semantics |
|---|---|---|
| Node → controller | `Hello`, `Heartbeat`, `InventorySnapshot`, `InventoryDelta`, `CommandAck`, `Progress`, `Result`, `LogChunk`, `ProtocolError` | Observations and operation execution state |
| Controller → node | `Welcome`, `InventoryRequest`, `Command`, `Cancel`, `CredentialRotate`, `Drain`, `UpgradeNotice` | Bounded requested work and control |
| Either | `Ping/Pong`, flow-control acknowledgement | Liveness and backpressure |

Every command includes operation ID, command kind/schema version, deadline, idempotency key, actor/authorization context digest, output limits, and cancellation policy. Arbitrary shell is a distinct privileged command kind, not the substrate for every provider action.

## Delivery and recovery

- Delivery is at least once. Exactly-once claims are prohibited in documentation and UI.
- The controller owns operation truth; `fleetd` keeps a small durable journal of accepted command IDs and terminal results.
- A duplicate command returns the recorded acknowledgement/result or resumes the same idempotent execution. It never starts a second process silently.
- On reconnect, both sides reconcile journal positions and outstanding operations.
- Heartbeat timestamps determine connected/stale/offline state, but a missed heartbeat does not change desired state.
- Deadlines use controller wall time and node monotonic duration where possible. Cancellation is best effort and terminal results say whether the process/resource was actually stopped.
- Inventory snapshots are periodic baselines; deltas reference a baseline revision. A gap triggers a full snapshot.
- Backpressure limits in-flight commands, unacknowledged bytes, and log rate per node.

## Local agent path

The initial Linux `fleetd` exposes a local Unix domain socket whose OS permissions restrict callers. A later Windows implementation uses a named pipe with equivalent peer restrictions. `fleetctl` prefers the local route when invoked on a managed node and can ask the daemon to forward an allowed Fleet request using node/local-agent context.

```text
agent -> fleetctl -> local socket/pipe -> fleetd -> outbound WSS -> controller
```

The local API exposes a smaller allowlisted surface than the controller API. It cannot return controller/provider secrets. OS peer credentials identify the local account where supported. Direct-controller mode remains available to trusted-LAN callers and machines without `fleetd`; authenticated mode later adds explicit agent sessions and scopes.

## Commands and privilege

Node providers run under the least-privileged service account. Privileged actions require a platform-specific helper/allowlist rather than running all of `fleetd` as root/Administrator. Initial implementation may support a deliberately small privileged surface (service installation/update and selected package actions) and mark unsupported operations clearly.

Process execution requirements:

- Argument arrays by default; shell execution must be explicit in a reviewed recipe/action.
- Declared working directory resolved under an allowed project root.
- Clean, allowlisted environment plus just-in-time secret injection where authorized.
- Process-tree cancellation and timeout on every platform.
- Byte/time bounds for stdout/stderr, secret redaction, and artifact spillover.
- Caller/run-as identity, exit status, truncation, duration, and binary/provider version in the result.

## Agentless SSH parity

The SSH provider implements the same application-level `Probe`, `Inventory`, and `Execute` contracts, but it does not pretend to have realtime health, offline queuing, local agent delegation, or reliable cancellation after transport loss. Capability facts disclose these limits. “Install Fleet Node” upgrades the machine using a normal audited operation and one-time enrollment.
