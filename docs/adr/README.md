# Architecture decision records

These records were proposed with the master plan and accepted on 2026-08-25 under [FM-000](../planning/fm-000-acceptance.md). An accepted decision is changed by a new superseding ADR, not an incidental implementation issue.

Accepting these ADRs did not close every open question inside them. The named spikes in [../planning/spikes.md](../planning/spikes.md) resolve implementation choices *within* the accepted boundaries; a spike may add a follow-up ADR, but it does not reopen the decision it serves.

| ADR | Decision | Status | Accepted | Open spikes |
|---|---|---|---|---|
| [0001](0001-controller-first-modular-monolith.md) | Controller-first modular monolith | Accepted | 2026-08-25 | — |
| [0002](0002-api-and-protocol-split.md) | OpenAPI HTTP/SSE public API and separate outbound WSS node protocol | Accepted | 2026-08-25 | FM-S01 |
| [0003](0003-node-identity-and-local-broker.md) | Fleet-owned node identity and constrained local daemon broker | Accepted | 2026-08-25 | FM-S04 |
| [0004](0004-state-and-secret-ownership.md) | Git desired state, SQLite runtime state, encrypted referenced secrets | Accepted | 2026-08-25 | — |
| [0005](0005-provider-and-external-cli-boundaries.md) | Narrow provider ports and public CLI integrations | Accepted | 2026-08-25 | FM-S05, FM-S06, FM-S07, FM-S08 |
| [0006](0006-rust-vue-monorepo-migration.md) | Rust/Vue monorepo with staged legacy migration | Accepted | 2026-08-25 | — |
| [0007](0007-sqlite-single-controller.md) | SQLite and one active controller initially | Accepted | 2026-08-25 | — |
| [0008](0008-durable-operations-and-lab-leases.md) | Durable operations and explicit Lab lease/reservation state machines | Accepted | 2026-08-25 | FM-S03 |

FM-S02 (embedded authorization engine) is not scoped by an existing ADR. It is expected to produce ADR-0009 before M1 authorization code lands.
