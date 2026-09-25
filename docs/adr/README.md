# Architecture decision records

These records were proposed with the master plan and accepted on 2026-08-25 under [FM-000](../planning/fm-000-acceptance.md). An accepted decision is changed by a new superseding ADR, not an incidental implementation issue.

Accepting these ADRs did not close every open question inside them. The named spikes in [../planning/spikes.md](../planning/spikes.md) resolve implementation choices *within* the accepted boundaries; a spike may add a follow-up ADR, but it does not reopen the decision it serves.

The [2026-08-27 master-plan scope revision](../PLAN.md#confirmed-2026-08-27-product-scope-revision) changes release sequencing, initial deployment scope, and provider work while its design review continues. It does not retroactively rewrite this acceptance table. Any final revision that reverses an ADR decision requires a superseding ADR before implementation.

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
| [0010](0010-tailscale-serve-identity.md) | Optional Tailscale Serve request principal | Accepted | 2026-09-25 | — |

FM-S02 (authenticated authorization engine) is not scoped by an existing ADR. The trusted-LAN release needs the authorization port and explicit `anonymous-lan-admin` policy, but an embedded policy engine is deferred until authenticated deployment. FM-S02 is expected to produce ADR-0011 before that engine lands.
