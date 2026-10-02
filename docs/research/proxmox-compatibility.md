# Proxmox endpoint compatibility

Endpoint inventory checked on 2026-10-02 against the provider on `dev` after FM-604, FM-607, FM-608 and FM-609. Paths are relative to `/api2/json`; placeholders name API parameters, not real infrastructure. Each method/path pair appears once. Dynamic config and lifecycle paths are expanded; query parameters do not create another endpoint. The task-history module is included because `lib.rs` delegates to it.

Documentation evidence: the official [PVE 8.x API viewer](https://pve.proxmox.com/pve-docs-8/api-viewer/) and [PVE 9.x API viewer](https://pve.proxmox.com/pve-docs/api-viewer/), using their generated schemas ([8.x apidoc.js](https://pve.proxmox.com/pve-docs-8/api-viewer/apidoc.js), [9.x apidoc.js](https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js)). ✅ means the HTTP method and endpoint are documented, ❌ means absent. Documentation coverage does not imply identical privileges or response shapes; see the [per-major token guide](../operations/proxmox-token.md#8x-vs-9x-differences) and [contract fixtures](../../crates/providers/fleet-provider-proxmox/tests/fixtures/README.md).

Live evidence combines the FM-600–FM-603 delivery summaries in the [M6 ledger](../planning/initial-issues.md#m6--proxmox-infrastructure-provider) with FM-613's redacted passing runs: [2026-10-01 nested fixtures](https://github.com/Frogbyte-io/fleet-manager/issues/215#issuecomment-5938954379), PVE 8.4.0 (`pve-manager/8.4.0/ec58e45e1bcdf2ac`) and a two-node PVE 9.2.2 cluster (`pve-manager/9.2.2/b9984c6d90a4bd80`), **11 pass, 0 fail, 1 skip**; [2026-10-02 physical host](https://github.com/Frogbyte-io/fleet-manager/issues/215#issuecomment-5962492229), PVE 9.2.2, **5 pass, 0 fail, 1 skip**. The single-node targets skipped partial-node failure; that scenario passed on the two-node 9.x cluster. No two-node 8.x cluster was tested. The optional live Windows check was not run because no Windows guest was reachable; Windows observations are covered by both majors' contract fixtures.

✅ means recorded live verification; — means no endpoint-specific live evidence is attributed here. The FM-611 suite's trust, association, task-polling and destructive-gate scenarios exercise the discovery/capacity, QEMU config/agent, start/shutdown, snapshot, clone and task-status paths. Its privilege-failure scenario reads effective permissions, and its direct PVE task-history reads verify completed tasks. LXC config and template conversion retain the earlier FM-601/FM-603 9.x evidence only. Stop, reboot, explicit remote task cancellation and next-ID checks remain —: cancelling a Fleet operation mid-poll leaves its remote task running and does not exercise `DELETE /nodes/{node}/tasks/{upid}`.

| Method | Path | Fleet use | PVE 8.x doc | PVE 9.x doc | Live 8.x | Live 9.x |
|---|---|---|:---:|:---:|:---:|:---:|
| GET | `/version` | Discovery and privilege-table version selection | ✅ | ✅ | ✅ | ✅ |
| GET | `/cluster/resources` | Cluster, node, storage, template and guest discovery; clone idempotency | ✅ | ✅ | ✅ | ✅ |
| GET | `/nodes/{node}/status` | Node capacity | ✅ | ✅ | ✅ | ✅ |
| GET | `/nodes/{node}/storage` | Storage capacity | ✅ | ✅ | ✅ | ✅ |
| GET | `/nodes/{node}/qemu/{vmid}/config` | QEMU configuration, MACs and OS hint | ✅ | ✅ | ✅ | ✅ |
| GET | `/nodes/{node}/lxc/{vmid}/config` | LXC configuration and MACs | ✅ | ✅ | — | ✅ |
| GET | `/nodes/{node}/qemu/{vmid}/agent/info` | Guest-agent health and Lab readiness | ✅ | ✅ | ✅ | ✅ |
| GET | `/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces` | Guest IP and MAC observations | ✅ | ✅ | ✅ | ✅ |
| GET | `/nodes/{node}/qemu/{vmid}/agent/get-osinfo` | Guest OS observations | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/status/start` | Lifecycle start | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/status/stop` | Lifecycle stop | ✅ | ✅ | — | — |
| POST | `/nodes/{node}/qemu/{vmid}/status/shutdown` | Lifecycle shutdown | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/status/reboot` | Lifecycle reboot | ✅ | ✅ | — | — |
| GET | `/nodes/{node}/qemu/{vmid}/snapshot` | Snapshot list and idempotency | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/snapshot` | Snapshot create | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback` | Snapshot revert | ✅ | ✅ | ✅ | ✅ |
| DELETE | `/nodes/{node}/qemu/{vmid}/snapshot/{snapname}` | Snapshot delete | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/clone` | Reviewed clone and Lab provisioning | ✅ | ✅ | ✅ | ✅ |
| POST | `/nodes/{node}/qemu/{vmid}/template` | Template conversion | ✅ | ✅ | — | ✅ |
| GET | `/nodes/{node}/tasks/{upid}/status` | UPID task polling | ✅ | ✅ | ✅ | ✅ |
| DELETE | `/nodes/{node}/tasks/{upid}` | Reviewed task cancellation | ✅ | ✅ | — | — |
| GET | `/access/permissions` | Token privilege diagnostics | ✅ | ✅ | ✅ | ✅ |
| GET | `/cluster/nextid` | Next free VMID; optional vmid query checks clone-target availability | ✅ | ✅ | — | — |
| GET | `/nodes/{node}/tasks` | Task history (src/tasks.rs) | ✅ | ✅ | ✅ | ✅ |

Fleet currently calls QEMU lifecycle and destructive endpoints. LXC config discovery is listed separately; corresponding LXC mutation endpoints are not called by this provider. Guest deletion used by the live test harness is also outside this provider inventory.
