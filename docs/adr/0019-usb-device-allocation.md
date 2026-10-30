# ADR 0019: USB devices are allocated exclusively through Proxmox resource mappings

Status: Proposed

Proposed: 2026-10-28 (epic [#16](https://github.com/Frogbyte-io/fleet-manager/issues/16); plan in [`docs/planning/m11-usb-hardware.md`](../planning/m11-usb-hardware.md)). Maintainer decisions on the plan's open questions are recorded in the plan (2026-10-30). It extends the reservation and compensation rules of [ADR 0008](0008-durable-operations-and-lab-leases.md), the provider boundary of [ADR 0005](0005-provider-and-external-cli-boundaries.md) and the persistent machines of [ADR 0018](0018-persistent-machines.md); it reverses none of them. Mapping and inventory shapes were confirmed read-only on PVE 9.2.2; the remaining behaviours are listed as unconfirmed in the plan and settled by spike FM-S11 (including PVE 8.4), which may amend this ADR.

## Context

Lab leases reserve capacity (cores, memory, disk) transactionally before any Proxmox call. Physical USB devices are different: they are exclusive, they belong to one node, a guest that holds one cannot be live-migrated, and Proxmox identifies them in two ways of very different stability. A plain `usbN: host=<vendor>:<product>` cannot tell two identical devices apart, and `host=<bus>-<port>` follows the physical port, not the device. Proxmox also offers cluster resource mappings (`/cluster/mapping/usb`) that give a device a stable, operator-chosen name and let non-root users attach it with `Mapping.Use`. A device may already be attached by hand (the Dot X test device is on VM 200 today), so Fleet cannot assume it owns every device it can see.

## Decision

1. **Identity is the mapping.** A Fleet hardware device is bound to one PVE USB resource mapping (account, mapping id). Fleet attaches only with `usbN: mapping=<id>`; it never writes `host=` for a Fleet-managed device. Observed facts (vendor:product, `usbpath`, node, present or missing) are recorded and compared with the expected fingerprint immediately before an attach, but they do not name the device. The node inventory (`GET /nodes/{node}/hardware/usb`, confirmed on PVE 9.2) returns no serial. Identical devices on one node need separate path-based (`path=<bus-port>`) mappings, so their identity is a port: swapping cables swaps them. Fleet does not create or edit mappings in the first release; the operator does, so Fleet needs no `Mapping.Modify`. The privileges Fleet does need (`Mapping.Use`, `VM.Config.HWType`) live in a separate opt-in token role.
2. **Reserve in the database first.** A hardware reservation row (owner kind `lease` or `machine`) is inserted in one `BEGIN IMMEDIATE` transaction before any Proxmox call. A partial unique index over live states makes two live holders of one device impossible. The owner's state is authoritative, as for capacity reservations: a lost release write never strands a device.
3. **Attach is a saga with compensation.** Reserve, verify the device is present and no other guest references it, write `usbN` conditional on the config digest, read back, mark attached. A failure removes the entry, reads back, and only then releases. An outcome that cannot be determined keeps the reservation held (`attach_unknown`) for the reconciler; it is never released on a guess.
4. **Hotplug follows the same saga.** A lease holder may attach a device the lease reserved to its running guest, or detach it, mid-run. A running-guest write that PVE leaves `pending` is reported as pending, never as attached.
5. **Detach precedes every guest fate.** Lab cleanup detaches before destroy or snapshot revert, and a failed detach keeps the reservation held and the lease in cleanup retry, as a failed destroy keeps capacity.
6. **Fleet does not steal.** A device referenced by a guest Fleet did not attach is `externally_attached`. It is not allocatable until an audited adoption or until the reference disappears. A conflict fails the lease request with the holder named (`hardware_busy`); queueing is a later, separate decision.
7. **Explicit unsupported states.** A device or host is `unsupported` with a stable reason (no mapping entry for the node, token lacks `Mapping.Use` or `VM.Config.HWType`, PVE too old, inventory unreadable) rather than being silently skipped. USB host passthrough is not expected to need IOMMU, so none is required by this ADR (FM-S11 confirms); whole-controller (PCI) passthrough is out of scope.
8. **Reconciliation compares four sources:** reservations, guest configs across the account's cluster, mapping definitions, and the node's USB inventory. It repairs only what Fleet itself attached, reports everything else, and never detaches a device from a guest it did not attach.
9. **Authorization and audit.** Attach, detach, adopt and release-override are mutations with their own catalog entries and audit events; delegated Lab credentials (ADR 0011) get only the lease-bound path. Overriding a held reservation is an elevated, audited action, not a normal release.
10. **Records are runtime state.** Device records and reservations live in SQLite; what a lease needs is declared in the Lab template in Fleet Git by mapping id. A serial is not a secret, but fixtures and screenshots must not publish real hardware serials or hostnames.

## Consequences

- A device that is not in a PVE mapping is invisible to allocation. The operator creates mappings; a runbook documents it.
- Guests holding a mapped device are expected not to be live-migratable or HA-relocatable across nodes; a template that needs hardware pins placement to the node with a mapping entry.
- Reservation-before-call can leave a held reservation with no attachment after a crash; that is by design and the reconciler resolves it.
- Live tests need a spare device or an agreed window; the existing Decker mapping serves manual Dot X work and stays external; live tests use the spare SuperDrives and Verbatim device.
- A new migration and a new catalog family are needed; no new crate, queue, or plugin interface.

## Rejected

- `host=vendor:product` or `host=bus-port` as Fleet's identity: ambiguous with identical devices, and unstable across replug.
- Discovering devices by reading another tool's state or the host's udev database from Fleet code; inventory comes from the Proxmox API.
- Creating mappings automatically: it needs `Mapping.Modify` on the cluster and decides naming for the operator.
- In-memory or lock-based exclusivity, and best-effort detach at lease expiry.
- Stealing a device from a manually attached guest.
