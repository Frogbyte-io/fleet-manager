# M11 — USB hardware inventory and exclusive allocation

Status: planned (2026-10-28), not started. Epic: [#16](https://github.com/Frogbyte-io/fleet-manager/issues/16) (filed under M7, which closed without it; see [m7-acceptance.md](m7-acceptance.md#deferred-usb-and-hardware-sub-epic-16)). Proposed milestone: **M11**, because M7 is closed and M10 is the latest. Boundaries: [ADR 0019](../adr/0019-usb-device-allocation.md) (Proposed), [ADR 0008](../adr/0008-durable-operations-and-lab-leases.md), [ADR 0018](../adr/0018-persistent-machines.md), and the "Later USB and physical resources" and FM-715 sections of [lab.md](../architecture/lab.md).

## Goal

A physical USB device is inventoried under a stable identity, can be exclusively reserved by one Lab lease or one persistent machine, is attached to exactly that guest, and is always detached again, with compensation when either side fails. The Dot X case is the motivating one: a Decker device must reach a test VM for a run and go back afterwards, with nobody moving it by hand.

It also delivers what #16 asks for: the documented hardware-in-the-loop workflow, and an explicit unsupported state instead of an untested "exclusive" claim (lab.md forbids shipping one).

## What is verified and what is not

From the Proxmox VE documentation ([USB passthrough in the qm chapter](https://pve.proxmox.com/pve-docs/chapter-qm.html), [USB devices in virtual machines](https://pve.proxmox.com/wiki/USB_Devices_in_Virtual_Machines), read 2026-10-28):

- `usb[n]: [[host=]<HOSTUSBDEVICE|spice>][,mapping=<mapping-id>][,usb3=<1|0>]`. `host` is a `bus-port` path, a `vendor:product` hex ID, or `spice`; `mapping` is "the ID of a cluster wide mapping"; one of `host` or `mapping` is required. `usb3` defaults to 0 and is irrelevant for newer guests, which attach everything to an xhci controller. `n` is 0 to 4 (up to 14 on machine version 7.1+ with Linux or newer Windows).
- A configured device that is missing at VM start does not stop the VM; it is passed through once it appears on the host.
- Host passthrough ties the VM to the host: "it is no longer possible to migrate such machines". The documentation says nothing for `mapping`, so it is treated as not migratable until the spike shows otherwise.
- The wiki says the lsusb "Device" number changes on replug, vendor:product identifies the model only (identical devices cannot be told apart), and the bus-port path identifies the physical port. Running VMs accept hotplug; on the wiki's QEMU-monitor route, deleting a config entry "does not remove the usb device from a running VM". The API behaviour must be measured (FM-S11).
- Resource mappings give a device a stable, user-chosen ID that can map to different hardware on different nodes. Creating needs `Mapping.Modify` on `/mapping/<type>/<name>`; using needs `Mapping.Use` on the same path, in addition to normal guest privileges. "You can currently only map one USB device per node per mapping." Each node needs its own `map` entry.
- USB host passthrough is a QEMU `usb-host` device on the host's USB stack. It does **not** need IOMMU or VT-d, unlike PCI passthrough (stated from general knowledge of the mechanism; the pages read do not discuss it, and FM-S11 confirms it on the integration host, whose IOMMU is off). The epic's "IOMMU validation" therefore becomes "host validation" here: IOMMU matters only for passing a whole USB controller (PCI), which is a non-goal.

Confirmed by read-only checks on the integration host (PVE 9.2.2, 2026-10-28; PVE 8.4 still to be checked by FM-S11):

- `pvesh get /cluster/mapping/usb` returns `[{"id":"decker","type":"usb","description":…,"digest":…,"map":["node=pve,id=04d8:e626"]}]`; the per-mapping GET returns the same without `id`. A map entry is `node=<node>,id=<vendor:product>`; PVE also supports `path=<bus-port>` entries, which the plan uses for identical devices (the field list is from the PVE mapping schema; FM-S11 records a path entry on the host).
- `GET /nodes/<node>/hardware/usb` lists `busnum`, `devnum`, `level`, `port`, `usbpath`, `vendid`, `prodid`, `manufacturer`, `product`, `speed` and `class`. It has **no serial**, so inventory and the pre-attach fingerprint use vendor:product plus `usbpath` and never a serial.
- VM 200 carries `usb0: mapping=decker,usb3=1`: the `externally_attached` case, on a real guest.
- The host also has unused devices: two identical "MacBook Air SuperDrive" (05ac:1500, `usbpath` 10 and 7 on bus 1) and a "Verbatim" device on bus 5. The identical pair is a real case for path-based mappings.

Still not confirmed (items 1 and 2 of the earlier list are now settled on 9.2 above). FM-S11 must settle each on the integration host, on PVE 8.4 and 9.2, before the dependent issues start:

1. The 8.4 shapes of `/cluster/mapping/usb` and `/nodes/{node}/hardware/usb`; whether `Mapping.Audit` is needed to list as a non-root token; the exact `path=` entry syntax and how PVE resolves a path entry versus an `id=` entry when several devices match.
2. Whether `usbpath` is stable across replug and host reboot for the SuperDrive pair (it is the identity of a path-based mapping).
3. Whether an API token, which cannot be `root@pam`, may write `usbN: host=…` at all. The documentation we read implies raw host devices are root-only; if so, mappings are the only path for Fleet, which the ADR already assumes.
4. Behaviour of `PUT …/config` with `usbN=mapping=<id>` and `delete=usbN` on a **running** guest (immediate hotplug and unplug, or `pending` until restart), and which privileges it checks (`VM.Config.HWType`, `Mapping.Use`).
5. What happens when a guest starts with a mapped device absent, or on a node the mapping has no entry for, and whether a second guest can reference a mapping already held (assumed not prevented by PVE, which is why Fleet must).
6. Whether snapshot and rollback carry or drop `usbN`, and whether a clone inherits it from a template.
7. Whether live migration or HA is refused for a guest with `mapping=`.

## Decisions (proposed; ADR 0019 records the boundaries)

- **Identity is the PVE resource mapping**, never `host=vendor:product` or `bus-port`. Observed facts are a fingerprint checked immediately before an attach, not the name. The node inventory exposes no serial at all, so the fingerprint is vendor:product plus `usbpath`. Identical devices on one node get separate path-based mappings (`path=<bus-port>`), one per physical port.
- **Operators create mappings**; Fleet reads them. No `Mapping.Modify` in the first release.
- **Reserve first, call second.** One `BEGIN IMMEDIATE` transaction, a partial unique index over live states, and the owner's state authoritative, mirroring `lab_capacity_reservations` (FM-715).
- **Attach happens during provisioning**, in the existing hardware step after the clone and unprotect and before start, as a digest-conditional config write that does not depend on hotplug. Persistent machines use an explicit reviewed attach and detach that may hotplug (the Decker already hotplugs on VM 200).
- **Detach precedes any guest fate** (destroy, revert, return to pool). A failed detach keeps the reservation held and the lease in cleanup retry.
- **No stealing.** A device referenced by a guest Fleet did not attach is `externally_attached` and not allocatable until adopted (audited) or released by the operator.
- **Conflicts fail fast in v1** with `hardware_busy` and the holder named. lab.md says conflicts queue, but placement refuses today; queueing is a later issue, not smuggled in.
- **The reconciler reports, and repairs only its own attachments.**

## The model

### Device inventory

`hardware_devices` (SQLite, runtime): Fleet UUID, account, `mapping_id`, `kind = usb`, per-node observed entries (node, vendor:product, `usbpath`, manufacturer and product strings, last seen; no serial, the API does not return one), derived `status`, and an operator note. Rows are created by a refresh that lists `/cluster/mapping/usb` and the nodes' USB inventory, and are never deleted while a reservation exists.

| `status` | Meaning |
|---|---|
| `available` | Mapping valid, an entry exists for the node, the device was seen recently, nothing references it |
| `reserved` | A live Fleet reservation holds it |
| `externally_attached` | A guest references the mapping and Fleet has no reservation for it |
| `missing` | Mapping exists, device not seen on the node (unplugged, host down) |
| `unsupported` | Cannot be allocated; carries a reason: `no_node_entry`, `ambiguous_mapping`, `token_lacks_mapping_use`, `token_lacks_guest_hwtype`, `pve_too_old`, `usb_inventory_unreadable` |
| `quarantined` | A failed or unknown attach or detach needs the reconciler or an operator |

Host capability is evaluated per (account, node) from the token's effective permissions (FM-604 already reads them) and the PVE version, so `unsupported` is explained, not guessed. Observations older than a configured bound count as stale, as for capacity.

### Reservation

`lab_hardware_reservations` (a migration after 0066): id, device id, owner kind (`lease` or `machine`), owner id, state, guest account/node/VMID and `usbN` slot once known, timestamps. States: `held` → `attaching` → `attached` → `detaching` → `released`; side states `attach_unknown`, `detach_failed`. A partial unique index on `device_id` where state is not `released` makes a double hold impossible. A lease reservation is released by cleanup; a machine reservation by an explicit detach.

### Attach and detach saga

```text
reserve (DB) -> verify (device present on node, fingerprint matches, no guest references the mapping)
  -> write usbN=mapping=<id> (digest-conditional) -> read back -> attached
failure after reserve: delete usbN -> read back -> released
unknown outcome: stay attach_unknown, reconciler reads the guest config
```

Detach: delete `usbN`, read back, confirm the guest config no longer references the mapping, release. A running guest that keeps the device until restart is a reported state, not a silent success (FM-S11 decides how). Every step is an operation step with audit, runs inside the lease's existing provision and cleanup operations, and is idempotent by (reservation id, step).

### Reconciliation

The sweeper (and a startup pass) compares: reservations, every guest config in the account's cluster that carries a `mapping=` USB entry, mapping definitions, and node inventory. Outcomes: a held reservation with no entry and no live owner step is released; an entry Fleet recorded for a released reservation is removed; an entry with no Fleet record marks the device `externally_attached` and is reported, never removed; a reservation whose guest is gone is released. The invariant from lab.md: never a device reserved by two live leases, never a released lease whose device is still silently assigned.

### Permissions and audit

New catalog entries, none granted to delegated Lab credentials except the lease-bound path: `hardware.read`, `hardware.refresh`, `hardware.adopt`, `hardware.override-release` (elevated), `machines.usb.attach` and `machines.usb.detach` (reviewed, payload-bound). PVE privileges the token needs, added to the privilege table: `Mapping.Use` on `/mapping/usb/<id>` and `VM.Config.HWType` on the guest. Events: `hardware_reserved`, `hardware_attached`, `hardware_detached`, `hardware_released`, `hardware_attach_failed`, `hardware_refused`, `hardware_externally_attached`, `hardware_adopted`.

### Lab declaration

The Lab template in Fleet Git gains an optional `hardware: [{ kind: usb, mapping: <id> }]`. Placement fixes the node to a mapping entry's node and intersects it with the clone's node constraint; a conflict is a refusal naming both. Groups or labels ("any Decker") are deferred.

## The real test device

PVE USB mapping `decker` (04d8:e626) is defined on the integration host and currently attached by hand to VM 200 (`dotx-ubuntu`) for Dot X testing; the maintainer moves it with `qm set`. The plan therefore:

- never assumes it can move: development tests use the fake PVE harness (`crates/fleet-controller/tests/support/fake_pve.rs`) and recorded fixtures;
- treats the manual attachment as the first `externally_attached` case in tests and the runbook;
- requires the maintainer's go for any live step that touches it (FM-S11 reads only unless told otherwise; FM-1133 attaches). The host has spare devices: two identical "MacBook Air SuperDrive" (05ac:1500) and a "Verbatim" device. Live validation uses the SuperDrives (also exercising path-based mappings), with the maintainer's consent to create test mappings (`Mapping.Modify`, done by the maintainer, not by Fleet);
- needs the maintainer to detach the device from VM 200 (`qm set 200 --delete usb0`) when a live run starts, since Fleet will not steal it.

## Issues

IDs follow the M10 series (FM-11xx). Routing follows the usual split; codex holds at most half (5 of 15 here). These are drafts to file against #16 and milestone M11; none is created yet.

| ID | Issue | Agent | Depends on |
|---|---|---|---|
| FM-1100 | Accept the plan and ADR 0019; PLAN.md M11 section | claude | — |
| FM-S11 | Spike: PVE USB mapping API, hotplug, privileges, and migration behaviour | claude | FM-1100, maintainer window |
| FM-1101 | Hardware domain types and storage (devices, reservations) | codex | FM-1100 |
| FM-1110 | Proxmox provider: mapping and node USB reads with fixtures | glm | FM-S11 |
| FM-1111 | Hardware inventory service, support states, API and `fleetctl hardware` read | codex | FM-1101, FM-1110 |
| FM-1120 | Transactional reservation store and refusal rules | codex | FM-1101 |
| FM-1121 | Template `hardware` declaration, placement, and lease request | claude | FM-1120, FM-1111 |
| FM-1122 | Proxmox provider: attach and detach `usbN` with digest and read-back | glm | FM-S11 |
| FM-1123 | Lab saga: attach in provisioning, detach in cleanup, with compensation | claude | FM-1121, FM-1122 |
| FM-1124 | Hardware reconciler in the sweeper | codex | FM-1123, FM-1111 |
| FM-1125 | Persistent machine attach and detach actions | claude | FM-1120, FM-1122, ADR 0018 |
| FM-1130 | Failure-injection and double-lease tests for hardware | codex | FM-1123, FM-1124 |
| FM-1131 | Hardware view in the console | claude | FM-1111, FM-1121 |
| FM-1132 | `fleet` skill and docs: hardware reads and requesting a lease with hardware | glm | FM-1111, FM-1121 |
| FM-1133 | Hardware-in-the-loop runbook and live validation | claude | FM-1123, FM-1124, FM-1130, maintainer window |

Waves: FM-1100 → FM-S11 and FM-1101 → FM-1110, FM-1120, FM-1122 → FM-1111, FM-1121, FM-1125 → FM-1123 → FM-1124, FM-1131, FM-1132 → FM-1130 → FM-1133. The read path (FM-1111) delivers an honest inventory and unsupported states before any attach exists, and is shippable alone.

### Draft issues

Common to all: read `AGENTS.md`, this document and ADR 0019; no secrets in logs, audit, fixtures; every mutation is authorized centrally and audited; provider models stay in the provider crate; no real device serial, hostname or IP in fixtures.

**FM-1100 — Accept the plan and ADR 0019** (claude). Goal: maintainer review of this plan and the ADR; add an M11 section to `docs/PLAN.md`, update the #16 body, create milestone M11, and file the issues below. Owned: `docs/PLAN.md` (M11 section only), `docs/adr/0019-*`, `docs/adr/README.md`, `docs/planning/m11-usb-hardware.md`. Acceptance: open questions answered or turned into spike scope; ADR status Accepted with a date, or revised. Non-goals: any code. Tests: docs link check in CI.

**FM-S11 — Spike: PVE USB mapping behaviour** (claude). Goal: answer the seven unconfirmed questions with measurements, on PVE 8.4 and 9.2 (nested fixtures), using a device the maintainer designates or a virtual USB device on a throwaway guest. Owned: `docs/research/proxmox-usb.md`, `docs/research/fixtures/proxmox-usb/**` (recorded JSON), amendments to the ADR. Acceptance: each question has a recorded request, response and version; the ADR is amended where reality differs; the semantics of detaching from a running guest are stated. Non-goals: product code; moving the Decker without the maintainer. Tests: fixtures are sanitized and parse in the follow-up provider tests.

**FM-1101 — Hardware domain types and storage** (codex). Goal: the types and tables everything else uses. Owned: `crates/fleet-core/src/hardware.rs`, `crates/fleet-application/src/hardware.rs` (port only), `crates/fleet-storage-sqlite/migrations/00NN_hardware.sql` and its store module. Acceptance: `HardwareDevice`, `DeviceStatus` with reasoned `unsupported`, `HardwareReservation` and its state machine with legal-transition tests; STRICT tables with the partial unique index on live reservations; round-trip store tests; the migration is additive. Non-goals: provider calls, API. Tests: state-machine unit tests, store tests including the double-hold constraint violation, migration applies on a database with data.

**FM-1110 — Proxmox provider: mapping and USB inventory reads** (glm). Goal: read `/cluster/mapping/usb` and the node USB inventory and translate to provider-owned shapes. Owned: `crates/providers/fleet-provider-proxmox/src/usb.rs` and its tests; one `mod usb;` line in `lib.rs`. Acceptance: tolerant parsing (malformed entries isolated into warnings, bounded lists), version-specific shapes per the spike, errors classified (permission, endpoint absent on old PVE, unreadable). Non-goals: any write. Tests: contract tests on the FM-S11 fixtures for 8.4 and 9.2, malformed and oversized answers.

**FM-1111 — Inventory service, support states, API and CLI read** (codex). Goal: refresh and list devices with explained status. Owned: `crates/fleet-application/src/hardware_inventory.rs`, controller wiring in `crates/fleet-controller/src/hardware_*.rs`, `crates/fleet-api/**` routes and OpenAPI for `GET /hardware/devices` and `POST /hardware/refresh`, the `hardware` subcommand in `crates/fleetctl/**`, regenerated client. Acceptance: statuses per the table above; `externally_attached` computed from all guest configs in the account; `unsupported` reasons from token permissions and version; refresh is an authorized, audited mutation; `fleetctl hardware list --output json` matches the API. Non-goals: reservation, attach. Tests: fake-PVE scenarios for each status, permission refusal, stale observation, API/CLI contract tests, OpenAPI drift check.

**FM-1120 — Transactional reservation store** (codex). Goal: reserve and release devices with the guarantees of ADR 0019 decision 2. Owned: `crates/fleet-controller/src/hardware_reservation_store.rs`, `crates/fleet-application/src/hardware_reservation.rs`. Acceptance: one `BEGIN IMMEDIATE` transaction checks device status and inserts; a repeat for the same owner returns the existing row; a second owner gets `hardware_busy` naming the holder; a row whose owner lease no longer counts is released first (as FM-715 does); refusal and release are audited best-effort in the way capacity events are. Non-goals: calling Proxmox. Tests: concurrent reservation race (many tasks, one winner), lease-state-authoritative release, restart idempotency, property test over transitions.

**FM-1121 — Template declaration, placement, lease request** (claude). Goal: a lease can ask for hardware. Owned: the hardware field of the template in `crates/fleet-core/src/lab.rs`, `crates/fleet-schema/**` and `schemas/**` for that field, the hardware rule in `crates/fleet-application/src/lab_placement.rs`, lease request/response fields, the USB section of `docs/architecture/lab.md`. Acceptance: `hardware` is validated; placement fixes the node from the mapping entry, intersects with the clone's node, and refuses with a message naming the constraint; the reservation is taken in the placement step with the same compensation as capacity; leases without hardware are unchanged. Non-goals: queueing; device groups. Tests: placement unit tests (no entry, wrong node, busy, unsupported), schema validation, no regression in existing placement tests.

**FM-1122 — Provider attach and detach** (glm). Goal: write and remove `usbN=mapping=` with the safety the guest config path already has. Owned: `crates/providers/fleet-provider-proxmox/src/usb_attach.rs`, privilege-table rows in `permissions.rs`. Acceptance: reads the config, checks the guest is not a template, picks a free `usbN` slot, writes conditional on the digest, reads back and returns what it saw; delete is the symmetric call; both are idempotent and report a running-guest `pending` state per the spike; a slot Fleet did not write is never deleted. Non-goals: Lab orchestration. Tests: fake-PVE tests for digest conflict, locked guest, full slots, running guest, refused privilege; fixture contract tests.

**FM-1123 — Lab saga: attach and detach with compensation** (claude). Goal: the end-to-end Lab behaviour. Owned: `crates/fleet-controller/src/lab_hardware.rs`, minimal hooks in the provision executor and `lab_cleanup.rs` (each hook one call). Acceptance: attach after the existing hardware step and before start, verified against the fingerprint; any failure removes the entry and releases, or leaves `attach_unknown`; cleanup detaches before destroy or revert and a failed detach keeps the reservation and the lease in cleanup retry; pool members detach before return and are quarantined when detach cannot be confirmed; audit events are written. Non-goals: persistent machines; hotplug during a run. Tests: fake-PVE end-to-end lease with a device, each failing step, cancel during attach, destroy refused while detach is unconfirmed.

**FM-1124 — Hardware reconciler** (codex). Goal: converge the database and Proxmox after crashes and manual changes. Owned: `crates/fleet-controller/src/hardware_reconciler.rs`, one registration in the sweeper. Acceptance: outcomes per the Reconciliation section; startup and periodic passes; repairs only Fleet-attached entries; other findings reach the inventory status; idempotent and bounded per run. Non-goals: adopting manual attachments automatically. Tests: table-driven reconciliation over (reservation state × config × inventory × lease state), restart mid-attach, an entry on a foreign guest left untouched.

**FM-1125 — Persistent machine attach and detach** (claude). Goal: reserve a device for a persistent machine until explicitly detached (ADR 0018). Owned: `crates/fleet-controller/src/machine_usb.rs`, API routes `/machines/{id}/usb/*` with review and execute, `fleetctl machines usb`. Acceptance: reviewed, payload-bound routes with the new catalog entries; refuses a machine without a guest link, or a guest that is a Lab clone, template or pool member; hotplug per the spike; destroy and unregister of the machine are refused while a reservation is held. Non-goals: lease semantics; adopting the existing manual Decker attachment (that is `hardware adopt`, exercised in the runbook issue). Tests: review-token binding, refusals, attach and detach, double-attach conflict with a lease.

**FM-1130 — Failure-injection and double-lease tests** (codex). Goal: the release gate lab.md requires: no device reserved twice, no released lease with a silently assigned device. Owned: `crates/fleet-controller/tests/lab_hardware_failure_injection.rs`, support in `tests/support/**` (append only). Acceptance: the controller is killed at reserve, after verify, after write, after read-back, at ready, at TTL expiry, and at detach; each recovers to a valid owned attachment or to nothing; two competing leases serialize. Non-goals: live hardware. Tests: the suite itself, run in CI.

**FM-1131 — Hardware view in the console** (claude). Goal: show devices, statuses with reasons, holder, and recent events. Owned: `apps/web/src/pages/hardware/**`, one route and one nav entry. Acceptance: shows only what the API and `fleetctl --output json` report; dark and light, desktop and narrow, every status; screenshots in the PR per AGENTS.md. Non-goals: attach controls beyond what the API exposes. Tests: component tests and the Fleet Console verification skill.

**FM-1132 — Skill and docs** (glm). Goal: agents and humans discover hardware and request it. Owned: the hardware section of `skills/fleet/**`, the hardware section of `docs/operations/lab.md` (replacing "separate sub-epic"). Acceptance: examples use `fleetctl hardware list`, a template with `hardware`, and the refusal messages. Non-goals: new commands. Tests: skill lint, docs checks.

**FM-1133 — Runbook and live validation** (claude). Goal: the hardware-in-the-loop workflow end to end on real hardware, recorded as evidence, closing #16. Owned: `docs/operations/hardware.md`, `docs/planning/m11-acceptance.md`. Live-test devices (proposed): the two SuperDrives on the integration host, each with its own path-based mapping, so the Decker is never touched; a two-lease contention test uses both devices. Acceptance: the operator creates the mapping, Fleet lists it, a lease attaches it, a test runs, cleanup detaches it, and a failure variant is shown; the manual attachment to VM 200 is first seen as `externally_attached` and then adopted or released by the maintainer; unverified items are listed. Non-goals: anything not on the maintainer's go. Tests: the recorded run, sanitized (no real serials, hostnames or IPs).

## Deferred

- Queueing for a busy device, fairness, and groups or labels ("any device of model X").
- Fleet-created or edited mappings (`Mapping.Modify`).
- Whole-controller USB passthrough and any PCI or GPU passthrough (needs IOMMU; out of scope per #16).
- Device firmware and driver management.
- Live migration of guests holding devices.

## Open questions for the maintainer

1. **Milestone.** Open M11 for this, or reopen M7 with a sub-milestone? (Proposed: M11, since M7 closed.)
2. **Live-test hardware.** The host has two identical SuperDrives (05ac:1500) and a Verbatim device, so live tests need not touch the Decker. May FM-S11 and FM-1133 create test mappings for them (path-based for the SuperDrives)? Consent is needed because mappings change cluster configuration; the Decker mapping and VM 200 stay as they are.
3. **Conflict behaviour.** Fail fast with `hardware_busy` in v1, or must queueing ship in the first release (the lab.md text says conflicts queue)?
4. **Mappings.** Are operator-created mappings with a runbook acceptable, or should Fleet create them (needs `Mapping.Modify`, a larger privilege)?
5. **Manual attachment.** Should the existing Decker attachment to VM 200 be adopted as a Fleet-held reservation for the Dot X persistent VM, or released from VM 200 when the first lease needs it?
6. **Token privileges.** Is adding `Mapping.Use` on `/mapping/usb/*` and `VM.Config.HWType` to the documented Fleet token role acceptable?
7. **Attach timing.** Is attaching before boot enough for hardware-in-the-loop tests, or are mid-run attach and detach (hotplug) required?
8. **Identical devices.** The SuperDrive pair has the same vid:pid on one node, and PVE allows one device per node per mapping, so they need two path-based mappings (separate ids in templates). Is that acceptable, given a path identifies a port, not the device, so swapping the cables swaps identities?

## Sources

- Proxmox VE admin guide, QEMU/KVM: USB passthrough, resource mapping: https://pve.proxmox.com/pve-docs/chapter-qm.html
- Proxmox wiki, USB devices in virtual machines: https://pve.proxmox.com/wiki/USB_Devices_in_Virtual_Machines
- Proxmox VE API viewer (`/cluster/mapping/usb`, `/nodes/{node}/hardware/usb`, `PUT /nodes/{node}/qemu/{vmid}/config`): https://pve.proxmox.com/pve-docs/api-viewer/ (to be recorded by FM-S11)
- Fleet: ADR 0005, 0008, 0011, 0018; `docs/architecture/lab.md` (FM-715 reservation, "Later USB and physical resources", failure-injection acceptance); [m7-acceptance.md](m7-acceptance.md)
