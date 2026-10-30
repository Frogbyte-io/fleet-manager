# Proxmox USB resource mappings: the FM-S11 spike (#563)

Status: resolved 2026-10-30. The decisions it supports are recorded in
[ADR 0019](../adr/0019-usb-device-allocation.md) and the
[M11 plan](../planning/m11-usb-hardware.md), both amended by this spike.
No product code was written.

## Question

The M11 plan listed seven behaviours of the Proxmox USB mapping API as
"not confirmed". This spike measures each one, records the request and the
response, and states where reality differs from the plan and the ADR.

## Method

Live, on the integration host (physical, PVE 9.2.2, `pve-manager/9.2.2`,
`qemu-server 9.1.15`, QEMU 11.0.0, kernel 7.0, IOMMU off: `/sys/kernel/iommu_groups`
is empty) and on the nested fixture `pve8` (PVE 8.4.0, QEMU 9.2). Every call was
made twice over where it mattered: as `root@pam` through `pvesh`, and as a
temporary privilege-separated API token (`curl` over HTTPS, real HTTP status and
body) to learn which privileges PVE checks.

- Devices (9.2.2): the two spare "MacBook Air SuperDrive" (05ac:1500) at host
  ports `1-10` and `1-7`, and the "Verbatim 4K BD RW" (18a5:0428). The Decker mapping, VM 200,
  VM 201, VM 100, VM 7150 and the nested fixtures' configuration were not touched.
- Devices (8.4.0): the nested VM has no physical USB. Its only device is the QEMU
  USB tablet (0627:0001, port `1-1`), which behaves like a real device for every API
  question and is used as the stand-in. What could not be measured there is listed
  [below](#what-was-not-measured).
- Guests: throwaway clones of the acceptance template (VMIDs 9563 to 9567, tagged
  `fm-s11-spike`; one was converted to a template for the template test). The template's
  cloud kernel has no USB drivers, so on 9.2.2 the throwaway guest was given the stock
  Debian `linux-image-amd64` and `usbutils` so `lsusb` shows what the guest sees. On
  8.4 the evidence is QEMU's own `info usb` (via `qm monitor`).
- Evidence of who holds a device: the QEMU process's open `/dev/bus/usb/<bus>/<dev>`
  file descriptors (`/proc/<pid>/fd`).
- Recordings are sanitized and live in
  [`fixtures/proxmox-usb/`](fixtures/proxmox-usb/README.md) (`pve-9.2.2/` and
  `pve-8.4.0/`); fixture names are quoted below in `code`. IP addresses, MACs, UUIDs
  and certificate fingerprints are replaced; no token, ticket, password, hostname
  other than the node name, or device serial is present (the API returns no serial).

## Results at a glance

| # | Question | Answer |
|---|---|---|
| 1 | 8.4 shapes, `Mapping.Audit`, `path=` syntax and resolution | Shapes identical on 8.4.0 and 9.2.2. A path entry is `node=<n>,id=<vid:pid>,path=<bus>-<port>`; **`id` is mandatory**, `path` is optional. Listing needs `Mapping.Audit`. **`/nodes/{node}/hardware/usb` needs `Sys.Modify` on `/`.** An id-only entry resolves to the first matching device. |
| 2 | Is `usbpath` stable? | Stable across re-enumeration (`devnum` changes, `usbpath` and `port` do not). Host reboot not measured. |
| 3 | May a token write `usbN: host=`? | No: "only root can set 'usbN' config for real devices". Mappings are the only path. |
| 4 | Running-guest attach and detach | Immediate hotplug and unplug, guest sees it; **unless** the guest's `hotplug` option lacks `usb`, then `pending`. A failed hotplug leaves a `pending` entry behind. Detach also needs `Mapping.Use`. |
| 5 | Absent device, no node entry, second guest | Start is **refused** for an absent device or a mapping without a node entry. PVE does **not** stop a second guest from referencing, starting with, or hotplugging a held mapping. |
| 6 | Snapshot, rollback, clone, template | All of them carry `usbN`; rollback restores the snapshot's set; clones and template clones inherit it. |
| 7 | Migration and HA | Preflight lists `usbN` under `mapped-resources`; per `qemu-server`, offline migration needs a node entry on the target, live migration is refused. No second node was available; not exercised. |

## 1. Shapes, `Mapping.Audit`, and `path=` entries

**Shapes.** `GET /cluster/mapping/usb` (optionally `?check-node=<node>`),
`GET /cluster/mapping/usb/<id>` and `GET /nodes/{node}/hardware/usb` return the same
fields on 8.4.0 and 9.2.2 (`pve-8.4.0/v8-mapping-list.json`,
`pve-9.2.2/q1-mapping-list.json`, `q1-mapping-get-path.json`, `q1-hardware-usb.json`,
`pve-8.4.0/v8-hardware-usb.json`). Fields: list item `id`, `type`, `map[]` (strings),
`digest`, optional `description`; with `check-node`, also `errors[]` of
`{message, severity}`. The inventory item has `busnum`, `devnum`, `level`, `port`,
`vendid`, `prodid`, `manufacturer`, `product`, `speed` (string), `class`, and `usbpath`
**only on devices that are not root hubs**. There is no serial.

**Path entry syntax** (PVE's `PVE::Mapping::USB` schema, confirmed by creating entries
through the API, `usb.cfg` on the host):

```text
map node=pve,id=05ac:1500,path=1-10
```

- `id` (`vendorid:productid`, hex) is **required**. A `path=`-only entry is refused
  with `400 map[0].id: property is missing and it is not optional`. With `path`,
  `id` "is only used for detecting hardware changes" (the schema's wording).
- `path` matches `^\d+-\d+(\.\d+)*$` (`<busnum>-<usbpath>`; the host's `1-10` is bus 1,
  `usbpath` 10, i.e. the inventory's `busnum` and `usbpath` joined).
- Creation does **not** validate hardware. Accepted without error: a path that does not
  exist (`1-99`), an `id` that does not match the device at the path, and a `node` that
  is not in the cluster.
- Validation happens at `check-node`, at start, and at hotplug. With the device present
  `errors` is `[]`. Measured messages: `usb device '1-55' not found`,
  `'id' does not match for '<name>' (05ac:1500 != 05ac:1501)`, and, for a mapping with no
  entry for the node, `{"message":"No mapping for node pve.","severity":"warning"}`
  (`q5-mapping-nonode-check.json`).

**Resolution when several devices match.** An `id`-only entry for the identical
SuperDrive pair resolved to the first device in PVE's scan (host port `1-7`, the lower
`devnum`) whenever that device existed, including when the other guest already held the
second one (`a1-attach-ambig-second.json`) and when the first was already held by the same
guest (`i1-`, `i2-`: PVE did not pick the free device). `check-node` reports no error for an ambiguous id-only entry, so PVE does
not flag it. **Identical devices therefore need `path=` entries**, as the plan says. A
mapping with two entries for the same node is accepted at creation and by `check-node`
(no errors), but any attach is refused: `More than one USB mapping per host not
supported` (`i4-attach-two-entries.json`, `i4-two-entries-check.json`).

**Privileges to read** (non-root token, 9.2.2 and 8.4.0 identical,
`pr0-`, `pr1-`, `pr2d-`, `pr3-` and `qr0-` to `qr3-` fixtures):

| Token holds | `GET /cluster/mapping/usb` | `GET .../usb/<id>` | `?check-node=` | `GET /nodes/{n}/hardware/usb` |
|---|---|---|---|---|
| nothing | `200 []` | 403 | n/a | 403 `(/, Sys.Modify)` |
| `Mapping.Audit` on `/mapping/usb` | all mappings | 200 | works, incl. `errors` | 403 `(/, Sys.Modify)` |
| `Mapping.Audit` on one mapping | only that one | not tried | n/a | 403 |
| `PVEAuditor` on `/` | all mappings | not tried | n/a | 403 `(/, Sys.Modify)` |
| `Sys.Audit` on `/` or `Sys.Modify` on `/nodes/pve` | n/a | n/a | n/a | 403 `(/, Sys.Modify)` |
| `Sys.Modify` on `/` | n/a | n/a | n/a | 200 |

Two consequences. First, an unprivileged list is an empty `200`, not an error, so
"no devices" and "no `Mapping.Audit`" look the same; a per-mapping GET is the
distinguishing probe. Second, **the node USB inventory is not readable with any
read-only role**: it needs `Sys.Modify` on `/`, which Fleet must not require. The
mapping's own `map` entry already carries `node`, `id` and `path`, and `check-node`
reports whether the device is present and matches, so **presence and the fingerprint
come from the mapping list**; the inventory adds only the manufacturer and product
strings and is optional.

## 2. Stability of `usbpath`

Method: disable and re-enable the hub port (`/sys/bus/usb/devices/usb1/1-0:1.0/usb1-port10/disable`),
which is a real disconnect and reconnect of the SuperDrive at `1-10`. A physical replug
was not possible (remote host). Results (`r0-`, `r1-`, `r3-` fixtures):

| State | `devnum` | `usbpath` | `port` |
|---|---|---|---|
| before | 2 | `10` | 9 |
| port disabled | absent from inventory | | |
| re-enabled | 4 (later 5 after another cycle) | `10` | 9 |

`check-node` reported `usb device '1-10' not found` while it was disconnected and `[]`
again afterwards. `devnum` changes on every enumeration, `usbpath` does not, which is
why PVE resolves a path entry by `busnum-usbpath` and never by `devnum`. **Not measured:**
stability across a host reboot (the host runs other guests). `usbpath` is derived from
the hub topology, so it is stable for a fixed cabling, but `busnum` is assigned by the
kernel in controller probe order; the fingerprint check (`id` must match the device at
the path) is what protects against a reshuffle.

## 3. May a token write `usbN: host=`?

No. As a non-root token with `VM.Config.HWType` on the guest and `Mapping.Use`
(`pw2-put-host-bus-port.json`, `pw2-put-host-vidpid.json`):

```text
PUT /nodes/pve/qemu/9563/config  usb2=host=1-7        -> 500 "only root can set 'usb2' config for real devices"
PUT /nodes/pve/qemu/9563/config  usb2=host=05ac:1500   -> 500 same
PUT /nodes/pve/qemu/9563/config  usb2=usb3=1           -> 500 "either 'host' or 'mapping' must be set."
```

(`host=spice` is exempt; irrelevant to Fleet.) Root accepts all of them, including a
`usbN` with neither key, which is a stored but unusable value. Mappings are the only path
for Fleet, as ADR 0019 assumes.

## 4. Writing `usbN` on a running guest

### Privileges (9.2.2 and 8.4.0 identical)

PVE checks, in this order (`check_usb_perm` in `PVE::API2::Qemu`):

1. a generic "some `VM.Config.*`" gate on the guest (error lists
   `VM.Config.Disk|CDROM|CPU|Memory|Network|HWType|Options|Cloudinit`),
2. `VM.Config.HWType` on the guest,
3. `Mapping.Use` on `/mapping/usb/<id>`.

Measured (`pw1-` to `pw5-`, `pr4-`, `pr5-`, `qw1-` to `qw3-`):

| Token | Action | Result |
|---|---|---|
| `VM.Audit`+`VM.Config.HWType` on the VM, no `Mapping.Use` | attach | 403 `(/mapping/usb/<id>, Mapping.Use)` |
| plus `Mapping.Use` on that one mapping | attach it / attach another | 200 `null` / 403 for the other |
| `Mapping.Use` only | attach | 403 (no VM config privilege) |
| `Mapping.Use` on `/mapping/usb` (inherited) | attach a mapping that does not exist | 200 `null` (stopped guest; fails later) |
| `HWType` only | **detach** (`delete=usb0`) | 403 `(/mapping/usb/<id>, Mapping.Use)` |
| `Mapping.Use` only | detach | 403 (no VM config privilege) |
| both | detach | 200 `null` |
| user has the roles, privsep token has none | attach | 403 (the token's own ACL decides) |

**A detach needs `Mapping.Use` on the mapping that is currently configured**, not only
`VM.Config.HWType`. A token that has lost `Mapping.Use` (role changed, mapping renamed)
can attach nothing and detach nothing; cleanup must report that as an operator-visible
failure. `VM.PowerMgmt` is not needed to hotplug. The result is the same whether the
guest is running or stopped.

### Immediate or pending

On a running guest whose `hotplug` option is the default (`network,disk,usb`),
**both directions are immediate**:

```text
PUT /nodes/pve/qemu/9563/config   usb0=mapping=fm-test-superdrive-a
  -> 200 {"data":null}                       (synchronous; the POST form returns a UPID)
  GET config   -> usb0: mapping=fm-test-superdrive-a
  GET pending  -> {"key":"usb0","value":"mapping=fm-test-superdrive-a"}   (no "pending" member)
  guest lsusb  -> Bus 002 Device 002: ID 05ac:1500 Apple, Inc. SuperDrive   (within seconds)
  qm monitor "info usb" -> "Product MacBook Air SuperDrive, ID: usb0"

PUT /nodes/pve/qemu/9563/config   delete=usb1
  -> 200 null; usb1 gone from config and from pending; guest lsusb no longer lists it
```

(`h2-`, `d1-` fixtures; on 8.4 `h8-`.) A device attached with `usb3=1` appeared on the same
guest bus as one without. The wiki's claim that deleting an entry "does not remove the
device from a running VM" describes the manual QEMU-monitor route, not the API: the API
unplugs it.

**Exception: `hotplug` without `usb`.** With `hotplug=network,disk` on the guest the same
calls return `200` but nothing happens to the guest (`p1-`, `p2-`, `p5-`, `p6-`, 8.4
`p8-`):

```text
GET pending -> {"key":"usb1","pending":"mapping=fm-test-verbatim"}           (add)
            -> {"delete":1,"key":"usb0","value":"mapping=fm-test-superdrive-a"}   (delete)
GET config            -> shows the PENDING view (usb1 present, usb0 absent)
GET config?current=1  -> shows what is running (usb0 present, usb1 absent)
guest lsusb           -> unchanged
```

The change is applied by the next guest reboot (`qm reboot` applied both on 9.2.2).
`GET config` without `current=1` is therefore **not** proof that a device is attached.
Read-back must use `pending` (a plain `value` with no `pending`/`delete` member means
applied) or `config?current=1`.

**A failed hotplug leaves state behind.** Hotplug of an absent device, a mapping with no
node entry, an unknown mapping, or a mapping with two node entries fails with
`400 {"message":"Parameter verification failed.","errors":{"usb0":"hotplug problem - USB
Mapping invalid (hardware probably changed): usb device '1-55' not found"}}`
(`a3-`, `a5-`, `a6-`, `i4-attach-two-entries.json`), **but the entry stays in the config as
a pending value** (`a3-pending.json`: `{"key":"usb0","pending":"mapping=..."}`). The next
start would then fail. The saga's "failure after reserve: delete `usbN`, read back" step is
mandatory, not defensive.

**Physical unplug while attached.** The guest loses the device, QEMU keeps the `usb-host`
object, PVE's config is unchanged, and when the device reappears on the same port QEMU
re-attaches it to the guest without any API call (`u1-` fixtures; guest `lsusb` showed it
gone, then back as a new device number). PVE gives no event; absence is visible only
through `check-node`.

**Digest.** `digest=<d>` on the PUT is honoured for attach and for delete: with a stale
digest the call fails `500 "checksum mismatch (file change by other user?)"` and writes
nothing (`k2-` to `k4-`).

## 5. Absent device, missing node entry, and a second guest

**Start refuses.** `POST .../status/start` returns a UPID; the task ends in error
(`tasks-qmstart.json`, `n-start-*.json`):

| Guest config | Task result |
|---|---|
| mapping with no entry for this node | `TASK ERROR: USB device mapping not found for 'fm-test-tmp-nonode'` |
| mapping id that does not exist | `TASK ERROR: USB device mapping not found for 'fm-test-does-not-exist'` |
| path entry, port empty | `TASK ERROR: USB Mapping invalid (hardware probably changed): usb device '1-55' not found` |

All three configs were **accepted** by `PUT config` on a stopped guest, so a config
write succeeding proves nothing about startability. This corrects the plan's reading of
the documentation ("a configured device that is missing at VM start does not stop the
VM"): that sentence is about `host=`; it does not hold for `mapping=` on 9.2.2. (The
`host=` case was not measured.) A Lab provisioning attach before boot therefore fails the
start step, and the compensation must delete the entry.

**No exclusivity in PVE.** With `fm-test-superdrive-a` attached to running guest 9563,
a second guest (9564) accepted `usb0=mapping=fm-test-superdrive-a`, **started**, and had
the device on its QEMU bus; both QEMU processes held `/dev/bus/usb/001/004` open at the
same time (`e0-`, `e2-` fixtures; the same on 8.4 with the tablet, `e8-`). A hotplug of a
mapping into a second running guest also succeeded. PVE refuses none of this; **Fleet's
reservation is the only exclusivity.** What the two guests then see when both drive the
device was not measured and should be treated as undefined.

## 6. Snapshot, rollback, clone, template

All on 9.2.2 (`t1-` to `t9-`) and, for snapshot and clone, 8.4.0 (`s8-`):

- A snapshot's config (`GET .../snapshot/<name>/config`) contains the `usbN` entries.
  A snapshot of a running guest with a mapped device succeeded, with and without
  `vmstate=1` (no refusal; resuming a `vmstate` snapshot was not tried).
- **Rollback replaces the current `usbN` set with the snapshot's**: after adding `usb2`
  and deleting `usb1`, rollback restored `usb0`+`usb1`, and left the guest stopped. A
  revert can therefore reintroduce a reference to a mapping Fleet no longer holds, and
  remove one it does.
- **Clone inherits `usbN`**, full or linked, from the current state or from a snapshot
  (`t5-`, `t6-`). A template keeps its `usbN`, and a clone of the template inherits it
  (`t9-`). A Lab base template with a mapping reference would make every clone reference
  the same device.

## 7. Migration and HA

Not exercised on a second node (the physical host is a single node, and the nested
cluster could not be used, see [below](#what-was-not-measured)). Measured on the single
node (`m1-`, `m2-`, 8.4 `mg8-`): `GET /nodes/{n}/qemu/{vmid}/migrate` reports, for a guest with
`usb0`/`usb1` mappings, stopped or running:

```text
"local_resources":["usb1","usb0"],
"mapped-resources":["usb0","usb1"],
"mapped-resource-info":{"usb0":{"name":"fm-test-superdrive-a"},"usb1":{"name":"fm-test-verbatim"}},
"allowed_nodes":[], "not_allowed_nodes":{}
```

(8.4.0 has the same keys apart from `has-dbus-vmstate`.) The refusal rules are in
`qemu-server`'s `PVE::QemuMigrate` and `PVE::QemuMigrate::Helpers::check_local_resources`
(read on the host, 9.1.15): a USB mapping is **not** a hard blocker for an offline
migration but the target node must have an entry (`can't migrate to '<node>': missing
mapped devices usb0`), and a running guest is refused because USB mappings have no
`live-migration` flag (`can't live migrate running VM which uses following mapped
devices: usb0:<mapping>`). HA relocation uses the same migrate path. Treat both as
documented-by-source, not as measured behaviour.

## Consequences for the design

Recorded in the amended ADR 0019 and plan. In short:

1. The mapping list (`Mapping.Audit`, `check-node`) is the device source; the node
   inventory needs `Sys.Modify` on `/` and becomes optional enrichment.
2. Path entries carry `id`; the fingerprint is `id` plus `path`, both readable from the
   mapping.
3. An id-only entry or a multi-entry node is `ambiguous_mapping`.
4. Detach needs `Mapping.Use` as well as `VM.Config.HWType`; the opt-in role must keep
   `Mapping.Use` for as long as the device is attached.
5. Hotplug is immediate when the guest's `hotplug` includes `usb`; otherwise it is pending
   and must be reported as such. Read-back uses `pending`/`config?current=1`.
6. A failed hotplug leaves a pending entry; compensation deletes it.
7. The start of a guest referencing an absent or unmapped device fails; the attach is
   verified against `check-node` before the write.
8. Snapshot revert and clone propagate `usbN`; Lab cleanup and provisioning must clear
   inherited references.
9. PVE provides no exclusivity.

## Test mappings kept for later M11 live tests

Created on the integration host (cluster-wide `usb.cfg`), all for node `pve`, by hand
with `Mapping.Modify` (root), never by Fleet:

| Mapping id | Map entry | Device |
|---|---|---|
| `fm-test-superdrive-a` | `node=pve,id=05ac:1500,path=1-10` | MacBook Air SuperDrive |
| `fm-test-superdrive-b` | `node=pve,id=05ac:1500,path=1-7` | MacBook Air SuperDrive |
| `fm-test-verbatim` | `node=pve,id=18a5:0428` | Verbatim 4K BD RW (unique, id is enough) |

They are not referenced by any guest after the spike. The `decker` mapping is unchanged.
Re-check the ports before a live test: `usbpath` is a physical port, so moving a cable
moves the device.

## What was not measured

- A host reboot's effect on `usbpath` and `busnum` (host runs other guests).
- Live migration, offline migration with and without a target entry, and HA relocation
  of a guest with a mapping: the physical host is one node, and the nested two-node
  cluster could not be used. After starting it, node-a's SSH host key no longer matched
  the pinned one because its fixed address is now leased to another guest on the host
  (VM 200). Both nodes were stopped again at once, unmodified, rather than risk an address
  clash. Only the single-node preflight and the `qemu-server` source were read.
- On 8.4.0: real hardware, the guest's own view of the device (no USB driver in the
  nested guest image; `info usb` was used), and behaviour under an unplug. Shapes,
  privileges, hotplug/pending semantics, snapshot and clone were measured and match 9.2.2.
- Two guests driving one device at once: only the shared open handle was observed.
- Resuming a `vmstate` snapshot of a guest with a mapped device.
- Raw `host=` behaviour for a missing device (the documentation sentence the plan
  quoted).
- `Mapping.Modify`: Fleet does not create mappings, so create, edit and delete privileges
  were measured only as root.

## Sources

- Proxmox VE admin guide, QEMU/KVM USB passthrough and resource mapping:
  <https://pve.proxmox.com/pve-docs/chapter-qm.html>
- Proxmox wiki, USB devices in virtual machines:
  <https://pve.proxmox.com/wiki/USB_Devices_in_Virtual_Machines>
- Proxmox VE source on the test host (read-only): `PVE/Mapping/USB.pm`,
  `PVE/QemuServer/USB.pm`, `PVE/API2/Qemu.pm` (`check_usb_perm`), `PVE/QemuMigrate.pm`,
  `PVE/QemuMigrate/Helpers.pm`.
