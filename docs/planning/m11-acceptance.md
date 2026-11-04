# M11 acceptance: hardware-in-the-loop run (TEMPLATE, nothing recorded)

Status: **TEMPLATE for the recorded run. No live run has happened.** Every `Status` below reads `not run` and every evidence field is blank. Nothing in this document is evidence until someone fills a field in from a real run and dates it. Until then the claim that a USB device is exclusively held, attached and always detached rests on the reservation store's guarantees and on tests against a fake Proxmox (`crates/fleet-controller/tests/support/fake_pve.rs`), not on hardware.

Issue: [#577](https://github.com/Frogbyte-io/fleet-manager/issues/577) (FM-1133), epic [#16](https://github.com/Frogbyte-io/fleet-manager/issues/16). Plan: [m11-usb-hardware.md](m11-usb-hardware.md). Decision record: [ADR 0019](../adr/0019-usb-device-allocation.md). The procedure each item refers to is [docs/operations/hardware.md](../operations/hardware.md); this document records its results. Filling it in does not by itself close #16: the maintainer decides that.

## How to fill this in

- Run the steps of the runbook on the integration host, in order, and fill the matching item. Do not edit a `Status` before the step was run.
- `Status` is one of `not run`, `passed`, `failed`, `partly` (say which part), or `blocked` (say why). Anything but `passed` needs a note in the evidence field.
- Evidence is the command, the sanitized output, what you observed, the date and who ran it. Paste outputs, not summaries.
- Sanitize first: no real serials, hostnames, IP addresses, MAC addresses, tokens, certificate fingerprints. Use `<node>`, `<account-id>`, `<lease-id>` and the like. VM 200 and the Decker's guest appear in the `decker` observation; write them as "the guest that holds the Decker" if you quote them.
- When reality differs from a document, record what was measured and name the document. Fix the document in a separate change.

## Live-test scope and authorization

The live devices are the two SuperDrive test mappings on the integration host, `fm-test-superdrive-a` and `fm-test-superdrive-b`, each a path-based mapping of one of two identical `05ac:1500` devices.

- The **Decker mapping and VM 200 are never touched**. No template, lease, hotplug, override or manual command in the run names either. The Decker is observed (read only) as `externally_attached`.
- The nested test cluster's `node-a` has an **unresolved address conflict with VM 200** (its fixed address is leased to VM 200 on the host), so it must not be started for this run. The run uses the physical host `pve` only, and **only after the maintainer authorizes it**.

| Field | Value |
|---|---|
| Maintainer authorization for the physical host (who, where recorded, date) | |
| Run date(s) | |
| Operator | |
| Fleet controller version / commit | |
| `fleetctl` version / commit | |
| Proxmox VE version and node (`<node>`) | |
| Guest image used (id as `<image-version-id>`, kernel with USB drivers and `usbutils`: yes/no) | |
| Token ACL choice for `FleetUsb` (broad `/mapping/usb`, or narrowed per mapping) and what Fleet reported | |
| `hardware_refresh_interval_seconds` in effect | |

Before the run: [ ] `fm-test-superdrive-a` and `-b` are referenced by no guest (checked read only) · [ ] no template names `decker` · [ ] the controller includes the saga, reconciler, override release and hotplug routes · [ ] a scratch guest `<scratch-vmid>` designated by the maintainer (never VM 200)

## Acceptance criteria (from #577)

The acceptance criteria of #577 read: *the operator creates the mapping, Fleet lists it, a lease attaches it, a test runs, cleanup detaches it, and a failure variant is shown; the manual Decker attachment to VM 200 is shown as `externally_attached` and left alone; a mid-run hotplug attach and detach is shown; unverified items are listed.* The *Tests* line asks for the recorded run, sanitized (no real serials, hostnames or IPs). Each clause is one item below.

### AC1. The operator creates the mapping

Runbook: [step 2](../operations/hardware.md#2-the-operator-creates-the-pve-mapping), and [step 3](../operations/hardware.md#3-grant-the-opt-in-fleetusb-role) for the role.

- Status: not run
- Mapping definitions as created (ids and `node=<node>,id=05ac:1500,path=<bus-port>` with ports as placeholders):
- `check-node` output showing no errors for both mappings:
- `FleetUsb` role and ACLs granted (what, where):
- Date / operator:
- Notes:

### AC2. Fleet lists it

Runbook: [step 1](../operations/hardware.md#1-read-only-pre-flight) and [step 4](../operations/hardware.md#4-fleet-lists-the-devices).

- Status: not run
- `fleetctl --output json hardware refresh --account <account-id>` output:
- `fleetctl --output json hardware list --account <account-id>` output (both test mappings `available`, `stale: false`, entries show vendor `05ac`, product `1500`, the mapped port, no serial):
- `fleetctl hardware list` text table:
- Console Hardware page screenshot (if taken; reviewed for secrets):
- Date / operator:
- Notes:

### AC3. A lease attaches it

Runbook: [step 5](../operations/hardware.md#5-a-template-that-declares-the-device) and [step 6](../operations/hardware.md#6-lease-reserve-and-attach).

- Status: not run
- Template with `hardware` (the request body, sanitized) and `lab publish` result:
- `fleetctl --output json lab create <version-id> --purpose ... --wait` result:
- `lab status` `hardware[]` showing `reservation.state` `attached` and `usbSlot`:
- `hardware list` showing the device `reserved` with the lease as `holder`, and the other device still `available`:
- Read-only view of the clone's `usbN` entry in Proxmox:
- Audit events seen (`hardware_reserved`, `hardware_attach_requested`, `hardware_attached`):
- Date / operator:
- Notes:

### AC4. A test runs

Runbook: [step 7](../operations/hardware.md#7-test-the-guest-sees-the-device).

- Status: not run
- `fleetctl --output json lab exec <lease-id> --wait -- lsusb -d 05ac:1500` output and exit status:
- Guest image has USB host drivers and `lsusb` (yes/no; if no, the step is `blocked`, not `passed`):
- Date / operator:
- Notes:

### AC5. Cleanup detaches it

Runbook: [step 8](../operations/hardware.md#8-cleanup-detaches).

- Status: not run
- `lab destroy <lease-id> --wait` result and final lease state:
- Audit sequence (`hardware_detach_requested`, `hardware_detached`, `hardware_released`) and that the detach preceded the guest's destruction:
- After a refresh, `hardware list` showing the device `available` with no `holder`:
- Read-only check that no guest in Proxmox references the mapping:
- Date / operator:
- Notes:

### AC6. A failure variant is shown

Runbook: [step 9](../operations/hardware.md#9-failure-variants). #577 asks for one; the others are worth recording because each exercises a documented path. Mark any not attempted as `not run`, never as passed.

| Variant | Status | Expected | Evidence (command, sanitized output, observation) |
|---|---|---|---|
| F1 Unknown mapping | not run | Placement refusal `hardware_unknown`, nothing allocated | |
| F2 Missing device (cable unplugged, then replugged to the same port) | not run | `missing`, `hardware_missing`; back to `available` on the same `usbpath` after replug and refresh | |
| F3 Detach the token cannot do (ACL removed after `ready`) | not run | `detach_failed`, device `quarantined`, guest kept, lease in cleanup retry; recovers after the ACL is restored (record by retry or reconciler, and how long) | |
| F3b The ACL removal also removes `Mapping.Audit` | not run | The next refresh may report the account `unsupported` (`no_mapping_audit`); recorded separately from F3 | |
| F4 Guest `hotplug` without `usb`: detach | not run | `detach_pending` (HTTP 202, exit 2), device still on the guest, row `detaching`; confirmed after restart | |
| F4 Guest `hotplug` without `usb`: attach | not run | `hardware_attach_pending` (409), entry removed again | |

- Overall AC6 status: not run
- Date / operator:
- Notes:

### AC7. The manual Decker attachment to VM 200 is `externally_attached` and left alone

Runbook: [step 11](../operations/hardware.md#11-a-manually-attached-device-is-externally_attached-and-left-alone).

- Status: not run
- The `decker` device in `hardware list` (`externally_attached`, no `holder`, observation naming the guest; sanitize the guest):
- Confirmation that no write of any kind was issued against the Decker mapping or VM 200 (the run's command log, plus the audit trail showing only reads and `hardware.refresh`):
- Scratch-guest case: `qm set <scratch-vmid> --usb0 mapping=fm-test-superdrive-b`, refresh, `externally_attached`:
- The lease for that mapping refused with `hardware_externally_attached`, nothing allocated:
- The scratch guest's `usb0` entry unchanged after a reconciler pass; then removed by hand and the device `available` again after a refresh:
- Date / operator:
- Notes:

### AC8. A mid-run hotplug attach and detach is shown

Runbook: [step 10](../operations/hardware.md#10-mid-run-hotplug).

- Status: not run
- `lab hardware detach <lease-id> fm-test-superdrive-a` result (`outcome` `detached`, `onGuest` false) and `lsusb` in the guest before and after:
- `hardware list` during the detached period (device still `reserved` by the lease, holder state `held`):
- `lab hardware attach <lease-id> fm-test-superdrive-a` result (`attached`) and `lsusb` in the guest after:
- Repeat calls answering `already_detached` / `already_attached`:
- `--release` variant: device `available` after a refresh, and the same lease then refused with `hardware_not_reserved`:
- A refusal or two (`lease_not_ready`, `hardware_not_reserved`):
- Audit events (`source=hotplug`):
- Date / operator:
- Notes:

### AC9. Unverified items are listed

- Status: not run (the list below is written in advance from the sources; it becomes the record only once each item is marked measured, still unmeasured, or contradicted by the run)

See [Still unmeasured or assumed](#still-unmeasured-or-assumed) below. After the run, edit each row's `Outcome` and add what the run turned up.

### Tests: the recorded run is sanitized

- Status: not run
- Reviewer who checked the recorded run for serials, hostnames, IPs, MACs, tokens and fingerprints (name, date):
- Notes:

## Further items the runbook exercises

These go beyond the literal acceptance sentence, but the plan's failure-injection gate ("no device reserved by two live leases, no released lease whose device stays silently assigned") is only shown on hardware by them.

### X1. Two-lease contention

Runbook: [step 12](../operations/hardware.md#12-two-lease-contention).

- Status: not run
- Different devices, two leases at once, each `ready` with one device (`lsusb` shows exactly one SuperDrive in each guest):
- Same device while held: `hardware_busy` naming the holder, for `a` and for `b`; the holders undisturbed:
- Race: two simultaneous `lab create` for the same version, exactly one `ready` and one `hardware_busy` (record both lease ids and the final `hardware list`):
- Hand-over: after the holder is destroyed and a refresh, the device leases again:
- Date / operator:
- Notes:

### X2. Recovery with the override release

Runbook: [step 13](../operations/hardware.md#13-recovery-a-reservation-that-will-not-clear).

- Status: not run
- A stuck reservation reproduced (how, and its state):
- What Fleet reported before acting (`hardware list`, reconciler findings in `audit list --action hardware.refresh`):
- `hardware override-release <reservation-id> --confirm-unverified` result (`outcome` `released`, `previous`):
- Audit events (`hardware_override_release_requested` before `hardware_released` with outcome `override`, `hardware_override_released`):
- After a refresh: device `available` if the entry was removed, `externally_attached` if it was left, and the next lease refused with `hardware_externally_attached` in the second case:
- Date / operator:
- Notes:

### X3. Reconciler on real PVE

- Status: not run
- A hold that never attached, or an owner-finished row, released by the reconciler without a request (which row, after how long):
- A foreign `usbN` entry left untouched with a `hardware_reconcile_finding`:
- Date / operator:
- Notes:

## Still unmeasured or assumed

Everything here is written in advance, from the pull-request descriptions ([#587](https://github.com/Frogbyte-io/fleet-manager/pull/587), [#588](https://github.com/Frogbyte-io/fleet-manager/pull/588), [#589](https://github.com/Frogbyte-io/fleet-manager/pull/589), [#594](https://github.com/Frogbyte-io/fleet-manager/pull/594)), the FM-S11 research ([proxmox-usb.md](../research/proxmox-usb.md)), the token guide and the M11 plan. `Outcome` is blank until a run settles it. "Unmeasured" means nobody observed it on real PVE through Fleet; "assumed" means a behaviour the code relies on without an observation; "by design" means a documented limit that is not a question.

### What PVE does (unmeasured on real Proxmox)

| Item | Where it comes from | Outcome |
|---|---|---|
| A **pending detach after the guest stops**: with `hotplug` lacking `usb`, what PVE does with the stored delete when the guest then stops (applied, kept, lost) | #587, #588, #589; lab.md "Not measured" | |
| **Deleting a pending-only leftover from a running guest**: whether the delete of a `usbN` that exists only as a pending value succeeds | #587, #588, #589 | |
| The **unknown-mapping answer**: what PVE answers an attach, a `check-node` or a start for a mapping id deleted or renamed after the last refresh, and whether Fleet's refusal (verify, fingerprint) reads as documented. FM-S11 recorded PVE's raw `400 hotplug problem` and start failure, never Fleet's handling of it | proxmox-usb.md section 4 and 5; this draft's reading of the item | |
| The **`usbN` slot limit by `ostype` and machine type**: the PVE documentation says `n` is 0 to 4, up to 14 on machine version 7.1+ with Linux or newer Windows; Fleet records at most five slots (`usb0` to `usb4`) and refuses beyond that. Which of the two applies to a Lab clone was not measured | m11-usb-hardware.md; #587 ("beyond the five slots Fleet records") | |
| **`check-node` on multi-node clusters**: Fleet calls `?check-node=` per node; only a single physical node (and a nested pair that could not be used) was ever exercised | proxmox-usb.md "What was not measured"; #589 (cost per node) | |
| Whether the **`usbpath` survives a host reboot** (measured only across a hub-port disable and enable) and what `busnum` does | proxmox-usb.md section 2 and "What was not measured" | |
| **Narrowing `FleetUsb`** to `/mapping/usb/<id>`: per-mapping `Mapping.Audit` is measured for the list and the single read, not for `?check-node=`; the device may read `unsupported` (`usb_inventory_unreadable`) | proxmox-token.md | |
| **Two guests driving one device**: only the shared open handle was observed; what each guest sees is undefined. PVE gives no exclusivity, so Fleet's reservation is the only guard | proxmox-usb.md section 5 | |
| **Migration and HA** of a guest holding a mapped device: offline needs a target entry, a running guest is refused; read from `qemu-server`, never exercised on a second node | proxmox-usb.md section 7; ADR 0019 | |
| **Resuming a `vmstate` snapshot** of a guest with a mapped device | proxmox-usb.md | |
| **Raw `host=`** behaviour for a missing device (the documentation sentence the plan quoted); root-only for a token | proxmox-usb.md | |
| **Behaviour on PVE 8.x with real hardware** (only the nested USB tablet was available there) and the guest's own view of the device under an unplug | proxmox-usb.md | |
| `Mapping.Modify` privileges for create, edit and delete were measured only as root; Fleet never uses them | proxmox-usb.md | |
| A **Lab guest image with USB host drivers**: the acceptance template's cloud kernel has none; the spike added the stock kernel and `usbutils` to a throwaway guest. Whether Lab's images need that, and what the guest sees with the default image, is unmeasured | proxmox-usb.md "Method" | |

### What Fleet assumes or has not measured on hardware

| Item | Where it comes from | Outcome |
|---|---|---|
| **The crash window between a PVE write and its record**: a controller killed in that window leaves an `attaching` row; with an entry on the guest it becomes `attach_unknown` with no slot, never deleted, and clears only by the guest showing no reference or by `hardware.override-release`. Exercised by fake-PVE failure injection only | #587, #589 | |
| **Narrow case: an `attach_unknown` row that carries a slot**: if the provider's write never landed and an operator added an identical `mapping=<id>` to the clone before cleanup read the guest, cleanup would delete that entry (an exact value in the recorded slot, never anything else) | #587 | |
| **VMID reuse after a hand-deleted guest** is not detected; a stuck live row blocks the destroy of an unrelated guest that reuses its VMID until the row is resolved | #587 (D5) | |
| **An absent guest is not a confirmed detach** (the cluster listing omits guests the token cannot audit), so a hand-deleted guest holding a device needs the override | #587, #589 | |
| **The fingerprint pin** is written by a second hook just after the reserve, not inside the reserve transaction; a reservation with no pin is pinned at its first attach (the older, weaker behaviour) | #587 | |
| **Whole-account inventory refresh per attach** (up to 512 guest config reads, two for a running guest, concurrency 8): the latency of an attach and of a mid-run hotplug on a real cluster was not measured | #587, #588, #589 | |
| **The scheduled refresh** (default every 600 s; devices read `stale` above 900 s): its load on a real cluster and the `hardware_status_changed` audit trail were not measured | #589 | |
| **The reconciler's pass and its limits** (180 s deadline, 256 rows, 32 guest reads, backoff 10 to 60 minutes) against a real, slow or unreachable Proxmox | #589 | |
| **The hotplug route is synchronous and not a durable operation**; a crash mid-request leaves a row cleanup resolves. **The per-device lock is in-process** (one controller) | #588 | |
| **A pending mid-run attach is rolled back** rather than left to apply at the next restart: a choice, because the alternative needs a new state | #588 | |
| **`already_attached` reports the reservation row**, not a fresh read of the guest | #588 | |
| **The pool detach path** is exercised at cleanup level only; pooled templates with hardware are refused (`hardware_pool_unsupported`) | #587 | |
| **VMID hold and cleanup identity**: while one failed record holds a VMID every new lease is refused with `conflict` (a `cleanup_failed` lease holds its VMID until an operator resolves it); a clone queued but not yet written can look like an absent guest to the identity check; the holder check is scoped by account, not node | #594 | |
| **A guest the token cannot audit** is omitted from the cluster listing, so a reference to a device on it may be invisible to the scan and the device would read `available` while attached. This is an inference from the listing limit stated in #587, not something any test or run observed; the scan-completeness refusal (`hardware_scan_incomplete`) covers unreadable guests the listing does name | #587 (inference) | |

### Not covered by M11 at all

Persistent machines with devices (FM-1125, separate), queueing for a busy device, groups or labels ("any device of this model"), Fleet-created or edited mappings, whole-controller USB and PCI passthrough, live migration of guests holding devices, and the Decker and VM 200 (non-goals of #577).

## Result

To be filled in by the maintainer or the person who ran it, only after the items above are filled from a real run.

- Items passed / failed / blocked / not run:
- Anything that contradicts [lab.md](../operations/lab.md), [ADR 0019](../adr/0019-usb-device-allocation.md) or the runbook, and which:
- Whether #16 can close, and who decided:
