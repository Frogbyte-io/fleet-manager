# Hardware-in-the-loop runbook: USB devices in Lab leases

Status: **draft, written before any live run** (FM-1133, [#577](https://github.com/Frogbyte-io/fleet-manager/issues/577)). **No live run has happened.** Every behaviour below comes from the code, the fake-PVE test suites, the merged pull-request descriptions, and the FM-S11 measurements in [`docs/research/proxmox-usb.md`](../research/proxmox-usb.md). Nothing here has been exercised against real hardware through Fleet. The recorded run belongs in [`docs/planning/m11-acceptance.md`](../planning/m11-acceptance.md), which is a blank template until that run exists; what is still unmeasured is listed there.

This is the operator's end-to-end walk through the USB workflow: create the Proxmox mapping, let Fleet list it, lease a guest that declares it, run a test, clean up, then the failure, hotplug, contention and recovery variants. The reference material stays where it is: the design is [ADR 0019](../adr/0019-usb-device-allocation.md) and the [M11 plan](../planning/m11-usb-hardware.md); the refusal table, the reconciler and the override-release runbook are in [Lab operations, USB hardware](lab.md#usb-hardware); the token role is in [proxmox-token.md](proxmox-token.md). This page does not repeat them; it sequences them and says what to look for at each step.

## Read this first: what the live run may touch

The only live devices for this work are the two SuperDrive test mappings on the integration host:

| Mapping id | Meaning |
|---|---|
| `fm-test-superdrive-a` | Path-based mapping of the first of two identical SuperDrives (`05ac:1500`) |
| `fm-test-superdrive-b` | Path-based mapping of the second one, a different port |

(The Verbatim mapping `fm-test-verbatim` also exists, but this runbook does not need it.)

- **The Decker mapping (`decker`) and VM 200 are never touched.** No template, lease, hotplug request, override or manual command in this runbook names either. The Decker is attached to VM 200 by hand for Dot X work and must stay so. Fleet will show it as `externally_attached`; the runbook only *looks* at that (step 11).
- **Reading is not touching, but say it out loud.** `fleetctl hardware refresh` reads every guest config in the account's cluster, VM 200's included, through the Fleet token, and writes nothing to Proxmox. That read is what makes the Decker show as `externally_attached`. If even a config read of VM 200 is unacceptable for a given run, do not refresh that account until the maintainer says so.
- **Physical host only after authorization.** The nested test cluster's `node-a` has an unresolved address conflict with VM 200 (its fixed address is leased to VM 200 on the host; see [What was not measured](../research/proxmox-usb.md#what-was-not-measured)). Do not start it for this work. The live run uses the physical host, and only after the maintainer has authorized it. Record the authorization in the acceptance document's header before step 1. Until then everything below is a plan.
- **Sanitize everything you record.** No real serials (the PVE API returns none anyway), hostnames, IP addresses, MAC addresses, tokens or certificate fingerprints. Use the placeholders below.

### Placeholders

| Placeholder | Meaning |
|---|---|
| `<account-id>` | The Fleet Proxmox account id (`fleetctl --output json proxmox accounts`) |
| `<node>` | The PVE node that holds the devices and the Lab image's template |
| `<image-version-id>` | The promoted Lab image version the templates pin |
| `<template-id>`, `<version-id>` | Lab template and published version ids |
| `<version-a-id>`, `<version-b-id>` | The published versions of the templates that declare `fm-test-superdrive-a` and `fm-test-superdrive-b` |
| `<lease-id>`, `<lease-id-2>` | Lease ids |
| `<vmid>` | The Lab clone's VMID (`lab status` shows it) |
| `<scratch-vmid>` | A throwaway guest the maintainer designates for step 11. Never VM 200 and never a Fleet-managed guest |
| `<reservation-id>` | A hardware reservation id (`hardware list` `holder.id`, or `lab status` `hardware[].reservation.id`) |
| `<bus-port-a>`, `<bus-port-b>` | The physical ports of the two SuperDrives, as `<bus>-<port>` (for example the form `1-10`) |
| `$FLEET_URL`, `$FLEET_TOKEN` | The controller URL and the credential for the one `curl` call in step 5 |

## What the run proves, and what it does not

It shows, on real hardware and through Fleet, that:

1. Fleet lists a path-based mapping the operator created, with a status.
2. A lease that declares the mapping reserves the device exclusively, attaches it to its guest before the guest starts, and the guest sees it.
3. Cleanup detaches it before the guest is destroyed, and the device is available again.
4. A device someone else attached stays `externally_attached` and is never taken, adopted or removed.
5. A lease holder can detach and re-attach the device mid-run.
6. Two leases cannot hold the same device; a second request fails with `hardware_busy` and names the holder.
7. The failure and recovery paths behave as documented.

It does **not** prove anything about persistent machines (FM-1125 is separate), queueing (there is none), pooled templates with hardware (refused), the Decker, migration, or anything the acceptance document lists as unmeasured.

## Before you start

1. **Maintainer authorization** for the physical host is recorded (see above).
2. **Fleet controller** is a build that includes the saga, the reconciler, the override release and the hotplug routes (FM-1123, FM-1124, FM-1126). Confirm `fleetctl hardware --help` and `fleetctl lab hardware --help` print usage. Do not deploy hardware templates to a controller without them: a crash in the milliseconds between a PVE write and its record leaves a row only the override release or a maintainer can clear.
3. **A trusted Fleet Proxmox account** for the integration host exists and has the Lab tier working (an ordinary `lab create` without hardware succeeds). `fleetctl --output json proxmox accounts` shows it with a confirmed fingerprint.
4. **A Lab image whose guest has USB support.** The acceptance template used for FM-S11 had a cloud kernel with no USB drivers; the spike installed the stock `linux-image-amd64` and `usbutils` on its throwaway guest so `lsusb` could show the device. The test in step 7 needs the same: a guest kernel with USB host drivers and `usbutils` (`lsusb`). Build or choose such an image first. This is an assumption the run has to confirm, not something measured for Fleet's Lab images.
5. **The guest's `hotplug` option includes `usb`** (the Proxmox default is `network,disk,usb`). Steps 7 to 10 assume it; the variant in step 9 changes it on purpose.
6. **No guest references either test mapping.** Check by hand in Proxmox (read only) that neither `fm-test-superdrive-a` nor `-b` appears in any guest's `usbN` entry. If one does, Fleet will (correctly) show it `externally_attached` and refuse it.

## 1. Read-only pre-flight

```sh
fleetctl --output json proxmox accounts
fleetctl --output json proxmox privileges <account-id>
fleetctl --output json hardware list --account <account-id>
```

Expect: the account is trusted; `privileges` shows the `usb.read-mappings`, `usb.attach-*` and `usb.detach-*` opt-in checks and is expected, before step 3, to report them missing (see [Verify with `fleetctl proxmox privileges`](proxmox-token.md#verify-with-fleetctl-proxmox-privileges)); `hardware list` is empty or lists only devices from an earlier refresh. An empty list means nothing has been refreshed, not that there are no devices. These three commands change nothing.

Record the output in the acceptance document (sanitized).

## 2. The operator creates the PVE mapping

Fleet never creates or edits a mapping and never holds `Mapping.Modify`. A person with that privilege does this on the Proxmox side, **once per physical device**. The two SuperDrives are identical (`05ac:1500`), so each needs a **path-based** entry: the mapping's identity is then the physical port, and swapping the cables swaps the devices. A `vendor:product`-only entry would resolve to the first matching device and PVE would not flag it as ambiguous.

For each device, find its port (`<bus>-<port>`) on the host, for example with `lsusb -t`, and confirm which cable is which before you name it. Then create (or confirm) the mapping, either in the web UI (Datacenter, Resource Mappings, USB Devices) or on the host:

```sh
# On the Proxmox host, as an operator with Mapping.Modify. Not a Fleet command.
pvesh create /cluster/mapping/usb --id fm-test-superdrive-a \
  --map "node=<node>,id=05ac:1500,path=<bus-port-a>"
pvesh create /cluster/mapping/usb --id fm-test-superdrive-b \
  --map "node=<node>,id=05ac:1500,path=<bus-port-b>"
```

Notes, all from FM-S11:

- `id` is mandatory even with `path` (a path-only entry is refused); with `path` it is only a hardware-change check.
- Creation validates nothing: a wrong path, a mismatched `id` or a wrong node is accepted. Check the result instead:

  ```sh
  pvesh get /cluster/mapping/usb --check-node <node>
  ```

  An empty `errors` list for both mappings means the device is present at that port and matches. `usb device '<bus-port>' not found` or `'id' does not match` means fix the mapping now, before Fleet reads it.
- One entry per node per mapping. Two entries for one node are accepted and refused at attach.
- The mapping id becomes `usbN: mapping=<id>`: letters, digits, `-`, `_`, `.`, 1 to 64 characters.
- The `pvesh` form above is the documented API path, but it was not re-run for this draft. If the flags differ on your PVE version, use the web UI.

Record the mapping definitions (ids and `node=…,id=…,path=…` with the ports as placeholders) and the `check-node` output.

## 3. Grant the opt-in `FleetUsb` role

Without it Fleet does not guess: the devices read `unsupported` with `token_lacks_mapping_use` or `token_lacks_guest_hwtype`. Follow [proxmox-token.md](proxmox-token.md) (the role is created in step 2 of its setup, the ACLs in step 5, the USB paragraph under it):

```sh
pveum role add FleetUsb --privs "Mapping.Audit,Mapping.Use,VM.Config.HWType"
for who in "--users fleet@pve" "--tokens fleet@pve!fleet"; do
  pveum acl modify /mapping/usb --roles FleetUsb $who
  # VM.Config.HWType on each Lab clone-target VMID (not the template, not VM 200):
  pveum acl modify /vms/<clone-target-vmid> --roles FleetUsb $who
done
```

Decisions for the maintainer, because the safe choice is not measured:

- **`/mapping/usb` grants `Mapping.Use` on every mapping, the Decker's included.** Fleet's code never writes `decker`, and no template here names it, but the token could attach it. Narrowing the grant to `/mapping/usb/fm-test-superdrive-a` and `…-b` would keep the Decker out of the token's reach, but [proxmox-token.md](proxmox-token.md) says narrowing is **not measured** for `?check-node=`, which Fleet uses for presence: the devices may read `unsupported` (`usb_inventory_unreadable`). `Mapping.Audit` on `/mapping/usb` is still needed to list mappings at all. Either decide to accept the broad grant for the run, or try the narrow one first and record what Fleet reports. Do not guess; write the choice and the result into the acceptance document.
- **`VM.Config.HWType` only on the Lab clone-target VMIDs.** Do not grant it on `/pool/<pool>` if VM 200 is in that pool, and never on VM 200.

After granting, re-run `fleetctl --output json proxmox privileges <account-id>`; the USB checks should now pass for the guests you granted.

## 4. Fleet lists the devices

```sh
fleetctl --output json hardware refresh --account <account-id>
fleetctl --output json hardware list --account <account-id>
fleetctl hardware list            # the text table
```

`hardware refresh` reads the account's USB mappings, a `check-node` per node, the token's permissions and every guest config it can see (up to 512), then records each device's status. It is an audited mutation of Fleet's records and changes nothing on Proxmox. `hardware list` reads Fleet's own records only, so it is as fresh as the last refresh.

Expect, for the two test mappings, `status: available`, `stale: false`, one `entries` item with `node`, `vendorId` `05ac`, `productId` `1500` and the `usbpath` you mapped, and no `holder`. There is no serial in the output. If a device is anything else, the status says why:

| You see | It means | Do |
|---|---|---|
| `unsupported` with `token_lacks_mapping_use` / `token_lacks_guest_hwtype` | The `FleetUsb` role is missing or too narrow | Step 3 |
| `unsupported` with `usb_inventory_unreadable` | `check-node` could not be read for the node (the unmeasured narrow-grant case) | Widen the `Mapping.Audit` grant |
| `unsupported` with `no_node_entry` or `ambiguous_mapping` | The mapping has no entry for a node, or two entries for one | Fix the mapping (step 2) |
| `missing` | `check-node` reports the device not found at that port | Check cable and port, refresh |
| `externally_attached` | A guest Fleet did not attach references the mapping | Step 11 explains; do not "fix" it from Fleet |
| `stale: true` | The last observation is older than the bound (900 s) | Refresh again |

The same list is on the console's Hardware page; its tones are in [DESIGN.md](../../DESIGN.md#hardware-conventions). The controller also refreshes accounts that have devices on a schedule (default every 600 s), so devices rarely stay stale; refresh yourself right before a lease when you have just changed a mapping, a cable or a guest.

Also expected: the `decker` mapping appears in the list as `externally_attached`, with a refresh observation naming VM 200. That is the "left alone" case; see step 11. It is only observed here.

## 5. A template that declares the device

A Lab template (and each published version) has an optional `hardware` list of up to four `{ "kind": "usb", "mapping": "<id>" }`, each mapping named once. `fleetctl lab template-create` has **no** hardware flag, and neither does `lab create`. Create the draft through the API with the fields the CLI sends plus `hardware`, then publish with the CLI. Add whatever `Authorization` header your controller requires (the form used in [the registry workflow](../guides/registry-workflow.md) is `-H "Authorization: Bearer $FLEET_TOKEN"`; not confirmed for this endpoint):

```sh
curl -fsS -X POST "$FLEET_URL/api/v1/lab/templates" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "lab-usb-a",
    "description": "Disposable guest with SuperDrive A",
    "imageVersionId": "<image-version-id>",
    "cores": 2, "memoryMib": 2048, "diskGib": 20,
    "readinessProbe": "guest_agent", "readinessDeadlineSeconds": 600,
    "ttlSeconds": 3600, "cleanup": "destroy",
    "hardware": [{ "kind": "usb", "mapping": "fm-test-superdrive-a" }]
  }' | jq -r .id                                            # the template id

fleetctl --output json lab publish <template-id> | jq -r .id   # the version id
```

Make a second template, `lab-usb-b`, the same way with `fm-test-superdrive-b`. Later steps need one template per device. A `PUT /api/v1/lab/templates/{id}` replaces the whole draft, so repeat `hardware` or it is cleared. `fleetctl --output json lab templates` shows `hardware` on each version that has any.

Never put `decker` in a template.

## 6. Lease: reserve and attach

```sh
fleetctl --output json hardware refresh --account <account-id>
fleetctl --output json lab create <version-id> --purpose "usb acceptance a" \
  --account <account-id> --wait --timeout 900            # prints the lease; note its id
fleetctl --output json lab status <lease-id> | jq '{state, node, vmid, hardware}'
fleetctl --output json hardware list --account <account-id>
```

Placement reserves the device with the capacity, before any clone. The saga then, after the clone and before the start, re-observes the account, checks the device is present on the clone's node and matches the fingerprint pinned at reservation time, finds no other guest referencing the mapping, writes `usbN=mapping=<id>` conditional on the config digest, and reads it back. The lease is `ready` only after every declared device is `attached`.

Expect:

- The lease reaches `ready`. `hardware[0].reservation.state` is `attached`, `usbSlot` is set (`0` for the first free slot), `deviceId` and `id` are filled.
- `hardware list` shows `fm-test-superdrive-a` as `reserved`, `holder.ownerKind` `lease`, `holder.ownerId` the lease id, `holder.state` `attached`, with the guest and slot. The console's card shows the holder block with an `ATTACHED` chip.
- `fm-test-superdrive-b` is still `available`.
- In Proxmox, read-only: the clone's config shows `usbN: mapping=fm-test-superdrive-a` and nothing else about USB.

If the provision fails instead, it fails at the `usb_attach` step with a `reason` in the operation's `errorJson` and the guest is never started; see [When a device is refused](lab.md#when-a-device-is-refused) and the failure variants below.

## 7. Test: the guest sees the device

```sh
fleetctl --output json lab exec <lease-id> --wait -- lsusb -d 05ac:1500
```

Expect exit status 0 and one line naming vendor `05ac` and product `1500` (the Apple SuperDrive). This depends on the guest image having USB host drivers and `lsusb` (see Before you start, item 4); a guest without them cannot show the device even when the attach is correct. Record which it was.

You may also run a longer command with `lab exec` while the device is attached; the point of the step is only that the guest, not just PVE's config, has the device.

## 8. Cleanup detaches

```sh
fleetctl --output json lab destroy <lease-id> --wait --timeout 900
fleetctl --output json lab status <lease-id> | jq '{state, hardware}'
fleetctl --output json hardware refresh --account <account-id>
fleetctl --output json hardware list --account <account-id>
```

Cleanup detaches every device the lease holds before it decides the guest's fate. Expect: the lease ends `released`; `hardware[].reservation` is null again; `fm-test-superdrive-a` is `available` with no `holder` after the refresh; the guest is gone, and no guest in Proxmox references the mapping. Check the audit trail for the sequence:

```sh
fleetctl --output json audit list --action lab.provision --limit 100
```

and look for `hardware_reserved`, `hardware_attach_requested`, `hardware_attached`, `hardware_detach_requested`, `hardware_detached` and `hardware_released` for this lease. (The filter value is the action the saga files under; if your controller files them under another action, list without `--action` and filter with `jq`.)

## 9. Failure variants

Run each as its own recorded case. After each, return to a clean state (device `available`, no live lease, no guest referencing the mapping) before the next.

### F1. Unknown mapping

Create a draft template that declares a mapping id that does not exist (for example `fm-test-does-not-exist`), publish it and lease it.

Expect: the provision fails at placement, before any allocation (no VMID, no clone), with reason `hardware_unknown` and a message that names the account and tells the operator to create the mapping and refresh. No device is touched, so this is the cheapest variant. Find the reason with `fleetctl --output json operations list`, then `operations get <id>` (`errorJson`), and the lease's `failedStep` in `lab status`.

### F2. Missing device (the cable)

Physically unplug the cable of `fm-test-superdrive-b` (an operator action; only this device), then:

```sh
fleetctl --output json hardware refresh --account <account-id>
fleetctl --output json hardware list --account <account-id>
fleetctl --output json lab create <version-b-id> --purpose "usb missing" --account <account-id> --wait
```

Expect: the device reads `missing`; the lease fails at placement with `hardware_missing` and nothing is allocated. Replug into the **same port**, refresh, and confirm the device is `available` again with the same `usbpath`. If it does not come back, or comes back on another port, you have found the cable-swap case: the mapping is path-based, so the identity is the port. Record it.

### F3. A detach the token cannot do (`detach_failed`)

This is the destructive variant; run it last among the failure cases, and only with the maintainer's agreement to touch the token's ACL.

1. Lease `lab-usb-a` and wait for `ready` (step 6).
2. In Proxmox, remove `Mapping.Use` for the Fleet user and token. `FleetUsb` bundles `Mapping.Audit`, `Mapping.Use` and `VM.Config.HWType`, so the only documented way is to remove the `FleetUsb` ACL on `/mapping/usb` (note exactly what you removed). That also removes `Mapping.Audit`, so the next refresh may report the account itself `unsupported` (`no_mapping_audit`); that is a different outcome from the detach refusal, so record it separately. Removing only `Mapping.Use` needs a separate audit-only role, which this repository does not document.
3. `fleetctl --output json lab destroy <lease-id> --wait`.

Expect: cleanup cannot detach (PVE checks a delete against the mapping the slot currently names, so a token without `Mapping.Use` cannot detach); the reservation goes `detach_failed`, the device reads `quarantined`, the guest is **not** destroyed, the lease stays in cleanup retry and then `cleanup_failed` after the last attempt. `fleetctl --output json hardware list` shows the holder `detach_failed`; `audit list --action hardware.refresh` shows reconciler findings.

Recover: restore the ACL (same commands as step 3), then `fleetctl lab cleanup-retry <lease-id> --wait`, or wait for the reconciler's next pass. The device should return to `available`. If it does not, use step 13. Record the time it took and which of the two resolved it.

### F4. A guest that keeps the change pending (`hotplug` without `usb`)

This is how the pending paths are produced, and they cover two of the behaviours FM-S11 did not measure (see the acceptance document). The clone is Fleet's disposable guest, but the edit is a by-hand change to it, so do it only on a lease created for this purpose:

1. Lease `lab-usb-a` and wait for `ready`.
2. In Proxmox, set that clone's hotplug option without `usb` (for example `qm set <vmid> --hotplug network,disk`). Do not touch any other guest.
3. `fleetctl --output json lab hardware detach <lease-id> fm-test-superdrive-a` (the exit status is 2).

Expect: `outcome` `detach_pending`, HTTP 202, **the device is still on the guest** (check `lsusb` in the guest), the reservation stays `detaching`. Then restart the guest, run the same detach again, and expect it confirmed (`detached`). Then, with `hotplug` still lacking `usb`, `fleetctl --output json lab hardware attach <lease-id> fm-test-superdrive-a` is refused (`hardware_attach_pending`, 409) and Fleet removes the entry it wrote, so a restart cannot attach it. Record what is in the guest's config (stored and `current=1` views) after each step.

Optional extension for the two unmeasured questions: stop the guest between the pending detach and the confirmation (what does PVE do with the pending delete?), and look for a pending-only `usbN` leftover on a running guest after the refused attach. Record whatever PVE does; the saga reads every result back and assumes neither.

## 10. Mid-run hotplug

On a `ready` lease the holder (or an administrator) takes a reserved device off the running guest and puts it back. Both calls need `lab.hardware.detach` / `lab.hardware.attach`, and only a device the lease declared up front can be used.

```sh
fleetctl --output json lab create <version-id> --purpose "usb hotplug" --account <account-id> --wait
fleetctl --output json lab exec <lease-id> --wait -- lsusb -d 05ac:1500         # present

fleetctl --output json lab hardware detach <lease-id> fm-test-superdrive-a
fleetctl --output json lab exec <lease-id> --wait -- lsusb -d 05ac:1500         # absent
fleetctl --output json hardware list --account <account-id>                     # still reserved by the lease, holder state held

fleetctl --output json lab hardware attach <lease-id> fm-test-superdrive-a
fleetctl --output json lab exec <lease-id> --wait -- lsusb -d 05ac:1500         # present again
```

Expect: detach answers `outcome` `detached` (`onGuest` false); the guest loses the device within seconds (the FM-S11 measurement; this is the first time Fleet's write is observed doing it); the lease **keeps the device reserved**, so a second lease asking for it still gets `hardware_busy`; attach answers `attached` (`onGuest` true) and the guest sees it again. Repeating either call answers `already_detached` / `already_attached`.

Then the release variant: `fleetctl --output json lab hardware detach <lease-id> fm-test-superdrive-a --release`. Expect the device `available` after a refresh and that this lease can no longer attach it (`hardware_not_reserved`). A second lease can now take it, which is a convenient bridge into step 12. Finally `lab destroy <lease-id> --wait`; a detached or released device needs nothing from cleanup, and an attached one is detached before the guest is destroyed.

Refusals to see once each if convenient: `lease_not_ready` (call it on a lease that is not `ready`), `hardware_not_reserved` (name `fm-test-superdrive-b` on a lease that declared only `a`; the same answer is given for an unknown or another lease's device, so nothing can be probed).

## 11. A manually attached device is `externally_attached` and left alone

Two cases, in this order.

**The Decker (read only).** After step 4's refresh:

```sh
fleetctl --output json hardware list --account <account-id> | jq '.items[] | select(.mappingId=="decker")'
fleetctl hardware list
```

Expect `status` `externally_attached`, no `holder`, and the refresh's observation naming the guest that references it (VM 200, which you will see in the output, so sanitize it). Fleet does not adopt, detach or allocate it, and has no command to; nothing in this runbook issues a write against it. The step is the observation and nothing else. If any step ever seems to need `decker` or VM 200 to change, stop.

**A SuperDrive on a scratch guest (the same behaviour, on a device you may touch).** The maintainer designates `<scratch-vmid>`: a throwaway guest, not VM 200, not a Fleet-managed machine. Its config is written by hand; it does not need to be started.

```sh
# On the Proxmox host, as an operator. Not a Fleet command.
qm set <scratch-vmid> --usb0 mapping=fm-test-superdrive-b

fleetctl --output json hardware refresh --account <account-id>
fleetctl --output json hardware list --account <account-id>     # fm-test-superdrive-b: externally_attached
fleetctl --output json lab create <version-b-id> --purpose "usb external" --account <account-id> --wait
```

Expect: `externally_attached`; the lease for `b` fails at placement with `hardware_externally_attached` and allocates nothing; wait for a reconciler pass (or a second refresh) and confirm the scratch guest's `usb0` entry is **unchanged** (Fleet never removes an entry it did not write). Then remove it yourself and refresh:

```sh
qm set <scratch-vmid> --delete usb0
fleetctl --output json hardware refresh --account <account-id>   # fm-test-superdrive-b: available
```

(Both `qm` lines are the standard Proxmox CLI and were not re-run for this draft.)

## 12. Two-lease contention

This is where both devices are used. Start from both devices `available` and no live lease.

**Different devices, concurrently.**

```sh
fleetctl --output json lab create <version-a-id> --purpose "usb contention 1" --account <account-id> --wait
fleetctl --output json lab create <version-b-id> --purpose "usb contention 2" --account <account-id> --wait
```

Expect both `ready`, each with its own device attached (`lsusb` in each guest shows exactly one SuperDrive), `hardware list` showing both `reserved` by different leases.

**Same device, while held.** With both leases live, lease `<version-a-id>` again:

```sh
fleetctl --output json lab create <version-a-id> --purpose "usb contention 3" --account <account-id> --wait
```

Expect the new lease to fail at placement with `hardware_busy` and a message naming the holder (lease id and reservation id), before anything is allocated. There is no queue and nothing retries. Do the same for `b`. Neither failure may disturb the holders: `lab status` on the holders and `lsusb` in their guests are unchanged.

**Race.** From both-devices-available, start two leases for the same version at the same moment (two shells, or two backgrounded commands with `--wait`):

```sh
fleetctl --output json lab create <version-a-id> --purpose "usb race 1" --account <account-id> --wait &
fleetctl --output json lab create <version-a-id> --purpose "usb race 2" --account <account-id> --wait &
wait
```

Expect exactly one `ready` and one failing with `hardware_busy`. Never both. Record both lease ids and the final `hardware list`.

**Hand-over.** Destroy the holder of `a` (`lab destroy <lease-id> --wait`), refresh, and lease `a` again: it now succeeds. A hold whose lease is already over is also freed by the next request, which must still find the device seen within the bound.

Clean up every lease (`lab destroy`) and confirm both devices are `available`.

## 13. Recovery: a reservation that will not clear

When cleanup cannot show a device is off a guest, the reservation stays `attach_unknown`, `detach_failed` or `detaching`, the device is `quarantined`, the lease is in cleanup retry (then `cleanup_failed`) and the guest is kept on purpose. The full procedure is [A device that cannot be detached](lab.md#a-device-that-cannot-be-detached); in short:

1. See what Fleet sees, and wait one reconciler pass (about five minutes):

   ```sh
   fleetctl --output json hardware list --account <account-id>
   fleetctl --output json audit list --action hardware.refresh --limit 50    # hardware_reconcile_finding
   ```

2. Look at the guest yourself in Proxmox (both the stored and the running `usbN` views). Remove an entry only if you are sure Fleet wrote it. If the finding is `detach_pending`, restart the guest. If the guest is gone, confirm it is really gone and not hidden from the token. Then `fleetctl lab cleanup-retry <lease-id> --wait`.
3. Only if Fleet cannot resolve it (the guest was deleted by hand, the entry is yours and stays, an `attach_unknown` row with no slot beside an entry you have decided about) use the elevated override. **It releases Fleet's record without verifying the guest and never calls Proxmox, so it removes nothing from the guest:**

   ```sh
   fleetctl --output json hardware override-release <reservation-id> --confirm-unverified
   ```

   Without `--confirm-unverified` the command sends nothing. It needs `hardware.override-release`, which an operator has and no delegated Lab credential does, and it is audited (`hardware_override_release_requested` first; if that cannot be written, nothing is released).
4. After an override, `fleetctl --output json hardware refresh --account <account-id>`. A device still attached now reads `externally_attached`, and **the next lease that asks for it fails with `hardware_externally_attached`** until someone detaches it by hand and refreshes. An absent one reads `available`.

The override also works on a reservation whose lease is provisioning or ready, and then it takes the device away from a lease that still believes it holds it. Never use it on a live lease unless you mean that.

To exercise it on purpose, the F3 state (ACL removed) is the safest source of a `detach_failed` row. Once you have recorded F3's own recovery, repeat F3 and this time resolve it with this step instead: confirm in Proxmox that the entry is gone (remove it by hand if you are sure it is Fleet's), then run the override, refresh, and record the audit events.

## 14. What to record, and how

For every step, in [`m11-acceptance.md`](../planning/m11-acceptance.md): the command, the sanitized output, the observed result, and who ran it and when. Sanitize before writing anything down:

- No real serials, hostnames, IPs, MACs, tokens, fingerprints or certificate details. Use the placeholders above; the node can be written `<node>`.
- VM 200, the Decker's guest, will appear in the `decker` observation. Write it as "the guest that holds the Decker" if you quote it at all.
- Lease, reservation and device ids are Fleet's own UUIDs and may be kept, or replaced by `<lease-id>` style placeholders if you prefer.
- Screenshots of the Hardware page need the same review (the repository is public) and follow AGENTS.md for GUI evidence.

When something is not as documented, record it as measured and say which document it contradicts; do not fix the document inside the run.

## Commands used in this runbook

All of these exist in `fleetctl` today (checked against `crates/fleetctl` and `skills/fleet/SKILL.md`): `proxmox accounts`, `proxmox privileges <account-id>`, `hardware list [--account]`, `hardware refresh --account`, `hardware override-release <reservation-id> --confirm-unverified`, `lab templates`, `lab publish`, `lab create <version-id> --purpose --account --wait --timeout`, `lab status`, `lab exec --wait -- <command>`, `lab hardware attach|detach <lease-id> <mapping> [--release]`, `lab destroy --wait`, `lab cleanup-retry --wait`, `operations list|get`, `audit list --action --limit`. Not in `fleetctl`: creating a template with `hardware` (the API call in step 5), and every Proxmox-side step (`pvesh`, `pveum`, `qm`, the web UI), which are Proxmox commands and were not run for this draft.
