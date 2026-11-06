# M11 acceptance: hardware-in-the-loop run (PARTIAL, 2026-11-04)

Status: **one live run happened on 2026-11-04 and it stopped early on purpose.** It reached the reserve, attach-before-start and detach-before-destroy steps on real hardware, the failure variant for an unknown mapping, the narrowed-token measurement and the Decker observation. It did **not** reach a `ready` lease: the Lab guest never reported an address (see [What stopped the run](#what-stopped-the-run)), so the in-guest test, mid-run hotplug, contention, the other failure variants and the recovery runs are `not run`. Every item says which it is. The claim that a USB device is held exclusively, used by a guest and always detached is therefore still only partly shown on hardware; the rest rests on the reservation store's guarantees and on tests against a fake Proxmox (`crates/fleet-controller/tests/support/fake_pve.rs`).

Issue: [#577](https://github.com/Frogbyte-io/fleet-manager/issues/577) (FM-1133), epic [#16](https://github.com/Frogbyte-io/fleet-manager/issues/16). Plan: [m11-usb-hardware.md](m11-usb-hardware.md). Decision record: [ADR 0019](../adr/0019-usb-device-allocation.md). The procedure each item refers to is [docs/operations/hardware.md](../operations/hardware.md); this document records its results. Filling it in does not by itself close #16: the maintainer decides that.

## How to fill this in

- Run the steps of the runbook on the integration host, in order, and fill the matching item. Do not edit a `Status` before the step was run.
- `Status` is one of `not run`, `passed`, `failed`, `partly` (say which part), or `blocked` (say why). Anything but `passed` needs a note in the evidence field.
- Evidence is the command, the sanitized output, what you observed, the date and who ran it. Paste outputs, not summaries.
- Sanitize first: no real serials, hostnames, IP addresses, MAC addresses, tokens, certificate fingerprints. Use `<node>`, `<account-id>`, `<lease-id>` and the like. VM 200 and the Decker's guest appear in the `decker` observation; write them as "the guest that holds the Decker" if you quote them.
- When reality differs from a document, record what was measured and name the document. Fix the document in a separate change. (The run of 2026-11-04 was told to correct the runbook in the same change, which it did; this document records the measurement.)

## Live-test scope and authorization

The live devices are the two SuperDrive test mappings on the integration host, `fm-test-superdrive-a` and `fm-test-superdrive-b`, each a path-based mapping of one of two identical `05ac:1500` devices.

- The **Decker mapping and VM 200 are never touched**. No template, lease, hotplug, override or manual command in the run names either. The Decker is observed (read only); the run expected `externally_attached` and got `available` (AC7).
- The nested test cluster's `node-a` has an **unresolved address conflict with VM 200** (its fixed address is leased to VM 200 on the host), so it must not be started for this run. The run uses the physical host `pve` only, and **only after the maintainer authorizes it**.

| Field | Value |
|---|---|
| Maintainer authorization for the physical host (who, where recorded, date) | Andreas, in the instruction that started this run on 2026-11-04: an isolated controller built from `dev`, the physical host only, only the two SuperDrive mappings, the production controller not touched or redeployed, the `FleetUsb` grant kept broad. The authorization lives in that instruction; it is not written anywhere else yet, so Andreas should confirm it on #577. |
| Run date(s) | 2026-11-04, about 21:57 to 22:16 UTC (host clock) |
| Operator | Claude (agent), on Andreas's behalf |
| Fleet controller version / commit | `dev` at `8fb914f5` (merge of #595), debug build, run as an isolated controller: its own temporary data directory and master key, a loopback port, nothing shared with any deployed controller |
| `fleetctl` version / commit | the same build |
| Proxmox VE version and node (`<node>`) | PVE 9.2.2, one physical node `<node>`, kernel 7.0 |
| Guest image used (id as `<image-version-id>`, kernel with USB drivers and `usbutils`: yes/no) | Template VM 7000 (`fleet-agent-template`, a Debian cloud image with the guest agent), pinned through a **seeded** build record promoted with `images promote` (deviation from the Packer route, see [Deviations](#deviations-from-the-runbook)). USB drivers and `usbutils`: **unknown**, the guest never became ready |
| Token ACL choice for `FleetUsb` (broad `/mapping/usb`, or narrowed per mapping) and what Fleet reported | Broad `/mapping/usb` (the maintainer's choice), kept. The narrowed per-mapping grant was also measured and works, see [the unmeasured table](#what-pve-does-unmeasured-on-real-proxmox) |
| `hardware_refresh_interval_seconds` in effect | The default, 600 (not overridden) |

Before the run: [x] `fm-test-superdrive-a` and `-b` are referenced by no guest (read only on the host: the only guest config with a `mapping=` entry is the Decker's guest) · [x] no template names `decker` · [x] the controller includes the saga, reconciler, override release and hotplug routes (`dev` at `8fb914f5`) · [ ] a scratch guest `<scratch-vmid>` designated by the maintainer: **none designated, and none was needed because the run stopped before that step**

## Acceptance criteria (from #577)

The acceptance criteria of #577 read: *the operator creates the mapping, Fleet lists it, a lease attaches it, a test runs, cleanup detaches it, and a failure variant is shown; the manual Decker attachment to VM 200 is shown as `externally_attached` and left alone; a mid-run hotplug attach and detach is shown; unverified items are listed.* The *Tests* line asks for the recorded run, sanitized (no real serials, hostnames or IPs). Each clause is one item below.

### AC1. The operator creates the mapping

Runbook: [step 2](../operations/hardware.md#2-the-operator-creates-the-pve-mapping), and [step 3](../operations/hardware.md#3-grant-the-opt-in-fleetusb-role) for the role.

- Status: **passed** (the mappings were created earlier by the maintainer, as root, in the FM-S11 spike; this run created and edited none, and Fleet cannot)
- Mapping definitions as found (ids, and `node=<node>,id=05ac:1500,path=<bus-port>` with the ports as placeholders):

  ```text
  fm-test-superdrive-a   map node=<node>,id=05ac:1500,path=<bus-port-a>
  fm-test-superdrive-b   map node=<node>,id=05ac:1500,path=<bus-port-b>
  fm-test-verbatim       map node=<node>,id=18a5:0428
  ```

- `check-node` output (root, read only, `pvesh get /cluster/mapping/usb --check-node <node> --output-format json`), reduced to id and errors; the `decker` entry is shown only as present:

  ```text
  decker                 errors: []
  fm-test-superdrive-a   errors: []
  fm-test-superdrive-b   errors: []
  fm-test-verbatim       errors: []
  ```

  The host's `lsusb -t` showed two mass-storage devices (driver `usb-storage`) on bus 1 at exactly the two mapped ports, and `/sys/bus/usb/devices/<bus-port>/product` read `MacBook Air SuperDrive` for both.
- `FleetUsb` role and ACLs granted (what, where): `pveum role add FleetUsb --privs "Mapping.Audit,Mapping.Use,VM.Config.HWType"`, then `pveum acl modify /mapping/usb --roles FleetUsb --users <fleet-test-user> --tokens <fleet-test-token>`. No per-VMID grant: the test token already holds `PVEVMAdmin` on `/vms`, which includes `VM.Config.HWType`. Before the grant, `fleetctl proxmox privileges` read `usb.read-mappings` granted (part of `PVEAuditor`) and `usb.attach-mapping` and `usb.detach-mapping` **missing** (`Mapping.Use`), with the `lab` tier still `granted` because these checks are not required; after it all five USB checks read `granted`.
- Date / operator: 2026-11-04, Claude
- Notes: the grant is broad, so the token **can** use the `decker` mapping. No template, lease or command named it. See the narrowed measurement below.

### AC2. Fleet lists it

Runbook: [step 1](../operations/hardware.md#1-read-only-pre-flight) and [step 4](../operations/hardware.md#4-fleet-lists-the-devices).

- Status: **passed**
- `hardware list` before any refresh: `{"items": [], "page": {...}}` (empty, as documented).
- `hardware refresh` **before** the grant: all four devices `unsupported`, `reason` `token_lacks_mapping_use`, `reasonText` "the token lacks Mapping.Use on the mapping (the opt-in FleetUsb role)"; `guestScan` `{listed: 1, read: 1, truncated: false, unreadable: 0}` (the one guest the token can see is the Lab template).
- `hardware refresh` **after** the grant (abbreviated; there is no serial anywhere in the output, and `manufacturer` and `product` are `null` because the node inventory is not readable with this token):

  ```text
  decker                 available   stale: false   holder: null   (note: the entry for node <node> is id-only (<vendor:product>); identical devices cannot be excluded without the node USB inventory)
  fm-test-superdrive-a   available   stale: false   holder: null   entries: [{node: <node>, vendorId: 05ac, productId: 1500, usbpath: <bus-port-a>}]
  fm-test-superdrive-b   available   stale: false   holder: null   entries: [{node: <node>, vendorId: 05ac, productId: 1500, usbpath: <bus-port-b>}]
  fm-test-verbatim       available   stale: false   holder: null   (same id-only note)
  support: {state: supported}   warnings: []   pveVersion: 9.2.2
  ```

- `fleetctl hardware list` text table (ports shown as placeholders):

  ```text
  MAPPING                  STATUS       NODE/ID@PORT                   STALE  HOLDER
  decker                   available    <node>/<vendor:product>        -      -
  fm-test-superdrive-a     available    <node>/05ac:1500@<bus-port-a>  -      -
  fm-test-superdrive-b     available    <node>/05ac:1500@<bus-port-b>  -      -
  fm-test-verbatim         available    <node>/18a5:0428               -      -
  ```

- Console Hardware page screenshot: not taken (no GUI change; the run was CLI only).
- Date / operator: 2026-11-04, Claude
- Notes: the `decker` row reads `available`, **not** `externally_attached`; see AC7 and [#596](https://github.com/Frogbyte-io/fleet-manager/issues/596).

### AC3. A lease attaches it

Runbook: [step 5](../operations/hardware.md#5-a-template-that-declares-the-device) and [step 6](../operations/hardware.md#6-lease-reserve-and-attach).

- Status: **partly**. The reserve and the attach before the start were recorded on real hardware, and the guest then started with the mapping attached. The lease never reached `ready` (the guest never reported an address), so `lab status` `hardware[]` in the `attached` state, `hardware list` showing the holder, and a read-only look at the clone's `usbN` entry were **not captured**: the run did not read the guest's configuration while the lease was alive.
- Template with `hardware` (request body as sent; the controller is the trusted-LAN release, so no `Authorization` header was needed, and the response wraps the template in `data`, so the id is `.data.id`) and `lab publish` result:

  ```json
  {"name": "lab-usb-a", "description": "FM-1133 live validation: lab-usb-a", "imageVersionId": "<image-version-id>",
   "cores": 1, "memoryMib": 1024, "diskGib": 4, "bootstrapProjectId": null, "readinessProbe": "guest_agent",
   "readinessCommand": null, "sshUser": "root", "readinessDeadlineSeconds": 600, "ttlSeconds": 3600,
   "cleanup": "destroy", "hardware": [{"kind": "usb", "mapping": "fm-test-superdrive-a"}]}
  ```

  The created template echoed `hardware: [{"kind":"usb","mapping":"fm-test-superdrive-a"}]`, and `lab publish` answered the version id `<template-id>@<digest-prefix>`. Templates for `fm-test-superdrive-b` and for a mapping that does not exist were made the same way.
- `lab create <version-a-id> --purpose "usb acceptance a" --account <account-id> --wait --timeout 900`, after a fresh `hardware refresh` (all four devices `available`): it ran for 10 minutes and exited non-zero. The lease went to `releasing` and was released, with `provisionState: never_ready`, `failedStep: guest_ip`, and `vmid: 102` (see [What stopped the run](#what-stopped-the-run)).
- Audit events for that lease (host clock, seconds). The attach happened about nine seconds after the lease was created, which includes the clone and the saga's own re-observation:

  ```text
  22:03:45  lab.lease        lab_lease_creating
  22:03:45  lab.provision    hardware_reserved             (device a; placement, before capacity and any clone)
  22:03:45  lab.provision    lab_capacity_reserved
  22:03:53  hardware.refresh hardware_refresh_started, hardware_refreshed   (the saga's re-observation, after the clone)
  22:03:53  lab.provision    hardware_attach_requested
  22:03:54  lab.provision    hardware_attached
  ```

- Proxmox's own task list for the lease's clone (read only, root, `pvesh get /nodes/<node>/tasks --vmid 102`, the latest rows): `resize` OK 22:03:51, `qmstart` OK 22:03:54, `qmstop` OK 22:13:55, `qmdestroy` OK 22:13:57, all by the Fleet token. So the guest was started after the attach and PVE accepted the start with the mapping in the config (a start with an absent or unknown mapping fails the task, FM-S11 section 5).
- Date / operator: 2026-11-04, Claude
- Notes: the saga's attach and PVE's write behaved as designed. Missing: the read-only look at `usbN` and the lease's `hardware[]` while attached.

### AC4. A test runs

Runbook: [step 7](../operations/hardware.md#7-test-the-guest-sees-the-device).

- Status: **blocked** (no `ready` lease, so nothing could be executed in a guest)
- `lab exec ... lsusb -d 05ac:1500`: not run.
- Guest image has USB host drivers and `lsusb`: not determined. Template 7000 is a Debian cloud image, whose cloud kernel has no USB host drivers according to the FM-S11 notes, so even a ready guest would probably have needed the stock kernel and `usbutils` first (the runbook's "Before you start", item 4). Not checked.
- Date / operator: 2026-11-04, Claude
- Notes: see [What stopped the run](#what-stopped-the-run).

### AC5. Cleanup detaches it

Runbook: [step 8](../operations/hardware.md#8-cleanup-detaches).

- Status: **partly**. Cleanup detached the device before it destroyed the guest, on real hardware, but as the cleanup of the lease that failed at `guest_ip`, not on a `ready` lease ended with `lab destroy`.
- `lab destroy`: not run (the lease had already failed and its cleanup ran by itself). Final lease state `released`; the `lab.provision` operation `failed` (`reason` `never_ready`, `step` `guest_ip`); the `lab.cleanup` and `proxmox.guest.destroy` operations `succeeded`.
- Audit sequence (host clock, seconds). The first `hardware_detached` precedes the creation of the destroy operation, which is the point of the criterion:

  ```text
  22:13:54  lab.provision  hardware_attached (closing event, outcome failed)      the provision failed here
  22:13:54  operation.create  kind lab.cleanup
  22:13:54  lab.provision  hardware_detach_requested
  22:13:55  lab.provision  hardware_released
  22:13:55  lab.provision  hardware_detached
  22:13:55  operation.create  kind proxmox.guest.destroy
  22:13:59  operation.create  proxmox.guest.destroy, outcome succeeded
  22:13:59  lab.provision  lab_capacity_released
  22:13:59  lab.lease      lab_lease_released
  22:13:59  lab.provision  hardware_detached (closing event, outcome succeeded)
  ```

  The order differs slightly from the runbook's list: `hardware_released` is recorded between `hardware_detach_requested` and `hardware_detached`, and `hardware_detached` appears twice (an opening and a closing event; `hardware_attached` likewise). The listing carries only `event` and `node` in `metadata`.
- After a refresh, `hardware list`: `fm-test-superdrive-a` `available`, `holder: null` (all four devices `available`).
- Read-only check on the host (root): the only guest config containing `mapping=` is the Decker's guest; `qm list` shows no guest outside the original set; the clone at VMID 102 no longer exists.
- Date / operator: 2026-11-04, Claude
- Notes: from the detach request to the end of the whole cleanup (detach, destroy, release) took about five seconds.

### AC6. A failure variant is shown

Runbook: [step 9](../operations/hardware.md#9-failure-variants). #577 asks for one; the others are worth recording because each exercises a documented path. Mark any not attempted as `not run`, never as passed.

| Variant | Status | Expected | Evidence (command, sanitized output, observation) |
|---|---|---|---|
| F1 Unknown mapping | **passed** | Placement refusal `hardware_unknown`, nothing allocated | Template declaring `fm-test-does-not-exist`, published, `lab create ... --wait` after a refresh. The lease ended `failed`, `vmid: null`, `hardware[0].reservation: null`; `lab_placement_refused` with `reason: hardware_unknown` was audited (written twice, an opening and a closing event) and no clone, no VMID and no guest appeared (`qm list` unchanged). The operation `errorJson` was exactly the documented message: `hardware fm-test-does-not-exist is not in the inventory of account <account-id>; an operator creates the Proxmox USB mapping and refreshes the inventory (fleetctl hardware refresh --account <account-id>)`, `reason: hardware_unknown`. Detail the runbook did not give: `lab status` reports `failedStep: clone` and `provisionState: never_ready` for this placement refusal. |
| F2 Missing device (cable unplugged, then replugged to the same port) | not run (needs a person to unplug a cable; a remote run cannot) | `missing`, `hardware_missing`; back to `available` on the same `usbpath` after replug and refresh | |
| F3 Detach the token cannot do (ACL removed after `ready`) | not run (needs a `ready` lease) | `detach_failed`, device `quarantined`, guest kept, lease in cleanup retry; recovers after the ACL is restored (record by retry or reconciler, and how long) | |
| F3b The ACL removal also removes `Mapping.Audit` | not run (same) | The next refresh may report the account `unsupported` (`no_mapping_audit`); recorded separately from F3 | |
| F4 Guest `hotplug` without `usb`: detach | not run (needs a `ready` lease) | `detach_pending` (HTTP 202, exit 2), device still on the guest, row `detaching`; confirmed after restart | |
| F4 Guest `hotplug` without `usb`: attach | not run (same) | `hardware_attach_pending` (409), entry removed again | |

- Overall AC6 status: **partly**. The acceptance sentence asks for one failure variant and F1 shows one; the failed lease of AC3/AC5 (the guest never ready) is a second fail-closed behaviour on a real device: the provision failed, and cleanup still detached the device before it destroyed the guest and released it. F2, F3, F3b and F4 are `not run`.
- Date / operator: 2026-11-04, Claude
- Notes: F1 touches no device (placement refuses first), so it shows the refusal path but nothing about attach compensation on hardware.

### AC7. The manual Decker attachment to VM 200 is `externally_attached` and left alone

Runbook: [step 11](../operations/hardware.md#11-a-manually-attached-device-is-externally_attached-and-left-alone).

- Status: **failed** for the criterion as written (the Decker did not read `externally_attached`; it read `available`), **passed** for "left alone". The cause is the test token's own ACL, not a Fleet fault, but it exposes a real gap, filed as [#596](https://github.com/Frogbyte-io/fleet-manager/issues/596).
- The `decker` device in `hardware list` after the grant and a refresh: `status: available`, `holder: null`, `observation.externalReferences: []`, and only the note about an id-only entry. The test token carries an explicit `NoAccess` ACL on the guest that holds the Decker (and on every guest that is not Fleet's), so `GET /cluster/resources` as the token omits it: the refresh's `guestScan` was `{listed: 1, read: 1, truncated: false, unreadable: 0}` (the Lab template only), a complete-looking scan. Fleet cannot report a reference it cannot see. The runbook's expectation was written without this; the runbook is corrected.
- Why it was not worked around: showing `externally_attached` for the Decker would have meant changing the token's ACL on the Decker's guest (a protected guest), which the run did not do. The same behaviour on a scratch guest could not be shown because no `ready` lease or designated scratch guest existed.
- Confirmation that no write of any kind was issued against the Decker mapping or its guest, or VM 100, 201 and 7150: the run's own Proxmox commands as root were reads (`qm list`, `pvesh get` of the mapping list and `check-node`, `pveversion`, `lsusb`, task list and config reads of the run's own clone and of template 7000) plus the `pveum` role and ACL changes listed under [Host changes](#host-changes-and-reverts). The only reads that touched the protected guests were an `md5sum` of every guest config file under `/etc/pve/qemu-server/` and a `grep -l mapping=` over them (read only, to prove nothing changed); the md5 of every config file, those of VMs 100, 200, 201 and 7150 included, was identical before and after the run. Fleet itself called no write on any guest but its own clone, and the token cannot see VM 200 or 201 at all.
- Scratch-guest case: not run. The lease for that mapping refused with `hardware_externally_attached`: not run. The scratch guest's `usb0` entry after a reconciler pass: not run.
- Date / operator: 2026-11-04, Claude
- Notes: also true in the other direction: because the token can use every mapping (the broad grant) and cannot see the Decker's guest, a template naming `decker` would have been reserved and attached to a lease's guest while the other guest still drives it. No template named it.

### AC8. A mid-run hotplug attach and detach is shown

Runbook: [step 10](../operations/hardware.md#10-mid-run-hotplug).

- Status: **not run** (needs a `ready` lease; none was reached, see [What stopped the run](#what-stopped-the-run)). Every field below is blank for that reason.
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

- Status: **passed** (the list exists and every row now says measured, not reached, or contradicted)

See [Still unmeasured or assumed](#still-unmeasured-or-assumed) below. Most rows are `not reached`, because the run did not get a `ready` lease; two are measured (the narrowed `FleetUsb` grant, and the guest the token cannot audit), and one is new (#596).

### Tests: the recorded run is sanitized

- Status: **partly**. The author sanitized every output here (placeholders for the node, ports, account, ids; no serial exists in any output; no token, secret, fingerprint, host address or hostname was copied), but no second person has reviewed it.
- Reviewer who checked the recorded run for serials, hostnames, IPs, MACs, tokens and fingerprints (name, date): none yet.
- Notes: Fleet's own ids (lease, reservation, device, template) are kept out as placeholders. The raw outputs are not kept in the repository.

## Further items the runbook exercises

These go beyond the literal acceptance sentence, but the plan's failure-injection gate ("no device reserved by two live leases, no released lease whose device stays silently assigned") is only shown on hardware by them.

### X1. Two-lease contention

Runbook: [step 12](../operations/hardware.md#12-two-lease-contention).

- Status: **not run** (needs two `ready` leases, or at least one live holder; none was reached). `hardware_busy` was never provoked on hardware, so the contention path is still shown only by the fake-PVE suites.
- Different devices, two leases at once, each `ready` with one device (`lsusb` shows exactly one SuperDrive in each guest):
- Same device while held: `hardware_busy` naming the holder, for `a` and for `b`; the holders undisturbed:
- Race: two simultaneous `lab create` for the same version, exactly one `ready` and one `hardware_busy` (record both lease ids and the final `hardware list`):
- Hand-over: after the holder is destroyed and a refresh, the device leases again:
- Date / operator:
- Notes:

### X2. Recovery with the override release

Runbook: [step 13](../operations/hardware.md#13-recovery-a-reservation-that-will-not-clear).

- Status: **not run**. No reservation of this run ever got stuck, and the only safe way to make one (the F3 ACL removal on a `ready` lease) needs a `ready` lease.
- A stuck reservation reproduced (how, and its state):
- What Fleet reported before acting (`hardware list`, reconciler findings in `audit list --action hardware.refresh`):
- `hardware override-release <reservation-id> --confirm-unverified` result (`outcome` `released`, `previous`):
- Audit events (`hardware_override_release_requested` before `hardware_released` with outcome `override`, `hardware_override_released`):
- After a refresh: device `available` if the entry was removed, `externally_attached` if it was left, and the next lease refused with `hardware_externally_attached` in the second case:
- Date / operator:
- Notes:

### X3. Reconciler on real PVE

- Status: **not run**, apart from one observation: about ten minutes after the controller started, the scheduled inventory refresh (default interval, 600 s) recorded one `hardware_status_changed` audit event for the device the lease held (the failed lease was still holding it then). The listing does not carry `from_status` and `to_status`, so the transition itself was not read. No reconciler repair or finding was seen.
- A hold that never attached, or an owner-finished row, released by the reconciler without a request (which row, after how long):
- A foreign `usbN` entry left untouched with a `hardware_reconcile_finding`:
- Date / operator:
- Notes:

## What stopped the run

The Lab guest cloned from template 7000 never reported an IPv4 address. The first hardware lease failed at step `guest_ip` after the whole 600 s readiness deadline (`never_ready`); Proxmox's task list shows the guest was started (after the attach) and ran for those ten minutes. **Why it never got an address is not known.** Nothing about the guest was observed while it lived (no console output, no agent query), because the run stopped instead of looking. The sources offer candidates, none checked: the M7 acceptance run found that the fixture template 7000 has no `/etc/machine-id` (#328) and used a DHCP-capable clone of it, template 7001, which does not exist on the physical host; or the guest agent in the physical host's copy of 7000 may not start.

The run did not go on, for two reasons that were outside what it was allowed to change:

1. **Another lease means another clone at VMID 102, not in the 900-919 range the run had been told to use.** The host sets no cluster `next-id` range, so `GET /cluster/nextid` answers the lowest free number, 102 (Proxmox's task history for VMID 102 shows earlier Fleet-token clones there, so this is how the host has behaved before, but it is not the range the run was given). The clone was destroyed by Fleet, and VMID 102 was free before and after.
2. **Fixing the guest most likely needs a different template** (a new template VM, or a change to template 7000), which the run's list of allowed host changes did not include.

The safe state was made (device available, no guest left, controller stopped, see [Host changes](#host-changes-and-reverts)) and the work that needs neither a guest nor a new VMID was finished: F1, the narrowed `FleetUsb` measurement, and the Decker observation.

To finish the run: give Lab a template whose clones get an address (run a plain `lab create` without hardware first, the runbook's "Before you start", item 3, and the step this run skipped), install a kernel with USB host drivers and `usbutils` in it (item 4), and either set the cluster's `next-id` range or accept VMID 102 for the leases.

## Deviations from the runbook

- **The image was a seeded build record, not a Packer build.** Packer (1.16.1 with the Proxmox plugin) is installed on the dev machine, but a real build would have created a new template VM on the host, which was outside the allowed host changes, and the run was told to use template 7000. So the recipe (`proxmox-clone` of VMID 7000) was created and published with `fleetctl images create|publish`, one succeeded `image.build` record was written into the **stopped, isolated** controller's own SQLite store (the same seeding that `crates/fleet-controller/tests/lab_failure_injection.rs` does for the repository's own live Lab scenarios), and `fleetctl images promote` ran through the real promotion gate. The record's Packer and plugin versions read `seeded-fm577`. This is not the documented route ([lab.md, First run](../operations/lab.md#3-build)); no Fleet-built image was tested.
- **The VMID was 102, not 900-919** (above).
- **A protective ACL step was added and reverted.** The test token held `PVEVMAdmin` on `/vms`, with `NoAccess` only on the guests that existed when it was created. Five guests made later (VMIDs 7100, 7110, 7111, 7140 and 7150) were therefore visible to, and writable by, the token. Following the maintainer notes ("a VM created on the host later needs its own NoAccess ACL for fleet-test"), `NoAccess` was added on them for the test user and the test token before Fleet read anything, and removed again at the end so that the host is as found. **Recommendation: keep those ACLs**; the controller's `hardware refresh` reads every guest the token can see.
- **No scratch guest was designated** and none was needed, as the run stopped first.
- **The template request body** in the runbook was shortened: the run sent the fields the repository's live harness sends (`bootstrapProjectId`, `readinessCommand`, `sshUser` as well). Whether the shorter body is accepted was not tested.

## Host changes and reverts

Everything the run changed on the integration host, with its state at the end. Nothing else was changed: no mapping was created, edited or deleted, no guest config was edited by hand, and no VM was started, stopped, created or destroyed by hand.

| # | Change | State at the end |
|---|---|---|
| 1 | Role `FleetUsb` created: `Mapping.Audit`, `Mapping.Use`, `VM.Config.HWType` | **Kept** (the documented grant) |
| 2 | `FleetUsb` on `/mapping/usb` for the test user and the test token (the maintainer's broad choice) | **Kept** |
| 3 | The narrowed-grant measurement: `FleetUsb` added on `/mapping/usb/fm-test-superdrive-a` and `-b`, the broad entry removed, measured, then the broad entry restored and the two narrow entries removed | **Reverted** (only the broad grant of #2 remains) |
| 4 | `NoAccess` on `/vms/7100`, `/vms/7110`, `/vms/7111`, `/vms/7140`, `/vms/7150` for the test user and the test token | **Reverted** (see the recommendation above) |
| 5 | One Lab clone, VMID 102, created, resized, started, stopped and destroyed by Fleet through the test token (lease failed at `guest_ip`) | **Destroyed by Fleet** at 22:13:57; verified absent |
| 6 | `fm-test-superdrive-a` attached to that clone by Fleet (`usbN: mapping=...`) | **Detached by Fleet before the destroy**; verified: no guest config but the Decker's guest contains `mapping=` |

How the end state was checked (root, read only): the `md5sum` of every file in `/etc/pve/qemu-server/` is identical to the one taken before the run (VMs 100, 200, 201 and 7150 included); `pveum acl list` differs from the start only by the two `FleetUsb` entries of change 2; `qm list` equals the start; the four mappings are unchanged and all `available`. The isolated controller was stopped by its process id, and its temporary data directory, which holds the account record and its master key, and the build directory are deleted.

## Still unmeasured or assumed

Each `Outcome` below says what the run settled. It was written in advance, from the pull-request descriptions ([#587](https://github.com/Frogbyte-io/fleet-manager/pull/587), [#588](https://github.com/Frogbyte-io/fleet-manager/pull/588), [#589](https://github.com/Frogbyte-io/fleet-manager/pull/589), [#594](https://github.com/Frogbyte-io/fleet-manager/pull/594)), the FM-S11 research ([proxmox-usb.md](../research/proxmox-usb.md)), the token guide and the M11 plan, and most rows stay as they were. "Unmeasured" means nobody observed it on real PVE through Fleet; "assumed" means a behaviour the code relies on without an observation; "by design" means a documented limit that is not a question.

### What PVE does (unmeasured on real Proxmox)

| Item | Where it comes from | Outcome |
|---|---|---|
| A **pending detach after the guest stops**: with `hotplug` lacking `usb`, what PVE does with the stored delete when the guest then stops (applied, kept, lost) | #587, #588, #589; lab.md "Not measured" | **Not reached.** Needs a `ready` lease and a guest whose `hotplug` lacks `usb` (runbook F4 extension). |
| **Deleting a pending-only leftover from a running guest**: whether the delete of a `usbN` that exists only as a pending value succeeds | #587, #588, #589 | **Not reached.** Same. |
| The **unknown-mapping answer**: what PVE answers an attach, a `check-node` or a start for a mapping id deleted or renamed after the last refresh, and whether Fleet's refusal (verify, fingerprint) reads as documented. FM-S11 recorded PVE's raw `400 hotplug problem` and start failure, never Fleet's handling of it | proxmox-usb.md section 4 and 5; this draft's reading of the item | **Partly measured.** A template that names a mapping Fleet has never inventoried is refused at placement with `hardware_unknown` and the documented message, nothing allocated (F1, AC6). **Not reached:** a mapping deleted or renamed after the last refresh (the attach-time verify and the fingerprint pin), and PVE's raw answer to an attach, `check-node` or start for it through Fleet. Deleting or renaming a mapping would have touched the shared mapping configuration, which this run did not do. |
| The **`usbN` slot limit by `ostype` and machine type**: the PVE documentation says `n` is 0 to 4, up to 14 on machine version 7.1+ with Linux or newer Windows; Fleet records at most five slots (`usb0` to `usb4`) and refuses beyond that. Which of the two applies to a Lab clone was not measured | m11-usb-hardware.md; #587 ("beyond the five slots Fleet records") | **Not reached.** Needs a guest to write `usb5` to; none was ready to be edited by hand. |
| **`check-node` on multi-node clusters**: Fleet calls `?check-node=` per node; only a single physical node (and a nested pair that could not be used) was ever exercised | proxmox-usb.md "What was not measured"; #589 (cost per node) | **Not reached.** The host is one node and the nested cluster is off limits. On the single node, `?check-node=<node>` answered `200` with an empty `errors` list for all four mappings, both as root and as the Fleet token, and Fleet used it for presence. |
| Whether the **`usbpath` survives a host reboot** (measured only across a hub-port disable and enable) and what `busnum` does | proxmox-usb.md section 2 and "What was not measured" | Not measured. A reboot or a physical re-plug of the cable is not possible on this remote host, which runs other people's guests. The mappings were found at the same two ports as in FM-S11 (`lsusb -t` and `check-node` at the start of this run), which shows only that they had not moved since 2026-10-30. |
| **Narrowing `FleetUsb`** to `/mapping/usb/<id>`: per-mapping `Mapping.Audit` is measured for the list and the single read, not for `?check-node=`; the device may read `unsupported` (`usb_inventory_unreadable`) | proxmox-token.md | **Measured: it works, with one condition.** With `FleetUsb` granted only on `/mapping/usb/fm-test-superdrive-a` and `/mapping/usb/fm-test-superdrive-b` (user and token) and the broad grant removed: `GET /cluster/mapping/usb?check-node=<node>` as the token answered `200` with all four mappings and an empty `errors` list; `fleetctl hardware refresh` answered `support.state` supported with no warning; the two test mappings read `available`; the `decker` and `fm-test-verbatim` mappings read `unsupported` with `token_lacks_mapping_use`, so the token and Fleet are kept away from the Decker; `fleetctl proxmox privileges` showed `usb.attach-mapping` and `usb.detach-mapping` granted on exactly the two mapping paths. **Condition:** `Mapping.Audit` still came from `PVEAuditor` on `/` (the test token has it), so `?check-node=` and the list were readable without `FleetUsb`. A token whose only `Mapping.Audit` is per mapping was **not** measured (the FM-S11 table only measured list and single read for that case). The broad grant was restored afterwards, as the maintainer chose. |
| **Two guests driving one device**: only the shared open handle was observed; what each guest sees is undefined. PVE gives no exclusivity, so Fleet's reservation is the only guard | proxmox-usb.md section 5 | **Not reached.** Never attempted on purpose: it would need the device attached to two guests. |
| **Migration and HA** of a guest holding a mapped device: offline needs a target entry, a running guest is refused; read from `qemu-server`, never exercised on a second node | proxmox-usb.md section 7; ADR 0019 | **Not reached.** One node. |
| **Resuming a `vmstate` snapshot** of a guest with a mapped device | proxmox-usb.md | **Not reached.**  |
| **Raw `host=`** behaviour for a missing device (the documentation sentence the plan quoted); root-only for a token | proxmox-usb.md | **Not reached.**  |
| **Behaviour on PVE 8.x with real hardware** (only the nested USB tablet was available there) and the guest's own view of the device under an unplug | proxmox-usb.md | **Not reached.** Only the physical PVE 9.2.2 host was used. |
| `Mapping.Modify` privileges for create, edit and delete were measured only as root; Fleet never uses them | proxmox-usb.md | **Not reached.** Fleet does not use them, and this run created or edited no mapping. |
| A **Lab guest image with USB host drivers**: the acceptance template's cloud kernel has none; the spike added the stock kernel and `usbutils` to a throwaway guest. Whether Lab's images need that, and what the guest sees with the default image, is unmeasured | proxmox-usb.md "Method" | **Not reached, and a precondition failed first.** The Lab guest built from template 7000 never reported an address in 600 s (see [What stopped the run](#what-stopped-the-run)), so what it sees of a USB device is unknown. |

### What Fleet assumes or has not measured on hardware

| Item | Where it comes from | Outcome |
|---|---|---|
| **The crash window between a PVE write and its record**: a controller killed in that window leaves an `attaching` row; with an entry on the guest it becomes `attach_unknown` with no slot, never deleted, and clears only by the guest showing no reference or by `hardware.override-release`. Exercised by fake-PVE failure injection only | #587, #589 | **Not reached.** It needs the controller killed between a PVE write and its record. |
| **Narrow case: an `attach_unknown` row that carries a slot**: if the provider's write never landed and an operator added an identical `mapping=<id>` to the clone before cleanup read the guest, cleanup would delete that entry (an exact value in the recorded slot, never anything else) | #587 | **Not reached.**  |
| **VMID reuse after a hand-deleted guest** is not detected; a stuck live row blocks the destroy of an unrelated guest that reuses its VMID until the row is resolved | #587 (D5) | **Not reached.**  |
| **An absent guest is not a confirmed detach** (the cluster listing omits guests the token cannot audit), so a hand-deleted guest holding a device needs the override | #587, #589 | **Not reached.**  |
| **The fingerprint pin** is written by a second hook just after the reserve, not inside the reserve transaction; a reservation with no pin is pinned at its first attach (the older, weaker behaviour) | #587 | **Not reached.** The attach passed the fingerprint check, so a pin or the first-attach fallback worked; the pin table was not read. |
| **Whole-account inventory refresh per attach** (up to 512 guest config reads, two for a running guest, concurrency 8): the latency of an attach and of a mid-run hotplug on a real cluster was not measured | #587, #588, #589 | **Partly measured.** On this account the saga's re-observation (a refresh of an account with one visible guest) started and finished within the same second, and the attach was recorded one second later; the whole path from lease creation to `hardware_attached` took about nine seconds, including the clone and the disk resize. The 512-guest case and a running-guest hotplug latency were not measured. |
| **The scheduled refresh** (default every 600 s; devices read `stale` above 900 s): its load on a real cluster and the `hardware_status_changed` audit trail were not measured | #589 | **Partly measured.** The scheduled refresh ran ten minutes after the controller started (the default 600 s) and audited one `hardware_status_changed`; no `hardware_refresh_failed`. Its load on a real cluster was not measured, and the event listing does not carry `from_status` and `to_status`. |
| **The reconciler's pass and its limits** (180 s deadline, 256 rows, 32 guest reads, backoff 10 to 60 minutes) against a real, slow or unreachable Proxmox | #589 | **Not reached.** It ran (the process was up for about 15 minutes) but no row of the run was in a state it repairs, and no finding was seen. |
| **The hotplug route is synchronous and not a durable operation**; a crash mid-request leaves a row cleanup resolves. **The per-device lock is in-process** (one controller) | #588 | **Not reached.**  |
| **A pending mid-run attach is rolled back** rather than left to apply at the next restart: a choice, because the alternative needs a new state | #588 | **Not reached.**  |
| **`already_attached` reports the reservation row**, not a fresh read of the guest | #588 | **Not reached.**  |
| **The pool detach path** is exercised at cleanup level only; pooled templates with hardware are refused (`hardware_pool_unsupported`) | #587 | **Not reached.**  |
| **VMID hold and cleanup identity**: while one failed record holds a VMID every new lease is refused with `conflict` (a `cleanup_failed` lease holds its VMID until an operator resolves it); a clone queued but not yet written can look like an absent guest to the identity check; the holder check is scoped by account, not node | #594 | **Not reached.** One observation: Lab took VMID 102, the lowest free number, from `GET /cluster/nextid`, because the host sets no `next-id` range (see the [deviations](#deviations-from-the-runbook)). |
| **A guest the token cannot audit** is omitted from the cluster listing, so a reference to a device on it may be invisible to the scan and the device would read `available` while attached. This is an inference from the listing limit stated in #587, not something any test or run observed; the scan-completeness refusal (`hardware_scan_incomplete`) covers unreadable guests the listing does name | #587 (inference) | **Measured: confirmed, and worse than an inference.** The Decker's guest is hidden from the Fleet test token by a `NoAccess` ACL; the refresh reported `guestScan` `{listed: 1, read: 1, truncated: false}` and the `decker` device read `available`, with no hint that a guest was invisible. `hardware_scan_incomplete` does not fire for a guest the listing omits. Filed as [#596](https://github.com/Frogbyte-io/fleet-manager/issues/596). |

### Not covered by M11 at all

Persistent machines with devices (FM-1125, separate), queueing for a busy device, groups or labels ("any device of this model"), Fleet-created or edited mappings, whole-controller USB and PCI passthrough, live migration of guests holding devices, and the Decker and VM 200 (non-goals of #577).

## Result

Filled in by the run of 2026-11-04 (partial). The decision on #16 is the maintainer's.

- Items passed / failed / blocked / not run:
  - passed: AC1, AC2, AC9, and F1 of AC6
  - partly: AC3 (reserve and attach before start recorded; `ready` never reached), AC5 (detach before destroy recorded, on a failed lease's cleanup), AC6 overall, the sanitization check (no second reviewer), X3 (one scheduled-refresh observation)
  - failed: AC7 as written (the Decker read `available`, not `externally_attached`, because the token cannot see its guest; it was left alone)
  - blocked: AC4 (no `ready` lease, and the guest image's USB drivers are unknown)
  - not run: AC8 (hotplug), X1 (contention), X2 (override release), F2, F3, F3b and F4
- Anything that contradicts [lab.md](../operations/lab.md), [ADR 0019](../adr/0019-usb-device-allocation.md) or the runbook, and which:
  - ADR 0019 decisions 6 and 8 assume the scan sees every guest in the account's cluster; a token that cannot audit a guest hides it silently ([#596](https://github.com/Frogbyte-io/fleet-manager/issues/596)).
  - The runbook: step 11's expectation for the Decker, the `jq` path in step 5, the prerequisites of "Before you start" (a `next-id` range, a guest that gets an address first, a token that can audit every guest), and the audit order in step 8. All corrected in `docs/operations/hardware.md` by the same change. lab.md and the token guide are not changed here; their relevant lines (the narrowed-grant "not measured" note in the token guide) are now measured above and should be updated by their owner.
- Whether #16 can close, and who decided: **No**, on this evidence. The saga's reserve, attach and detach-before-destroy steps worked on real hardware, but the in-guest test, hotplug, contention, the other failure variants and the recovery runs are `not run`, and #596 is open. Not decided by the run.
