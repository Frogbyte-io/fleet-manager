# Persistent machines

A persistent machine is a long-lived VM that Fleet creates, registers and keeps. Lab leases are the opposite: cloned, used, destroyed. Decision record: [ADR 0018](../adr/0018-persistent-machines.md). This page is the operator guide for `fleetctl machines create`.

## Which controller

Persistent machines are **created and owned by the permanent controller**: the Compose-on-Coolify deployment in [`deploy/COOLIFY.md`](../../deploy/COOLIFY.md) with private ingress over Tailscale is the **reference setup**; `deploy/fleetd` (a host install) is the alternative. Register the Proxmox account in it (`fleetctl proxmox create`, `observe`, `confirm`). A trusted-LAN controller in `/tmp` or any controller whose data directory can disappear is **unsuitable**: the machine record, its endpoint, the host key it trusts and the SSH key Fleet generated live in that controller's database and master key. Lose them and the VM survives but Fleet can no longer reach it.

Back up the whole data volume and the master key separately, as `deploy/COOLIFY.md` ("Backup and recovery") describes, before creating machines you cannot recreate, and after creating them. A restore needs both: the generated private keys are encrypted under the master key.

## Create

Prerequisites: a promoted image version of a template with the QEMU guest agent and an SSH server, and a credential Fleet can log in with before it has its own key (the image's bootstrap key).

```
fleetctl machines create --account <account> --image-version <version> --name build-box \
  --cores 4 --memory 8192 --bootstrap-user root \
  --bootstrap-auth identity-file --bootstrap-identity /path/to/image-key
```

`--review-only` prints the spec as it will run and the review token without creating anything. The operation:

1. reserves the VMID (the next free one, or `--vmid`) and writes the **persistent marker**;
2. full-clones the promoted image's template (optionally `--node`, `--storage`);
3. waits for the clone's lock, grows the disk (`--disk`), and writes **one** allow-listed settings change: tags, description, `onboot` (default on), `protection` (default on), cores, memory, `net0` bridge, audio. The template's tags are never inherited; fixture and Lab tag prefixes are refused;
4. starts the guest and waits for the guest agent's IPv4 address;
5. refuses an address that is already another machine's SSH endpoint, takes the address only from the guest-agent interface whose MAC address Proxmox gave the VM, registers the machine and its SSH endpoint, waits for SSH and records the host key: trust on first use with an audit event, or `--pin-fingerprint SHA256:...`, which fails the operation if the guest presents anything else;
6. links the guest to the machine;
7. rotates the credential (below), then, on Windows, the computer name, the administrator password and activation.

A failed run keeps the VM, the machine and the marker, and names the failing `step`. Run the same command again: it adopts the guest and continues, also after the credential switch (the Fleet-held key is used, the image key is not needed, and no second key is generated). A re-run is refused for a machine that is already created, and for an unfinished one when the image version differs. Nothing is deleted automatically. The image version must still be promoted with its pinned build when the operation runs, not only when it was reviewed.

The marker records whether the clone completed. A marker guards a VMID against Lab only while its clone completed or the guest there still has the marked name; a clone that failed with nothing at the VMID removes its marker. A marker left behind by a hand-removed guest holds its VMID (Lab provisioning skips it) until you drop it: `fleetctl machines abandon --account <a> --vmid <n>` (reviewed and audited; refused for a created machine).

### SSH key choice

- default / `--credential generate`: Fleet generates a per-machine ed25519 key. The private key is stored only in the encrypted secret store, bound to the machine (`machines/ssh/<machine>/<id>`); no API, CLI output, payload, log or audit event contains it.
- `--credential <reference>`: an existing Fleet SSH credential not bound to another machine.
- `--public-key '<line>'`: a key held outside Fleet. Fleet cannot log in with it, so it cannot verify it: it installs the key, **keeps** the bootstrap credential as the endpoint's default, and reports `bootstrapKeyRemoved: false`.
- `--login-user <user>`: a login user other than the image's, created if missing (needs a root bootstrap login on Linux). Not allowed with `--public-key`: Fleet could not log in as that user.

A reference must be a machine key (`machines ssh-key store`); a repository credential is refused. Generated keys, and the administrator passwords Fleet stores for a machine, are bound to the machine and deleted when the machine is deleted.

Order for the first two: install the new key while the bootstrap credential works, verify a login with the new key, switch the endpoint's default auth, replace `authorized_keys` with only the new key over the new key, verify again. A failure before the switch leaves the bootstrap key working. Afterwards `fleetctl machines exec <machine> -- uname -a` uses the stored key.

### Windows

Persistent Windows machines must come from the **generalized base** (#452), never a Fleet clone image: clone images are specialized for Lab and carry no way to give each machine its own identity. Pass `--os windows`. The computer name is the machine name (at most 15 characters, validated) and is set by a post-boot step with a restart. The key goes to `administrators_authorized_keys` with its required ACL. `--admin-password store|discard` rotates the local administrator password to a value generated on the guest, stored as a Fleet secret or not kept at all (key login only).

Activation is optional; unactivated is a valid state.

- Product key: `fleetctl machines product-key store` (key on stdin) prints a reference; `--activate-key <reference>`. The key is stored encrypted, never returned by any API, and sent to the guest on the SSH session's **stdin** only, as part of the script. It is installed through the licensing service's `InstallProductKey` CIM method, so no child process has it in its argument list (`slmgr /ipk <key>` would, and echoes it). Caveat: Windows PowerShell script-block logging, if a policy enables it on the guest, records script text including the key; leave it off on machines you activate this way, or activate with KMS. Then `slmgr /ato`, and `SoftwareLicensingProduct.LicenseStatus` and `/xpr` are read back and recorded as the machine fact `windows/activation`.
- KMS: `--activate-kms <host[:port]>` (`slmgr /skms`).
- A failed activation (no internet, key in use, wrong edition) fails only that step, with Microsoft's error code; the VM stays created and registered. A retail key activates one machine at a time: to move it, deactivate the old machine first (`slmgr /upk`).

## Agents ask; people approve (#496)

A restricted agent credential cannot create a persistent VM: `machines.provision` is refused to delegated credentials, so the direct create and its review answer 403. Such a caller asks instead:

```
fleetctl machines create --request --purpose "nightly build host" --account <a> --image-version <v> --name build-box --cores 4 --memory 8192 --disk 40 --wait-approval=15m
```

`POST /api/v1/machines/create/request` (`requestMachineCreate`) takes the same `spec` and a `purpose`, runs the same checks as the review (rules, promoted image, references), and files an action request for `proxmox.machine.create` (needs `action.request`, not `machines.provision`). The parameters are the spec's references and public keys only, with the credential-shaped key names (`credential`, `secret`, `publicKey`, `adminPassword`) renamed so the broker's credential check passes honestly; an activation key is only ever a `machines/product-key/` id. The request is `approve` class: it waits for a person (`fleetctl requests approve <id>`, or the Approvals page), and the answer says whether policy or a person decided.

On approval the broker builds the same `machine.create` operation and review token a direct create builds, with one addition: the spec is stamped with the requesting principal, the purpose (the request's reason, folded to one line) and the request id. #489's executor then runs unchanged, and when it registers the machine it records the stamp on the machine's persistent marker (`persistent_guests.owner`, `purpose`, `request_id`, migration 0064). It is **not** a machine fact: fleetd and SSH inventory reports can write arbitrary fact namespaces, so the `fleet` fact namespace is reserved and dropped from every report. `GET /machines/{id}` returns the record as `ownership` and the machine page shows it under Summary. A direct create records none, and a direct call that carries the stamp is refused. The executor also records the `machine_provision_requested` audit event with the request id when a brokered creation starts.

### Authorization is checked again when it runs

- Whoever approved it, the requester must still hold `action.request`.
- The approver needs `action.approve` and `machines.provision`. An approver without the second is refused when approving and the request stays pending for one who has it.
- When the operation starts, the broker checks again: an approval by a person needs that person to still hold both; an approval by policy needs the requester to still hold `action.request` and the request to still be inside the bounds. A request that fails the check ends `failed` with the reason and creates nothing.
- An operation the request already created (a crash before it was linked) is linked as it is; only creating a new one is gated.
- A policy that turned to `deny` ends a pending request `denied` when someone approves it, as for any action.
- A rejection or an expiry creates nothing.

### Policy bounds

By default every request waits for a person. An operator can allow small requests without one with `FLEET_PERSISTENT_AUTO_POLICY`, a JSON object (a malformed value stops startup):

```
FLEET_PERSISTENT_AUTO_POLICY='{"maxCores":4,"maxMemoryMib":8192,"maxDiskGib":64,"imageVersions":["<version-id>"],"nodes":["pve1"],"storages":["local-lvm"],"maxPerPrincipal":2}'
```

With none set nothing is auto-approved. When any is set, `maxCores`, `maxMemoryMib` and `maxDiskGib` must all be set (otherwise startup stops: bounds without size limits would approve any size). Other fields: `imageVersions`, `nodes`, `storages`, `bridges` (allow-lists; empty means any), `allowedTags` (tags that may be requested; empty means none), `allowVmid` and `allowLoginUser` (default false) and `maxPerPrincipal`. A request inside **all** set bounds, and of the plain shape below, is approved by policy and starts at once; anything else waits for a person.

- A limit the request leaves to the image's default (no `--cores`, `--memory`, `--disk`, `--node`, `--storage` or `--bridge` where that bound is set) cannot be shown to be inside it, so it needs a person.
- Only the plain shape is auto-approved: the default first-login (the controller's agent), a `generate`d or `--public-key` credential, no explicit VMID, tags outside `allowedTags` or login user unless allowed, and protection on.
- `maxPerPrincipal` counts the principal's requests for this action that are pending, approved, running or succeeded. A machine destroyed later still counts: the quota guards against a runaway agent, it is not an inventory.
- `FLEET_ACTION_POLICY=proxmox.machine.create=deny` refuses every request outright; `=approve` keeps everything for a person whatever the bounds; `=auto` is an explicit decision to approve by policy: without bounds it auto-approves **every** request, so combine it with bounds (an out-of-bounds request then waits).

### Audit

The request, the decision (the approver, or `policy:auto`), the start of the operation (with its id) and the outcome are the broker's linked events, keyed by the request id. The machine's `fleet/request` fact and the operation result's `requestId` carry that id forward, so the creation can be traced back to the request, the requester and the approver.

## Lab never selects it

The persistent marker (not the name) keeps the guest out of the Lab sweeper's inventory, Lab pools and Lab cleanup. Persistent names may not start with `fm-lab-`.

## Change settings and destroy

```
echo '{"description":"CI runner","tags":["ci"]}' | fleetctl proxmox config --account <a> --node <n> --vmid <v>
```

`proxmox config` accepts only tags, description, onboot, protection, cores and memoryMib, and refuses templates, promoted image artifacts, Lab guests and pool members. Destroying a persistent VM is a separate, confirmed act. `--confirm-persistent` is required (checked when the review and the run are made); it also lifts the Proxmox protection itself, with an audit event, before the delete. The marker goes with the guest.

```
fleetctl proxmox destroy <account> <node> <vmid> --confirm-persistent --wait
```

Then delete the machine record with `fleetctl machines` if it should go too.

## List and register

`fleetctl machines persistent list` (API `GET /machines/persistent`, and the Persistent machines section of the console Fleet page) shows every guest Fleet keeps: created by Fleet or registered.

An existing VM becomes persistent without being recreated:

```
fleetctl machines persistent register --account <a> --vmid <n> [--machine <machine-id>]
```

The command shows the review and asks for confirmation (`--yes` skips it; without a terminal `--yes` is required), then registers. The guest is looked at live: it must be a QEMU VM and not a template, a promoted image artifact, a Lab clone (`fm-lab-` name) or a Lab pool member, must carry no `fleet-pve-test`, `fleet-lab` or `fm-lab` tag (remove it with `proxmox config` first), and must not be marked already. `--machine` names an existing Fleet machine for the marker; it needs the link permission on that machine, and the machine must be free and not linked to another guest (a guest link is still made with `machines link-guest`). Registration writes only the marker (audited as `persistent_guest_registered`): protection, tags and the SSH key are unchanged; set them with `proxmox config` and rotate credentials separately. A registered marker guards the VM only while its name is unchanged, so a VM that is gone or renamed stops being shielded. To undo a registration: `fleetctl machines persistent unregister --account <a> --vmid <n>` (reviewed, audited, the VM is left as it is). Destroying a registered VM never lifts its protection: lift it yourself (`proxmox config`, `protection=false`), then `proxmox destroy --confirm-persistent`.

The console's Create persistent machine dialog is the same review and create as `fleetctl machines create`.

## Create from an ISO with an unattended install (Linux)

When there is no promoted image, `machines create` can install a Linux guest from an ISO that is already on Proxmox storage:

```
fleetctl machines create --account <a> --iso local:iso/ubuntu-24.04-live-server-amd64.iso \
  --answer-iso local:iso/ci-seed.iso --node pve1 --storage local-lvm --disk 40 --name ci-linux \
  --bootstrap-user ci --bootstrap-auth identity-file --bootstrap-identity /path/to/key [--efi] [--tpm]
```

`--iso` replaces `--image-version`; `--node`, `--storage` and `--disk` are required (there is no template to take them from). The ISOs are named by Proxmox volume id (`storage:iso/file.iso`). **Fleet does not build or carry the answer file**: no password, key or product key travels in an operation payload, audit event or log. You prepare the answer media and upload it to ISO storage yourself.

The operation: reserves the VMID and writes the persistent marker; creates the VM (virtio-SCSI disk of `--disk` GiB, `net0` on `--bridge` or `vmbr0`, guest agent on, the installer as CD-ROM `ide2` and the answer ISO as `ide3`, boot order installer then disk, optional OVMF/EFI disk and TPM v2.0; `--efi` creates the EFI disk with the default Microsoft Secure Boot keys enrolled, which Ubuntu and Debian boot, but a custom kernel or an unsigned installer will not); applies the same reviewed hardware and metadata settings as an image clone (tags, description, `onboot`, protection); starts the guest and **waits for it to power off**; ejects the install media (each CD-ROM becomes empty; it is never deleted, because Proxmox refuses to remove a drive from a protected guest, and protection is on by default), sets the boot order to the disk, and boots the installed system. From there it is the same as a clone: guest agent address, registration, host key trust, link, key rotation. The first login is the `--bootstrap-*` credential, which your answer file must have installed. The end of the install is seen from the VM's live power state (not the cluster listing, which lags by seconds), and only after this run has seen it running and then stopped. A re-run adopts the guest and continues: if the installer had started and the guest is stopped with the media still attached, it ejects without installing again. A guest with no media attached is adopted only when Fleet's own earlier run ejected it; otherwise the run stops with `media_missing`, because a guest nobody installed is not an installed one.

Requirements on the answer file:

- It must **power the guest off when the install ends** (Ubuntu autoinstall: `shutdown: poweroff`; Debian preseed: `d-i debian-installer/exit/poweroff boolean true`). Fleet detects the end of the install by the VM stopping; an installer that reboots would boot the ISO again. If it never stops, the operation fails with `install_timeout` and the guest is left as it is. A real install takes 20 to 60 minutes: the default `--timeout` is 1800 seconds (the maximum is 7200), so pass a longer `--timeout` for a server install.

Recovery from an installer that powered off early (a failed install): Fleet cannot tell a failed install from a finished one, so it ejects the media and goes on, then fails at the guest agent address or the SSH step. Fix the answer file, destroy the VM (`fleetctl proxmox destroy <account> <node> <vmid> --confirm-persistent`, which lifts the protection Fleet set) and create the machine again.
- It must install the QEMU guest agent and an SSH server, and the bootstrap key or password.
- The guest must start the install without a keypress. Ubuntu live-server asks for confirmation before it applies an autoinstall unless `autoinstall` is on the kernel command line, which Fleet cannot add; use an installer image that is already set up for this (for example one remastered with `autoinstall` in its boot entry, or a Debian preseeded ISO). This is the reason an answer-file generator is separate work.

Secrets: an answer file that sets a password holds it on the ISO storage. Use a key, or a throwaway password you rotate afterwards, and keep the ISO storage restricted. An ISO install is never approved by the agent policy bounds: it always waits for a person, because the answer file is code that runs as root on the new VM. Windows is not supported here: `guestOs windows` is refused with a pointer to the generalized base image; autounattend delivery is follow-up work.

## Not in this release

Fleet-generated answer media (a NoCloud seed builder), Windows autounattend installs, LXC, cluster placement and HA.
