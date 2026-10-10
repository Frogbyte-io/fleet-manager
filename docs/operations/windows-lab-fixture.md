# Windows 11 Pro fixture: base template and Fleet image (#442)

This runbook builds a Windows 11 Pro base VM on the integration PVE host from Microsoft's official ISO, turns it into a template, and builds a Fleet image version from it with a `--source clone` recipe. Lab templates and pools for Windows guests start from that image. It implements the image requirements of [ADR 0015](../adr/0015-windows-lab-guest-transport.md) (OpenSSH Server in the image) and belongs to [#396](https://github.com/Frogbyte-io/fleet-manager/issues/396). It sits beside [the nested PVE runbook](proxmox-test-cluster.md), whose conventions it follows (fixture VMs tagged `fleet-pve-test`, secrets under `~/.config/fleet/`, nothing private in Git).

The tooling is `deploy/pve-test/windows/windows-template`, with the answer files and in-guest scripts next to it. It reads the same env file as `deploy/pve-test/pve-test`.

## Status

| Part | State |
|---|---|
| virtio-win ISO downloaded and hashed; config ISO built | done |
| Microsoft ISO downloaded and its SHA-256 matches Microsoft's | done, from a link the operator got through the browser |
| Unattended install, guest agent, OpenSSH, key login, PowerShell default shell | done (2026-10-10); first try, the GVLK was accepted |
| Sysprep, template 7100, two clones | done after one manual fix (BitLocker, below); clones get new names and host keys. The committed scripts were then verified end to end on a throwaway VM, not on 7100 itself |
| Fleet recipe, image version, build, promotion, Lab template | image built and promoted, Lab templates created; **lease not verified** (stream J, #441). The first recipe built an image that did not boot (CPU type); the second boots but is **not generalized** (below) |
| Pool member and activation | not created: the operator does it. The point is [documented](#activating-a-pool-member-with-a-retail-key) |

**Microsoft ISO.** The download page issues a time-limited link through the browser, and Microsoft's own download connector rejects scripted requests for it (`Sentinel marked this request as rejected`). This runbook does not work around that and does not use third-party mirrors. A person opens [the download page](https://www.microsoft.com/en-us/software-download/windows11), picks "Windows 11 (multi-edition ISO for x64 devices)" and the language, and copies the 64-bit download link (valid for 24 hours). Then `FLEET_WIN_ISO_URL=<link> windows-template fetch-iso` downloads it on the host. Never paste the link into Git, an issue, or a log.

## What exists

| Item | Value |
|---|---|
| Template VMID | `7100`, name `fleet-windows11-base`, tag `fleet-pve-test` (outside the acceptance suite's scratch range 900-919) |
| Fleet image build VMID | `7110` (set in the recipe), name `fleet-windows11-image`; it is the template of the promoted Fleet image |
| Test clones | `7120` and up (outside the acceptance suite's scratch range), tag `fleet-pve-test`, destroyed after each check |
| virtio-win ISO | `virtio-win-0.1.302` (SHA-256 also pinned in `windows-template`, which refuses a different file), from the [stable direct download](https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso) (Fedora), 877,373,440 bytes, SHA-256 `303f7ae40dad495d6ae474fdc571df58958a4dbc5c37a522d80f9a203867949d`, last modified 2026-08-27 |
| OpenSSH fallback MSI | Win32-OpenSSH `10.0.0.0p2` `OpenSSH-Win64-v10.0.0.0.msi`, SHA-256 `ddec9c53864280759cf9f74791cefd387100e3946aa849a1c138a4ed1b96b7d9` (the GitHub release's digest; the builder checks it before use). Upstream publishes every Win32-OpenSSH release as a preview, including this one, and it is only the fallback used when `Add-WindowsCapability` fails; the in-box feature is the preferred path |
| Windows ISO | Windows 11 multi-edition x64, English (United States), build 26300.9457, 9,047,330,816 bytes, SHA-256 `bd4307df32bc8af33b39ccecb1174aeb345386630f89a2b86c7a4e36b55ea650`. It equals Microsoft's published value for "English 64-bit" on the download page (`BD4307DF...5EA650`), checked 2026-10-10 |
| Windows build | `26300.9457` (`CurrentBuildNumber.UBR`), Windows PowerShell 5.1.26100.9444. The registry's `ProductName` still says "Windows 10 Pro", as on every Windows 11 |

Host files, all on the host's ISO storage (`local`): `virtio-win.iso`, `windows11-x64-multi.iso` (after `fetch-iso`), and `fleet-win-cfg.iso` (0600, deleted after the install because the answer file in it holds the install-time administrator password).

Secrets, on the machine that runs the tool, 0600, never printed:

- `~/.config/fleet/pve-test-windows-admin.password`: the generated local administrator password (24 alphanumeric characters plus a fixed suffix that satisfies the complexity rule).
- `~/.config/fleet/pve-test-windows-ssh` and `.pub`: a dedicated ed25519 fixture key. Only the public half goes into the guest. Load the private half into the ssh-agent the Lab controller uses ([M7 evidence](../planning/m7-acceptance.md#evidence)); Lab authenticates with the controller user's agent keys.

## Licensing

- The answer file uses Microsoft's published (public, non-secret) KMS client setup key for Windows 11 Pro ([Microsoft Learn, KMS client activation and product keys](https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys)). That key only selects the edition during setup. It is not a licence: Microsoft's page says KMS client keys do not activate retail copies and are for volume-licensing scenarios against a KMS host. There is no KMS host on the fixture network, so Windows stays **unactivated**. Unactivated Windows 11 runs with a watermark and personalization limits, and that is acceptable for the fixture.
- No retail key, and nothing that bypasses activation, appears in Git, logs, the recipe, the template, or this runbook. The operator enters their own retail key inside a guest.
- A retail key covers one running copy, and a clone changes hardware identity (SMBIOS UUID, MAC, disks), so activating the template or its clones is not the supported pattern. The supported pattern is a [revert pool](#activating-a-pool-member-with-a-retail-key) with one member per licence, activated in the member before its baseline snapshot. Whether your licence allows running Windows 11 in a virtual machine this way is set by its Microsoft Software License Terms; confirm that before relying on it. This is not legal advice.
- The `Sysprep` limit is 1001 runs per image ([ADR 0015](../adr/0015-windows-lab-guest-transport.md#for-the-image-recipe-and-template)). Rebuild the template from a fresh install instead of re-sysprepping it.

## Steps

All commands run from the repository root on the dev machine. Each step prints what it did and never prints a secret.

### 1. Prepare (done)

```sh
deploy/pve-test/windows/windows-template prepare
```

Generates the password and key if missing, downloads virtio-win to the host and prints its SHA-256, downloads the OpenSSH MSI and refuses it unless it matches the pinned hash, renders `autounattend.xml` and builds `fleet-win-cfg.iso` (volume label `FLEETCFG`) on the host with `xorriso`.

### 2. Fetch the Microsoft ISO

```sh
FLEET_WIN_ISO_URL='<fresh link>' deploy/pve-test/windows/windows-template fetch-iso
```

The host downloads the file (the link travels on stdin, so it is not in a process list) and prints its SHA-256. Compare it with the value Microsoft shows under "Verify your download" for the same language on the download page, and record both here. The command only accepts Microsoft hosts.

### 3. Create the VM and install

```sh
deploy/pve-test/windows/windows-template create        # qm create 7100 and start
deploy/pve-test/windows/windows-template wait-install  # polls the guest agent, then SSH
```

The VM: `q35`, OVMF with `efidisk0 ...,efitype=4m,pre-enrolled-keys=1`, `tpmstate0 ...,version=v2.0`, `virtio-scsi-single`, a 64 GiB `scsi0` on `local-lvm`, `virtio` net on `vmbr0`, 4 cores (`cpu: host`), 8 GiB with ballooning off, guest agent enabled, tag `fleet-pve-test`, three CD drives (`sata0` Windows, `sata1` virtio-win, `sata2` the config ISO). The disk is blank, so firmware boots the Windows CD. The CD asks for a key press, so `create` sends 25 (one per second).

What `autounattend.xml` does:

- **windowsPE**: loads the virtio storage (`vioscsi`, `viostor`) and network (`NetKVM`) drivers from the virtio-win ISO (the drive letter depends on attach order, so it lists D: to G:; paths that do not exist are skipped), lays out GPT disks for UEFI (EFI 260 MB, MSR 16 MB, the rest NTFS), selects the image named `Windows 11 Pro`, and sets the KMS client key.
- **specialize**: random computer name (`*`), `BypassNRO` so OOBE does not wait for a network.
- **oobeSystem**: hides the EULA and online-account screens, creates the local administrator `fleetadmin` (password from the secret file, written to the config ISO only), and auto-logs on once to run the first-logon command.
- **first logon** (`setup-guest.ps1` from the config ISO): installs `virtio-win-guest-tools.exe` quietly (VirtIO drivers and `qemu-ga`, service Automatic); installs OpenSSH Server with `Add-WindowsCapability` (three tries), and if that fails, from the MSI on the config ISO after re-checking its hash; sets `sshd` Automatic, ensures the `OpenSSH-Server-In-TCP` firewall rule on all profiles; writes the public key to `%ProgramData%\ssh\administrators_authorized_keys` (UTF-8 without BOM) with `icacls /inheritance:r /grant Administrators:F /grant SYSTEM:F`; sets `HKLM\SOFTWARE\OpenSSH\DefaultShell` to Windows PowerShell 5.1; turns password authentication off; stops Store auto-download so `sysprep /generalize` does not trip on updated apps; clears the autologon secrets; writes `C:\ProgramData\fleet\setup-complete`.

`wait-install` reports the Windows build number (`CurrentBuildNumber.UBR`), the default shell and the licence status (0 means unlicensed, the expected state). Record the build here. Verify by hand as well:

```sh
ssh -i ~/.config/fleet/pve-test-windows-ssh -o IdentitiesOnly=yes fleetadmin@<guest-ip> '$PSVersionTable.PSVersion; $env:ComSpec'
```

Result on 2026-10-10: key login works, the session is Windows PowerShell 5.1 (`$PSVersionTable` runs as the command), `sshd` and `QEMU-GA` are Automatic and running, the `OpenSSH-Server-In-TCP` rule is enabled on all profiles, and the license status is 5 (notification: unactivated). This is ADR 0015's "PowerShell 5.1 as `DefaultShell`" evidence item.

**Findings from the first run.**

- *Setup key.* Accepted: the retail multi-edition media took the Windows 11 Pro KMS client key as the setup key and installed Windows 11 Pro without a prompt. Had it rejected the key, the answer file would stop at the key page (`WillShowUI` is `OnError`) and the install would hang: look at the PVE console. Fallback: remove the `<ProductKey>` element from `autounattend.xml` (the `/IMAGE/NAME` metadata already selects Windows 11 Pro), rebuild the config ISO with `prepare`, and if setup still asks, choose "I don't have a product key" on the console. The VM stays unactivated either way.
- *BitLocker (found and fixed).* With a TPM, Windows 11 turns on automatic device encryption after setup, and `sysprep /generalize` then fails with `BitLocker is on for the OS volume (0x80310039)`. The first run hit this and was repaired by hand (`manage-bde -off C:`, kill the stuck `sysprep.exe`, start the task again), so **template 7100 was built with that manual step**. The committed fix is `PreventDeviceEncryption` in `setup-guest.ps1`, and a check in `generalize.ps1`: `Get-BitLockerVolume` `VolumeStatus` (an enum, so no locale dependence), `Disable-BitLocker` if needed, at most 8 minutes of waiting (the host waits 20), and a logged failure (`C:\Windows\Temp\fleet\generalize.log`) instead of running sysprep anyway. The committed scripts were verified end to end on a throwaway VM (7101, destroyed): install, setup, generalize and two clones with no manual step. That re-run also found and fixed a `setup-guest.ps1` bug (`New-Item -Force` on the existing BitLocker policy key aborted the script before `setup-complete`).
- *Administrator password.* The install-time password is in the install media only and is removed from the guest (autologon values and cached answer files). The sysprep answer file sets a new random password for the administrator on each clone's specialize pass, so no clone carries the known one. Checked on a clone: `PasswordLastSet` is the clone's first boot, not the install. If the command fails a clone keeps the known password. Use SSH key login, or `qm guest passwd <vmid> fleetadmin` for console use.

If the install stops, open the PVE console. Setup logs are in `C:\Windows\Panther`, the first-logon script's transcript is `C:\ProgramData\fleet\setup-guest.log`.

### 4. Detach media, generalize, template

```sh
deploy/pve-test/windows/windows-template generalize     # sysprep, waits for the guest to power off
deploy/pve-test/windows/windows-template detach-media   # removes the three CDs and deletes the config ISO
deploy/pve-test/windows/windows-template template
```

`generalize` prints the Ed25519 host key fingerprint, then runs `generalize.ps1` on the guest. The script only registers and starts a one-shot SYSTEM scheduled task and returns, because the task stops `sshd`, which would end the SSH session running it. The task stops `sshd`, deletes `C:\ProgramData\ssh\ssh_host_*` (ADR 0015: sysprep does not touch them), deletes the cached answer files that hold the install password (`C:\Windows\Panther\unattend.xml` and others), and runs `sysprep /generalize /oobe /shutdown /unattend:` with `sysprep-unattend.xml`. That answer file keeps the local administrator (it has no `UserAccounts`, so no password), skips OOBE, and again picks a random computer name. 

Once the guest is off, `detach-media` removes the three CDs and deletes the config ISO, so no clone boots with the install media and the install password does not stay on the host. Then `template` converts the stopped VM with `qm template 7100`.

Verify the clone, twice, with different ids:

```sh
deploy/pve-test/windows/windows-template test-clone 7120
deploy/pve-test/windows/windows-template test-clone 7121
deploy/pve-test/windows/windows-template destroy-clone 7120
deploy/pve-test/windows/windows-template destroy-clone 7121
```

Each prints the computer name, the default shell and the host key fingerprint. Pass criteria, which are also the remaining [ADR 0015 evidence items](../adr/0015-windows-lab-guest-transport.md#evidence-not-yet-gathered): both clones reach sshd; both host keys differ from each other and from the pre-generalize fingerprint (`sshd` generated them on first start); both computer names differ from each other and from the base; each has a new MAC. Result for clones of 7100: both reach sshd with key login, computer names `WIN-QCAMIM1R8NL` and `WIN-988DD0GC68D`, host keys `SHA256:snHv4I...` and `SHA256:elMSdu...`, and different DHCP addresses (the MACs were not read for this pair). The pre-generalize fingerprint of 7100 was not captured (the output was lost). The re-run on 7101 with the committed scripts captured it: pre-generalize `SHA256:gzNlI0...`; two clones `SHA256:GMAJoS...` and `SHA256:96h7v3...`, computer names `WIN-O915R1GCNU0` and `WIN-OTOK01P3JF7`, MACs read from the PVE config all different from each other and from the template's, and three different DHCP addresses. Not compared: the machine SID. The shared-key case would mean `sshd` regenerated a key before sysprep powered off.

### 5. Fleet image version

Use the physical-host acceptance env (`~/.config/fleet/pve-acceptance-phys.env`: the `fleet-test@pve!admin` token, node `pve`, storage `local-lvm`) and a controller started as in the [M7 evidence](../planning/m7-acceptance.md#evidence): `fleet-controller serve` on loopback with a temporary data directory and master key, and an `ssh-agent` holding the fixture key. Add a Proxmox account for the host, `observe` and `confirm` its certificate, and store the token, as in [the Lab runbook](lab.md).

The fixture token needs no ACL change for these VMs. Its `/vms` grant (`PVEVMAdmin`, propagated) covers 7100, 7110 and the test clones, and its `NoAccess` entries are only on the pre-existing VMs (creating, cloning and building with the token worked on 2026-10-10). Check with `pveum user token permissions fleet-test@pve admin --path /vms/7100`.

```sh
BUILD_ACCOUNT=<account-id>
fleetctl --output json images create --name fleet-windows11 --description "Windows 11 Pro, OpenSSH in the image" \
  --node pve --storage-pool local-lvm --source clone < deploy/pve-test/windows/recipe.example.json | jq -r .id
fleetctl --output json images publish <recipe-id> | jq -r .id
fleetctl --output json images build <version-id> --account "$BUILD_ACCOUNT" --wait --timeout 3600
fleetctl --output json images promote <version-id>
fleetctl --output json lab template-create --name windows11 --image-version <version-id> \
  --cores 4 --memory 8192 --disk 64 --probe guest_agent --readiness-deadline 1200 --ttl 3600 --cleanup revert --guest-os windows
fleetctl --output json lab publish <template-id>
```

Edit `proxmox_url` (and `node`) in a copy of `recipe.example.json` for your host first. **`lab template-create` has no SSH user option and defaults to `root`, which does not exist on this image, so a lease on that template cannot log in. Create the template through the API with `sshUser` set to the fixture administrator** (`POST /api/v1/lab/templates`, the same JSON the CLI sends plus `"sshUser": "fleetadmin"`, and `"guestOs": "windows"`), then `lab publish` it. The recipe (`cpu_type` and `os` matter, see below) builds a full clone of 7100 (`full_clone: true`: the TPM state and the efidisk are copied) as VMID 7110 with `communicator: none`, like the plain clone-to-template recipe in the Lab runbook. The plugin and Fleet's recipe gate accept it for a Windows guest.

**Two findings from the first build.**

1. **CPU type.** The Proxmox builder gives its VM `cpu: kvm64` and `ostype: other` unless the recipe says otherwise. The first image (recipe without them) booted the generalized guest on `kvm64`, and its clones then stopped at the Windows recovery screen (`0xc0000001`): Windows 11 needs a modern CPU model. The recipe now sets `cpu_type: host`, `os: win11` and `tags`.
2. **The build boots the clone, so the image is not generalized.** The base template is generalized, and the Proxmox builder starts the clone and stops it again. With `communicator: none` that boot runs specialize and OOBE, so the resulting Fleet image is a specialized system. Checked: two clones of 7110 have the **same** computer name (`WIN-DT7LBDAIC18`) and the same SSH host key, where two clones of 7100 do not. Consequences:
   - Clones of the Fleet image (non-pooled Lab leases) share a computer name, machine SID and SSH host key. Each lease still pins its own endpoint with trust on first use, and the guests are disposable and isolated, so the Lab checklist runs, but the ADR 0015 uniqueness requirement is not met for them.
   - **Pool members must be cloned from 7100, not from 7110** ([below](#activating-a-pool-member-with-a-retail-key)). A member cloned from the generalized base gets its own identity at its first boot.
   - Re-generalizing at the end of the build needs a communicator login, and a recipe may hold no credential or key file. Packer's temporary key is installed through cloud-init, which Windows lacks (Cloudbase-Init in the image would fix that). Tracked in [#452](https://github.com/Frogbyte-io/fleet-manager/issues/452); not done here.

The Fleet image built from the working recipe, and its Lab templates, are in [Evidence](#evidence).

### 6. Shut down

The build VMs are not left running. `status` shows them; templates are stopped by definition. Leave 7100 (and 7110) in place.

## Activating a pool member with a retail key

Read from `crates/fleet-controller/src/lab_pool.rs`, `docs/architecture/lab.md` (Pooled guests) and `docs/operations/lab.md` (Pooled guests):

- **Fleet never creates, boots, activates or snapshots a pool member.** `lab pool create` (`--template-version`, `--account`, `--baseline <name>`, `--size`) only records a pool bound to a published template version whose cleanup is `revert`. `lab pool fill <pool> --vmid ...` registers operator-supplied VMIDs and queues `lab.pool.fill`.
- **The baseline is an ordinary Proxmox snapshot the operator takes.** For each member, fill checks that it is a QEMU guest, not a template, not an `fm-lab-*` clone, not an image artifact, and that it carries a snapshot named like the pool's baseline. Then it **rolls the member back to that snapshot** through the reviewed `proxmox.guest.snapshot-revert` child (`revert_member`: `POST .../snapshot/<name>/rollback`, params only `{ "snapshot": <baseline> }`) and verifies the result. Every release does the same rollback. It starts the member only at the next lease's provision.
- **Pool members are not created from the template by Fleet.** The operator makes each one, for example `qm clone <image-template> <vmid> --full 1 --name win-pool-N`, outside the `fm-lab-` prefix, in a VMID that is not a promoted image's template. A member's hardware is the operator's, and the template's cores, memory and disk are not applied to it.

**Therefore the activation point is on the member, after its first boot and before `qm snapshot`.** The sequence:

1. `qm clone 7100 <member-vmid> --full 1 --name win-pool-1` (**the generalized base 7100, not the Fleet image 7110**, which is not generalized), then start it. Wait until Windows has finished specialize (about as long as the clone test) and the guest agent reports an address.
2. In the guest (console, or SSH as `fleetadmin`), enter the retail key and activate: `slmgr /ipk <your key>`, then `slmgr /ato`, or Settings > System > Activation. This needs internet. **This is the point where the retail key is typed. It is in the member only, never in Fleet, the recipe, the template version, the build, or Git.**
3. Check `slmgr /xpr` reports a permanent activation, and that `sshd` is running with its own host keys, which the snapshot then keeps (ADR 0015 open question 3: a baseline taken after first boot gives a stable host key per member, so a revert never trips a pinned key).
4. Shut the member down cleanly (`Stop-Computer`), then `qm snapshot <member-vmid> baseline` (the pool's baseline name; no `--vmstate`, so the rollback leaves it stopped and the lease boots it from cold). The snapshot holds the disk, the EFI vars and the TPM state, so the activation is inside it.
5. Then `lab pool create ... --baseline baseline`, `lab pool fill <pool> --vmid <member-vmid> --wait`. Fill's first action is that rollback, so **anything done in the member after the snapshot is thrown away**: activate, then snapshot, then fill, never the other way round. To change the key later: drain the member, boot it, activate, shut down, `qm delsnapshot` and snapshot again, fill again (`proxmox snapshot-delete` refuses a current member until it is drained).

The current pool flow does not prevent any of this, so no code change is required. The Proxmox token needs `VM.Audit`, `VM.Snapshot.Rollback` and `VM.PowerMgmt` on `/vms/<member-vmid>`; the fixture token has them through `PVEVMAdmin`. Two things to say in `lab.md`, not code: that a Windows member must be booted past specialize before its baseline, and that the retail key is entered in the member, not in the image or recipe. This runbook is the place until a Windows guide exists. A possible later convenience is `lab pool member-create` (clone from the image and register), which stays out of scope here because Fleet deliberately never creates a member's guest.

Not verified yet: a snapshot and rollback of a guest with a `tpmstate0` volume on `local-lvm` (PVE supports snapshots with vTPM state on snapshot-capable storage; it must be confirmed on the first Windows member), and that Windows keeps its activation across Fleet's rollback. Both are checked when the first member exists.

## Evidence

Run on 2026-10-10 against `dev` at `987c22f` (controller built from the same commit, trusted-LAN mode on loopback, a temporary data directory and master key, and a dedicated `ssh-agent` holding the fixture key), with the physical-host account for `fleet-test@pve!admin`, node `pve`, storage `local-lvm`. Packer 1.16.1, Proxmox plugin 1.2.4.

| Item | Result |
|---|---|
| Install | about 20 min from `create` to `setup-complete`, no console interaction |
| Template | VMID 7100, `template: 1`, tag `fleet-pve-test`, 64 GiB disk, `efidisk0 ... pre-enrolled-keys=1`, `tpmstate0 ... version=v2.0` |
| Clones of 7100 | unique names, host keys and addresses (above) |
| Clones of 7110 (Fleet image) | same computer name and same SSH host key; different DHCP addresses (above, #452) |
| Recipe, version | `images create ... --source clone` then `publish`: the second recipe version (with `cpu_type: host`) is the working one |
| Build | succeeded in about 150 s, artifact `pve:7110`. A full clone of a 64 GiB disk dominates |
| Promotion | `images promote` accepted the version |
| Lab templates | `windows11` (`--guest-os windows --cleanup revert --probe guest_agent`) and `windows11-fleetadmin`, the same plus `sshUser: fleetadmin` through `POST /api/v1/lab/templates`. The CLI has no SSH user flag and defaults to `root`, which does not exist on this image, so a lease needs the second template |
| Ids | recorded in the PR and the issue (they belong to the temporary controller's database, so they are not repeated in Git) |

Not verified: the machine SID of clones, a lease on these templates (stream J, #441), TPM snapshot and rollback of a pool member, activation (the operator's), a Packer build that re-generalizes the image.

## Host changes

| Change | Where | Reverse with |
|---|---|---|
| `virtio-win.iso` downloaded | host ISO storage `local` | `rm` the file |
| `fleet-win-cfg.iso` (0600) | host ISO storage `local` | deleted by `detach-media` (done) |
| `windows11-x64-multi.iso` (9 GB) | host ISO storage `local` | `rm` the file; kept for rebuilds |
| VM 7100 template and 7110 (the Fleet image's template) | `local-lvm`, tag `fleet-pve-test` | `qm destroy <id> --purge 1` |
| Throwaway VM 7199 created to validate the VM definition, then destroyed | | already removed |
| ACLs | none | the fixture token's `/vms` grant already covers these VMIDs |

The host's apt repositories, the pre-existing VMs and the pre-existing templates are not touched.

## Sources

- [Microsoft Learn: KMS client activation and product keys](https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys)
- [Windows 11 ISO download](https://www.microsoft.com/en-us/software-download/windows11)
- [Windows unattended setup reference](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/)
- [OpenSSH Server configuration for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)
- [virtio-win ISO (Fedora)](https://docs.fedoraproject.org/en-US/quick-docs/creating-windows-virtual-machines-using-virtio-drivers/)
- [Proxmox VE: Windows 11 guest best practices](https://pve.proxmox.com/wiki/Windows_11_guest_best_practices)
- [PowerShell/Win32-OpenSSH releases](https://github.com/PowerShell/Win32-OpenSSH/releases)
