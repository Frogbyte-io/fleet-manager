# Fleet Lab operator runbook

This runbook covers enabling Fleet Lab and running it day to day: building and promoting an image, publishing a Lab template, leasing a guest, and handling what cleanup leaves behind. The design lives in [Lab architecture](../architecture/lab.md). The Proxmox side lives in the [least-privilege token guide](proxmox-token.md).

Fleet Lab is still being built (M7). This page describes what the `dev` branch does today. Behaviour that waits on an open pull request or an open issue is marked **pending**, with its number. Do not rely on pending behaviour until it merges.

Examples use placeholders only: the host `pve.example.test`, the node `pve1`, addresses from `192.0.2.0/24`, and IDs in angle brackets. Every command below is checked against `fleetctl --help` on `dev`.

## Prerequisites

### Packer, installed by you

Fleet builds images with an operator-installed Packer CLI. Fleet never bundles or downloads Packer. Packer is BUSL 1.1; Fleet calls a binary you installed, which stays inside the license's Additional Use Grant ([evidence](../research/ecosystem.md#image-building-packer-and-the-proxmox-plugin)).

On the machine that runs the controller, as the user the controller runs as:

1. Install Packer `>= 1.15, < 2` from HashiCorp's releases and check its checksum. The controller runs `packer` from its `PATH`.
2. Install the Proxmox plugin `>= 1.2.4, < 2`:

   ```sh
   packer plugins install github.com/hashicorp/proxmox
   packer plugins installed     # must list packer-plugin-proxmox_v1.2.4 or later
   ```

   Plugins install under the user's home directory, so run this as the controller's user.

Before each build, Fleet runs `packer -machine-readable version` and `packer plugins installed`. A version outside the pins fails the build with `version_gate` or `plugin_version_gate` before Packer touches the host.

The published controller image (`deploy/controller.Dockerfile`) does not contain Packer, and its root filesystem is read-only. To build images, run the controller where Packer is installed, or derive your own image. Lab leasing does not need Packer.

### Proxmox accounts and privileges

Fleet talks to PVE with privilege-separated API tokens. Follow the [token guide](proxmox-token.md) for roles and ACLs, then register and confirm each account ([step 6](proxmox-token.md#6-register-the-token-in-fleet)). Fleet sends no credentials to an account until you confirm its certificate fingerprint.

- **Lab.** Grant `FleetLab` on the image template's VMID, the clone storage, the bridge, and every clone-target VMID. On 8.x, also grant `FleetAgent8`, but only on the clone-target VMIDs: its `VM.Monitor` allows agent exec inside the guest. See [why clone and Lab need more than the pool](proxmox-token.md#why-clone-and-lab-need-more-than-the-pool).
- **Cleanup.** Lab cleanup deletes clones through Fleet's reviewed guest-destroy primitive (FM-712). That needs `VM.PowerMgmt` (to stop the guest) and `VM.Allocate` on `/vms/<newid>`. `FleetLab` on the clone-target VMIDs already holds both.
- **Protected templates.** The token guide recommends `qm set <template> --protection 1`. Clones inherit that flag, and Fleet's destroy does not clear it today. A protected clone makes every cleanup attempt fail, and the lease ends `cleanup_failed`. Either leave the image template unprotected and rely on Fleet's cleanup guard, which refuses to destroy templates and promoted image artifacts, or keep the flag and expect to remove each clone by hand (`qm set <vmid> --protection 0`, then destroy).
- **Builds.** Packer calls the PVE API itself. Fleet's privilege table does not cover the plugin's calls, so `fleetctl proxmox privileges` does not evaluate them. Use a separate account for builds, scoped to the source template and the build VMIDs, and prove it with a test build.

Check the Lab account:

```sh
fleetctl --output json proxmox privileges <lab-account-id>
```

The `lab` tier must read `granted`. A `missing … on /vms/{newid}` line means the clone-target ACL is absent.

### VMID ranges

Lab takes each clone's VMID from `GET /cluster/nextid`. Limit that range to the VMIDs you granted Fleet:

```sh
pvesh set /cluster/options --next-id lower=9000,upper=9010   # 9000 to 9009
```

- `upper` is exclusive. The range applies to every automatic VMID choice in the cluster, including the web UI.
- The range size is the hard limit on concurrent Lab guests today. When it is full, provisioning fails with "unable to get any free VMID in range" and clones nothing.
- Give image builds their own VMIDs, outside the Lab range. Set `vm_id` in every recipe. Without it, the plugin asks PVE for the next free VMID, which comes from the Lab range.

### Storage and network

- **Storage.** Lab clones are full clones. They land on the storage of the image template's disks. The Lab token needs `Datastore.AllocateSpace` there, and the storage needs room for one full copy per concurrent guest.
- **Bridge.** The guest's NIC bridge needs `SDN.Use` for the Lab token (`/sdn/zones/localnetwork/<bridge>` for a plain Linux bridge).
- **DHCP.** The bridge must hand the guest an IPv4 address. Readiness needs a non-loopback, non-link-local IPv4 address from the guest agent, and SSH-communicator builds need one too.
- **Reachability.** The controller must reach the guest's address on the template's SSH port (default 22).

### The image

A Lab image must contain:

- `qemu-guest-agent`, enabled in the guest and in the VM (`--agent enabled=1`). Readiness polls the agent for every template, whatever its probe.
- The controller's SSH public key, authorized for the template's SSH user (default `root`). The controller authenticates with its own SSH agent (`SSH_AUTH_SOCK`); Fleet never installs keys.

## First run

The walkthrough builds a linked clone of an existing cloud-image template, promotes it, and leases a guest from it. Every command uses `--output json`, the machine-readable form agents use too. Set the two account IDs first:

```sh
BUILD_ACCOUNT=<build-account-id>
LAB_ACCOUNT=<lab-account-id>
```

### 1. Write a recipe

Recipes are legacy-JSON Packer templates with exactly one `proxmox-iso` or `proxmox-clone` builder. Fleet's structured keys follow the plugin schema: `disks[0].storage_pool`, `network_adapters[0].bridge`, and `boot_iso` for ISO builds. Unknown keys are kept as written, and `packer validate` refuses keys the plugin does not have.

```json
{
  "builders": [{
    "type": "proxmox-clone",
    "proxmox_url": "https://pve.example.test:8006/api2/json",
    "node": "pve1",
    "clone_vm_id": 8000,
    "full_clone": false,
    "vm_id": 8100,
    "vm_name": "lab-base-8100",
    "template_name": "lab-base-8100",
    "scsi_controller": "virtio-scsi-pci",
    "cores": 2,
    "memory": 2048,
    "network_adapters": [{ "model": "virtio", "bridge": "vmbr0" }],
    "qemu_agent": true,
    "communicator": "none",
    "task_timeout": "10m"
  }]
}
```

What the live runs taught:

- **`proxmox_url` must end in `/api2/json`.** The plugin does not append it. Without it, PVE answers `500 no such file '/cluster/resources'`, which looks like a permission error. Fleet also uses this URL to pick the build's account: it must equal `https://<account host>:<account port>/api2/json`.
- **Set `"scsi_controller": "virtio-scsi-pci"` for clones of cloud-image templates.** The plugin default is `lsi`. The clone then hangs in its initramfs, and the shutdown before template conversion times out with "VM quit/powerdown failed - got timeout".
- **`"communicator": "none"` works for a plain clone-to-template.** Add provisioners and an SSH communicator only when you change the guest. Then the guest needs DHCP on its bridge.
- **Do not add `disks` to a clone just to choose storage.** The plugin adds clone `disks` after the source's disks, so you get an extra disk. A clone without `disks` keeps the source template's storage.
- **Provisioners are limited.** Fleet accepts `shell` with `inline` lines and `file` with inline `content`. A provisioner that reads host files is refused (`asset_snapshot_missing`), because Fleet cannot snapshot those files.
- **Never put credentials in a recipe.** Recipes are stored and shown as written.
- **TLS: leave out `insecure_skip_tls_verify`.** Fleet gives Packer the certificate you confirmed for the account as its only trusted root, so a default self-signed PVE certificate verifies without skipping anything ([how](../architecture/lab.md#build-credentials-and-tls-trust)). For builds without `allowInsecureTls`, the host in `proxmox_url` must appear in the certificate's SANs. PVE's `pve-ssl.pem` lists the node name, its FQDN, and the node's addresses from when the certificate was made. Check with `openssl s_client -connect <host>:8006 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName`. These build failures happen after Packer's version probes and before its `validate` and `build` commands, so the token never leaves Fleet:
  - `target_certificate_name_mismatch`: the host is not in the SANs. Point the account and `proxmox_url` at a name or address the certificate lists, or install a certificate that names your host (a CA-signed one, or `pvecm updatecerts --force` after fixing the node's address), then observe and confirm the new fingerprint.
  - `target_certificate_changed`: the host now presents a different certificate than the one you confirmed, for example after a renewal. Run `fleetctl proxmox observe` and `confirm` again after checking the new fingerprint on the host.
  - `insecure_tls_not_allowed`: the recipe sets `insecure_skip_tls_verify`. Remove it. If you really must skip verification, publish with `fleetctl images publish <recipe-id> --allow-insecure-tls`. That opt-in is audited and part of the version, and the build still refuses a changed certificate. Versions published before this release that set the field fail this way. Publishing again, with or without the opt-in, makes a new version.
  - The pin applies to every HTTPS connection Packer makes. Let PVE fetch ISOs (`iso_file` on PVE storage, or `iso_download_pve`) rather than having Packer download them.

### 2. Create and publish the recipe

```sh
fleetctl --output json images create --name lab-base --description "Ubuntu base for Lab" \
  --node pve1 --storage-pool local-lvm --source clone < lab-base.json \
  | jq -r .data.id                         # the recipe id
fleetctl --output json images publish <recipe-id> | jq -r .data.id   # the version id
```

The flags must appear in exactly this order. `--node` and `--source` must match the builder. A clone without `disks` cannot show its storage, so `--storage-pool` is your declaration of the source template's storage, and Fleet cannot verify it. With `disks`, every disk must name that pool. A mismatch fails the build with `target_snapshot_mismatch`.

Publishing freezes the content as an immutable version, identified by its digest. Editing a recipe and publishing again makes a new version. `--allow-insecure-tls` (an audited opt-in, only for a recipe that sets `insecure_skip_tls_verify`) is part of that identity too.

### 3. Build

```sh
fleetctl --output json images build <version-id> --account "$BUILD_ACCOUNT" --wait --timeout 3600
```

- Pass `--account` when more than one account matches the recipe's `proxmox_url`. Otherwise the build fails with `target_account_missing`.
- The build's own deadline is four hours. `--timeout` only bounds how long `fleetctl` waits; the default of 300 s is short for a build.
- **Credentials.** Each build gets its account's token in Packer's child environment only. For builds that verify TLS, Fleet writes the confirmed certificate to private files in the operation's work directory and points the child at them with `SSL_CERT_FILE` and `SSL_CERT_DIR`. Recipe secret variables travel separately, in the operation's private `-var-file`. An account with an unconfirmed fingerprint is refused (`target_account_untrusted`). Ambient `PROXMOX_*` variables in the controller's environment are never passed to Packer.

Read the immutable build record:

```sh
fleetctl --output json images builds --version <version-id>
fleetctl --output json images build-show <build-id>
```

The record holds the content digest, the Packer and plugin versions, the account, the node, the storage pool, the `outcome`, a `reason` on failure, and the built `template` (node and VMID) on success. Packer's output never enters the record.

Common reasons: `version_gate` and `plugin_version_gate` (Packer or plugin outside the pins), `validate_failed` (`packer validate` refused the recipe), `build_failed`, `artifact_missing` (Packer reported no template on the version's node), and `deadline_killed`.

**Cancel and deadline.** On `dev`, cancelling a build (`fleetctl operations cancel <operation-id>`) or hitting its deadline kills Packer. The plugin removes its in-progress VM only when Packer is interrupted, so a killed build can leave that VM at the recipe's `vm_id`. Fleet does not check the host afterwards. Look for it, and remove it by hand if it is there (it is not a template yet). Graceful interrupt is **pending** ([PR #283](https://github.com/Frogbyte-io/fleet-manager/pull/283)): Packer gets SIGINT, up to 180 s to clean up, and only then a kill. The record then tells `deadline_interrupted` (clean) apart from `deadline_killed` (host state unknown).

### 4. Promote

```sh
fleetctl --output json images promote <version-id>
```

Promotion is manual. A build never promotes anything. It needs the version's latest build record to have succeeded with the same inputs and a template. Promoting a version demotes the recipe's previous promotion.

Then grant `FleetLab` on the new template's VMID (`/vms/8100` here), as in [token guide step 5](proxmox-token.md#5-acls).

### 5. Create and publish a Lab template

```sh
fleetctl --output json lab create --name lab-base --description "Disposable Ubuntu guest" \
  --image-version <version-id> --cores 2 --memory 2048 --disk 20 \
  --probe guest_agent --readiness-deadline 600 --ttl 3600 --cleanup destroy \
  | jq -r .data.id                         # the template id
fleetctl --output json lab publish <template-id> | jq -r .data.id    # the template version id
```

- A template can pin only a promoted image version.
- From the CLI, use `--probe guest_agent`. The `ssh_exec` probe needs a readiness command and `project_ready` needs a bootstrap project; `fleetctl lab create` sets neither, so create those templates through `POST /api/v1/lab/templates`. The SSH settings (`sshUser` root, `sshPort` 22, `sshTrustMode` tofu) also take their defaults from the CLI.
- The clone keeps the image template's hardware today. The template's cores, memory, and disk are recorded but not applied to the guest.
- `--readiness-deadline` is 1 to 3600 seconds, `--ttl` 1 to 2592000 seconds.

The one-command `fleetctl lab create/status/exec/destroy` workflow is **pending** (FM-720, [#259](https://github.com/Frogbyte-io/fleet-manager/issues/259)). Its command names may replace the ones in steps 5 and 6.

### 6. Lease, provision, and use

```sh
fleetctl --output json lab lease <template-version-id> --purpose "first run" | jq -r .data.id   # the lease id
fleetctl --output json lab provision-lease <lease-id> --account "$LAB_ACCOUNT" | jq -r .data.id # the operation id
fleetctl --output json operations get <operation-id>
fleetctl --output json lab leases | jq '.items[] | select(.id == "<lease-id>") | {state, expiresAt}'
fleetctl --output json lab provisions
```

The lease moves through `provisioning`, `booting`, and `bootstrapping` to `ready`. The provision record shows the node, the VMID, and the guest's address (`guestIpv4`, for example `192.0.2.50`). The guest is named `fm-lab-<record-id>` in PVE.

At `bootstrapping`, the controller trusts the guest's SSH host key on first contact (`tofu`) and registers a temporary Fleet machine tagged `lab`, in the groups `lab-provision:<id>` and `lab-lease:<id>`. Find it with:

```sh
fleetctl --output json machines list --tag lab
```

Lab exec through the lease (`fleetctl lab exec`) is **pending** (FM-720). Until then, run commands on that machine through the normal machine surfaces.

The TTL starts at `ready`. Extend it, up to 30 days after the lease was created:

```sh
fleetctl --output json lab extend <lease-id> --seconds 3600
```

### 7. Release

```sh
fleetctl --output json lab release <lease-id>
```

Release moves the lease to `releasing` and queues one `lab.cleanup` operation. With the default `destroy` strategy, cleanup stops and destroys the guest, removes the Lab machine record, and marks the lease `released`.

`fleetctl --output json lab release <lease-id> --keep` needs the elevated `lab.keep` permission. It releases the lease and leaves the guest and its machine record in place, outside automatic cleanup. From then on the guest is yours to remove.

## Operations

### Expiry and the sweeper

On `dev`, nothing sweeps on its own. An expired `ready` lease stays `ready` until someone runs:

```sh
fleetctl --output json lab sweep
```

The sweep moves each expired lease to `releasing` and queues its cleanup. Run it from a timer until the sweeper merges.

**Pending ([PR #286](https://github.com/Frogbyte-io/fleet-manager/pull/286), FM-716).** The controller runs a sweeper every `FLEET_LAB_SWEEP_INTERVAL_SECONDS` seconds (TOML `lab_sweep_interval_seconds`; default 60; `0` disables it, and `lab sweep` stays available). Each tick:

1. releases expired `ready` leases;
2. compensates provisions stuck more than 10 minutes past their readiness deadline, or past their maximum lifetime: to `releasing` if a guest was allocated, otherwise to `failed`;
3. queues every due cleanup retry, and repairs a release whose cleanup was never queued;
4. reports orphan guests (see [Orphans](#orphans)).

All deadlines and attempt counts live in the database, so a restarted controller continues where it stopped.

### Cleanup retries and `cleanup_failed`

A failed cleanup attempt keeps the lease `releasing` and schedules the next attempt. The delay is one minute, doubling, capped at one hour. The lease shows `cleanupAttempts` and `cleanupNextAt` (epoch milliseconds):

```sh
fleetctl --output json lab leases | jq '.items[] | select(.state == "releasing" or .state == "cleanup_failed")
  | {id, state, cleanup, cleanupAttempts, cleanupNextAt}'
```

On `dev`, nothing queues the retry for you. Run `fleetctl --output json lab release <lease-id>` again once `cleanupNextAt` has passed. An earlier repeat queues nothing, so it cannot burn attempts. The sweeper does this automatically (pending, #286).

After five failed attempts the lease becomes `cleanup_failed` and Fleet stops retrying. An audit event records why, and the node and VMID the lease last knew:

```sh
fleetctl --output json audit list --action lab.lease --resource <lease-id>
```

Look for the event `lab_lease_cleanup_failed`, and read the failed `lab.cleanup` operation's `errorJson` with `fleetctl --output json operations get <operation-id>`.

To resolve it:

1. Find the cause. Common ones are a protected clone (see [Proxmox accounts and privileges](#proxmox-accounts-and-privileges)), a missing `VM.Allocate` or `VM.PowerMgmt` on the clone VMID, an unconfirmed account, or an unreachable host.
2. Check whether the guest still exists. It may already be gone if only the machine-record removal failed.
3. Remove the guest. Fleet's reviewed destroy stops it first, and refuses templates and promoted image artifacts:

   ```sh
   fleetctl --output json proxmox destroy <lab-account-id> <node> <vmid> --wait
   ```

   For a protected clone, run `qm set <vmid> --protection 0` on the host first.

`cleanup_failed` is terminal. `lab release` refuses it, and no Fleet command re-arms cleanup today. The lease stays as the record that a guest was owned and needed a human. `fleetctl` cannot remove the guest's Lab machine record yet either.

`revert` cleanup needs pooled guests (FM-717, [#260](https://github.com/Frogbyte-io/fleet-manager/issues/260)). Until then, cleanup refuses `revert` with `unsupported_until_pooled`. It destroys nothing and spends no attempt; the lease stays `releasing`. Release it with `--keep`, then remove the guest yourself.

### Orphans

An orphan is a Fleet-named guest (`fm-lab-*`) that no live lease or standalone provision owns.

On `dev`, find them by hand. Compare the account's guests with the provision records:

```sh
fleetctl --output json proxmox guests <lab-account-id>
fleetctl --output json lab provisions
```

**Pending (#286).** Each sweeper tick lists the `fm-lab-*` guests on every trusted account. It reports each unowned guest once per controller run, as the audit event `lab_orphan_guest` (account, node, VMID) and a log line:

```sh
fleetctl --output json audit list --action lab.lease
```

Fleet **never** deletes an orphan. To remove one:

1. Confirm in PVE that nothing else uses it.
2. Check `fleetctl --output json lab provisions` and `fleetctl --output json lab leases` for a record that still owns that VMID. A guest released with `keep` is owned on purpose.
3. Destroy it with `fleetctl --output json proxmox destroy <account> <node> <vmid> --wait`, or with `qm destroy` on the host.

### Capacity

**Pending (FM-715, [#257](https://github.com/Frogbyte-io/fleet-manager/issues/257)).** On `dev` there is no placement and no capacity reservation. The caller picks the account, and nothing stops over-allocation. Capacity refusals and an overcommit policy do not exist yet. Until they do:

- The `next-id` range size caps how many Lab guests exist at once.
- Size the image template's CPU, memory, and disk for the node, because the clone uses the template's hardware.
- Watch the node and storage with `fleetctl --output json proxmox nodes <account-id>` and PVE's own graphs.

This section will describe refusals and overcommit when FM-715 merges.

### Artifacts and storage sizing

**Pending (FM-721, [#261](https://github.com/Frogbyte-io/fleet-manager/issues/261)).** Lab artifacts and exec logs, and their retention, do not exist yet. This section will describe retention and the controller volume they need when FM-721 merges.

What uses space today:

- **Image templates.** Each successful build leaves a template on PVE. Fleet never deletes one: its destroy refuses templates. Remove superseded, unpromoted templates in PVE yourself. Keep the promoted version's template; Lab clones from it.
- **Lab guests.** One full copy of the image template per live guest, on the template's storage.
- **Build work files.** Each build writes its recipe to `<FLEET_DATA_DIR>/image-builds/<operation-id>/` and deletes that directory when the build ends.
- **Database.** Build records, provision records, leases, and audit events grow in the controller's SQLite database. Nothing prunes them.

## Failure behaviour

What Fleet guarantees on `dev`:

- **External IDs first.** The provision executor records the VMID and node before it sends the clone. A re-run reuses the recorded VMID and never clones a second guest for one record.
- **Adopt only its own guest.** On a re-run, a guest already at the recorded VMID is adopted only if it carries the record's name (`fm-lab-<record-id>`). Anything else there is a conflict, and Fleet touches nothing.
- **Owed cleanup is not forgotten.** A failed or cancelled provision that allocated a guest moves its lease to `releasing`. Cleanup retries five times, then the lease becomes `cleanup_failed` with an audit event that names the guest.
- **Cleanup refuses templates.** Cleanup refuses any VMID that is a promoted image's recorded build artifact, or that PVE reports as a template. It checks the template state before the stop and again after it. PVE has no conditional delete, so a guest converted to a template outside Fleet after the last check can still be deleted. Fleet never reserves such a VMID as a clone target.
- **No credentials to unconfirmed hosts.** No Proxmox operation sends a token to an account whose fingerprint you have not confirmed. Image builds on `dev` are the exception until #285 merges (see [Build](#3-build)).
- **Builds leave records.** Every build has an immutable record, written before Packer runs and completed with its outcome.

What Fleet never does:

- delete a guest it cannot attribute to a Lab record (an orphan), or one released with `keep`;
- retry cleanup after `cleanup_failed`;
- promote a build or replace a promoted version on its own.

Not yet guaranteed:

- **After a controller crash, on `dev`.** A lease stuck mid-provision, an expired lease, or a cleanup retry waits for an operator (`lab sweep`, `lab release`) until the sweeper merges (#286).
- **The failure-injection suite.** The suite that interrupts the controller at every lifecycle transition and checks these guarantees is **pending** (FM-741, [#262](https://github.com/Frogbyte-io/fleet-manager/issues/262)).
- **Cancelled builds.** Until #283 merges, a cancelled or timed-out build can leave its in-progress VM on the host.

## Out of scope

USB, GPU, and other hardware-in-the-loop resources are a separate sub-epic. Windows guests are later work.
