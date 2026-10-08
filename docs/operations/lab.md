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

- **Lab.** Grant `FleetLab` on the image template's VMID, the clone storage, the bridge, and every clone-target VMID. Also grant `FleetLabTarget` on the clone-target VMIDs only (see protected templates below). On 8.x, also grant `FleetAgent8`, but only on the clone-target VMIDs: its `VM.Monitor` allows agent exec inside the guest. See [why clone and Lab need more than the pool](proxmox-token.md#why-clone-and-lab-need-more-than-the-pool).
- **Cleanup.** Lab cleanup deletes clones through Fleet's reviewed guest-destroy primitive (FM-712). That needs `VM.PowerMgmt` (to stop the guest) and `VM.Allocate` on `/vms/<newid>`. `FleetLab` on the clone-target VMIDs already holds both.
- **Protected templates.** The token guide recommends `qm set <template> --protection 1`. PVE copies that flag into every clone, and refuses to delete a protected guest. Lab clears the copied flag itself: after the clone finishes and before the guest starts, the provision executor sets `protection=0` on its own `fm-lab-*` guest, never on the template. That needs the `FleetLabTarget` role (`VM.Config.Options`) on the clone-target VMIDs, and only there, so the token still cannot unprotect the template. See [token guide step 5](proxmox-token.md#5-acls) and [clone targets](proxmox-token.md#why-clone-and-lab-need-more-than-the-pool). Without the role, a clone of a protected template fails its provision at step `unprotect` (reason `unprotect_failed`) before it starts, and its cleanup cannot delete it.
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

The walkthrough builds a linked clone of an existing cloud-image template, promotes it, and leases a guest from it. Every command uses `--output json`, the machine-readable form agents use too. It prints the resource itself (so `jq -r .id`), or a page with `items` for a list. Set the two account IDs first:

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

- **`proxmox_url` must end in `/api2/json`.** The plugin does not append it. Without it, PVE answers `500 no such file '/cluster/resources'`, which looks like a permission error. Fleet also uses this URL to pick the build's account: it must equal `https://<account host>:<account port>/api2/json`, or `https://<account host>/api2/json` when the account's port is 443. A trailing `/` is ignored.
- **Set `"scsi_controller": "virtio-scsi-pci"` for clones of cloud-image templates.** The plugin default is `lsi`. The clone then hangs in its initramfs, and the shutdown before template conversion times out with "VM quit/powerdown failed - got timeout".
- **`"communicator": "none"` works for a plain clone-to-template.** Add provisioners and an SSH communicator only when you change the guest. Then the guest needs DHCP on its bridge.
- **Do not add `disks` to a clone just to choose storage.** The plugin adds clone `disks` after the source's disks, so you get an extra disk. A clone without `disks` keeps the source template's storage.
- **Provisioners are limited.** Fleet accepts `shell` with `inline` lines and `file` with inline `content`. A provisioner that reads host files is refused (`asset_snapshot_missing`), because Fleet cannot snapshot those files.
- **Never put credentials in a recipe.** Recipes are stored and shown as written.
- **TLS: leave out `insecure_skip_tls_verify`.** On a Linux controller, Fleet gives Packer the certificate you confirmed for the account as its only trusted root, so a default self-signed PVE certificate verifies without skipping anything ([how](../architecture/lab.md#build-credentials-and-tls-trust)). For builds without `allowInsecureTls`, the host in `proxmox_url` must appear in the certificate's SANs. PVE's `pve-ssl.pem` lists the node name, its FQDN, and the node's addresses from when the certificate was made. Check with `openssl s_client -connect <host>:8006 </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName`. On macOS or Windows such a build is refused (`certificate_pin_unsupported`), because Go uses the platform verifier there and ignores `SSL_CERT_FILE`. The certificate refusals below happen after Packer's version probes; `insecure_tls_not_allowed` happens before any Packer command. All of them happen before `validate` and `build`, so the token never leaves Fleet:
  - `target_certificate_name_mismatch`: the host is not in the SANs. Point the account and `proxmox_url` at a name or address the certificate lists, or install a certificate that names your host (a CA-signed one, or `pvecm updatecerts --force` after fixing the node's address), then observe and confirm the new fingerprint.
  - `target_certificate_changed`: the host now presents a different certificate than the one you confirmed, for example after a renewal. Run `fleetctl proxmox observe` and `confirm` again after checking the new fingerprint on the host.
  - `insecure_tls_not_allowed`: the recipe sets `insecure_skip_tls_verify`. Remove it. If you really must skip verification, publish with `fleetctl images publish <recipe-id> --allow-insecure-tls`. That opt-in is audited and part of the version, and the build still refuses a changed certificate. Versions published before this release that set the field fail this way. Publishing again, with or without the opt-in, makes a new version.
  - For builds without the opt-in, the confirmed leaf is the only trusted root for Go TLS clients that honor `SSL_CERT_FILE` and `SSL_CERT_DIR` (Packer and its plugins). A subprocess that uses another TLS implementation or trust store is not covered. Opted-in builds get only the pin check before Packer skips verification. Let PVE fetch ISOs (`iso_file` on PVE storage, or `iso_download_pve`) rather than having Packer download them.

### 2. Create and publish the recipe

```sh
fleetctl --output json images create --name lab-base --description "Ubuntu base for Lab" \
  --node pve1 --storage-pool local-lvm --source clone < lab-base.json \
  | jq -r .id                         # the recipe id
fleetctl --output json images publish <recipe-id> | jq -r .id   # the version id
```

The flags must appear in exactly this order. `--node` and `--source` must match the builder. A clone without `disks` cannot show its storage, so `--storage-pool` is your declaration of the source template's storage, and Fleet cannot verify it. With `disks`, every disk must name that pool. A mismatch fails the build with `target_snapshot_mismatch`.

Publishing freezes the content as an immutable version, identified by its digest. Editing a recipe and publishing again makes a new version. `--allow-insecure-tls` (an audited opt-in, only for a recipe that sets `insecure_skip_tls_verify`) is part of that identity too.

### 3. Build

```sh
fleetctl --output json images build <version-id> --account "$BUILD_ACCOUNT" --wait --timeout 3600
```

- Without `--account`, exactly one account must match the recipe's `proxmox_url`. With none or several, the build fails with `target_account_missing`; pass `--account` to choose among several. An `--account` that does not match the URL fails with `target_account_resolution_failed`.
- The build's own deadline is four hours. `--timeout` only bounds how long `fleetctl` waits; the default of 300 s is short for a build.
- **Credentials.** Each build gets its account's token ID and secret as `PROXMOX_USERNAME` and `PROXMOX_TOKEN` in the `packer build` child environment, and nowhere else. `packer validate` runs with placeholder credentials instead (its Proxmox plugin check never connects), so the account's real token reaches only the one child that builds (#313). For builds that verify TLS, Fleet also writes the account's confirmed certificate to an owner-only file in the build's work directory and points Packer at it with `SSL_CERT_FILE` and an empty `SSL_CERT_DIR`, so the plugin's API connection trusts only that certificate. Do not set `PROXMOX_*` in the controller's environment: Fleet removes every ambient `PROXMOX_*` variable from Packer's environment, including the version probes', so a build never uses a credential you did not give its account. An account whose fingerprint you have not confirmed is refused after the version checks and before `packer validate` or the build run (`target_account_untrusted`), and so is an account without a stored token (`account_credential_missing`). Other secret recipe variables travel separately: the build request's `secretVars` (API only) name secret-store references, which Fleet resolves into a `-var-file` in the build's work directory (`<FLEET_DATA_DIR>/image-builds/<operation-id>/`). Fleet deletes the directory when the build reaches a terminal outcome. If the controller stops mid-build, the directory and its var file stay on disk until you remove them ([#314](https://github.com/Frogbyte-io/fleet-manager/issues/314)). On Unix, Fleet makes these owner-only whatever the controller's umask: it sets `image-builds/` to `0700`, tightening it if it already exists and refusing it if it is a symlink or another user owns it. It creates each operation's directory fresh at `0700`, replacing any leftover, and creates the var file, the recipe copy, and the pinned certificate as new `0600` files before writing anything to them. On other platforms these files inherit the directory's access control. Keeping `FLEET_DATA_DIR` readable by the controller's user only (for example `chmod 700`) is still good practice. The certificate pin protects only the plugin's own TLS channel to the API; it does not by itself keep the token from recipe content. Recipe content is a privileged, untrusted input, so Fleet refuses — at publish time and again before every build, before any secret is resolved — a recipe that could read `PROXMOX_TOKEN` out of Packer's process or read files on the controller: any top-level key other than exactly `builders`, `provisioners`, `variables`, `sensitive-variables`, `description`, and `min_packer_version` (so `post-processors`, which can run `shell-local` on the controller, `error-cleanup-provisioner`, `_` comments, and case variants such as `Provisioners` are rejected); a repeated key in any object, even in another letter case, and any non-ASCII key; any `{{env}}`, `{{vault}}`, `{{consul_key}}`, `{{aws_secretsmanager}}`, or `{{aws_secretsmanager_raw}}` template function anywhere in the recipe, in any spelling, and any unclosed `{{`, comment, or quoted string inside one; and builder fields that read controller files or fetch on the controller (`http_directory`, `cd_files`, an `iso_url` without `iso_download_pve: true` or that is not a plain `http(s)://` URL, and an `iso_checksum` that is not a literal digest or `none`). The refusal reason names the rule (`recipe_*`; see [Lab architecture](../architecture/lab.md#build-credentials-and-tls-trust)). A version published before this gate is refused the same way at build time. Still review recipes as privileged inputs; an inline `shell` provisioner runs in the guest, which has network access.

Read the immutable build record:

```sh
fleetctl --output json images builds --version <version-id>
fleetctl --output json images build-show <build-id>
```

The record holds the content digest, the Packer and plugin versions, the account, the node, the storage pool, the `outcome`, a `reason` on failure, and the built `template` (node and VMID) on success. Packer's output never enters the record.

Common reasons: `version_gate` and `plugin_version_gate` (Packer or plugin outside the pins), `target_account_untrusted` and `account_credential_missing` (see Credentials above), `validate_failed` (`packer validate` refused the recipe), `build_failed`, `artifact_missing` (Packer reported no template on the version's node), and the cancel and deadline reasons below.

**Cancel and deadline.** Cancelling a build (`fleetctl operations cancel <operation-id>`) or hitting its deadline interrupts Packer the way Ctrl-C does (SIGINT). The plugin then stops and deletes its in-progress VM. Packer gets up to 180 s for that, and is killed only if it is still running. Fleet trusts only Packer's own "Cleanly cancelled builds" report; it does not check the host itself. The record's `reason` says what happened:

- `cancelled`: you cancelled, and Packer reported a clean cancel.
- `cancelled_unverified`: you cancelled, and Packer did not report a clean cancel.
- `deadline_interrupted`: the deadline interrupted Packer, and it reported a clean cancel.
- `deadline_interrupted_unverified`: the deadline interrupted Packer, and it exited within the grace period without reporting a clean cancel.
- `deadline_killed`: Packer was killed after the grace period. Host state is unknown.

After any of the `_unverified` reasons or `deadline_killed`, the in-progress VM may still be at the recipe's `vm_id`. Look for it, and remove it by hand if it is there (it is not a template yet). A build that finished before the interrupt took effect keeps its template and succeeds.

### 4. Promote

```sh
fleetctl --output json images promote <version-id>
```

Promotion is manual. A build never promotes anything. It needs the version's latest build record to have succeeded with the same inputs and a template. Promoting a version demotes the recipe's previous promotion.

Then grant `FleetLab` on the new template's VMID (`/vms/8100` here), as in [token guide step 5](proxmox-token.md#5-acls).

### 5. Create and publish a Lab template

```sh
fleetctl --output json lab template-create --name lab-base --description "Disposable Ubuntu guest" \
  --image-version <version-id> --cores 2 --memory 2048 --disk 20 \
  --probe guest_agent --readiness-deadline 600 --ttl 3600 --cleanup destroy \
  | jq -r .id                         # the template id
fleetctl --output json lab publish <template-id> | jq -r .id    # the template version id
```

- A template can pin only a promoted image version.
- From the CLI, use `--probe guest_agent`. The `ssh_exec` probe needs a readiness command and `project_ready` needs a bootstrap project; `fleetctl lab template-create` sets neither, so create those templates through `POST /api/v1/lab/templates`. The SSH settings (`sshUser` root, `sshPort` 22, `sshTrustMode` tofu) also take their defaults from the CLI.
- The clone keeps the image template's hardware today. The template's cores, memory, and disk are recorded but not applied to the guest.
- `--readiness-deadline` is 1 to 3600 seconds, `--ttl` 1 to 2592000 seconds.
- `lab create --name …` still creates a template. It is a deprecated alias of `lab template-create`; use `template-create` in new scripts. `lab create <template-version-id>` now creates a lease (step 6).

### 6. Lease, provision, and use

One command creates the lease and provisions it:

```sh
fleetctl --output json lab create <template-version-id> --purpose "first run" \
  --account "$LAB_ACCOUNT" --wait --timeout 900   # prints the lease; its id is the lease id
fleetctl --output json lab status <lease-id>
```

- `--purpose` is required. `--project <id>` ties the lease to a project.
- Without `--account`, `lab create` uses the only trusted account (one with a confirmed fingerprint). With none or more than one, pass `--account`. `fleetctl` picks that account before it creates the lease, so finding none or several leaves no lease behind. Nothing checks an explicit `--account` first: if the provision request is refused after the lease was created, the lease stays `requested`. Release it with `lab destroy <lease-id>`.
- `--wait` polls until the lease is `ready`, or ends in `failed`, `releasing`, `released`, or `cleanup_failed`. It exits non-zero unless the lease is `ready`. `--timeout` bounds the wait (default 900 s). Without `--wait`, the command prints the lease as it is right after the provision was queued.
- `lab status` shows the lease with its guest: `provisionState`, `node`, `vmid`, `address` (for example `192.0.2.50`), `machineId`, `endpointId`, and `failedStep` when provisioning failed.

The two-step form still works:

```sh
fleetctl --output json lab lease <template-version-id> --purpose "first run" | jq -r .id   # the lease id
fleetctl --output json lab provision-lease <lease-id> --account "$LAB_ACCOUNT" | jq -r .id # the operation id
fleetctl --output json operations get <operation-id>
fleetctl --output json lab provisions
```

The lease moves through `provisioning`, `booting`, and `bootstrapping` to `ready`. The provision record shows the node, the VMID, and the guest's address (`guestIpv4`). The guest is named `fm-lab-<record-id>` in PVE.

At `bootstrapping`, the controller trusts the guest's SSH host key on first contact (`tofu`) and registers a temporary Fleet machine tagged `lab`, in the groups `lab-provision:<id>` and `lab-lease:<id>`. Find it with:

```sh
fleetctl --output json machines list --tag lab
```

Run a command on the guest through the lease:

```sh
fleetctl --output json lab exec <lease-id> --wait --timeout 120 -- uname -a
```

- The words after `--` are shell-quoted and run as one command over SSH on the lease's Lab machine, through the controller's SSH agent. Output has the same size limits and redaction as machine exec.
- The lease must be `ready` and unexpired, both when you ask and when the command runs. The command is at most 64 KiB. `--timeout` is the command's deadline, 1 to 900 seconds (default 60).
- With `--wait`, `fleetctl` prints `exitCode`, `stdout`, `stderr`, and whether either was truncated, and exits with the remote command's exit code (1 if the command did not run; `reason` and `detail` say why). It waits at most `--timeout` plus 60 seconds. If the operation has not finished by then, `fleetctl` prints an error naming the operation and exits 1 like any other CLI error, so an exit code of 1 does not always come from the remote command. Read the result later with `fleetctl --output json operations get <operation-id>`. Without `--wait`, it prints the queued `lab.exec` operation; read it with `fleetctl --output json operations get <operation-id>`.
- It needs the `lab.exec` permission. The request is audited (`lab_exec_requested`) without the command text. The queued `lab.exec` operation does store the command in its payload, in the controller's database, though `operations get` does not show the payload. Do not put secrets on the command line.

The TTL starts at `ready`. Extend it, up to 30 days after the lease was created:

```sh
fleetctl --output json lab extend <lease-id> --seconds 3600
```

### 7. Destroy

```sh
fleetctl --output json lab destroy <lease-id> --wait
```

`lab destroy` releases the lease: it moves to `releasing`, and one `lab.cleanup` operation is queued. With the default `destroy` strategy, cleanup stops and destroys the guest, removes the Lab machine record, and marks the lease `released`. `--wait` polls until the lease is `released` or `cleanup_failed`, and exits non-zero unless it is `released`. `--timeout` bounds the wait (default 900 s). `fleetctl lab release <lease-id>` does the same without waiting.

`fleetctl --output json lab destroy <lease-id> --keep` (or `lab release <lease-id> --keep`) needs the elevated `lab.keep` permission. It releases the lease and leaves the guest and its machine record in place, outside automatic cleanup. From then on the guest is yours to remove.

## Operations

### Expiry and the sweeper

The controller runs a sweeper every `FLEET_LAB_SWEEP_INTERVAL_SECONDS` seconds (TOML `lab_sweep_interval_seconds`; default 60; `0` disables it). Each tick:

1. releases expired `ready` leases;
2. compensates leases stuck in `provisioning`, `booting`, or `bootstrapping` once 10 minutes have passed since their readiness deadline, or once their maximum lifetime is reached: to `releasing` if a guest was allocated, otherwise to `failed`. A `failed` lease whose provision still holds a guest moves to `releasing` at once. Each compensation is audited as `lab_lease_stuck_compensated`;
3. queues the `lab.cleanup` of every `releasing` lease whose next attempt is due. That covers retries after a failed attempt, and a release whose cleanup was never queued;
4. reports orphan guests (see [Orphans](#orphans)).

The sweeper runs as the controller and never talks to Proxmox except to list guests for step 4. A step that fails for one lease is logged (`lab sweeper: …`) and retried on the next tick; the other leases still run. All deadlines and attempt counts live in the database, so a restarted controller continues where it stopped.

With the sweeper disabled, nothing expires on its own. Run the manual sweep from a timer instead:

```sh
fleetctl --output json lab sweep
```

`lab sweep` does step 1 only: it moves each expired lease to `releasing` and queues its cleanup. It does not compensate stuck leases, retry cleanups, or look for orphans.

### Cleanup retries and `cleanup_failed`

A failed cleanup attempt keeps the lease `releasing` and schedules the next attempt. The delay is one minute, doubling, capped at one hour. The lease shows `cleanupAttempts` and `cleanupNextAt` (epoch milliseconds):

```sh
fleetctl --output json lab leases | jq '.items[] | select(.state == "releasing" or .state == "cleanup_failed")
  | {id, state, cleanup, cleanupAttempts, cleanupNextAt}'
```

The sweeper queues the next attempt once `cleanupNextAt` has passed. With the sweeper disabled, run `fleetctl --output json lab release <lease-id>` again after that time. An earlier repeat queues nothing, so it cannot burn attempts.

After five failed attempts the lease becomes `cleanup_failed` and Fleet stops retrying. An audit event records why, and the node and VMID the lease last knew:

```sh
fleetctl --output json audit list --action lab.lease --resource <lease-id>
```

Look for the event `lab_lease_cleanup_failed`, and read the failed `lab.cleanup` operation's `errorJson` with `fleetctl --output json operations get <operation-id>`.

To resolve it:

1. Find the cause. Common ones are a protected clone whose flag Lab could not clear (a missing `FleetLabTarget`; see [Proxmox accounts and privileges](#proxmox-accounts-and-privileges)), a missing `VM.Allocate` or `VM.PowerMgmt` on the clone VMID, an unconfirmed account, or an unreachable host.
2. Check whether the guest still exists. It may already be gone if only the machine-record removal failed.
3. If the cause stays (for example, you keep the clone protected), remove the guest yourself. If you fixed the cause, skip this step: the re-armed cleanup destroys the guest. Fleet's reviewed destroy stops the guest first, and refuses templates and promoted image artifacts:

   ```sh
   fleetctl --output json proxmox destroy <lab-account-id> <node> <vmid> --wait
   ```

   A clone that is still protected (its provision failed at step `unprotect`) refuses deletion. Grant `FleetLabTarget` for the future, and for this guest run `qm set <vmid> --protection 0` on the host before the destroy.

   If Fleet's destroy fails for the same reason as the cleanup (a missing ACL, an unconfirmed account, an unreachable API), remove the guest on the PVE node instead. First check that `qm config <vmid>` shows the lease's `fm-lab-<record-id>` name and is not a template:

   ```sh
   qm stop <vmid>
   qm destroy <vmid> --purge
   ```

4. Re-arm the cleanup:

   ```sh
   fleetctl --output json lab cleanup-retry <lease-id> --wait
   ```

   The lease goes back to `releasing` and one new `lab.cleanup` attempt is queued at once. A guest that is already gone counts as destroyed, so a guest you removed by hand resolves the lease to `released`, and the cleanup removes the guest's Lab machine record. Fleet still has to ask the account's PVE API to learn that the guest is gone, so removing it by hand is not enough on its own: restore the account's trust (a confirmed fingerprint) and its connectivity first, or the new attempt fails like the last ones. If you cannot, leave the lease `cleanup_failed`. `--wait` waits for that one attempt and exits non-zero unless the lease ended `released`. Without `--wait` the command prints the queued operation.

   **Exception: leases provisioned before FM-713.** Their provision record has no Proxmox account (and, for some, no node), so every `destroy` attempt fails before it looks for the guest. Removing the guest by hand does not change that, so a plain re-arm only spends another round: the lease stays `releasing` through five failed attempts, with 1, 2, 4, and 8 minutes between them (about 15 minutes in all), and then returns to `cleanup_failed`. The way out is the `keep` strategy, which releases a lease without touching Proxmox:

   1. Destroy the guest by hand on the host (`qm config <vmid>` first, as above).
   2. Re-arm with `fleetctl --output json lab cleanup-retry <lease-id> --wait`. Its one attempt fails, and the lease is `releasing`, backing off.
   3. While it is still `releasing`, run `fleetctl --output json lab release <lease-id> --keep` (needs `lab.keep`). The next attempt, which the sweeper queues once `cleanupNextAt` passes, takes the `keep` path and marks the lease `released`. With the sweeper disabled, repeat the same command after `cleanupNextAt`. The `keep` path leaves the Lab machine record in place; remove it yourself if you no longer need it.

   If the round runs out before step 3, the lease is `cleanup_failed` again; re-arm and try step 3 once more. Leaving the lease `cleanup_failed` instead is also fine: it stays as the record, because `lab release` (with any strategy) refuses that state.

The re-arm needs `lab.lease` on the lease and `operation.create`, as a release does; the controller checks both before it changes the lease. It is audited: `lab_lease_cleanup_rearm_requested` is recorded before the change, and a re-arm that cannot record it fails without changing the lease. `lab_lease_cleanup_rearmed` is recorded once the change is made, but only best effort, so do not rely on finding it; the requested event is the audit of record. It grants a fresh round of five attempts, with the backoff restarting at one minute. A failed attempt backs off as before, and the lease returns to `cleanup_failed` after the round. `cleanupAttempts` keeps counting across rounds: 5 just after the re-arm, and 10 if the new round is exhausted too. A lease that is not `cleanup_failed` when the request arrives is refused with `400 invalid_request`. If the lease changes between that check and the re-arm (another retry, release or sweep won the race), the request is refused with `409 conflict` and changes nothing; read the lease again before retrying.

Until you re-arm it, `cleanup_failed` stays put: `lab release` refuses it, and Fleet does not retry it. The lease remains the record that it owned a guest that needed a human.

`revert` cleanup applies only to a lease that holds a pool member (see [Pooled guests](#pooled-guests)). A `revert` lease whose guest is a clone is refused with `not_pooled`. Nothing is destroyed and no attempt is spent; the lease stays `releasing`. Release it with `--keep`, then remove the guest yourself.

### Pooled guests

A pool is a small set of preallocated QEMU guests (FM-717, [#260](https://github.com/Frogbyte-io/fleet-manager/issues/260)). It is bound to one published template version, and leases from that version take a member instead of a clone. Cleanup rolls the member back to a baseline snapshot instead of destroying it. Fleet never creates or destroys a pool guest:
- you build and snapshot the guests yourself;
- fill registers them;
- drain only releases them from Lab.

Before you create a pool, prepare it:

1. Publish a template version whose cleanup is `revert` (`lab template-create ... --cleanup revert`, then `lab publish`). A pool refuses any other version.
2. For each member, make a QEMU guest (not a template, not a container) on a node of the account you will name.
   - The guest's name must not start with `fm-lab-`, which Lab uses for its own clones.
   - Its VMID must not be a promoted image's template.
   - Take the baseline snapshot on it (`qm snapshot <vmid> baseline`). Every member must carry a snapshot with the same name.
   - Install the controller's SSH key and the QEMU guest agent before the snapshot, as for an image.
3. Grant the account's token `VM.Audit` and `VM.Snapshot.Rollback` (or `VM.Snapshot`) on each member's `/vms/<vmid>`, plus `VM.PowerMgmt` to start it.

Then create, fill, and check the pool:

```sh
fleetctl --output json lab pool create --template-version <version-id> --account <account-id> --baseline baseline --size 3
fleetctl --output json lab pool fill <pool-id> --vmid 700 --vmid 701 --vmid 702 --wait
fleetctl --output json lab pool show <pool-id>
```

Fill registers the VMIDs as `filling` and queues a `lab.pool.fill` operation. For each member, the operation:
- checks that the guest exists, is a QEMU guest, is not an `fm-lab-*` clone or an image artifact, and carries the baseline;
- rolls it back to the baseline through the reviewed `proxmox.guest.snapshot-revert` path. The rollback stops a running guest first;
- reads the config back. The config's `parent` must name the baseline, with no lock left.

Only then is the member `available`. Otherwise it is `quarantined` and its `detail` says why. Sometimes Fleet cannot decide: the account is untrusted, the cluster or a config cannot be read, or the rollback did not finish in time. The member then stays `filling` (listed as `pending`), and the operation fails with `fill_incomplete`. Fix the cause and run `lab pool fill <pool-id>` again. `--wait` exits non-zero when any member was quarantined or left pending. The member records the guest's name, and later reverts refuse a guest at that VMID with another name: a replaced guest is never rolled back. Fill refuses more VMIDs than the pool's `size` (at most 16), and a guest that is already a member of any pool. `lab pool fill <pool-id>` with no `--vmid` re-queues members that are still `filling`, for example after a controller restart.

Leasing works as before. `lab create <version-id> --purpose ...` takes the free member with the lowest VMID, in the same SQLite transaction that records it on the lease's provision. Two leases never share a member. A pooled provision uses the pool's account; `--account` must name it or be omitted. It reserves no capacity, because the member already exists. It boots the member and runs the template's readiness as usual. With no free member, the provision fails with `pool_exhausted` and the lease ends `failed`, owning nothing.

Release (`lab release`, `lab destroy`, expiry) queues the usual `lab.cleanup`:
- **Revert.** A lease that holds a member always reverts it, even if its strategy says `destroy`; Lab never destroys a member. Cleanup re-checks the guest, rolls it back, verifies it, and removes the lease's Lab machine record. It then returns the member to `available` in the same transaction that marks the lease `released`.
- **Failed revert.** A failed check, rollback, or verification quarantines the member at once, still bound to the lease, and is a failed attempt with the usual backoff. After five attempts the lease is `cleanup_failed`. Fix the guest (for example `qm unlock <vmid>`, or restore the baseline), then run `lab cleanup-retry`; a verified revert returns the member.
- **`keep`.** The lease is released, and the guest and its machine record stay. The member is quarantined out of rotation. Drain it, then fill it again once it is back at its baseline.

Drain releases members from Lab:

```sh
fleetctl --output json lab pool drain <pool-id> --vmid 701
fleetctl --output json lab pool drain <pool-id>
fleetctl --output json lab pool delete <pool-id>
```

A member that no lease holds leaves at once (`removed`). A member that is bound to a lease, or still filling, is flagged and leaves when that cleanup or fill finishes, instead of returning (`deferred`). Without `--vmid`, drain covers every member. A pool is deleted only once it is empty. After that, leases from its template version clone again.

Every pool mutation needs `lab.config`, and fill also needs `operation.create`. The controller checks both before anything is registered. The intent is audited before the change: `lab_pool_creating`, `lab_pool_fill_requested`, `lab_pool_draining`, `lab_pool_deleting`. The executors record each member change best effort (resource: the pool):
- `lab_pool_member_available` and `lab_pool_member_quarantined` (with `reason`);
- `lab_pool_member_claimed`, `lab_pool_member_returned`, and `lab_pool_member_removed`.

Find them with `fleetctl --output json audit list --action lab.config`.

### Orphans

An orphan is a Fleet-named guest (`fm-lab-*`) that no live lease or standalone provision owns.

Each sweeper tick lists the `fm-lab-*` QEMU guests on every trusted account. A guest is owned when its provision record names that account and VMID, and the record is standalone or its lease still links back to that same record (a lease whose provision link names another record does not vouch for this guest). Such a lease owns the guest in any state but `released` or `failed`, and also when it was released with `keep`. The sweeper reports each unowned guest once per controller run, as the audit event `lab_orphan_guest` (resource: the guest's name; facts: `accountId`, `node`, `vmid`) and a log line (`lab sweeper: guest … has no live Lab owner`). A restarted controller reports it again.

```sh
fleetctl --output json audit list --action lab.lease
```

The sweeper skips an account it cannot read (unconfirmed, no stored token, or unreachable) without a log line. A controller without a secret store skips step 4 entirely. For such an account, without a secret store, or with the sweeper disabled, find orphans by hand. Compare the account's guests with the provision records:

```sh
fleetctl --output json proxmox guests <lab-account-id>
fleetctl --output json lab provisions
```

Fleet **never** deletes an orphan. To remove one:

1. Confirm in PVE that nothing else uses it.
2. Check `fleetctl --output json lab provisions` and `fleetctl --output json lab leases` for a record that still owns that VMID. A guest released with `keep` is owned on purpose.
3. Destroy it with `fleetctl --output json proxmox destroy <account> <node> <vmid> --wait`, or with `qm destroy` on the host.

### Capacity

Before a provision takes a VMID, Fleet reserves the template's CPU, memory, and disk on the node that holds the template (FM-715, [#257](https://github.com/Frogbyte-io/fleet-manager/issues/257)). Without `--account`, `lab provision-lease` places the lease on the one trusted account whose cluster holds the pinned template, and refuses when none or several do. Just before reserving, Fleet tries to refresh the node's capacity observation. If the refresh fails or comes back incomplete, the previous stored observation is used, and it is still refused once it is older than `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS`. The check subtracts the reservations Fleet already holds on the node. It is not a live host guarantee: workloads started outside Fleet use headroom that only a later observation shows.

Refusals fail the provision operation with a reason:

| Reason | Meaning | What to do |
| --- | --- | --- |
| `placement_no_candidate` | No trusted account's cluster reports the pinned template | Restore the template, or the token's visibility of it. `--account` does not help: that account then fails with `template_missing` |
| `placement_ambiguous` | Several trusted accounts report a template under the pinned VMID | Pass `--account <account-id>` to choose one |
| `placement_unresolved` | A trusted account's cluster or credential could not be read | Fix that account, or pass `--account <account-id>`, which skips the scan |
| `capacity_unknown` | No usable observation, or it lacks a CPU or memory figure | Check that the account can read node status (`proxmox nodes <account-id>`) |
| `capacity_stale` | The observation is older than `FLEET_LAB_CAPACITY_MAX_AGE_SECONDS`, or dated in the future | Fix the node read or the controller clock |
| `storage_unknown` | The image's storage pool is unknown, or the observation does not report it | Check the build's storage pool and the token's storage visibility |
| `insufficient_memory`, `insufficient_cpu` | The node lacks memory or cores after overcommit, usage, and held reservations | Release leases, free the node, or raise `FLEET_LAB_MEMORY_OVERCOMMIT` or `FLEET_LAB_CPU_OVERCOMMIT` |
| `insufficient_disk` | The image's storage pool on the node lacks free space after held reservations (no overcommit applies). A running Lab guest's disk is in the observed used space and in its reservation, so it counts twice | Free space on that pool, or release leases that hold disk on it |
| `reservation_mismatch` | The lease's held reservation is for another node, account, demand, or storage pool. This can happen when the template moved or a re-promotion changed the pinned build's pool | Release the lease and request a new one |

`FLEET_LAB_MEMORY_OVERCOMMIT` and `FLEET_LAB_CPU_OVERCOMMIT` (default `1.0`, at most 16) scale the node's total memory and CPU count; disk is never overcommitted. A lease's reservation stops counting once the lease is released, or failed without a guest. A lease in `cleanup_failed` keeps its reservation until `lab cleanup-retry` destroys the guest. [`docs/architecture/lab.md`](../architecture/lab.md) has the exact rule.

### Artifacts and storage sizing

Lab artifacts are exec logs and guest files you collect. They outlive the lease. The controller stores their bytes in `FLEET_LAB_ARTIFACTS_DIR` (default `<FLEET_DATA_DIR>/lab-artifacts`) and their metadata in the database.

- **Exec logs.** Every `lab exec` that ran keeps its exit code and bounded output (at most 3,000 bytes per stream, credentials in URLs scrubbed) as an `exec-log` artifact.
- **Collected files.** Copy files off a ready lease before you release it:

  ```sh
  fleetctl --output json lab collect <lease-id> /var/log/syslog /tmp/report.xml --wait
  ```

  Name 1 to 16 absolute paths of regular files. A path with `.`, `..`, or empty components is refused. Each file must fit `FLEET_LAB_ARTIFACT_MAX_BYTES` (default 64 MiB). The controller copies over the lease machine's verified SSH endpoint. A path that fails (`missing`, `not_a_file`, `unreadable`, `too_large`, `deadline_exceeded`, `copy_failed`, `transfer_failed`, `store_failed`) fails the operation. The paths that did copy are kept, and the lease detail shows the failure as `collectionFailure`. Collection never changes the lease and never holds up its release or cleanup. Collect before you release: a collection that runs after release fails with `lease_not_ready`.
- **Listing and download.**

  ```sh
  fleetctl --output json lab artifacts --lease <lease-id>     # or --project <project-id>
  fleetctl --output json lab artifact-get <artifact-id> --out ./syslog
  ```

  `artifact-get` writes the file only after its size and sha256 match the artifact's record. The controller also re-hashes the bytes before it sends them, and refuses (409) bytes that changed on disk.
- **Retention.** The Lab sweeper deletes artifacts older than `FLEET_LAB_ARTIFACT_RETENTION_SECONDS` (default 7 days). Expiry needs the background sweeper: with `FLEET_LAB_SWEEP_INTERVAL_SECONDS=0`, artifacts stay until it runs. The audit event is `lab_artifact_expired`. Identical content is stored once, and its bytes go when the last artifact that uses them expires.
- **Sizing.** Size the volume that holds `FLEET_LAB_ARTIFACTS_DIR` for one retention window of collected files, plus one size cap of headroom for each collection in progress: a file is staged under the directory's `tmp/` before it is committed, and leftover staging files are removed at startup. Exec logs are small (two bounded streams and a header). For example, 20 files of 5 MiB a day kept for the default 7 days need about 700 MiB, plus 64 MiB of staging headroom. When the volume is full, collection fails with `store_failed` and the lease is not affected. Each artifact's deletion deadline is fixed when it is stored, so a shorter retention or a lower size cap (both need a controller restart) only applies to artifacts stored afterwards; free space now by growing the volume.
- **Permissions.** Collecting and downloading need `lab.artifacts`. Listing needs `lab.read`.

What else uses space:

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
- **No credentials to unconfirmed hosts.** No Proxmox operation of Fleet's own sends a token to an account whose fingerprint you have not confirmed. Image builds fail with `target_account_untrusted` before any credential is resolved, and with `target_certificate_changed` when the host's certificate is no longer the confirmed one (see [Build](#3-build)). Recipe content that could read the token out of Packer's process is refused at publish time and again before every build (#313; see [Credentials](#build)).
- **Recovery without an operator.** The sweeper expires leases, compensates stuck provisions, and queues due cleanups from what the database holds. After a controller crash or restart, it continues on its next tick.
- **Builds leave records.** Every build has an immutable record, written before Packer runs and completed with its outcome.

What Fleet never does:

- delete a guest it cannot attribute to a Lab record (an orphan), or one released with `keep`;
- retry cleanup after `cleanup_failed` on its own (only an explicit retry request re-arms it: `lab cleanup-retry`, or `POST /api/v1/lab/leases/{leaseId}/cleanup/retry`);
- promote a build or replace a promoted version on its own.

Not yet guaranteed:

- **The failure-injection suite.** The suite that interrupts the controller at every lifecycle transition and checks these guarantees is **pending** (FM-741, [#262](https://github.com/Frogbyte-io/fleet-manager/issues/262)).
- **Cancelled builds leave a clean host.** Fleet relies on Packer's clean-cancel report and does not check the host. A build that ends `cancelled_unverified`, `deadline_interrupted_unverified`, or `deadline_killed` can leave its in-progress VM on the host (see [Build](#3-build)).

## Out of scope

USB, GPU, and other hardware-in-the-loop resources are a separate sub-epic. Windows guests are later work.
