# Proxmox VE test hosts: a nested 8.x node and a two-node cluster

Status: runbook for FM-612 ([#211](https://github.com/Frogbyte-io/fleet-manager/issues/211)). First run end to end on the integration host on 2026-10-01: a PVE 8.4.0 node and a two-node PVE 9.2.2 cluster, nested on the PVE 9.2.2 host. The redacted evidence is on the issue, and the failure-mode table in step 8 records what the API returned in that run.

The [supported platform baseline](../PLAN.md#supported-platform-baseline) says Fleet supports Proxmox VE 8.x and 9.x, and the M6 real-cluster suite must pass on both majors. The integration environment has one physical PVE 9.x host. It has no 8.x node, and a single node cannot show a partial-node failure. That gap was the FM-S08 recorded deviation; the suite run on these fixtures replaced it with a live result on both majors (see [FM-S08](../research/ecosystem.md#fm-s08-proxmox-client-compatibility-spike)). This runbook adds three nested PVE VMs on that host:

| Role | What it is | Used by FM-611 as |
|---|---|---|
| `pve8` | A standalone nested PVE 8.4 node | The 8.x compatibility target |
| `node-a` | First node of a two-node nested cluster, where the cluster is created | The cluster target that Fleet talks to |
| `node-b` | Second cluster node | The node that `node-down` takes offline |

The physical 9.x host remains the 9.x target. The cluster can run 8.4 or 9.x. 9.x is the recommendation, because the 8.x leg is already covered by `pve8`.

All of this is automated by [`deploy/pve-test/pve-test`](../../deploy/pve-test/pve-test), a bash script configured only through environment variables (see [`pve-test.env.example`](../../deploy/pve-test/pve-test.env.example)). Every command is idempotent: it checks the current state and skips work that is already done. The script never acts on a VMID that exists without the `fleet-pve-test` tag.

> **This repository is public.** Addresses, host names, VMIDs, token IDs, fingerprints, password hashes, and token secrets belong in your local env file and secret directory. They never go in Git, in issue comments (except the redacted evidence), or in logs.

Non-goals, taken from the issue: this runbook doesn't automate the physical host's configuration and doesn't provision anything from CI. The nested hosts are long-lived fixtures that the maintainer runs by hand.

## Prerequisites

1. **Maintainer approval and capacity.** Confirm with the maintainer before provisioning. With the defaults, each nested node takes 4 vCPU, 8 GiB RAM (no ballooning), and a 64 GiB thin disk, so the three VMs need about 24 GiB RAM plus headroom for the nested guests the suite clones. To save capacity, the nodes can run at 6 GiB each (`FLEET_PVE_TEST_MEMORY_MB`). Or build the cluster from 8.4 and skip `pve8`, running the 8.x scenarios against `node-a` while the cluster is quorate. That shortcut mixes the 8.x and cluster evidence, though, so prefer three VMs.
2. **Nested virtualization on the physical host.** Check it:

   ```sh
   cat /sys/module/kvm_intel/parameters/nested   # Intel; expect Y (or 1)
   cat /sys/module/kvm_amd/parameters/nested     # AMD; expect 1
   ```

   If it is off, enable it persistently. Use `echo "options kvm-intel nested=Y" > /etc/modprobe.d/kvm-intel.conf` on Intel or `echo "options kvm-amd nested=1" > /etc/modprobe.d/kvm-amd.conf` on AMD. Then reload the module (`modprobe -r kvm_intel && modprobe kvm_intel`). Unloading the module fails while any VM is running on the host, so schedule a maintenance window or a reboot. Each nested VM also needs CPU type `host`, which `create-vm` sets. Source: Proxmox wiki, [Nested Virtualization](https://pve.proxmox.com/wiki/Nested_Virtualization).
3. **Tools on the physical host:** `qm` and `pvesm` (present on every PVE node), plus `proxmox-auto-install-assistant`, installed with `apt install proxmox-auto-install-assistant` from the host's configured Proxmox repository. Installing it is a manual host change. Source: [Automated Installation](https://pve.proxmox.com/wiki/Automated_Installation).
4. **On your workstation:** bash 4.4 or later, `ssh`, and `ssh-keygen`. You also need root SSH access to the physical host, unless you run the script on that host as root with `FLEET_PVE_TEST_PHYS_SSH` empty.
5. **Addresses.** Reserve three static addresses on the bridge's network, outside any DHCP pool, and a DNS name or `/etc/hosts` entry for each FQDN. A cluster node's host name and address cannot change after cluster creation ([Cluster Manager](https://pve.proxmox.com/pve-docs/chapter-pvecm.html)), so decide them now.
6. **Local secrets.** You need a root password *hash* (for example, `openssl passwd -6 > ~/.config/fleet/pve-test-root.hash`, which prompts for the password) and an SSH public key. The plain-text password is never stored by the script. You type it only at the `openssl` prompt and, in the default join mode, at the `cluster-join` prompt; `cluster-join --ssh` doesn't ask for it.

Copy [`pve-test.env.example`](../../deploy/pve-test/pve-test.env.example) to `~/.config/fleet/pve-test.env` (the default path; `FLEET_PVE_TEST_ENV_FILE` overrides it), `chmod 600` it, and fill it in. Then:

```sh
deploy/pve-test/pve-test check-host
```

This checks nesting, the tools, both storages, both source ISOs, and whether each VMID is free, already a fixture, or taken by something else. It exits non-zero until everything is ready.

## Network layout

```text
                    physical PVE 9.x host (existing integration host)
  LAN / lab bridge ──┬──────────────────────────────┬──────────────────────┐
  (FLEET_PVE_TEST_   │ net0 virtio, firewall=0      │                      │
   BRIDGE, optional  │                              │                      │
   VLAN tag)     ┌───┴──────────┐   ┌───────────────┴─┐   ┌────────────────┴┐
                 │ pve8 (8.4)   │   │ node-a          │   │ node-b          │
                 │ ens18 static │   │ ens18 static    │◄─►│ ens18 static    │
                 │ vmbr0        │   │ vmbr0           │   │ vmbr0           │
                 └──────────────┘   └─────────────────┘   └─────────────────┘
                                         corosync link0 + API 8006 on the same L2
  Fleet controller ── HTTPS 8006 ──► each nested node (and the physical host)
  nested guests (scratch VMs) ── bridged through vmbr0/ens18 ──► same L2, DHCP
```

- Each nested node has one VirtIO NIC. On PVE's default PCI layout it appears inside the node as **`ens18`**, not `eth0`. The answer file pins that name, which is the same trap as the cloud-init NIC name recorded for the integration VM. If you change the machine type or the NIC slot, set `FLEET_PVE_TEST_NESTED_NIC`.
- The installer makes each node's `vmbr0` bridge `ens18`, so guests the suite clones inside a nested node land on the same L2 and take DHCP leases there. The QEMU Guest Agent association scenario depends on this.
- The nested nodes' NIC is created with **`firewall=0`**. When the physical host's firewall is enabled on a NIC, its MAC filter drops frames from source MACs other than the VM's own, which would silently cut off the nested guests.
- Corosync's `link0` shares the LAN. A test fixture can accept that, even though production clusters separate corosync. Corosync needs UDP 5405-5412 between the nodes, and `pvecm add` needs the API on TCP 8006 ([Cluster Manager](https://pve.proxmox.com/pve-docs/chapter-pvecm.html)).

## Step 1: source ISOs

Download the PVE 8.4 ISO, and the 9.x ISO if the cluster runs 9.x, into `FLEET_PVE_TEST_ISO_STORAGE` on the physical host. Verify each one against the `SHA256SUMS` that Proxmox publishes next to it (<https://enterprise.proxmox.com/iso/>, linked from <https://www.proxmox.com/en/downloads>). The storage download endpoint verifies the checksum for you:

```sh
pvesh create /nodes/<physical-node>/storage/<iso-storage>/download-url \
  --content iso --filename proxmox-ve_8.4-<n>.iso \
  --url https://enterprise.proxmox.com/iso/proxmox-ve_8.4-<n>.iso \
  --checksum <sha256-from-SHA256SUMS> --checksum-algorithm sha256
```

Set `FLEET_PVE_TEST_ISO_PVE8` and `FLEET_PVE_TEST_ISO_CLUSTER` to the resulting volume IDs (`<iso-storage>:iso/<file>`).

## Step 2: answer files and auto-install ISOs

The automated installer (a tech preview since 8.2) reads an `answer.toml`. `proxmox-auto-install-assistant prepare-iso <iso> --fetch-from iso --answer-file <answer.toml>` embeds that file into a copy of the ISO. The prepared ISO adds an "Automated Installation" boot entry that is selected automatically after 10 seconds. Sources: [Automated Installation](https://pve.proxmox.com/wiki/Automated_Installation); the installer's own [answer-file test fixtures](https://github.com/proxmox/pve-installer/tree/master/proxmox-auto-installer/tests/resources/parse_answer).

The template is [`deploy/pve-test/answer.toml.template`](../../deploy/pve-test/answer.toml.template), and it contains placeholders only:

```toml
[global]
keyboard = "@KEYBOARD@"
country = "@COUNTRY@"
fqdn = "@FQDN@"
mailto = "@MAILTO@"
timezone = "@TIMEZONE@"
root-password-hashed = "@ROOT_PASSWORD_HASH@"
root-ssh-keys = [@ROOT_SSH_KEYS@]

[network]
source = "from-answer"
cidr = "@CIDR@"
gateway = "@GATEWAY@"
dns = "@DNS@"
filter.ID_NET_NAME = "@NIC@"

[disk-setup]
filesystem = "ext4"
disk-list = ["sda"]
```

**8.x vs 9.x key names.** The first 8.2 answer files used snake_case keys (`root_password`, `disk_list`). According to the [pve-installer changelog](https://github.com/proxmox/pve-installer/blob/master/debian/changelog), installer 8.4.0 started accepting kebab-case as well, and in 9.0.0 `validate-answer` warns about the old snake_case keys. One kebab-case file therefore serves both 8.4 and 9.x. The same file doesn't work on 8.2 or 8.3 ISOs, which this runbook doesn't use. `root-password-hashed` is available from installer 8.2.7 on.

```sh
deploy/pve-test/pve-test prepare-iso pve8
deploy/pve-test/pve-test prepare-iso node-a
deploy/pve-test/pve-test prepare-iso node-b
```

For each role, `prepare-iso` does the following:

1. Renders the answer from the env file on your workstation.
2. Streams it into a mode-0600 temporary file on the physical host.
3. Runs `validate-answer`, then `prepare-iso` with output to `<iso-storage>:iso/fleet-pve-test-<role>.iso`.
4. Deletes the rendered answer.

The prepared ISO still embeds the password hash, so `wait` deletes it as soon as the node is installed.

**Verified:** the 9.x assistant (9.2.8) prepares an 8.4 ISO that the 8.4 installer accepts. The boot menu shows "Install Proxmox VE (Automated)" and selects it automatically.

**Installing the assistant on a host without a subscription.** `apt install proxmox-auto-install-assistant` only works if the host has a Proxmox repository it can read. A host with only the enterprise repository and no subscription has none. To avoid changing the host's repositories, download the `.deb` from the no-subscription pool (`http://download.proxmox.com/debian/pve/dists/<suite>/pve-no-subscription/binary-amd64/`), check its SHA-256 against that directory's `Packages` index, unpack it with `dpkg -x`, and put the binary on `PATH`. `prepare-iso` also needs `xorriso`, which is in Debian's own repository.

## Step 3: create and install the nested nodes

```sh
for role in pve8 node-a node-b; do
  deploy/pve-test/pve-test create-vm "$role"
done
for role in pve8 node-a node-b; do
  deploy/pve-test/pve-test wait "$role"
done
```

`create-vm` runs `qm create` with the following settings:

- CPU type `host`, which nesting requires, and ballooning off.
- A VirtIO SCSI single controller with one `iothread` disk (`sda` in the installer).
- `net0 virtio,bridge=…,firewall=0`, with an optional VLAN tag.
- The prepared ISO on `ide2`, boot order `scsi0;ide2`, the `fleet-pve-test` tag, and `onboot=0`.

Then it starts the VM. The empty disk falls through to the CD-ROM, and once the unattended install reboots, the disk boots first, so a stale ISO never loops the install.

`wait` polls `pveversion` over SSH (default timeout 1800 s). The first connection records the node's host key in a fixture-only known_hosts file (`FLEET_PVE_TEST_KNOWN_HOSTS`), and teardown removes it. `wait` then detaches the ISO (`ide2: none`) and deletes the prepared ISO.

## Step 4: form the two-node cluster

```sh
deploy/pve-test/pve-test cluster-create   # pvecm create <name> --link0 <node-a address>, on node-a
deploy/pve-test/pve-test cluster-join     # pvecm add <node-a> --link0 <node-b> --fingerprint <node-a API cert>, on node-b
# or, unattended:
deploy/pve-test/pve-test cluster-join --ssh   # pvecm add <node-a> --link0 <node-b> --use_ssh 1, on node-b
deploy/pve-test/pve-test status
```

`pvecm add` authenticates against node-a's API and prompts for node-a's `root@pam` password. The script runs it on a TTY, so you type the password yourself. It is never an argument, and it is never stored. The script passes node-a's API certificate fingerprint, read over SSH, so the join doesn't need to trust on first use. All nodes should run the same PVE version.

`cluster-join --ssh` joins without a password, for unattended runs. `pvecm add --use_ssh` runs `ssh-copy-id -i /root/.ssh/id_rsa` and then BatchMode `ssh` from node-b to node-a (see `PVE/CLI/pvecm.pm`), so it needs node-b's root key authorized on node-a and node-a's host key known on node-b. The script copies both over its own SSH connections first. Those pinned each node's host key when `wait` first reached it (trust on first use, see step 3), so the join itself adds no new trust decision. It leaves node-b's key authorized on node-a, which a cluster does anyway. Source: [Cluster Manager (9.x)](https://pve.proxmox.com/pve-docs/chapter-pvecm.html); the `pvecm` commands are the same in the [8.x documentation](https://pve.proxmox.com/pve-docs-8/chapter-pvecm.html).

`status` should show `Quorate: Yes`, `Nodes: 2`, and `Expected votes: 2`.

## Step 5: test user, roles, and tokens

Create the roles, user, privilege-separated token, and ACLs with [steps 2–5 of the token guide](proxmox-token.md#2-roles). Follow the guide's per-major role definitions and clone-target/storage scopes for each acceptance target. The guide includes the 8.x agent-readiness role and leaves the role for cancelling other principals' tasks ungranted. Verify each token with [the verification section](proxmox-token.md#verify-with-fleetctl-proxmox-privileges), then use its ID and private secret file for `FLEET_PVE_TARGET_<NAME>_TOKEN_ID` and `…_TOKEN_SECRET_FILE` in step 7 below.

Keep a separate read-only `PVEAuditor` token for FM-611's privilege-failure scenario. On the machine that runs the suite, use the existing helper to create it on each nested target and capture its secret locally:

```sh
deploy/pve-test/pve-test tokens pve8
deploy/pve-test/pve-test tokens node-a    # cluster-wide; node-b shares it
```

The helper creates a fixture-only test user with `Administrator` on `/`, the user's ACLs, and two privilege-separated tokens: `ro` with `PVEAuditor` and `admin` with `Administrator`. It does not create the token guide's tier roles. Use the guide for the acceptance token; replace the admin token ID/secret-file values printed by `pve-test env` with your tier token's values. Privilege separation intersects the token's ACLs with the user's, so the `ro` token remains read-only. Sources: [User Management](https://pve.proxmox.com/pve-docs/chapter-pveum.html) and the [8.x edition](https://pve.proxmox.com/pve-docs-8/chapter-pveum.html).

Secrets are written directly into `FLEET_PVE_TEST_SECRET_DIR/<role>-<ro|admin>.token` **on the machine running the helper**, never to the terminal (directory mode 0700, file mode 0600). Use the local `<role>-ro.token` path for `FLEET_PVE_TARGET_<NAME>_RO_TOKEN_SECRET_FILE`, and the helper's read-only token ID for `…_RO_TOKEN_ID`. Re-running with the token and file present reuses them. If the token exists but its local secret file is missing, the helper refuses: remove that stale token on the nested node using the exact `pveum user token remove … ro` recovery command printed by the helper (it names the configured `FLEET_PVE_TEST_USER`, default `fleet-test@pve`), then re-run `tokens`. Remove a stale local file only after revoking its token. Never overwrite a secret file for a token that is still in use.

## Step 6: the test template for FM-611

FM-611's task-polling, destructive-gate, and association scenarios clone from a template on each target (`…_TEMPLATE_VMID`) that has the QEMU Guest Agent installed. On each target (`pve8`, and `node-a` for the cluster), create a small Linux VM with the guest agent enabled (`--agent enabled=1`) and `qemu-guest-agent` installed in the guest, with its NIC on `vmbr0`. Its NIC is `ens18` too; if you seed it with cloud-init, the seed must say `ens18`. Convert it with `qm template <vmid>`, give it a VMID **outside** the suite's `VMID_RANGE`, and put the template's VMID in your env file. FM-611 owns the exact template requirements. This runbook only guarantees the hosts.

## Step 7: environment for the acceptance suite (FM-611)

FM-611 ([#214](https://github.com/Frogbyte-io/fleet-manager/issues/214)) describes targets entirely through environment variables: `FLEET_PVE_LIVE=1`, plus `FLEET_PVE_TARGET_<NAME>_*` for each target. This runbook's targets map to these names:

| Target name | Host | Notes |
|---|---|---|
| `PVE9` | the existing physical 9.x host | Not created here; configure it from the existing integration credentials |
| `PVE8` | `pve8` | The 8.x leg |
| `CLUSTER` | `node-a` | Multi-node scenarios; `node-b` is the node taken down |

Print a target's block and paste it into your **local** env file:

```sh
deploy/pve-test/pve-test env pve8 PVE8
deploy/pve-test/pve-test env node-a CLUSTER
```

| Variable | Meaning | Source |
|---|---|---|
| `FLEET_PVE_TARGET_<NAME>_HOST` | Node address | Role `CIDR` |
| `FLEET_PVE_TARGET_<NAME>_PORT` | `8006` | |
| `FLEET_PVE_TARGET_<NAME>_TOKEN_ID` | ID of the tier token from the token guide | Step 5 |
| `FLEET_PVE_TARGET_<NAME>_TOKEN_SECRET_FILE` | Path to the 0600 secret file | Step 5 |
| `FLEET_PVE_TARGET_<NAME>_FINGERPRINT` | SHA-256 of the API certificate (`pveproxy-ssl.pem` if present, otherwise `pve-ssl.pem`) | `pve-test fingerprint <role>` |
| `FLEET_PVE_TARGET_<NAME>_NODE` | PVE node name (the first label of the FQDN) | Role `FQDN` |
| `FLEET_PVE_TARGET_<NAME>_STORAGE` | `local-lvm` (created by the ext4 install) | `FLEET_PVE_TEST_GUEST_STORAGE` |
| `FLEET_PVE_TARGET_<NAME>_TEMPLATE_VMID` | Test template VMID | Step 6 |
| `FLEET_PVE_TARGET_<NAME>_VMID_RANGE` | Scratch-VM range the suite may touch | `FLEET_PVE_TEST_GUEST_VMID_RANGE` |
| `FLEET_PVE_TARGET_<NAME>_RO_TOKEN_ID`, `…_RO_TOKEN_SECRET_FILE` | The read-only (`PVEAuditor`) token | Step 5; **proposed name** for FM-611's "optional low-privilege token" |
| `FLEET_PVE_TARGET_CLUSTER_DOWN_NODE`, `…_DOWN_ROLE` | PVE node name and `pve-test` role of the node to take down | **Proposed** for FM-611's partial-node scenario |
| `FLEET_PVE_TEST_ENV_FILE` | This runbook's env file, so the suite can call `deploy/pve-test/pve-test node-down/node-up` | **Proposed** |

FM-611 owns the final names. If it settles on different ones, update this table and `cmd_env` together. #211's examples (`FLEET_PVE8_*`, `FLEET_PVE_CLUSTER_*`) became `FLEET_PVE_TARGET_PVE8_*` and `FLEET_PVE_TARGET_CLUSTER_*` under FM-611's scheme.

## Step 8: simulating a partial-node failure

```sh
deploy/pve-test/pve-test node-down node-b                      # --mode stop (default)
deploy/pve-test/pve-test node-down node-b --mode partition
deploy/pve-test/pve-test node-down node-b --keep-quorum        # either mode
deploy/pve-test/pve-test node-up node-b
```

Both modes are deterministic and idempotent. `node-up` undoes either one: it starts the VM if it is stopped, removes any partition rules, and waits until `pvecm status` reports `Quorate: Yes`. When the node rejoins, expected votes return to 2 on their own, so `--keep-quorum` leaves nothing to undo. `FLEET_PVE_TEST_DOWN_MODE` sets the default mode.

Observed on 2026-10-01 (PVE 9.2.2 cluster, privilege-separated admin token, survivor `node-a`):

| | `--mode stop` | `--mode partition` |
|---|---|---|
| **What it does** | `qm stop` on the physical host: an immediate power-off with no guest shutdown, like pulling the plug | Dedicated iptables chains (`FLEET_TEST_IN`/`FLEET_TEST_OUT`) on the node **drop every packet to and from its peer**: corosync, the API, SSH, and migration. The node stays up and reachable from everywhere else, including the Fleet controller |
| **Detection** | The survivor's `/cluster/status` showed the node `online: 0` about 10 s after `node-down` | About 9 s |
| **Cluster view from the survivor** (`/cluster/status`, `/nodes`) | The down node is `online: 0` / `status: offline`, and the cluster entry is `quorate: 0` | The same. The isolated node's own `/cluster/status` is the mirror image: itself `online: 1`, its peer `online: 0`, `quorate: 0` |
| **Requests the survivor proxies to the down node** (`/nodes/<down>/…`) | `595 No route to host` in 1.7–3.1 s. **The first request after the power-off took 30 s**, presumably while the survivor's ARP entry for the node was still valid. Don't assume the stop case fails fast | Every request hangs **30 s**, then `595 Connection timed out`. The 595 responses carry no JSON body; the reason is only in the HTTP status line |
| **Fleet talking directly to the down node** | TCP connect fails at the client (curl exit 7), after anywhere from 3 s to 14 s. A transport error, not an API response | The API answers normally (`/version` 200 in a few ms), with the split view above |
| **Writes on the survivor** | Refused while inquorate: a pool create or delete returned `500 … cfs-lock 'file-user_cfg' error: no quorum!` after about 10 s (the cfs-lock wait) | Same |
| **With `--keep-quorum`** | The survivor is `quorate: 1`, and the same writes return 200 at once | Same |
| **Recovery** (`node-up` until quorate) | 27–28 s, mostly boot | 8–9 s |

A two-node cluster has two expected votes, so losing either node leaves the survivor **inquorate**. This is how two-node clusters fail, and Proxmox recommends a QDevice to supply the third vote ([Cluster Manager](https://pve.proxmox.com/pve-docs/chapter-pvecm.html)). For a scenario that needs the survivor writable, pass `--keep-quorum`, which runs `pvecm expected 1` on the survivor. It first waits until the survivor has dropped the node from membership (`Total votes: 1`): votequorum rejects expected votes below the votes it still counts, with `CS_ERR_INVALID_PARAM`. The docs reserve that command for when "you understand what you are doing", and it only suits a disposable fixture. Membership changes take a few seconds, and the status daemon refreshes every few seconds, so wait until `/cluster/status` reports the change before you assert on it.

These figures come from one run on one host. FM-613 should re-check them on 8.x and record anything that differs. In particular, the survivor took 30 s to give up on an unreachable node in every slow case. That figure is measured, not taken from PVE's documentation or source. An operation deadline in Fleet shorter than that turns an unreachable node into a Fleet timeout before PVE answers with 595.

## Step 9: the image build suite (FM-704)

`cargo xtask image-acceptance [--target NAME]` ([#255](https://github.com/Frogbyte-io/fleet-manager/issues/255)) reuses the Step 7 targets and gate: export `FLEET_PVE_LIVE=1` and the `FLEET_PVE_TARGET_<NAME>_*` lines you put in your local env file in Step 7 (this example calls it `~/.config/fleet/pve-acceptance.env`; any untracked path works):

```sh
set -a; . ~/.config/fleet/pve-acceptance.env; set +a
cargo xtask image-acceptance --target PVE8 > ~/image-acceptance.json
```

It also needs an operator-installed `packer` inside the FM-S09 pins (`>= 1.15 < 2`) with the Proxmox plugin (`>= 1.2.4 < 2`, `packer plugins install github.com/hashicorp/proxmox`) on the machine that runs it. The suite asks the product's own version gate. Without a usable Packer, only `version-gate` can pass (it needs no Packer); every other scenario fails with the gate's reason, so a live run never passes without building.

A whole run is bounded: four hours for this suite, two for Step 7's (compilation included). Past the bound the runner kills the suite's process tree, and every scenario that has not reported fails with that reason in the summary.

Builds are linked clones of `…_TEMPLATE_VMID` into `…_VMID_RANGE`. Each built template is named `fleet-acceptance-image-*` and tagged `fleet-acceptance`. The suite destroys exactly those templates at the start and end of every scenario. The shared Step 7 sweep never destroys a template.

Each build gets the trusted account's token through the product's own path (#272): the account is resolved from the recipe's `proxmox_url`, and its token reaches only the Packer child process, in its environment. Recipe secrets take the other channel: their resolved values go to Packer in a `-var-file` inside the operation's private work directory. The suite's recipes declare no secrets, so only the account token is exercised here. The harness strips any `PROXMOX_*` variables from the controller's environment, so a passing build proves the token came from the account. The recipes still set `insecure_skip_tls_verify` until [#284](https://github.com/Frogbyte-io/fleet-manager/issues/284) gives Packer the pinned certificate.

## Evidence for #211

```sh
deploy/pve-test/pve-test evidence
```

This prints `pveversion` from `pve8` and `node-a`, and `pvecm status` from the cluster, with IPv4 and IPv6 addresses replaced by `<redacted-…>`. It keeps host names and cluster names, so review and redact those by hand before posting if they are sensitive.

## Teardown

```sh
deploy/pve-test/pve-test teardown --yes             # all roles
deploy/pve-test/pve-test teardown --yes node-b      # one role
```

For each role, teardown does the following:

1. Stops and destroys the tagged VM (`qm destroy --purge 1 --destroy-unreferenced-disks 1`). It refuses any untagged VMID.
2. Deletes that role's prepared ISO if it is still present.
3. Deletes that role's local token-secret files.
4. Removes the node's host key from the fixture known_hosts file.

The tokens, the user, and the cluster exist only inside the nested VMs, so they are removed along with them. To rebuild, start again at step 2. The source ISOs and your env file are kept.

Removing a single node from a cluster that stays alive is a different procedure (`pvecm delnode` after powering the node off for good). This fixture doesn't need it; tear down both cluster nodes together.

## Sources

The Proxmox pages were cited as of 2026-09-30. `pve.proxmox.com` was not reachable from the authoring environment, so the command syntax and quoted text were checked against the same documentation sources in Proxmox's GitHub mirrors: [`pve-docs`](https://github.com/proxmox/pve-docs) (`pvecm.adoc`, `pveum.adoc`, `qm.adoc`, `pve-installation.adoc`) and [`pve-installer`](https://github.com/proxmox/pve-installer) (`debian/changelog`, `proxmox-auto-install-assistant`, the answer-file test fixtures).

- Proxmox wiki: [Nested Virtualization](https://pve.proxmox.com/wiki/Nested_Virtualization) and [Automated Installation](https://pve.proxmox.com/wiki/Automated_Installation)
- PVE admin guide, 9.x: [Cluster Manager](https://pve.proxmox.com/pve-docs/chapter-pvecm.html), [User Management](https://pve.proxmox.com/pve-docs/chapter-pveum.html), and [QEMU/KVM Virtual Machines](https://pve.proxmox.com/pve-docs/chapter-qm.html)
- PVE admin guide, 8.x: [Cluster Manager](https://pve.proxmox.com/pve-docs-8/chapter-pvecm.html) and [User Management](https://pve.proxmox.com/pve-docs-8/chapter-pveum.html)
- [pve-installer changelog](https://github.com/proxmox/pve-installer/blob/master/debian/changelog): automated installer from 8.2.0, kebab-case keys from 8.4.0, the snake_case warning in 9.0.0, and `root_password_hashed` from 8.2.7
