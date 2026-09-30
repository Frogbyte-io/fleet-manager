# Proxmox VE test hosts: a nested 8.x node and a two-node cluster

Status: runbook for FM-612 ([#211](https://github.com/Frogbyte-io/fleet-manager/issues/211)). Its first end-to-end run on the integration host is still pending. That run's evidence (`pveversion` from the 8.x node and `pvecm status` from the cluster, with addresses redacted) is posted on the issue, and each "expected" statement below is corrected wherever the live run disagrees.

The [supported platform baseline](../PLAN.md#supported-platform-baseline) says Fleet supports Proxmox VE 8.x and 9.x, and the M6 real-cluster suite must pass on both majors. The integration environment has one physical PVE 9.x host. It has no 8.x node, and a single node cannot show a partial-node failure; this is the [FM-S08 recorded deviation](../research/ecosystem.md#fm-s08-proxmox-client-compatibility-spike). This runbook adds three nested PVE VMs on that host:

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
6. **Local secrets.** You need a root password *hash* (for example, `openssl passwd -6 > ~/.config/fleet/pve-test-root.hash`, which prompts for the password) and an SSH public key. The plain-text password is typed only at the `cluster-join` prompt and is never stored.

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

**Unverified risk:** the assistant on a 9.x physical host prepares an 8.4 ISO here. If the 8.4 installer doesn't pick up the answer (for example, if the boot menu shows no "Automated Installation" entry), prepare the 8.x ISO with an 8.x `proxmox-auto-install-assistant` instead, and record the finding on #211.

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
deploy/pve-test/pve-test status
```

`pvecm add` authenticates against node-a's API and prompts for node-a's `root@pam` password. The script runs it on a TTY, so you type the password yourself. It is never an argument, and it is never stored. The script passes node-a's API certificate fingerprint, read over SSH, so the join doesn't need to trust on first use. All nodes should run the same PVE version. Source: [Cluster Manager (9.x)](https://pve.proxmox.com/pve-docs/chapter-pvecm.html); the `pvecm` commands are the same in the [8.x documentation](https://pve.proxmox.com/pve-docs-8/chapter-pvecm.html).

`status` should show `Quorate: Yes`, `Nodes: 2`, and `Expected votes: 2`.

## Step 5: test user, roles, and tokens (provisional)

> **Provisional until FM-605 ([#212](https://github.com/Frogbyte-io/fleet-manager/issues/212)) lands.** FM-605 defines least-privilege tiers (`FleetDiscover`, `FleetOperate`, `FleetDestructive`, `FleetLab`) that are generated from the FM-604 privilege table. Until then, as #211 allows, each target gets one **read-only** token and one **admin-scoped** token. Both are fixture-only and never a pattern for real accounts ([security architecture](../architecture/security.md)). Once FM-605 merges, replace this step with its `pveum` commands and add one token per tier.

```sh
deploy/pve-test/pve-test tokens pve8
deploy/pve-test/pve-test tokens node-a    # cluster-wide; node-b shares it
```

On the node, `tokens` runs the equivalent of the following:

```sh
pveum user add fleet-test@pve --comment "Fleet acceptance test user (provisional, FM-612)"
pveum acl modify / --users fleet-test@pve --roles Administrator
pveum user token add fleet-test@pve ro    --privsep 1 --output-format json
pveum acl modify / --tokens 'fleet-test@pve!ro'    --roles PVEAuditor
pveum user token add fleet-test@pve admin --privsep 1 --output-format json
pveum acl modify / --tokens 'fleet-test@pve!admin' --roles Administrator
```

- A token with privilege separation (`--privsep 1`) gets only the ACLs granted to the token itself, intersected with the user's: "permissions on API tokens are always a subset of those of their corresponding user". So the `ro` token is a genuine `PVEAuditor` ("read only access") token even though its user holds `Administrator`. That makes it the token for FM-611's privilege-failure scenario. Source: [User Management](https://pve.proxmox.com/pve-docs/chapter-pveum.html), and the [8.x edition](https://pve.proxmox.com/pve-docs-8/chapter-pveum.html).
- A token's secret is shown exactly once. The script parses the JSON response and writes the secret straight to `FLEET_PVE_TEST_SECRET_DIR/<role>-<ro|admin>.token` (the directory is mode 0700 and the file 0600). The secret never reaches the terminal. If a token exists but its secret file is missing, the script refuses to continue and tells you to remove the token so it can be recreated.
- The two majors differ in privilege names (9.x splits guest-agent privileges). That matters for FM-605's tiers, but not for the built-in `PVEAuditor` and `Administrator` roles used here.

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
| `FLEET_PVE_TARGET_<NAME>_TOKEN_ID` | `fleet-test@pve!admin` (provisional admin-scoped token) | Step 5 |
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

Both modes are deterministic and idempotent. `node-up` undoes either one: it starts the VM if it is stopped, removes any partition rules, and waits until `pvecm status` reports `Quorate: Yes`. `FLEET_PVE_TEST_DOWN_MODE` sets the default mode.

| | `--mode stop` | `--mode partition` |
|---|---|---|
| **What it does** | `qm stop` on the physical host: an immediate power-off with no guest shutdown, like pulling the plug | Dedicated iptables chains (`FLEET_TEST_IN`/`FLEET_TEST_OUT`) on the node **drop every packet to and from its peer**: corosync, the API, SSH, and migration. The node stays up and reachable from everywhere else, including the Fleet controller |
| **Cluster view from the survivor** (`/cluster/status`, `/cluster/resources`, `/nodes`) | Expected: the down node reports `online: 0` / `status: offline`, its guests `status: unknown`, and the cluster entry `quorate: 0` | Same as stop, and symmetric: the isolated node also reports its peer offline and itself inquorate |
| **Requests the survivor proxies to the down node** (`/nodes/<down>/…`) | Expected: fail fast with an HTTP 595 transport error (for example, no route to host) once ARP for the address fails | Expected: **hang until pveproxy's connect timeout**, then return 595 (connection timed out). This exercises Fleet's operation deadline |
| **Fleet talking directly to the down node** | TCP connect fails at the client (timeout or unreachable). This is a transport error, not an API response | The API answers normally, but reports its peer offline and itself inquorate: a split view |
| **Writes on the survivor** | Refused while inquorate: `/etc/pve` is read-only ("The cluster switches to read-only mode if it loses quorum"), so guest lifecycle calls are expected to fail with a "no quorum" error | Same, on both sides |

A two-node cluster has two expected votes, so losing either node leaves the survivor **inquorate**. This is how two-node clusters fail, and Proxmox recommends a QDevice to supply the third vote ([Cluster Manager](https://pve.proxmox.com/pve-docs/chapter-pvecm.html)). For a scenario that needs the survivor writable, pass `--keep-quorum`, which runs `pvecm expected 1` on the survivor. The docs reserve that command for when "you understand what you are doing", and it only suits a disposable fixture. Membership changes take a few seconds, and the status daemon refreshes every few seconds, so wait until `/cluster/status` reports the change before you assert on it.

Rows marked "expected" come from the PVE documentation and haven't been observed on this fixture yet. The first live run (FM-612 evidence, then FM-613) replaces them with what the API actually returns, including exact status codes and messages.

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
