# Least-privilege Proxmox API token

Fleet's own privilege table, `PROXMOX_PRIVILEGE_TABLE` in `crates/fleet-application/src/proxmox/privileges.rs` (FM-604), is the source of truth for what each tier needs. The [per-major tier tables](#required-privileges-per-tier) and the [role commands](#2-roles) below are checked against it by a test, so this guide and `fleetctl proxmox privileges` cannot drift apart. See [Consistency with Fleet's privilege table](#consistency-with-fleets-privilege-table).

This guide sets up a dedicated Proxmox VE (PVE) user and a privilege-separated API token for Fleet. Each Fleet capability tier gets the privileges it needs, and the few extras a role carries are labelled. Do not give Fleet `Administrator` on `/`. [Security architecture](../architecture/security.md) requires dedicated users/tokens with the minimum roles and path ACLs.

The guide covers PVE 8.x and 9.x. The two majors differ in one important way: the guest-agent privileges. [8.x vs 9.x differences](#8x-vs-9x-differences) explains it; read that section before you create roles.

## How PVE evaluates Fleet's token

From the PVE admin guide, chapter *User Management* ([9.x](https://pve.proxmox.com/pve-docs/chapter-pveum.html), [8.x](https://pve.proxmox.com/pve-docs-8/chapter-pveum.html)):

- **Roles and ACLs.** A role is a list of privileges. An ACL entry grants a role to a user, group, or token on a path, such as `/`, `/nodes/{node}`, `/vms/{vmid}`, `/storage/{storeid}`, `/pool/{poolid}`, or `/sdn/zones/{zone}/{vnet}`. Privileges can be assigned to a path only through a role.
- **Propagation.** ACLs propagate down the path tree by default. A permission on a deeper path replaces the one inherited from above. `NoAccess` cancels every other role on its path.
- **Pools.** A permission on `/pool/{poolid}` is inherited by every VM and storage that is a member of the pool. Nodes and SDN zones cannot be pool members, so they always need their own ACL entry.
- **Privilege-separated tokens.** With `privsep=1`, a token's effective permissions are the **intersection** of the user's ACLs and the token's own ACLs. A token can never exceed its user. Grant the same roles on the same paths to both `fleet@pve` and the token. Token ACLs are per token ID, so a new token starts with no permissions, even when the user has some.
- **Default.** In both majors, `pveum user token add` defaults to `privsep=1` (`generate_token` in `PVE/API2/User.pm`). This guide passes `--privsep 1` explicitly anyway.
- **Task ownership.** A token owns the tasks it starts. Reading or stopping its own task (UPID) needs no privilege. Reading another principal's task needs `Sys.Audit` on `/nodes/{node}`, and stopping one needs `Sys.Modify` there. Fleet's own tasks never need `Sys.Modify`; cancelling another principal's task is an opt-in this guide does not grant (see the [notes](#required-privileges-per-tier)).

## Tier table

Fleet's permission vocabulary (`crates/fleet-application/src/authz.rs`) and operation kinds (`crates/fleet-application/src/operation.rs`) group into four capability tiers. Each tier has one role, except Lab, which adds `FleetLabTarget` on its clone targets (and, on 8.x, `FleetAgent8`). A tier's roles hold every privilege it requires, so granting them on the recommended paths is enough for that tier.

| Tier | Fleet permission → operations | Role | Recommended ACL path |
|---|---|---|---|
| **discover** | `proxmox.read` → discovery, nodes, guests, guest observe (config MACs, agent info, network, OS), snapshot list, task status | `FleetDiscover` (8.x: plus the opt-in `FleetAgent8`) | `/nodes`, `/pool/<pool>` (storage in the pool, or `/storage/<id>`) — or `/` for whole-cluster inventory |
| **operate** | `proxmox.operate` → `proxmox.guest.start`, `.stop`, `.shutdown`, `.reboot` | `FleetOperate` | `/pool/<pool>` |
| **destructive** | `proxmox.destructive` → `proxmox.guest.snapshot`, `.snapshot-revert`, `.snapshot-delete`, `.clone`, `.template`, `.destroy`, `proxmox.task-cancel` | `FleetDestructive` | `/pool/<pool>` for existing guests and storage; clone targets also need `/vms/<newid>` (see [clone targets](#why-clone-and-lab-need-more-than-the-pool)); `/sdn/zones/<zone>/<bridge>` |
| **lab** | `lab.provision` → clone the pinned image, clear the clone's inherited protection flag, give it the template's cores, memory, and disk, start it, probe readiness | `FleetLab`, plus `FleetLabTarget` (8.x: and `FleetAgent8`) on the new guests' `/vms/<newid>` | the template's `/vms/<id>` (protected), `/storage/<id>`, the new guests' `/vms/<newid>`, `/sdn/zones/<zone>/<bridge>`; never `/pool/<pool>` |

### Required privileges per tier

The two tables below are the PVE privileges per tier, keyed by major. Each entry reads "privilege on the path PVE checks it on". `A` or `B` means either one is enough (PVE's `any => 1`); grant the first. The columns mean:

- **Required**: what `fleetctl proxmox privileges` needs before it reports the tier `granted`.
- **Opt-in**: what Fleet reports on the tier's checks without gating the tier. Without it, a sub-capability degrades honestly.
- **Also in the role**: what the role grants beyond Fleet's required rows ("`privilege`: why").

`{newid}` is a clone target that does not exist yet; a pool ACL never covers it. Rows that need no privilege (`GET /version`, and task status and cancel for the token's own tasks) are not listed. A test parses the tables between the `privilege-table` markers, so keep their format.

#### PVE 9.x

<!-- privilege-table:begin major=9 -->
| Tier | Role | Required | Opt-in | Also in the role |
|---|---|---|---|---|
| discover | `FleetDiscover` | `Sys.Audit` on `/nodes/{node}`, `VM.Audit` on `/vms/{vmid}`, `Datastore.Audit` on `/storage/{storage}`, `VM.GuestAgent.Audit` or `VM.GuestAgent.Unrestricted` on `/vms/{vmid}` | `Pool.Audit` on `/pool/{pool}` | `Pool.Audit`: the opt-in row. Fleet's discovery does not use pool rows today; drop it from the role if you prefer |
| operate | `FleetOperate` | `VM.PowerMgmt` on `/vms/{vmid}` | — | — |
| destructive | `FleetDestructive` | `VM.Audit` on `/vms/{vmid}`, `VM.PowerMgmt` on `/vms/{vmid}`, `VM.Snapshot` on `/vms/{vmid}`, `VM.Clone` on `/vms/{vmid}`, `VM.Allocate` on `/vms/{newid}`, `Datastore.AllocateSpace` on `/storage/{storage}`, `SDN.Use` on `/sdn/zones/{zone}/{bridge}`, `VM.Allocate` on `/vms/{vmid}` | `Sys.Modify` on `/nodes/{node}` | `VM.Snapshot.Rollback`: the revert row accepts either it or `VM.Snapshot`; it is kept so a rollback-only role can be split off |
| lab | `FleetLab`, `FleetLabTarget` | `VM.Audit` on `/vms/{vmid}`, `VM.Clone` on `/vms/{vmid}`, `VM.Allocate` on `/vms/{newid}`, `Datastore.AllocateSpace` on `/storage/{storage}`, `SDN.Use` on `/sdn/zones/{zone}/{bridge}`, `VM.Audit` on `/vms/{newid}`, `VM.Config.Options` on `/vms/{newid}`, `VM.Config.CPU` on `/vms/{newid}`, `VM.Config.Memory` on `/vms/{newid}`, `VM.Config.Disk` on `/vms/{newid}`, `VM.PowerMgmt` on `/vms/{newid}`, `VM.GuestAgent.Audit` or `VM.GuestAgent.Unrestricted` on `/vms/{newid}` | — | — |
<!-- privilege-table:end -->

Grant `VM.GuestAgent.Audit`, never `VM.GuestAgent.Unrestricted`: Unrestricted also permits agent `exec`.

#### PVE 8.x

<!-- privilege-table:begin major=8 -->
| Tier | Role | Required | Opt-in | Also in the role |
|---|---|---|---|---|
| discover | `FleetDiscover` | `Sys.Audit` on `/nodes/{node}`, `VM.Audit` on `/vms/{vmid}`, `Datastore.Audit` on `/storage/{storage}` | `Pool.Audit` on `/pool/{pool}`, `VM.Monitor` on `/vms/{vmid}` | `Pool.Audit`: the opt-in row, as on 9.x. The agent privilege is a separate opt-in role, not part of this one |
| operate | `FleetOperate` | `VM.PowerMgmt` on `/vms/{vmid}` | — | — |
| destructive | `FleetDestructive` | `VM.Audit` on `/vms/{vmid}`, `VM.PowerMgmt` on `/vms/{vmid}`, `VM.Snapshot` on `/vms/{vmid}`, `VM.Clone` on `/vms/{vmid}`, `VM.Allocate` on `/vms/{newid}`, `Datastore.AllocateSpace` on `/storage/{storage}`, `SDN.Use` on `/sdn/zones/{zone}/{bridge}`, `VM.Allocate` on `/vms/{vmid}` | `Sys.Modify` on `/nodes/{node}` | `VM.Snapshot.Rollback`: as on 9.x |
| lab | `FleetLab`, `FleetLabTarget`, `FleetAgent8` | `VM.Audit` on `/vms/{vmid}`, `VM.Clone` on `/vms/{vmid}`, `VM.Allocate` on `/vms/{newid}`, `Datastore.AllocateSpace` on `/storage/{storage}`, `SDN.Use` on `/sdn/zones/{zone}/{bridge}`, `VM.Audit` on `/vms/{newid}`, `VM.Config.Options` on `/vms/{newid}`, `VM.Config.CPU` on `/vms/{newid}`, `VM.Config.Memory` on `/vms/{newid}`, `VM.Config.Disk` on `/vms/{newid}`, `VM.PowerMgmt` on `/vms/{newid}`, `VM.Monitor` on `/vms/{newid}` | — | — |
<!-- privilege-table:end -->

On 8.x, `VM.Monitor` is opt-in for discover (agent facts), because it also permits agent `exec`. For lab it is **required**: the provision executor polls `agent/info` for readiness on every template today, whatever its readiness probe setting, so a token without it reaches `never_ready`. Grant `FleetAgent8` on the reserved clone-target VMIDs only ([clone targets](#why-clone-and-lab-need-more-than-the-pool)), not on the template or the pool. See [8.x vs 9.x differences](#8x-vs-9x-differences).

Notes:

- `proxmox.guest.snapshot-revert` passes if the token has **either** `VM.Snapshot` or `VM.Snapshot.Rollback` (`any => 1`). FleetDestructive already includes `VM.Snapshot`, so `VM.Snapshot.Rollback` is redundant there. It is in the role because it lets you build a rollback-only role if you ever need one.
- The destructive executors read the snapshot list and the cluster resources before they act (idempotency checks), so `FleetDestructive` carries `VM.Audit` itself.
- The Lab executor looks up the pinned image's template in `/cluster/resources`, which leaves out guests without `VM.Audit`. It uses the template VMID recorded by the image's build, and it takes the template's node from that listing. `FleetLab` therefore carries `VM.Audit` for the template's path (`lab.provision.template-lookup`).
- `proxmox.guest.template` requires `VM.Allocate` on `/vms/{vmid}`. **`VM.Allocate` also lets the token delete that VM.** It also counts as a substitute for `Permissions.Modify` on `/vms/...`, so the token can delegate subsets of its own privileges on that path. This is why the privilege is scoped to a pool and never granted on `/`.
- `proxmox.task-cancel` needs no privilege for tasks the token started. The cancel review binds the task's UPID to the reviewed guest's node and VMID, but not to the user that started it, so a reviewed UPID can name another principal's task on that guest. PVE stops such a task only with `Sys.Modify` on `/nodes/{node}`; that is the opt-in `proxmox.task-cancel.other-principal` row. This guide does not grant it: `Sys.Modify` on a node also allows changing its network, DNS, time, and services. Without it, cancelling a task Fleet did not start is refused with 403. If you need it anyway, the role blocks define `FleetCancelAnyTask`; grant it on `/nodes/<node>`.
- `proxmox.guest.destroy` stops a running QEMU guest before deleting it, so the destructive role also needs `VM.PowerMgmt` on `/vms/{vmid}`. `DELETE /nodes/{node}/qemu/{vmid}` needs `VM.Allocate` on `/vms/{vmid}` in both majors, which the destructive and lab roles already contain. Lab clones inherit the template's protection flag, which PVE checks before it deletes a guest. The Lab provision executor therefore clears the flag on each new guest right after its clone lands (`lab.provision.unprotect`, `VM.Config.Options` on `/vms/{newid}` through `FleetLabTarget`; see [step 5](#5-acls)), so cleanup can destroy it. Independently of the protection flag, Fleet's cleanup guard refuses to destroy any VMID that is a template or that matches the recorded build artifact of a promoted image version.
- Image builds (`image.build`) run Packer with the build account's token, not Fleet's tiered roles. [Image builds](#image-builds) lists what the plugin needs. `fleetctl proxmox privileges` does not evaluate it.

## Image builds

Packer's Proxmox plugin calls the PVE API itself, and Fleet's privilege table (FM-604) does not model those calls, so `fleetctl proxmox privileges` cannot check them. Use a separate account for builds. The list below follows the plugin's behavior (`proxmox-clone` and `proxmox-iso`, v1.2.x) and the privileges PVE's [API viewer](https://pve.proxmox.com/pve-docs/api-viewer/) documents for each call; it was not proven against a live host for every recipe option, and PVE 8.x and 9.x differ in the guest-agent privilege. Prove your role with a test build, because a missing privilege shows up only when the plugin reaches that call.

| Plugin step | PVE call | Privileges (on the build VMID unless noted) |
|---|---|---|
| Pick a VMID (only when the recipe has no `vm_id`) | `GET /cluster/nextid` | none |
| Look up VMs and read state | `GET /cluster/resources`, `GET …/status/current`, `GET …/config` | `VM.Audit` on the build VMID and the source template, `Datastore.Audit` on the storage the recipe names |
| Clone the source (`proxmox-clone`) | `POST /nodes/{node}/qemu/{clone_vm_id}/clone` | `VM.Clone` on the source, `VM.Allocate` on the new VMID, `Datastore.AllocateSpace` on the target storage, and `Pool.Allocate` on the pool when the recipe sets `pool` |
| Create the VM (`proxmox-iso`) | `POST /nodes/{node}/qemu` | `VM.Allocate`, `Datastore.AllocateSpace`, `SDN.Use`, and the `VM.Config.*` privileges for the fields the recipe sets (`VM.Config.Disk`, `.CPU`, `.Memory`, `.Network`, `.CDROM`, `.HWType`, `.Options`) |
| Set the configuration | `POST` or `PUT /nodes/{node}/qemu/{vmid}/config` | the `VM.Config.*` privileges above, `SDN.Use` on `/sdn/zones/{zone}/{bridge}` for the NIC's bridge, and `VM.Config.Cloudinit` when the recipe sets cloud-init fields |
| Fetch or attach an ISO | `POST /nodes/{node}/storage/{storage}/download-url` or `/upload` | `Datastore.AllocateTemplate` on the ISO storage |
| Start, stop, shut down | `POST …/status/start`, `…/stop`, `…/shutdown` | `VM.PowerMgmt` |
| Type the boot command | `POST …/sendkey`, `…/vncproxy` | `VM.Console` |
| Read the guest address | `GET …/agent/network-get-interfaces` | `VM.Monitor` on 8.x; `VM.GuestAgent.Audit` on 9.x |
| Convert to a template | `POST …/template` | `VM.Allocate` |
| Delete after a failure or cancel | `DELETE …/qemu/{vmid}` | `VM.Allocate` |

Grant them on the build VMIDs and the source template only, for example through a pool that holds the build range. `VM.Allocate` also lets the token delete the VM, so never grant it on `/`. Fleet's Lab roles do not cover these calls, and the build account should not be the Lab account.

### Set `vm_id` in every recipe

A recipe without `vm_id` lets the plugin take the next free VMID from `GET /cluster/nextid`. That is the Lab range (see [VMID ranges](lab.md#vmid-ranges)): the build can take a VMID Fleet granted to Lab guests, and the build account then needs privileges on a range it should not have. Set `vm_id` to a VMID outside the Lab range in every recipe, and grant the build account only that range.

### Several accounts for one endpoint

Fleet picks the build account from the recipe's `proxmox_url`. When more than one account matches, pass `--account` (`fleetctl images build <version-id> --account <id>`). Without it the build is refused with `target_account_ambiguous` before Packer runs.

## 8.x vs 9.x differences

**PVE 9 removed `VM.Monitor`.** The changelog entry for `libpve-access-control` 9.0.2 reads: "drop VM.Monitor in favor of more granular VM.GuestAgent.\* privileges". In its place:

| Purpose | 8.x | 9.x |
|---|---|---|
| Informational guest-agent commands (`info`, `network-get-interfaces`, `get-osinfo`, `ping`, …) | `VM.Monitor` | `VM.GuestAgent.Audit` (or `VM.GuestAgent.Unrestricted`) |
| Agent `file-read` | `VM.Monitor` | `VM.GuestAgent.FileRead` (or `…Unrestricted`) |
| Agent `file-write` | `VM.Monitor` | `VM.GuestAgent.FileWrite` (or `…Unrestricted`) |
| Agent `exec`, `exec-status`, `set-user-password` | `VM.Monitor` | `VM.GuestAgent.Unrestricted` |
| Agent `fsfreeze-*`, `fstrim` | `VM.Monitor` | `VM.GuestAgent.FileSystemMgmt` |
| QEMU HMP monitor (`POST …/monitor`) | `VM.Monitor` (+ `Sys.Modify` on `/` for non-`info` commands) | `Sys.Audit` or `Sys.Modify` on `/vms/{vmid}` |

What this means for Fleet:

1. **On 8.x, `VM.Monitor` is not a read privilege.** Fleet needs it only for the agent reads: `agent/info`, `agent/network-get-interfaces`, `agent/get-osinfo`, and the Lab `guest_agent` readiness probe. The same privilege also authorizes agent `exec`, `file-write`, and `set-user-password`, which means **arbitrary command execution as root inside every guest in scope**. For that reason this guide leaves `VM.Monitor` out of `FleetDiscover` on 8.x and puts it in a separate, opt-in `FleetAgent8` role. Without it, discovery still works: Fleet reports "the agent is unreachable" per guest, and machine association falls back to config MACs. Lab is different: the provision executor polls `agent/info` for readiness on every template today, even one whose readiness probe is `ssh_exec`, so on 8.x Lab requires `FleetAgent8` on the new guests' `/vms/<newid>` paths.
2. **Role definitions are not portable between majors.** `pveum role add` rejects unknown privilege names with "invalid privilege '…'". Creating a role with `VM.GuestAgent.Audit` fails on 8.x, and creating one with `VM.Monitor` fails on 9.x. Use the commands for your major below.
3. **Upgrading 8 → 9.** `pve8to9` fails its custom-role check while a custom role still holds `VM.Monitor`. After the upgrade, the config parser ignores unknown privileges with a warning ("user config - ignore invalid privilege 'VM.Monitor'"). After upgrading, delete `FleetAgent8` and add `VM.GuestAgent.Audit` to `FleetDiscover` (and to `FleetLab`) using the 9.x commands. Do **not** replace it with `VM.GuestAgent.Unrestricted`.
4. **Token defaults.** The 9.x guide states that privilege separation is the default and documents `--expire`. On 8.x the code defaults are the same (`privsep=1`, optional `expire`), even though the 8.x guide text does not say so.
5. Everything else Fleet uses is the same in both majors: the permission blocks for `/version`, `/cluster/resources`, node status and storage, guest config, lifecycle, snapshot, clone, template, and tasks, and the clone storage/bridge checks. See the [appendix](#appendix-endpoint--privilege-evidence).

## Setup

Run these commands as `root@pam` on one PVE node (the cluster shares the config), or as an administrator with `Permissions.Modify`. Replace `fleet` (pool), `local-lvm` (storage), and `vmbr0` (bridge) with your own names. None of the commands below prints or accepts the token secret except `token add` in [step 4](#4-token-privilege-separated).

### 1. Pool

Put the guests Fleet may operate on into a pool. Add the storage that clones write to as well, so that one pool ACL also covers `Datastore.AllocateSpace`.

```sh
pveum pool add fleet --comment "Guests managed by Fleet"
pveum pool modify fleet --vms 101,102,103 --storage local-lvm
```

In both majors, `pveum pool modify` calls `PUT /pools` with `vms` and `storage`. In the web UI, Datacenter → Pools → Members does the same.

### 2. Roles

Create the roles for your PVE major; the two blocks are not interchangeable (see [8.x vs 9.x differences](#8x-vs-9x-differences)).

#### PVE 9.x

<!-- privilege-roles:begin major=9 -->
```sh
pveum role add FleetDiscover    --privs "Sys.Audit,VM.Audit,Datastore.Audit,Pool.Audit,VM.GuestAgent.Audit"
pveum role add FleetOperate     --privs "VM.PowerMgmt"
pveum role add FleetDestructive --privs "VM.Audit,VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback,VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use"
pveum role add FleetLab         --privs "VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use,VM.PowerMgmt,VM.Audit,VM.GuestAgent.Audit"
# Only on the clone-target VMIDs, never on the template or the pool: it lets
# Lab clear the protection flag a clone copies from its template, and give the
# clone the template's cores (VM.Config.CPU), memory (VM.Config.Memory), and
# disk size (VM.Config.Disk).
pveum role add FleetLabTarget   --privs "VM.Config.Options,VM.Config.CPU,VM.Config.Memory,VM.Config.Disk"
# Opt-in only, not granted below. Sys.Modify on a node also allows changing its
# network, DNS, time, and services. It lets proxmox.task-cancel stop tasks
# Fleet did not start.
pveum role add FleetCancelAnyTask --privs "Sys.Modify"
```
<!-- privilege-roles:end -->

#### PVE 8.x

<!-- privilege-roles:begin major=8 -->
```sh
pveum role add FleetDiscover    --privs "Sys.Audit,VM.Audit,Datastore.Audit,Pool.Audit"
pveum role add FleetOperate     --privs "VM.PowerMgmt"
pveum role add FleetDestructive --privs "VM.Audit,VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback,VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use"
pveum role add FleetLab         --privs "VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use,VM.PowerMgmt,VM.Audit"
# Only on the clone-target VMIDs (see the 9.x block).
pveum role add FleetLabTarget   --privs "VM.Config.Options,VM.Config.CPU,VM.Config.Memory,VM.Config.Disk"
# VM.Monitor also permits guest-agent exec/file-write/set-user-password (root
# inside the guest). Lab readiness requires it on the clone targets; on the
# pool it is an opt-in for agent observations.
pveum role add FleetAgent8      --privs "VM.Monitor"
# Opt-in only, not granted below (see FleetCancelAnyTask in the 9.x block).
pveum role add FleetCancelAnyTask --privs "Sys.Modify"
```
<!-- privilege-roles:end -->

The role names must not start with `PVE`, because that prefix is reserved for built-in roles.

### 3. User

```sh
pveum user add fleet@pve --comment "Fleet Manager service account (API token only)"
```

The user gets no password. Fleet authenticates only with the token.

### 4. Token (privilege-separated)

```sh
# expire: Unix epoch seconds; pick your rotation interval (example: 90 days)
pveum user token add fleet@pve fleet --privsep 1 \
  --expire "$(( $(date +%s) + 90*24*3600 ))" \
  --comment "Fleet Manager"
```

PVE shows the token value **once**. Do not paste it into a shell command, a file in the repository, or a chat. Keep it at hand for [step 6](#6-register-the-token-in-fleet); grant the token its ACLs first.

Create the token **before** the ACLs: `pveum acl modify … --tokens` refuses a token that does not exist yet ("ACL update failed: no such token").

### 5. ACLs

Grant the tiers you want Fleet to use, **to both the user and the token** (see [privilege separation](#how-pve-evaluates-fleets-token)). Grant only the tiers you enable. A read-only Fleet needs only the FleetDiscover lines.

```sh
TOKEN='fleet@pve!fleet'   # the token ID (not a secret)
TEMPLATE=8000             # the VMID of the template Lab clones (if you enable lab)

for who in "--users fleet@pve" "--tokens $TOKEN"; do
  # discover: node status needs /nodes (nodes cannot be pool members)
  pveum acl modify /nodes           --roles FleetDiscover $who
  pveum acl modify /pool/fleet      --roles FleetDiscover $who
  # storage outside the pool: pveum acl modify /storage/<id> --roles FleetDiscover $who

  # operate
  pveum acl modify /pool/fleet      --roles FleetOperate $who

  # destructive (snapshot, rollback, delete snapshot, template, destroy, clone source)
  pveum acl modify /pool/fleet      --roles FleetDestructive $who
  # clone: bridges used by the source guests' netN (see below)
  pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles FleetDestructive $who

  # lab: the template it clones, the storage clones write to, the bridge, and
  # the new guests' VMIDs (see "Why clone and Lab need more than the pool").
  # Never on the pool: FleetLab holds VM.Allocate, which on an existing guest
  # also permits deleting it.
  pveum acl modify /vms/$TEMPLATE   --roles FleetLab $who
  pveum acl modify /storage/local-lvm --roles FleetLab $who
  pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles FleetLab $who
done
```

The `$who` expansion is left unquoted on purpose, so that it splits into a flag and its value. For whole-cluster read-only inventory, replace the two FleetDiscover lines with `pveum acl modify / --roles FleetDiscover $who`. On 9.x this grants informational agent reads for every VM. On 8.x, FleetDiscover contains no agent privilege.

FleetLab's `VM.Allocate` on the template's path would also let the token delete the template. Protect it; PVE then refuses to remove the VM or its disks while the flag is set ("can't remove VM … - protection mode enabled"), and cloning is unaffected:

```sh
qm set $TEMPLATE --protection 1
```

Clones inherit the flag: PVE copies `protection` into the new guest's config, and a protected guest cannot be deleted. Right after a clone lands, and before it starts the guest, the Lab provision executor clears the flag on that new guest (`PUT /nodes/{node}/qemu/{newid}/config` with `protection=0`), so Lab cleanup can destroy it later. It does this only on its own `fm-lab-<record>` guest at the reserved VMID, and never on a template. Clearing the flag needs `VM.Config.Options` on the guest. `FleetLabTarget` grants it, and you grant that role only on the clone-target VMIDs ([below](#why-clone-and-lab-need-more-than-the-pool)), never on the template's `/vms/$TEMPLATE`. The token therefore still cannot unprotect, and so cannot delete, the template.

Without `FleetLabTarget` on the clone targets, a clone of a protected template fails its provision at the `unprotect` step before it starts, and the cleanup that follows cannot delete the guest. The lease ends `cleanup_failed`. Fleet clears the flag only while provisioning, never at cleanup, so granting the role later does not help that guest: run `qm set <vmid> --protection 0` on the host, then destroy it. Clones of an unprotected template need no change.

The clone also starts with the image template's hardware, which the Lab template may override (issue #372). After the unprotect step and before the start, the executor reads the new guest's config and, only where it differs, sets the Lab template's `cores` and `memory` (`PUT /nodes/{node}/qemu/{newid}/config`, which needs `VM.Config.CPU` for cores and `VM.Config.Memory` for memory) and grows the boot disk to at least the template's `diskGib` (`PUT /nodes/{node}/qemu/{newid}/resize`, which needs `VM.Config.Disk` on the guest and `Datastore.AllocateSpace` on the disk's storage, which `FleetLab` already holds for the clone; PVE runs it as a task, which Fleet polls to its exit status, and a missing storage privilege shows up there as a failed task, not an HTTP 403). Each write is conditional on the config digest. A disk is never shrunk, and a guest with no identifiable boot disk, a memory setting with options such as a maximum, a vCPU layout (`vcpus`, else sockets times cores) that differs from the template's cores and is not a plain single-socket guest, or a `balloon` target above the template's memory, is refused rather than guessed at. `FleetLabTarget` grants all three, on the clone-target VMIDs only. **Upgrading:** a token whose `FleetLabTarget` still holds only `VM.Config.Options` keeps working for templates whose hardware already matches the image, and fails a provision at the `hardware` step (reason `hardware_failed`, naming the privilege) otherwise; add the privileges with `pveum role modify FleetLabTarget --privs "VM.Config.Options,VM.Config.CPU,VM.Config.Memory,VM.Config.Disk"`. Fleet grows the disk, not the partition or filesystem inside it: that is the image's job (for example cloud-init `growpart`).

On 8.x, if you opt into agent reads for the pool:

```sh
for who in "--users fleet@pve" "--tokens $TOKEN"; do
  pveum acl modify /pool/fleet --roles FleetAgent8 $who
done
```

### 6. Register the token in Fleet

`fleetctl proxmox create` reads the token secret from **standard input** and never takes it as an argument, so the value does not appear in the process list or in shell history. The controller stores it in Fleet's encrypted secret store. The command-line arguments carry only non-secret identifiers.

```sh
# bash/zsh: -s suppresses echo; the value never becomes part of a command line
read -rs PVE_TOKEN_SECRET
printf '%s\n' "$PVE_TOKEN_SECRET" | fleetctl proxmox create \
  --name <account-name> --host <pve-host> --token-id 'fleet@pve!fleet'
unset PVE_TOKEN_SECRET

fleetctl proxmox observe <account-id>                     # shows the certificate fingerprint
fleetctl proxmox confirm <account-id> --fingerprint <SHA256:...>   # after checking it out of band
```

`printf` is a shell builtin, so the value never appears in `ps`. If your password manager has a CLI, you can pipe its output directly into `fleetctl proxmox create` instead of using `read -s`. Until you confirm the fingerprint, Fleet sends no credentials to the host.

## Why clone and Lab need more than the pool

`POST /nodes/{node}/qemu/{vmid}/clone` checks the following in both majors:

1. `VM.Clone` on `/vms/{vmid}`, the source. A pool ACL covers this when the source is a pool member.
2. `VM.Allocate` on `/vms/{newid}`, **or** `VM.Allocate` on `/pool/{pool}` when the request passes the `pool` parameter (`require_param => 'pool'`). **Fleet's clone call does not pass `pool` today** (`guest_clone` sends `newid`, `name`, and `full`). A pool ACL therefore cannot authorize the new VM. Until Fleet passes `pool` (a follow-up for the executor owner), grant `VM.Allocate` on each VMID Fleet may allocate:

   ```sh
   for id in 9000 9001 9002; do                 # the VMIDs reserved for Fleet clones
     for who in "--users fleet@pve" "--tokens $TOKEN"; do
       pveum acl modify /vms/$id --roles FleetLab,FleetLabTarget $who
     done
   done
   ```

   `FleetLabTarget` (`VM.Config.Options`) lets Lab clear the protection flag a clone copies from a protected template ([step 5](#5-acls)). `VM.Config.CPU`, `VM.Config.Memory`, and `VM.Config.Disk` in the same role let Lab give the clone the Lab template's cores, memory, and disk size ([step 5](#5-acls)). On these VMIDs the role also permits changing the new guest's other general options, such as its name, description, and boot behavior, and its CPU, memory, and disks. Grant it here only.

   On 8.x, Lab's readiness probe also needs `VM.Monitor` on each new guest, so grant `FleetAgent8` on the same VMIDs (and only there):

   ```sh
   for id in 9000 9001 9002; do
     for who in "--users fleet@pve" "--tokens $TOKEN"; do
       pveum acl modify /vms/$id --roles FleetAgent8 $who
     done
   done
   ```

   `/vms/<id>` ACLs are accepted before the VM exists (the path pattern is `/vms/[1-9][0-9]{2,}`). Avoid `/vms` with propagation: it gives the token `VM.Allocate`, and so delete rights, on every VM in the cluster.

   **How Lab picks the clone VMID.** The Lab provision executor asks PVE for the next free VMID (`GET /cluster/nextid`). It records that VMID on the provision record before it sends the clone, and a re-run reuses the recorded VMID. PVE picks the lowest free VMID inside the `datacenter.cfg` `next-id` range (`lower` inclusive, `upper` exclusive; default 100 to 1000000). Set that range to the VMIDs you granted above, or `nextid` returns a VMID the token cannot allocate and the clone fails with 403:

   ```sh
   pvesh set /cluster/options --next-id lower=9000,upper=9003   # 9000, 9001, 9002
   ```

   The range applies to every automatic VMID choice in the cluster, including the web UI's "Create VM" default. When the range is exhausted, `nextid` fails with "unable to get any free VMID in range" and the provision fails without cloning. The clone runs on the node that holds the image template, as `/cluster/resources` reports it. The account's host is only the API endpoint.
3. `Datastore.AllocateSpace` on `/storage/{storeid}` for **every non-CD-ROM disk** of the source, full or linked clone. When `storage` is passed, the check uses that target storage instead of the source disk's storage. The same privilege is also required on the `vmstatestorage`, if the source defines one. Adding the storage to the pool covers this through the pool ACL. A physical `cdrom` passthrough drive would also need `Sys.Console` on `/`, so keep templates free of host CD-ROM passthrough.
4. `SDN.Use` on `/sdn/zones/<zone>/<bridge>` for every `netN` of the source. A plain Linux bridge is in the zone `localnetwork`. VLAN-tagged NICs are checked on `/sdn/zones/<zone>/<bridge>/<tag>`, which the bridge ACL covers through propagation.

After the clone, the Lab tier reads the new guest's config (`VM.Audit`) until the clone's lock is gone, and clears an inherited `protection` flag (`VM.Config.Options`). It then sets the template's cores and memory where they differ (`VM.Config.CPU`, `VM.Config.Memory`) and grows the boot disk where it is smaller (`VM.Config.Disk`). It then starts the new guest (`VM.PowerMgmt`) and polls `agent/info` for `guest_agent` readiness (`VM.GuestAgent.Audit` on 9.x, `VM.Monitor` on 8.x) on the new VMID. It polls for every template, whatever its readiness probe setting. That is why `FleetLab`, `FleetLabTarget`, and on 8.x `FleetAgent8` are granted on the clone-target paths.

## Verify

### PVE side

Show the token's effective permissions, which are the intersection of the user's and the token's ACLs:

```sh
pveum user token permissions fleet@pve fleet
pveum user token permissions fleet@pve fleet --path /pool/fleet
```

### Verify with `fleetctl proxmox privileges`

After you register and confirm the account, ask Fleet which tiers the token can perform:

```sh
fleetctl proxmox privileges <account-id>                 # text (the default)
fleetctl proxmox privileges <account-id> --output json   # the controller's report
```

The command calls `GET /api/v1/proxmox/accounts/{accountId}/privileges`. It needs only `proxmox.read` in Fleet, changes nothing on either side, and writes no audit event. The controller reads `GET /access/permissions` with the token itself, which any token may do without extra privileges. It then evaluates each tier against Fleet's privilege table for the PVE major it reads from `/version` (`rulesMajor`). A major newer than 9 is evaluated with the 9.x rules and a warning, and a major older than 8 with the 8.x rules and a warning. Each tier is one of:

- `granted`: every required check holds somewhere in its scope.
- `missing`: the tier lists what to grant, merged per path (`missing[]` with `privileges`, `anyOf`, `path`, and `capabilities`).
- `unknown`: the permissions read itself was refused (403), or the version has no major number. `unknownReason` says which. Fleet never reports `missing` when it could not read.

The command fails instead of reporting tiers when the controller cannot ask at all: `404` for an unknown account; `409` when the account's trust is unconfirmed (`proxmox_unconfirmed`), its certificate no longer matches the pin (`proxmox_fingerprint_mismatch`), or its token secret is unavailable (`proxmox_no_secret`); `502` when the PVE API fails or refuses the token; `500` when the controller's own storage or secret store fails; and `503` when the controller runs without the Proxmox surface wired.

Opt-in checks (`required: false`) never gate a tier. The text output lists them as `opt-in … not granted`.

**The full setup on 9.x** (every role from [step 5](#5-acls), plus FleetLab and FleetLabTarget on a free reserved clone VMID). Cancelling other principals' tasks stays an opt-in that is not granted:

```text
account <account-id>  PVE 9.0.10  rules 9.x
TIER         STATUS
discover     granted
operate      granted
destructive  granted
  opt-in proxmox.task-cancel not granted: Sys.Modify on /nodes/{node}
lab          granted
```

**The same setup on 8.x, with `FleetAgent8` on the clone targets but not on the pool.** Every tier is granted. The `VM.Monitor` grant on the clone-target VMIDs also satisfies the opt-in agent-read check, because Fleet counts a grant on any guest in scope, so no `read.guest-agent` line appears:

```text
account <account-id>  PVE 8.4.1  rules 8.x
TIER         STATUS
discover     granted
operate      granted
destructive  granted
  opt-in proxmox.task-cancel not granted: Sys.Modify on /nodes/{node}
lab          granted
```

Without `FleetAgent8` on the clone targets, 8.x lab is `missing VM.Monitor on /vms/{newid}`.

**A privilege-separated token whose own ACLs were never granted.** This is the most common mistake: the user has the roles, but the token does not. PVE answers `{}`, and every tier is missing. Excerpt:

```text
account <account-id>  PVE 9.0.10  rules 9.x
TIER         STATUS
discover     missing
  missing VM.Audit on /vms/{vmid}  (needed by read.cluster-resources, read.guest-config)
  missing Datastore.Audit on /storage/{storage}  (needed by read.cluster-resources)
  missing Sys.Audit on /nodes/{node}  (needed by read.node-status)
  missing Datastore.Audit or Datastore.AllocateSpace on /storage/{storage}  (needed by read.node-storage)
  missing VM.GuestAgent.Audit or VM.GuestAgent.Unrestricted on /vms/{vmid}  (needed by read.guest-agent)
  opt-in read.cluster-resources not granted: Pool.Audit on /pool/{pool}
operate      missing
  missing VM.PowerMgmt on /vms/{vmid}  (needed by proxmox.guest.start, proxmox.guest.stop, proxmox.guest.shutdown, proxmox.guest.reboot)
destructive  missing
  …
lab          missing
  missing VM.Audit on /vms/{vmid}  (needed by lab.provision)
  missing VM.Clone on /vms/{vmid}  (needed by lab.provision)
  missing VM.Allocate on /vms/{newid}  (needed by lab.provision)
  …
```

If an otherwise granted setup shows `missing … on /vms/{newid}`, the clone-target ACL is absent. A pool ACL cannot cover it; see [clone targets](#why-clone-and-lab-need-more-than-the-pool).

**JSON shape.** `--output json` prints the report object; the API wraps the same object in `data`. This example is trimmed to the 8.x discover tier, with one required check and one opt-in check:

```json
{
  "accountId": "<account-id>",
  "pveVersion": "8.4.1",
  "rulesMajor": 8,
  "tiers": [
    {
      "tier": "discover",
      "status": "granted",
      "missing": [],
      "checks": [
        {
          "requirement": "read.node-status",
          "capability": "read.node-status",
          "endpoint": "GET /nodes/{node}/status",
          "required": true,
          "status": "granted",
          "privileges": ["Sys.Audit"],
          "anyOf": false,
          "path": "/nodes/{node}",
          "grantedOn": ["/nodes"],
          "missing": [],
          "note": "Node capacity; without it /cluster/resources also strips node statistics."
        },
        {
          "requirement": "read.guest-agent",
          "capability": "read.guest-agent",
          "endpoint": "GET /nodes/{node}/qemu/{vmid}/agent/{info|network-get-interfaces|get-osinfo}",
          "required": false,
          "status": "missing",
          "privileges": ["VM.Monitor"],
          "anyOf": false,
          "path": "/vms/{vmid}",
          "grantedOn": [],
          "missing": ["VM.Monitor"],
          "note": "Opt-in on 8.x: VM.Monitor also permits agent exec and file-write (root inside the guest); without it agent facts are unavailable."
        }
      ]
    }
  ],
  "unknownReason": null,
  "effectivePermissions": { "/nodes": { "Sys.Audit": true, "VM.Audit": true } },
  "warnings": [],
  "observedAt": 1790000000000
}
```

`grantedOn` names up to 16 effective-permission paths a check held on. `effectivePermissions` is the token's map as PVE reported it: path → privilege → propagate flag. A tier granted "somewhere in scope" can still be refused for one guest that has an explicit `NoAccess`, because PVE omits such paths from the map. `grantedOn` shows the scope Fleet saw.

The manual walkthrough of this guide on the FM-612 test host, with this command's output for each token, is recorded on [#212](https://github.com/Frogbyte-io/fleet-manager/issues/212).

## Rotate the token

Every value stays off command lines and out of shell history.

1. **Create a new token** with a new ID, for example `fleet-2026q4`, as in [step 4](#4-token-privilege-separated). Re-grant the token ACLs from [step 5](#5-acls) with `TOKEN='fleet@pve!fleet-2026q4'`. Token ACLs belong to the token ID, so the new token starts with none. The user's ACLs stay in place.
2. **Register it** with `read -rs` and `fleetctl proxmox create`, then `observe` and `confirm` it, as in [step 6](#6-register-the-token-in-fleet).
3. **Move references to the new account.** Fleet has no in-place secret replacement for a Proxmox account today: no `fleetctl proxmox` verb replaces an account's secret, so rotation is create, re-link, delete. Machine guest links (`machines link-guest … --account`) and Lab provisioning (`lab provision-lease … --account`) name the account ID, so re-link them to the new account.
4. **Retire the old one.** `fleetctl proxmox delete <old-account-id>` removes the account and its stored secret. Then revoke the old token on PVE with `pveum user token remove fleet@pve fleet`. Run `pveum acl list` and confirm that no entry still names the old token ID.

If a token may have leaked, revoke it on PVE first (`pveum user token remove …`). Revoking takes effect immediately and does not disable `fleet@pve` or other tokens.

## Consistency with Fleet's privilege table

`PROXMOX_PRIVILEGE_TABLE` (FM-604) is the single Fleet-owned map from each Proxmox executor kind or read to its required privileges and ACL path, keyed by PVE major. `fleetctl proxmox privileges` evaluates it, and this guide restates it for operators. A test keeps the two in step: `crates/fleet-application/tests/proxmox_token_guide.rs` runs with `cargo test` (and so with `cargo xtask verify`). It fails when:

- a tier's **Required** or **Opt-in** cell in the [per-major tables](#required-privileges-per-tier) differs from the table's rows for that tier and major (the failure prints the expected cell);
- a [role command](#2-roles) lacks a required privilege of its tier, or grants something not named in **Also in the role**;
- a role names a privilege the table does not know for that major, for example `VM.Monitor` in a 9.x role;
- a role that belongs to no tier (`FleetCancelAnyTask`) grants anything but opt-in privileges;
- a `pveum acl modify /pool/…` line grants a Lab role that holds `VM.Allocate`.

When the privilege table changes, paste the cells the test prints, then update the role commands. The [appendix](#appendix-endpoint--privilege-evidence) is the upstream evidence the table was built from.

## Appendix: endpoint → privilege evidence

These are all the PVE endpoints `crates/providers/fleet-provider-proxmox/src/lib.rs` calls, as of FM-604. The *requirement* column quotes the `permissions` block from the method's schema. The API viewer ([9.x](https://pve.proxmox.com/pve-docs/api-viewer/), [8.x](https://pve.proxmox.com/pve-docs-8/api-viewer/)) is generated from those same schemas. Where the method checks more in its code, the column lists those checks too. **Unless marked, 8.x and 9.x are identical.**

| # | Method and path | Fleet caller | Requirement | Source |
|---|---|---|---|---|
| 1 | `GET /version` | discover | none (`user => 'all'`) | pve-manager `PVE/API2.pm` |
| 2 | `GET /cluster/resources` | discover, lab (template lookup), destructive (idempotency) | `user => 'all'`, **filtered**: a VM appears only with `VM.Audit` on `/vms/{vmid}`, a storage only with `Datastore.Audit` on `/storage/{id}`, a pool only with `Pool.Audit` on `/pool/{id}`. Node rows always appear, but their stats are stripped without `Sys.Audit` on `/nodes/{node}` | pve-manager `PVE/API2/Cluster.pm` (`resources`) |
| 3 | `GET /nodes/{node}/status` | discover (capacity) | `perm /nodes/{node} [Sys.Audit]` | pve-manager `PVE/API2/Nodes.pm` (`status`) |
| 4 | `GET /nodes/{node}/storage` | discover (capacity) | `user => 'all'`, lists only storages with `Datastore.Audit` or `Datastore.AllocateSpace` on `/storage/{storage}` | pve-storage `PVE/API2/Storage/Status.pm` (`index`) |
| 5 | `GET /nodes/{node}/qemu/{vmid}/config` | discover, destructive (`destroy`), lab (the new guest, after its clone) | `perm /vms/{vmid} [VM.Audit]` | qemu-server `PVE/API2/Qemu.pm` (`vm_config`) |
| 6 | `GET /nodes/{node}/lxc/{vmid}/config` | discover | `perm /vms/{vmid} [VM.Audit]` | pve-container `PVE/API2/LXC/Config.pm` (`vm_config`) |
| 7 | `GET /nodes/{node}/qemu/{vmid}/agent/info` | discover, lab readiness | **9.x:** `perm /vms/{vmid} [VM.GuestAgent.Audit, VM.GuestAgent.Unrestricted] any`; **8.x:** `perm /vms/{vmid} [VM.Monitor]` | qemu-server `PVE/API2/Qemu/Agent.pm` (`register_command`) |
| 8 | `GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces` | discover | same as #7 | same |
| 9 | `GET /nodes/{node}/qemu/{vmid}/agent/get-osinfo` | discover | same as #7 | same |
| 10 | `GET /nodes/{node}/qemu/{vmid}/snapshot` | destructive (idempotency) | `perm /vms/{vmid} [VM.Audit]` | qemu-server `Qemu.pm` (`snapshot_list`) |
| 11 | `POST /nodes/{node}/qemu/{vmid}/status/start` | operate, lab | `perm /vms/{vmid} [VM.PowerMgmt]` | qemu-server `Qemu.pm` (`vm_start`) |
| 12 | `POST …/status/stop` | operate, destructive (before destroy) | `perm /vms/{vmid} [VM.PowerMgmt]` | `vm_stop` |
| 13 | `POST …/status/shutdown` | operate | `perm /vms/{vmid} [VM.PowerMgmt]` | `vm_shutdown` |
| 14 | `POST …/status/reboot` | operate | `perm /vms/{vmid} [VM.PowerMgmt]` | `vm_reboot` |
| 15 | `POST /nodes/{node}/qemu/{vmid}/snapshot` | destructive | `perm /vms/{vmid} [VM.Snapshot]` (also with `vmstate=1`) | `snapshot` |
| 16 | `POST …/snapshot/{snapname}/rollback` | destructive | `perm /vms/{vmid} [VM.Snapshot, VM.Snapshot.Rollback] any` | `rollback` |
| 17 | `DELETE …/snapshot/{snapname}` | destructive | `perm /vms/{vmid} [VM.Snapshot]` | `delsnapshot` |
| 18 | `POST /nodes/{node}/qemu/{vmid}/clone` | destructive, lab | `and(perm /vms/{vmid} [VM.Clone], or(perm /vms/{newid} [VM.Allocate], perm /pool/{pool} [VM.Allocate] require_param pool))`. In code: `Datastore.AllocateSpace` on `/storage/{sid}` for every non-CD-ROM disk (the `storage` target if given) and on `vmstatestorage`; `Sys.Console` on `/` for a physical `cdrom`; `SDN.Use` on `/sdn/zones/{zone}/{bridge}` (`…/{tag}` per VLAN/trunk tag) for each `netN` | `clone_vm`, `$check_storage_access_clone`; `PVE::QemuServer::check_bridge_access` → pve-guest-common `PVE::GuestHelpers::check_vnet_access` |
| 19 | `POST /nodes/{node}/qemu/{vmid}/template` | destructive | `perm /vms/{vmid} [VM.Allocate]` | `template` |
| 20 | `GET /nodes/{node}/tasks/{upid}/status` | all executors | `user => 'all'`; `Sys.Audit` on `/nodes/{node}` only for a task the caller does not own (a token owns its own tasks) | pve-manager `PVE/API2/Tasks.pm` (`read_task_status`, `$check_task_user`) |
| 21 | `DELETE /nodes/{node}/tasks/{upid}` | destructive (`task-cancel`) | `user => 'all'`; `Sys.Modify` on `/nodes/{node}` only for a task the caller does not own | `Tasks.pm` (`stop_task`) |
| 22 | `GET /access/permissions` | privilege diagnostics (`fleetctl proxmox privileges`) | `user => 'all'`: every user or token may read its own permissions; reading another's needs `Sys.Audit` on `/access` | pve-access-control `PVE/API2/AccessControl.pm` (`permissions`) |
| — | `DELETE /nodes/{node}/qemu/{vmid}` | destructive (QEMU destroy) | `perm /vms/{vmid} [VM.Allocate]` | `destroy_vm` |
| — | `PUT /nodes/{node}/qemu/{vmid}/config` with `protection=0` | lab (the new guest, issue #290) | `perm /vms/{vmid} [VM.Config.Disk, VM.Config.CDROM, VM.Config.CPU, VM.Config.Memory, VM.Config.Network, VM.Config.HWType, VM.Config.Options, VM.Config.Cloudinit] any`; in code, `$check_vm_modify_config_perm` checks `VM.Config.Options` for `protection`, a general option. It refuses a locked guest (`check_lock`) and, with `digest`, a changed config | `update_vm`, `$update_vm_api` |
| — | `PUT /nodes/{node}/qemu/{vmid}/config` with `cores` and/or `memory` | lab (the new guest, issue #372) | the same `$check_vm_modify_config_perm`: `cores` needs `VM.Config.CPU` and `memory` needs `VM.Config.Memory`, both on `/vms/{vmid}`; it refuses a locked guest and, with `digest`, a changed config | `update_vm`, `$update_vm_api` |
| — | `PUT /nodes/{node}/qemu/{vmid}/resize` with `disk`, `size`, and `digest` | lab (the new guest, issue #372) | `perm /vms/{vmid} [VM.Config.Disk]` before the task starts (an HTTP 403), and `Datastore.AllocateSpace` on `/storage/{storeid}` of the disk's volume, which `resize_vm` checks inside the forked worker. The call answers a task id (UPID): a missing storage privilege (`Permission check failed (/storage/…, Datastore.AllocateSpace)`), a changed `digest`, a locked config, a shrink, and a missing disk are the task's exit status. Fleet polls the task and then reads the config again | `resize_vm` |

### Sources and versions read

pve.proxmox.com was not reachable from the environment this guide was written in. All requirements above were read on 2026-09-30 from Proxmox's official source mirrors on GitHub. These are the same schemas the API viewer renders. The versions are the head of each branch at that time:

| Component | 9.x (branch → version) | 8.x (branch → version) |
|---|---|---|
| qemu-server | [`master`](https://github.com/proxmox/qemu-server/tree/master) → 9.2.10 | [`stable-bookworm`](https://github.com/proxmox/qemu-server/tree/stable-bookworm) → 8.4.10 |
| pve-manager | [`master`](https://github.com/proxmox/pve-manager/tree/master) → 9.2.21 | [`stable-8`](https://github.com/proxmox/pve-manager/tree/stable-8) → 8.4.22 |
| pve-storage | [`master`](https://github.com/proxmox/pve-storage/tree/master) → 9.1.11 | [`stable-8`](https://github.com/proxmox/pve-storage/tree/stable-8) → 8.3.9 |
| pve-container | [`master`](https://github.com/proxmox/pve-container/tree/master) → 6.1.14 | [`stable-bookworm`](https://github.com/proxmox/pve-container/tree/stable-bookworm) → 5.3.6 |
| pve-access-control (privileges, roles, ACL, tokens, `pveum`) | [`master`](https://github.com/proxmox/pve-access-control/tree/master) → 9.1.2 | [`stable-bookworm`](https://github.com/proxmox/pve-access-control/tree/stable-bookworm) → 8.2.3 |
| pve-docs (`pveum.adoc`, User Management) | [`master`](https://github.com/proxmox/pve-docs/tree/master) → 9.2.13 | [`stable-bookworm`](https://github.com/proxmox/pve-docs/tree/stable-bookworm) → 8.4.2 |
| pve-guest-common (`check_vnet_access`) | [`master`](https://github.com/proxmox/pve-guest-common/tree/master) → 6.0.5 | not located; the 8.x `clone_vm` permission description names the same `SDN.Use` requirement |

Other evidence used: the `VM.Monitor` removal in the `libpve-access-control` 9.0.2 changelog, and the custom-role check in pve-manager `PVE/CLI/pve8to9.pm`.
