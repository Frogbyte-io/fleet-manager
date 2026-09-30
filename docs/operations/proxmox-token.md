# Least-privilege Proxmox API token

Status: draft (FM-605). The privilege evidence below is researched from upstream source. Two parts wait for FM-604 (#206): the `fleetctl proxmox privileges` check and the doc/table consistency check. Both are marked **Pending FM-604** where they appear.

This guide sets up a dedicated Proxmox VE (PVE) user and a privilege-separated API token for Fleet. Each Fleet capability tier gets exactly the privileges it needs. Do not give Fleet `Administrator` on `/`. [Security architecture](../architecture/security.md) requires dedicated users/tokens with the minimum roles and path ACLs.

The guide covers PVE 8.x and 9.x. The two majors differ in one important way: the guest-agent privileges. [8.x vs 9.x differences](#8x-vs-9x-differences) explains it; read that section before you create roles.

## How PVE evaluates Fleet's token

From the PVE admin guide, chapter *User Management* ([9.x](https://pve.proxmox.com/pve-docs/chapter-pveum.html), [8.x](https://pve.proxmox.com/pve-docs-8/chapter-pveum.html)):

- **Roles and ACLs.** A role is a list of privileges. An ACL entry grants a role to a user, group, or token on a path, such as `/`, `/nodes/{node}`, `/vms/{vmid}`, `/storage/{storeid}`, `/pool/{poolid}`, or `/sdn/zones/{zone}/{vnet}`. Privileges can be assigned to a path only through a role.
- **Propagation.** ACLs propagate down the path tree by default. A permission on a deeper path replaces the one inherited from above. `NoAccess` cancels every other role on its path.
- **Pools.** A permission on `/pool/{poolid}` is inherited by every VM and storage that is a member of the pool. Nodes and SDN zones cannot be pool members, so they always need their own ACL entry.
- **Privilege-separated tokens.** With `privsep=1`, a token's effective permissions are the **intersection** of the user's ACLs and the token's own ACLs. A token can never exceed its user. Grant the same roles on the same paths to both `fleet@pve` and the token. Token ACLs are per token ID, so a new token starts with no permissions, even when the user has some.
- **Default.** In both majors, `pveum user token add` defaults to `privsep=1` (`generate_token` in `PVE/API2/User.pm`). This guide passes `--privsep 1` explicitly anyway.
- **Task ownership.** A token owns the tasks it starts. Reading or stopping its own task (UPID) needs no privilege. Reading another principal's task needs `Sys.Audit` on `/nodes/{node}`, and stopping one needs `Sys.Modify` there. Fleet does not need `Sys.Modify`; do not grant it.

## Tier table

Fleet's permission vocabulary (`crates/fleet-application/src/authz.rs`) and operation kinds (`crates/fleet-application/src/operation.rs`) group into four capability tiers. Every tier assumes **FleetDiscover is granted on the same paths**: each executor reads the cluster resources, the guest config, and the snapshot list before it acts.

| Tier | Fleet permission → operations | PVE privileges (9.x) | PVE privileges (8.x) | Recommended ACL path |
|---|---|---|---|---|
| **discover** | `proxmox.read` → discovery, nodes, guests, guest observe (config MACs, agent info, network, OS), snapshot list, task status | `Sys.Audit`, `VM.Audit`, `Datastore.Audit`, `Pool.Audit`, `VM.GuestAgent.Audit` | `Sys.Audit`, `VM.Audit`, `Datastore.Audit`, `Pool.Audit`; agent reads need `VM.Monitor` (opt-in, see [warning](#8x-vs-9x-differences)) | `/nodes`, `/storage` (or storage in the pool), `/pool/<pool>` — or `/` for whole-cluster inventory |
| **operate** | `proxmox.operate` → `proxmox.guest.start`, `.stop`, `.shutdown`, `.reboot` | `VM.PowerMgmt` | `VM.PowerMgmt` | `/pool/<pool>` |
| **destructive** | `proxmox.destructive` → `proxmox.guest.snapshot`, `.snapshot-revert`, `.snapshot-delete`, `.clone`, `.template`, `proxmox.task-cancel` | `VM.Snapshot`, `VM.Snapshot.Rollback`, `VM.Clone`, `VM.Allocate`, `Datastore.AllocateSpace`, `SDN.Use` | same as 9.x | `/pool/<pool>` for existing guests; clone targets also need `/vms/<newid>` (see [clone targets](#why-clone-and-lab-need-more-than-the-pool)); `SDN.Use` on `/sdn/zones/<zone>/<bridge>` |
| **lab** | `lab.provision` → clone the pinned image, start it, probe readiness | `VM.Clone`, `VM.Allocate`, `Datastore.AllocateSpace`, `SDN.Use`, `VM.PowerMgmt`, `VM.Audit`, `VM.GuestAgent.Audit` | `VM.Clone`, `VM.Allocate`, `Datastore.AllocateSpace`, `SDN.Use`, `VM.PowerMgmt`, `VM.Audit`; the `guest_agent` readiness probe needs `VM.Monitor` | source template in `/pool/<pool>`; new guests on `/vms/<newid>` (or `/vms` today); storage and bridge as above |

Notes:

- `proxmox.guest.snapshot-revert` passes if the token has **either** `VM.Snapshot` or `VM.Snapshot.Rollback` (`any => 1`). FleetDestructive already includes `VM.Snapshot`, so `VM.Snapshot.Rollback` is redundant there. It is listed because it lets you build a rollback-only role if you ever need one.
- `proxmox.guest.template` requires `VM.Allocate` on `/vms/{vmid}`. **`VM.Allocate` also lets the token delete that VM.** It also counts as a substitute for `Permissions.Modify` on `/vms/...`, so the token can delegate subsets of its own privileges on that path. This is why the privilege is scoped to a pool and never granted on `/`.
- `proxmox.task-cancel` needs no privilege for tasks the token started, and `Sys.Modify` on `/nodes/{node}` for any other task. Fleet can therefore cancel only its own tasks, and that is intended.
- Fleet does not delete VMs today. `DELETE /nodes/{node}/qemu/{vmid}` would need `VM.Allocate` on `/vms/{vmid}` in both majors, which the destructive and lab roles already contain. When Lab `destroy` cleanup lands, it will need no new privilege, only the path.
- Image builds (`image.build`) run Packer, which uses its own credentials. This guide does not cover Packer's token.

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

1. **On 8.x, `VM.Monitor` is not a read privilege.** Fleet needs it only for the agent reads: `agent/info`, `agent/network-get-interfaces`, `agent/get-osinfo`, and the Lab `guest_agent` readiness probe. The same privilege also authorizes agent `exec`, `file-write`, and `set-user-password`, which means **arbitrary command execution as root inside every guest in scope**. For that reason this guide leaves `VM.Monitor` out of `FleetDiscover` on 8.x and puts it in a separate, opt-in `FleetAgent8` role. Without it, discovery still works: Fleet reports "the agent is unreachable" per guest, and machine association falls back to config MACs. Lab templates that use the `guest_agent` readiness probe need `FleetAgent8` on the new guests' path. Otherwise, choose `ssh_exec` readiness.
2. **Role definitions are not portable between majors.** `pveum role add` rejects unknown privilege names with "invalid privilege '…'". Creating a role with `VM.GuestAgent.Audit` fails on 8.x, and creating one with `VM.Monitor` fails on 9.x. Use the commands for your major below.
3. **Upgrading 8 → 9.** `pve8to9` fails its custom-role check while a custom role still holds `VM.Monitor`. After the upgrade, the config parser ignores unknown privileges with a warning ("user config - ignore invalid privilege 'VM.Monitor'"). After upgrading, delete `FleetAgent8` and add `VM.GuestAgent.Audit` to `FleetDiscover` (and to `FleetLab`) using the 9.x commands. Do **not** replace it with `VM.GuestAgent.Unrestricted`.
4. **Token defaults.** The 9.x guide states that privilege separation is the default and documents `--expire`. On 8.x the code defaults are the same (`privsep=1`, optional `expire`), even though the 8.x guide text does not say so.
5. Everything else Fleet uses is the same in both majors: the permission blocks for `/version`, `/cluster/resources`, node status and storage, guest config, lifecycle, snapshot, clone, template, and tasks, and the clone storage/bridge checks. See the [appendix](#appendix-endpoint--privilege-evidence).

## Setup

Run these commands as `root@pam` on one PVE node (the cluster shares the config), or as an administrator with `Permissions.Modify`. Replace `fleet` (pool), `local-lvm` (storage), and `vmbr0` (bridge) with your own names. None of the commands below prints or accepts the token secret except `token add` in [step 5](#5-token-privilege-separated).

### 1. Pool

Put the guests Fleet may operate on into a pool. Add the storage that clones write to as well, so that one pool ACL also covers `Datastore.AllocateSpace`.

```sh
pveum pool add fleet --comment "Guests managed by Fleet"
pveum pool modify fleet --vms 101,102,103 --storage local-lvm
```

In both majors, `pveum pool modify` calls `PUT /pools` with `vms` and `storage`. In the web UI, Datacenter → Pools → Members does the same.

### 2. Roles — PVE 9.x

```sh
pveum role add FleetDiscover    --privs "Sys.Audit,VM.Audit,Datastore.Audit,Pool.Audit,VM.GuestAgent.Audit"
pveum role add FleetOperate     --privs "VM.PowerMgmt"
pveum role add FleetDestructive --privs "VM.Snapshot,VM.Snapshot.Rollback,VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use"
pveum role add FleetLab         --privs "VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use,VM.PowerMgmt,VM.Audit,VM.GuestAgent.Audit"
```

### 2. Roles — PVE 8.x

```sh
pveum role add FleetDiscover    --privs "Sys.Audit,VM.Audit,Datastore.Audit,Pool.Audit"
pveum role add FleetOperate     --privs "VM.PowerMgmt"
pveum role add FleetDestructive --privs "VM.Snapshot,VM.Snapshot.Rollback,VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use"
pveum role add FleetLab         --privs "VM.Clone,VM.Allocate,Datastore.AllocateSpace,SDN.Use,VM.PowerMgmt,VM.Audit"
# Opt-in only. VM.Monitor also permits guest-agent exec/file-write/set-user-password
# (root inside the guest). Grant it only where agent observations or the
# guest_agent readiness probe are worth that authority.
pveum role add FleetAgent8      --privs "VM.Monitor"
```

The role names must not start with `PVE`, because that prefix is reserved for built-in roles.

### 3. User

```sh
pveum user add fleet@pve --comment "Fleet Manager service account (API token only)"
```

The user gets no password. Fleet authenticates only with the token.

### 4. ACLs

Grant the tiers you want Fleet to use, **to both the user and the token** (see [privilege separation](#how-pve-evaluates-fleets-token)). Grant only the tiers you enable. A read-only Fleet needs only the FleetDiscover lines.

```sh
TOKEN='fleet@pve!fleet'   # the token ID (not a secret)

for who in "--users fleet@pve" "--tokens $TOKEN"; do
  # discover: node status needs /nodes (nodes cannot be pool members)
  pveum acl modify /nodes           --roles FleetDiscover $who
  pveum acl modify /pool/fleet      --roles FleetDiscover $who
  # storage outside the pool: pveum acl modify /storage/<id> --roles FleetDiscover $who

  # operate
  pveum acl modify /pool/fleet      --roles FleetOperate $who

  # destructive (snapshot, rollback, delete snapshot, template, clone source)
  pveum acl modify /pool/fleet      --roles FleetDestructive $who
  # clone: bridges used by the source guests' netN (see below)
  pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles FleetDestructive $who

  # lab: clone source template and storage in the pool, the bridge, and the
  # new guests' VMIDs (see "Why clone and Lab need more than the pool")
  pveum acl modify /pool/fleet      --roles FleetLab $who
  pveum acl modify /sdn/zones/localnetwork/vmbr0 --roles FleetLab $who
done
```

The `$who` expansion is left unquoted on purpose, so that it splits into a flag and its value. For whole-cluster read-only inventory, replace the two FleetDiscover lines with `pveum acl modify / --roles FleetDiscover $who`. On 9.x this grants informational agent reads for every VM. On 8.x, FleetDiscover contains no agent privilege.

On 8.x, if you opt into agent reads for the pool:

```sh
for who in "--users fleet@pve" "--tokens $TOKEN"; do
  pveum acl modify /pool/fleet --roles FleetAgent8 $who
done
```

### 5. Token (privilege-separated)

```sh
# expire: Unix epoch seconds; pick your rotation interval (example: 90 days)
pveum user token add fleet@pve fleet --privsep 1 \
  --expire "$(( $(date +%s) + 90*24*3600 ))" \
  --comment "Fleet Manager"
```

PVE shows the token value **once**. Do not paste it into a shell command, a file in the repository, or a chat. Register it in Fleet straight away, as described in the next section.

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
       pveum acl modify /vms/$id --roles FleetLab $who
     done
   done
   ```

   `/vms/<id>` ACLs are accepted before the VM exists (the path pattern is `/vms/[1-9][0-9]{2,}`). Avoid `/vms` with propagation: it gives the token `VM.Allocate`, and so delete rights, on every VM in the cluster.
3. `Datastore.AllocateSpace` on `/storage/{storeid}` for **every non-CD-ROM disk** of the source, full or linked clone. When `storage` is passed, the check uses that target storage instead of the source disk's storage. The same privilege is also required on the `vmstatestorage`, if the source defines one. Adding the storage to the pool covers this through the pool ACL. A physical `cdrom` passthrough drive would also need `Sys.Console` on `/`, so keep templates free of host CD-ROM passthrough.
4. `SDN.Use` on `/sdn/zones/<zone>/<bridge>` for every `netN` of the source. A plain Linux bridge is in the zone `localnetwork`. VLAN-tagged NICs are checked on `/sdn/zones/<zone>/<bridge>/<tag>`, which the bridge ACL covers through propagation.

The Lab tier then starts the new guest (`VM.PowerMgmt`) and polls `agent/info` for `guest_agent` readiness (`VM.GuestAgent.Audit` on 9.x, `VM.Monitor` on 8.x) on the new VMID. That is why `FleetLab` carries those privileges and is granted on the clone-target paths, not only on the pool.

## Verify

**Now (PVE side).** Show the token's effective permissions, which are the intersection of the user's and the token's ACLs:

```sh
pveum user token permissions fleet@pve fleet
pveum user token permissions fleet@pve fleet --path /pool/fleet
```

**Pending FM-604 (#206): Fleet side.** `fleetctl proxmox privileges <account-id> --output json` will report, for each tier, one of `granted`, `missing` (with the missing privilege and path), or `unknown` (when the permissions read itself is refused). It reads `GET /access/permissions`, which any token may call for itself without extra privileges. This section will show the expected output for each role combination once FM-604 lands. The manual walkthrough on the FM-612 test host will be recorded on #212.

## Rotate the token

Every value stays off command lines and out of shell history.

1. **Create a new token** with a new ID, for example `fleet-2026q4`, as in [step 5](#5-token-privilege-separated). Re-grant the token ACLs from [step 4](#4-acls) with `TOKEN='fleet@pve!fleet-2026q4'`. Token ACLs belong to the token ID, so the new token starts with none. The user's ACLs stay in place.
2. **Register it** with `read -rs` and `fleetctl proxmox create`, then `observe` and `confirm` it, as in [step 6](#6-register-the-token-in-fleet).
3. **Move references to the new account.** Fleet has no in-place secret replacement for a Proxmox account today: `fleetctl proxmox` offers `create` and `delete` only. Machine guest links (`machines link-guest … --account`) and Lab provisioning (`lab provision-lease … --account`) name the account ID, so re-link them to the new account.
4. **Retire the old one.** `fleetctl proxmox delete <old-account-id>` removes the account and its stored secret. Then revoke the old token on PVE with `pveum user token remove fleet@pve fleet`. Run `pveum acl list` and confirm that no entry still names the old token ID.

If a token may have leaked, revoke it on PVE first (`pveum user token remove …`). Revoking takes effect immediately and does not disable `fleet@pve` or other tokens.

## Consistency with Fleet's privilege table

**Pending FM-604 (#206).** FM-604 introduces the single Fleet-owned table that maps each Proxmox executor kind or read to its required privileges and path scope, keyed by PVE major. Once it lands, a check in this repository (an xtask step or doc test, owned by FM-605) will fail if a privilege in this guide's [tier table](#tier-table) or role commands is missing from that table or differs from it. Until then, the [appendix](#appendix-endpoint--privilege-evidence) is the researched input for that table.

## Appendix: endpoint → privilege evidence

These are all the PVE endpoints `crates/providers/fleet-provider-proxmox/src/lib.rs` calls, as of this draft. The *requirement* column quotes the `permissions` block from the method's schema. The API viewer ([9.x](https://pve.proxmox.com/pve-docs/api-viewer/), [8.x](https://pve.proxmox.com/pve-docs-8/api-viewer/)) is generated from those same schemas. Where the method checks more in its code, the column lists those checks too. **Unless marked, 8.x and 9.x are identical.**

| # | Method and path | Fleet caller | Requirement | Source |
|---|---|---|---|---|
| 1 | `GET /version` | discover | none (`user => 'all'`) | pve-manager `PVE/API2.pm` |
| 2 | `GET /cluster/resources` | discover, lab (template lookup), destructive (idempotency) | `user => 'all'`, **filtered**: a VM appears only with `VM.Audit` on `/vms/{vmid}`, a storage only with `Datastore.Audit` on `/storage/{id}`, a pool only with `Pool.Audit` on `/pool/{id}`. Node rows always appear, but their stats are stripped without `Sys.Audit` on `/nodes/{node}` | pve-manager `PVE/API2/Cluster.pm` (`resources`) |
| 3 | `GET /nodes/{node}/status` | discover (capacity) | `perm /nodes/{node} [Sys.Audit]` | pve-manager `PVE/API2/Nodes.pm` (`status`) |
| 4 | `GET /nodes/{node}/storage` | discover (capacity) | `user => 'all'`, lists only storages with `Datastore.Audit` or `Datastore.AllocateSpace` on `/storage/{storage}` | pve-storage `PVE/API2/Storage/Status.pm` (`index`) |
| 5 | `GET /nodes/{node}/qemu/{vmid}/config` | discover | `perm /vms/{vmid} [VM.Audit]` | qemu-server `PVE/API2/Qemu.pm` (`vm_config`) |
| 6 | `GET /nodes/{node}/lxc/{vmid}/config` | discover | `perm /vms/{vmid} [VM.Audit]` | pve-container `PVE/API2/LXC/Config.pm` (`vm_config`) |
| 7 | `GET /nodes/{node}/qemu/{vmid}/agent/info` | discover, lab readiness | **9.x:** `perm /vms/{vmid} [VM.GuestAgent.Audit, VM.GuestAgent.Unrestricted] any`; **8.x:** `perm /vms/{vmid} [VM.Monitor]` | qemu-server `PVE/API2/Qemu/Agent.pm` (`register_command`) |
| 8 | `GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces` | discover | same as #7 | same |
| 9 | `GET /nodes/{node}/qemu/{vmid}/agent/get-osinfo` | discover | same as #7 | same |
| 10 | `GET /nodes/{node}/qemu/{vmid}/snapshot` | destructive (idempotency) | `perm /vms/{vmid} [VM.Audit]` | qemu-server `Qemu.pm` (`snapshot_list`) |
| 11 | `POST /nodes/{node}/qemu/{vmid}/status/start` | operate, lab | `perm /vms/{vmid} [VM.PowerMgmt]` | qemu-server `Qemu.pm` (`vm_start`) |
| 12 | `POST …/status/stop` | operate | `perm /vms/{vmid} [VM.PowerMgmt]` | `vm_stop` |
| 13 | `POST …/status/shutdown` | operate | `perm /vms/{vmid} [VM.PowerMgmt]` | `vm_shutdown` |
| 14 | `POST …/status/reboot` | operate | `perm /vms/{vmid} [VM.PowerMgmt]` | `vm_reboot` |
| 15 | `POST /nodes/{node}/qemu/{vmid}/snapshot` | destructive | `perm /vms/{vmid} [VM.Snapshot]` (also with `vmstate=1`) | `snapshot` |
| 16 | `POST …/snapshot/{snapname}/rollback` | destructive | `perm /vms/{vmid} [VM.Snapshot, VM.Snapshot.Rollback] any` | `rollback` |
| 17 | `DELETE …/snapshot/{snapname}` | destructive | `perm /vms/{vmid} [VM.Snapshot]` | `delsnapshot` |
| 18 | `POST /nodes/{node}/qemu/{vmid}/clone` | destructive, lab | `and(perm /vms/{vmid} [VM.Clone], or(perm /vms/{newid} [VM.Allocate], perm /pool/{pool} [VM.Allocate] require_param pool))`. In code: `Datastore.AllocateSpace` on `/storage/{sid}` for every non-CD-ROM disk (the `storage` target if given) and on `vmstatestorage`; `Sys.Console` on `/` for a physical `cdrom`; `SDN.Use` on `/sdn/zones/{zone}/{bridge}` (`…/{tag}` per VLAN/trunk tag) for each `netN` | `clone_vm`, `$check_storage_access_clone`; `PVE::QemuServer::check_bridge_access` → pve-guest-common `PVE::GuestHelpers::check_vnet_access` |
| 19 | `POST /nodes/{node}/qemu/{vmid}/template` | destructive | `perm /vms/{vmid} [VM.Allocate]` | `template` |
| 20 | `GET /nodes/{node}/tasks/{upid}/status` | all executors | `user => 'all'`; `Sys.Audit` on `/nodes/{node}` only for a task the caller does not own (a token owns its own tasks) | pve-manager `PVE/API2/Tasks.pm` (`read_task_status`, `$check_task_user`) |
| 21 | `DELETE /nodes/{node}/tasks/{upid}` | destructive (`task-cancel`) | `user => 'all'`; `Sys.Modify` on `/nodes/{node}` only for a task the caller does not own | `Tasks.pm` (`stop_task`) |
| — | `GET /access/permissions` (FM-604, not yet called) | privilege diagnostics | `user => 'all'`: every user or token may read its own permissions; reading another's needs `Sys.Audit` on `/access` | pve-access-control `PVE/API2/AccessControl.pm` (`permissions`) |
| — | `DELETE /nodes/{node}/qemu/{vmid}` (not called today) | future Lab `destroy` cleanup | `perm /vms/{vmid} [VM.Allocate]` | `destroy_vm` |

### Sources and versions read

pve.proxmox.com was not reachable from the environment this draft was written in. All requirements above were read on 2026-09-30 from Proxmox's official source mirrors on GitHub. These are the same schemas the API viewer renders. The versions are the head of each branch at that time:

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
