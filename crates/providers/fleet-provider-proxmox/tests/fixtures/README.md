# Proxmox capacity response fixtures

These bounded, secret-free JSON response fixtures are representative, synthetic
PVE 8.x and 9.x responses for the FM-915 contract tests. They are not live API
captures. Endpoint fields and units follow the upstream
`/nodes/{node}/status` and `/nodes/{node}/storage` implementations in
[`pve-manager`](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Nodes.pm)
and [`pve-storage`](https://github.com/proxmox/pve-storage/blob/master/src/PVE/API2/Storage/Status.pm).
Values and host names are synthetic so the fixtures contain no environment data.

The test transport verifies the request paths and normalized values. A real
PVE 8.x/9.x integration run remains the compatibility gate before claiming
live-cluster validation. The PVE 9 memory example includes buffers and cache
in the remainder between `used`, `free`, and `total`, reflecting PVE's
cache-excluding `used` calculation.

## Task history (FM-609)

`node-tasks.json` and `tasks-cluster-resources.json` back the
`task_history.rs` contract tests. They are synthetic in the same way: the
entry shape (`upid`, `node`, `pid`, `pstart`, `starttime`, `type`, `id`,
`user`, `tokenid`, `endtime`, `status`) follows `GET /nodes/{node}/tasks`
in [`PVE/API2/Tasks.pm`](https://github.com/proxmox/pve-manager/blob/master/PVE/API2/Tasks.pm),
which is identical on the `stable-8` and `master` (9.x) branches. Token tasks
are split into `user` plus `tokenid`, active tasks report `RUNNING`, and
node-level tasks (`vzdump`, `aptupdate`) carry an empty `id`. Each cluster
lists a second node that answers 595 and a third that is `offline`, so the
per-node failure isolation is part of every run. The UPID hex fields agree
with the decimal `pid`, `pstart`, and `starttime` values.

## Token permissions (FM-604)

`access-permissions-*.json` are synthetic `GET /access/permissions` answers
for the calling token. Their shape is the one `PVE/API2/AccessControl.pm`
(`permissions`) and `PVE/RPCEnvironment.pm` (`get_effective_permissions`)
in `pve-access-control` produce, identically on `master` (9.x) and
`stable-bookworm` (8.x): ACL path → privilege → propagate flag (`1`/`0`).
The listed paths are the top-level roots, every ACL path, and every pool
member; paths without privileges are omitted, so a privilege-separated
token without ACLs of its own answers `{}`.

- `full`: `Administrator` on `/`. The privilege names follow each major's
  `$privgroups` in `PVE/AccessControl.pm` (8.x has `VM.Monitor`; 9.x has
  the `VM.GuestAgent.*` split and `VM.Replicate`).
- `readonly`: `PVEAuditor` on `/` (9.x's audit group adds
  `VM.GuestAgent.Audit`).
- `privsep-empty`: a privilege-separated token with no ACLs.
- `pool-scoped`: the least-privilege layout from the FM-605 token guide
  (roles on `/nodes`, `/pool/fleet`, the bridge, and one reserved clone
  VMID). Pool members carry pool-derived, non-propagating privileges.

The 403 case (the permissions read itself refused) is inline in the test.

## Contract corpus (FM-607)

`contract-*.json` back `tests/contract_pve.rs`, which runs every scenario
once per major through one parameterized helper. Like the other fixtures,
they are synthetic, not live captures:

- Node names are `pveN-n1` and `pveN-n2`.
- MACs use the Proxmox `BC:24:11` prefix with made-up suffixes.
- Addresses come only from the documentation ranges (`192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), plus loopback,
  IPv6 link-local (`fe80::/10`, optionally with a Windows `%zone` suffix
  that the scan strips), and IPv4 link-local/APIPA (`169.254.0.0/16`,
  RFC 3927, added for FM-608). Link-local addresses are self-assigned and
  never routed, so they carry no environment data; the Windows corpus
  needs them to show they are never usable.
- Fingerprints are all zeros, and the token is `fleet@pve!contract`.

A test checks the address rule and that no credentials appear.

The partial-node shapes follow the FM-613 live observations in
`docs/operations/proxmox-test-cluster.md` (step 8). Node `n2` is down.
`cluster/status` shows it as `online: 0` and the cluster as `quorate: 0`.
`cluster/resources` and `/nodes` show it as `offline`. Its guest has lost
its rrd entry, so that guest has `status: unknown` and no name. Calls that
the survivor proxies to `n2` either answer **595 with an empty body**, with
the reason only in the HTTP status line, or run past the client's 15 s
deadline, because the survivor takes about 30 s to give up. The tests
script both cases.

The upstream sources are `pve-manager` (`stable-8` and `master`),
`qemu-server` (`stable-bookworm` and `master`), `pve-container`,
`pve-access-control`, and `pve-http-server` (`master`).

| Fixture | Endpoint | Upstream source |
|---|---|---|
| `cluster-resources` | `GET /cluster/resources` | `PVE/API2/Cluster.pm` (`resources`); `PVE/API2Tools.pm` (`extract_node_stats`, `extract_vm_stats`) |
| `cluster-status` | `GET /cluster/status` | `PVE/API2/Cluster.pm` (`get_status`) |
| `nodes` | `GET /nodes` | `PVE/API2/Nodes.pm` (`PVE::API2::Nodes` `index`) |
| `node-qemu`, `node-lxc` | `GET /nodes/{node}/qemu`, `…/lxc` | `qemu-server` `PVE/API2/Qemu.pm` (`vmlist`) over `PVE/QemuServer.pm` (`vmstatus`); `pve-container` `PVE/LXC.pm` (`vmstatus`) |
| `qemu-config-*`, `lxc-config-104` | `GET …/qemu/{vmid}/config`, `…/lxc/{vmid}/config` | `PVE/API2/Qemu.pm` (`vm_config`); `pve-container` `PVE/API2/LXC/Config.pm`. `netN` strings follow each package's config schema |
| `forbidden-config`, `forbidden-agent` | 403 bodies | `pve-access-control` `PVE/RPCEnvironment.pm` (`check`, `check_any`: "Permission check failed (path, privs)"). The agent privilege is `VM.Monitor` on 8.x and `VM.GuestAgent.Audit\|VM.GuestAgent.Unrestricted` on 9.x (`PVE/API2/Qemu/Agent.pm`) |
| `agent-info`, `agent-network`, `agent-osinfo`, and their `-loose` variants | `GET …/agent/{info,network-get-interfaces,get-osinfo}` | `PVE/API2/Qemu/Agent.pm` (`register_command` wraps the raw QGA answer in `{"result": …}`). Member names follow the QEMU guest agent's QAPI schema |
| `agent-not-running` | 500 from any agent command | `PVE/QemuServer/Agent.pm` (`assert_agent_available`: "QEMU guest agent is not running") |
| `status-{start,stop,shutdown,reboot}` | `POST …/qemu/{vmid}/status/{action}` | `PVE/API2/Qemu.pm` (`vm_start`, `vm_stop`, `vm_shutdown`, `vm_reboot`: the worker's UPID) |
| `task-*` | `GET /nodes/{node}/tasks/{upid}/status` | `PVE/API2/Tasks.pm` (`read_task_status`: `running` or `stopped`; `exitstatus` once stopped; token tasks split into `user` and `tokenid`; 400 "no such task" for an unknown UPID) |
| `snapshot-list` | `GET …/qemu/{vmid}/snapshot` | `PVE/API2/Qemu.pm` (`snapshot_list`: `vmstate` is 0 or 1, with a trailing `current` row) |
| `snapshot-{create,rollback,delete}`, `clone`, `template` | `POST …/snapshot`, `POST …/snapshot/{name}/rollback`, `DELETE …/snapshot/{name}`, `POST …/clone`, `POST …/template` | `PVE/API2/Qemu.pm` (`snapshot`, `rollback`, `delsnapshot`, `clone_vm`, `template`). On both majors each one returns its `fork_worker` UPID, `template` and `delsnapshot` included |
| `malformed-upid` | A lifecycle answer that is not a UPID | Defensive: the provider must refuse it as an invalid payload |

Shape drift between the majors:

- **`cluster/resources` on 9.x** adds `type: "network"` rows: every node's
  default `localnetwork` zone, plus any SDN fabrics. It also adds `memhost`
  on running QEMU guests and `host-arch` on nodes. 8.x lists each node's
  `localnetwork` zone as an `sdn` row instead. The provider skips `network` rows the same way it skips `sdn` and
  `pool` (this is an FM-607 fix).
- **The agent privilege** named in the 403 is `VM.Monitor` on 8.x and
  `VM.GuestAgent.Audit|VM.GuestAgent.Unrestricted` on 9.x (a `check_any`).
- **QGA, OS, and kernel versions** follow each major's Debian base
  (bookworm and trixie).
- **Error bodies** are modelled the same on both majors.
  `libpve-http-server-perl` 5.2.0, which shipped with PVE 8.4, added
  `message` to JSON error bodies (fix #6503). PVE 8.0–8.3 answer
  `{"data":null}` and put the reason only in the status line. The provider
  reads the HTTP status and never reads `message`, so both bodies decode the
  same way.

Some shapes don't come from an upstream code path:

- `task-stopped-no-exitstatus` is defensive. `read_task_status` always sets
  `exitstatus` on a stopped task. The provider reads a missing one as
  unknown.
- The **loose agent fields** are omissions, never `null` values, because
  QAPI omits optional members. The unit test
  `null_and_missing_envelopes_mean_empty` in `src/lib.rs` covers an
  explicit `null` envelope.
- `node-status.json` and `node-storage.json` (FM-915) carry no node name,
  so the contract tests reuse them for the healthy node instead of keeping
  a copy.

TLS mismatch is client-side and the same on every major, so it has no
fixture. The real `PinningVerifier` is covered by `tests/pin_live.rs` and
by the FM-611 `trust` scenario in
`crates/fleet-controller/tests/proxmox_live.rs`, which passed live on PVE
8.4 and 9.2 (FM-613).

## Windows guests (FM-608)

`contract-windows-*.json` back the Windows scenario in
`tests/contract_pve.rs` (`windows_guests_report_osinfo_interfaces_and_honest_agent_states`).
That scenario uses the same `fixtures!` table and runs once per major through
`for_each_major`. The fixtures are synthetic under the same rules as the
FM-607 corpus, and no live Windows guest was captured. One healthy node
carries four Windows guests:

| Guest | Config | Agent answer |
|---|---|---|
| 201 | `ostype: win11`, `agent: 1`, two NICs | `info`, `network-get-interfaces`, `get-osinfo` |
| 202 | `ostype: win10`, `agent: 1` | 500 "QEMU guest agent is not running" (the shared `agent-not-running` body) |
| 203 | `ostype: win11`, no `agent` key | 500 "No QEMU guest agent configured" (`windows-agent-not-configured`) |
| 204 | `ostype: win11`, `agent: enabled=1,…`, `status: stopped` | 500 "VM 204 is not running" (`windows-guest-not-running`) |

Upstream sources, read at the commits named:

- **qemu-ga on Windows**: QEMU
  [`qga/commands-win32.c`](https://github.com/qemu/qemu/blob/f7ada39edacaa5c26b30e98b94017b0b2ccbcf94/qga/commands-win32.c)
  and [`qga/qapi-schema.json`](https://github.com/qemu/qemu/blob/f7ada39edacaa5c26b30e98b94017b0b2ccbcf94/qga/qapi-schema.json)
  (`GuestOSInfo`, `guest-get-osinfo` since 2.10). The virtio-win guest tools
  ship this same agent as `qemu-ga-x86_64.msi`
  ([virtio-win-pkg-scripts](https://github.com/virtio-win/virtio-win-pkg-scripts)).
  - `qmp_guest_get_osinfo`:
    - `id` is `mswindows` and `name` is `Microsoft Windows`.
    - `pretty-name` is the registry `ProductName`. Windows 11 still says
      "Windows 10 …" there, and the 9.x fixture shows this.
    - `version` and `version-id` come from a build-number table: builds from
      22000 are client "Microsoft Windows 11" / `11`, and builds from 20344
      are server "Microsoft Windows Server 2022" / `2022`. When the table has
      no row, both are `N/A`.
    - `variant` and `variant-id` are `client` or `server`.
    - `kernel-release` is the build number, `kernel-version` is
      `major.minor` (`10.0`), and `machine` is one of `x86`, `x86_64`, `arm`,
      `ia64`.
  - `qmp_guest_network_get_interfaces`:
    - `name` is the adapter `FriendlyName` (`Ethernet`, `Ethernet 2`,
      `Loopback Pseudo-Interface 1`).
    - `hardware-address` is lowercase `%02x:` and is omitted when the
      adapter has no physical address, as with the loopback
      pseudo-interface.
    - Addresses are printed by `WSAAddressToString`, so an IPv6 link-local
      address carries a `%zone` suffix.
    - A DHCP-less NIC holds an APIPA `169.254.x.y/16` address.
- **The `ostype` enum**: `qemu-server` `src/PVE/QemuServer.pm`, the same on
  [`stable-bookworm`](https://github.com/proxmox/qemu-server/blob/5ccd363e5908aa5a7b969797babdff1df5159475/src/PVE/QemuServer.pm)
  (8.x) and
  [`master`](https://github.com/proxmox/qemu-server/blob/a7b4240bba1dd493d6c76daad1e70af62b2ebcc8/src/PVE/QemuServer.pm)
  (9.x): `other wxp w2k w2k3 w2k8 wvista win7 win8 win10 win11 l24 l26
  solaris`. `win10` covers 10/2016/2019 and `win11` covers 11/2022/2025, so
  the 8.x Windows Server 2022 guest is `win11`. The two branches differ only
  in the `l26` description and in 9.x's explicit `default => 'other'`.
- **The agent states**: `qemu-server` `src/PVE/QemuServer/Agent.pm`
  (`agent_available` on `stable-bookworm`, `assert_agent_available` on
  `master`). It dies, which the API answers as a 500, with "No QEMU guest
  agent configured", then "VM <vmid> is not running", then "QEMU guest agent
  is not running", in that order. The provider stops at the failed `info` in
  all three cases.

Per major: the 8.x guest 201 is Windows Server 2022 Standard (build 20348,
qemu-ga 8.1.2), and the 9.x guest 201 is Windows 11 Pro (build 26100,
qemu-ga 9.2.0). The agent version follows the virtio-win release, not the
PVE major. The interface shapes are the same on both.
