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
