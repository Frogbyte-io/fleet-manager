# M7 acceptance — closing the Fleet Lab exit gate

Status: planned (2026-10-05)

M7's image pipeline (FM-700/701) and Lab core (FM-710/711), plus the M9 Lab and Images pages (FM-930/931/932), have merged. The milestone is still open because a code survey on 2026-10-05 found that the **exit gate** cannot pass yet:

- **Released leases leak their VM.** `release_lease` moves a lease to `releasing` and stops. No cleanup executor exists, and the Proxmox provider has no guest-destroy primitive.
- **The sweeper never runs on its own.** `sweep_expired` is reachable only through `POST /lab/leases/sweep` and `fleetctl lab sweep`, so expiry after a controller restart is not automatic.
- **Readiness stops at the guest agent.** The `ssh_exec` and `project_ready` probes exist in `fleet-core` but are never executed. `bootstrap_project_id` is never applied, and the guest never becomes a Fleet machine, so "prepare a project, execute commands" is impossible.
- **There is no placement or capacity reservation.** The caller picks the account, and nothing prevents over-allocation.
- **Epic #15 is open**: no `lab create/status/exec/destroy`, no exec API, no lease → project link, no artifacts.
- **Epic #109 has leftovers**: no immutable build record and no recorded Packer fixtures or real-host build suite.
- **The failure-injection suite** (the last unticked box on #14) does not exist.

Epic #13's ticked boxes for the `ssh_exec`/`project_ready` probes and the bootstrap step describe the data model, not executed behavior. FM-714 delivers that behavior, and FM-743 corrects the checklist.

## Branching and agent routing

All M7 PRs target the **`dev`** branch, not `main`. Each issue has an agent label:

| Label | Work |
|---|---|
| `agent:codex` | Logic, API, provider, storage, the failure-injection harness |
| `agent:claude` | All GUI work, plus everything else needing judgment (runbooks, live acceptance harnesses and runs, optional pooling) |
| `agent:glm` | Simple, tightly specified tasks |

## Issues

| Planning ID | Issue | Epic | Agent | Depends on |
|---|---|---|---|---|
| FM-702 Immutable image build records | [#249](https://github.com/Frogbyte-io/fleet-manager/issues/249) | #109 | codex | — |
| FM-703 Recorded Packer CLI fixtures | [#250](https://github.com/Frogbyte-io/fleet-manager/issues/250) | #109 | glm | — |
| FM-712 Proxmox guest destroy primitive | [#251](https://github.com/Frogbyte-io/fleet-manager/issues/251) | #14 | codex | — |
| FM-714 Readiness probes, guest machine, bootstrap project | [#252](https://github.com/Frogbyte-io/fleet-manager/issues/252) | #13 | codex | — |
| FM-718 Lease project linkage | [#253](https://github.com/Frogbyte-io/fleet-manager/issues/253) | #15 | glm | — |
| FM-713 Lab cleanup executor and failure compensation | [#254](https://github.com/Frogbyte-io/fleet-manager/issues/254) | #14 | codex | FM-712 (FM-714 soft) |
| FM-704 Real-host image build suite | [#255](https://github.com/Frogbyte-io/fleet-manager/issues/255) | #109 | claude | FM-702, FM-703 |
| FM-705 Images console: build provenance | [#256](https://github.com/Frogbyte-io/fleet-manager/issues/256) | #109 | claude | FM-702 |
| FM-715 Placement and capacity reservation | [#257](https://github.com/Frogbyte-io/fleet-manager/issues/257) | #14 | codex | FM-713 |
| FM-716 Sweeper loop and cleanup reconciler | [#258](https://github.com/Frogbyte-io/fleet-manager/issues/258) | #14 | codex | FM-713 |
| FM-720 `lab create/status/exec/destroy` and exec API | [#259](https://github.com/Frogbyte-io/fleet-manager/issues/259) | #15 | codex | FM-713, FM-714 |
| FM-717 Pooled guests and revert cleanup (off gate path) | [#260](https://github.com/Frogbyte-io/fleet-manager/issues/260) | #14 | claude | FM-713, FM-715 |
| FM-721 Lab artifacts and exec logs | [#261](https://github.com/Frogbyte-io/fleet-manager/issues/261) | #15 | codex | FM-720 |
| FM-741 Lab failure-injection suite | [#262](https://github.com/Frogbyte-io/fleet-manager/issues/262) | #14 | codex | FM-713, FM-714, FM-715, FM-716 |
| FM-728 Fleet Lab operator runbook | [#263](https://github.com/Frogbyte-io/fleet-manager/issues/263) | #15 | claude | FM-713, FM-715, FM-716 |
| FM-722 Lab console parity | [#264](https://github.com/Frogbyte-io/fleet-manager/issues/264) | #15 | claude | FM-713, FM-715, FM-716, FM-718, FM-720, FM-721 |
| FM-723 `fleet` skill: one-command Lab workflow | [#265](https://github.com/Frogbyte-io/fleet-manager/issues/265) | #15 | glm | FM-720, FM-721 |
| FM-742 Run and record the exit gate | [#266](https://github.com/Frogbyte-io/fleet-manager/issues/266) | #15 | claude | FM-704, FM-741, FM-723 |
| FM-743 M7 close-out | [#267](https://github.com/Frogbyte-io/fleet-manager/issues/267) | #15 | glm | FM-742 and every gate-path issue above (FM-717 excluded) |

Totals: 9 codex, 6 claude (2 GUI), 4 glm. Codex holds under half: FM-718 is spelled out step by step for GLM, and the live build harness (FM-704) and the optional pooling (FM-717) go to Claude.

## Stages

```text
stage 1  FM-702 codex  FM-703 glm  FM-712 codex  FM-714 codex  FM-718 glm
            |   \         |            |             |
stage 2  FM-705 claude  FM-704 claude FM-713 codex <-+ (714 soft)
                                       |
stage 3              FM-715 codex  FM-716 codex  FM-720 codex (713+714)
                          |             |             |
stage 4  FM-741 codex (713-716)  FM-728 claude  FM-721 codex  FM-717 claude (optional)
                                                     |
stage 5  FM-722 claude (GUI)   FM-723 glm   ->   FM-742 claude (704+741+723)
                                                     |
stage 6                                         FM-743 glm
```

| Stage | Issues | Max agents | Gate to start |
|---|---|---|---|
| 1 | FM-702, FM-703, FM-712, FM-714, FM-718 | 5 | — |
| 2 | FM-713, FM-704, FM-705 | 3 | FM-712 for FM-713; FM-702 (+FM-703) for the image track |
| 3 | FM-715, FM-716, FM-720 | 3 | FM-713 merged (FM-720 also needs FM-714) |
| 4 | FM-721, FM-741, FM-728, FM-717 | 4 | Per the table above |
| 5 | FM-722, FM-723, FM-742 | 3 | FM-742 needs FM-704, FM-741, and FM-723 |
| 6 | FM-743 | 1 | FM-742 passing |

The image track (FM-702 → FM-703 → FM-704/FM-705) is independent of the Lab track and can finish early. The critical path is FM-712 → FM-713 → FM-716 → FM-741 → FM-742 → FM-743.

FM-717 (pooled revert) is in PLAN scope but not on the exit-gate path. If it is the only issue left, it may move to a follow-on milestone instead of blocking FM-743.

## Path conflicts to watch

- **`crates/fleet-controller/src/proxmox_exec.rs`**: FM-712 owns the new destroy executor, FM-714 owns `ProvisionExecutor`, and FM-713 owns only the `LabDispatch` arm (its executor lives in the new `lab_cleanup.rs`). FM-715 adds reservation calls to `ProvisionExecutor` and `lab_cleanup.rs` after FM-713/714 merge.
- **`crates/fleet-application/src/lab.rs`**: FM-714 (provision), FM-718 (lease create/list), FM-713 (release), FM-716 (sweep), and FM-720 (exec) each own the region named in their issue. New concerns go in new modules (`lab_placement.rs`, `lab_pool.rs`, `lab_artifacts.rs`).
- **`crates/fleetctl/src/lib.rs`** is one large file. Every CLI change touches it, so merge into `dev` one PR at a time and rebase before opening the next.
- **Migrations** are numbered sequentially. Take the next free number when you rebase onto `dev`, and never reuse one.
- **OpenAPI and the generated TS client** (`packages/api-client/`): regenerate after merging `dev`. Never resolve generated files by hand.

## Deferred: USB and hardware sub-epic (#16)

No issues are filed for #16 yet. `docs/architecture/lab.md` says the first Lab release must omit USB unless a real hardware validation environment exists, and that it must not ship an untested "exclusive" claim. When a host with passthrough-capable USB hardware is available, file the issues against #16, in this order:

1. USB inventory with stable identity (vendor/product/serial, physical port path) plus IOMMU/host validation with an explicit unsupported state — codex.
2. Transactional exclusive reservation, attach/detach around a lease with compensation, and a reconciler, extending FM-715's reservations — codex.
3. The USB attach/detach failure-injection points in the FM-741 suite — codex.
4. Hardware view in the Lab console — claude.
5. Hardware-in-the-loop runbook and live validation — claude.

Windows in-guest management and readiness also remain a later sub-epic.

## Exit

M7 (first Lab release) is complete when FM-742 records passing image, Lab, failure-injection, agent, and TTL-after-restart evidence, and FM-743 closes epics #13–#15 and ticks the remaining boxes on the already-closed image epic #109. `dev` then merges to `main` through a normal reviewed PR.

## Evidence

Recorded by FM-742 ([#266](https://github.com/Frogbyte-io/fleet-manager/issues/266)), run on 2026-10-08 against `dev` at `6afb7a3`. The redacted JSON summaries are posted on #266. Hosts, addresses, node names, and token IDs are redacted here; `<node-a>` is the cluster node Fleet talks to, and `<pve8>` is the standalone 8.x node.

**Verdict: the exit gate does not pass yet.** The image suite, the Lab suite, the human leg, and the TTL-after-restart leg pass. Three things still block it: the agent leg waits on FM-723 (#265); four failure-injection transitions are known-failing (#301, #302, #303, #310); and template-level project preparation fails on a live guest (#329, #330). The human leg needed one workaround for #326.

### Environment

| | |
|---|---|
| Fixtures | Nested PVE on the integration host: `<pve8>` (PVE 8.4.0) and the two-node cluster (PVE 9.2.2) from [the test-cluster runbook](../operations/proxmox-test-cluster.md). The physical host was not used. |
| Accounts | The fixtures' privilege-separated `Administrator` test token (`<fixture admin token>`) for the suites and the human leg. The least-privilege Lab roles were not exercised in this run. |
| Packer | 1.16.1, Proxmox plugin 1.2.4 |
| Controller (human and TTL legs) | `fleet-controller serve` from this commit, on loopback, with a temporary data directory and master key, trusted-LAN mode, and a dedicated `ssh-agent` holding a throwaway key. Default sweeper interval (60 s). |
| Scratch range | VMIDs 900-949 on both targets |

### Results

| Leg | Target | Result |
|---|---|---|
| `cargo xtask image-acceptance` | 9.x cluster, 8.x | **pass**: 16/16 (8 scenarios × 2 targets), 1274 s |
| `cargo xtask lab-acceptance` (`FLEET_LAB_LIVE=1`) | 9.x cluster, 8.x | **pass**: 4/4 (`lease-exec-destroy`, `ttl-expiry-restart` × 2 targets), 352 s. Run with `…_TEMPLATE_VMID=7103`, the Fleet-built image below. |
| Failure injection, offline (`cargo test -p fleet-controller --test lab_failure_injection`) | — | 22 pass, **4 ignored**, each pinned to an open bug: #301 (an interrupted cleanup is never retried), #302 (a provision interrupted before boot waits for its 30-day maximum lifetime), #303 (an interrupted reservation keeps its VMID reserved forever), #310 (a failed clone waits out the one-hour settle bound) |
| Human leg | 9.x cluster | **pass**, with the #326 workaround |
| Bootstrap project (supplement to the human leg) | 9.x cluster | **fail**: #329, then #330 |
| TTL leg | 9.x cluster | **pass** |
| Agent leg | — | **pending** FM-723 (#265) |

### Image and Lab suites

Both summaries report `"ok": true` with no skipped rows. Before the Lab run, both targets reported `/cluster/nextid` outside 900-949, so the Lab scenarios would have been skipped as "not a Lab fixture". Also, template 7000 cannot give a clone an IPv4 address (#328), so `lease-exec-destroy` cannot pass on it. Both were fixed in the fixtures (see [Fixture changes](#fixture-changes)). The Lab suite then ran against template 7103, which this run built through Fleet's own image path. Its harness seeds a build record for that template and promotes it through the real promotion gate.

### Human leg

On the 9.x cluster, through `fleetctl --output json` against the isolated controller:

1. **Build.** `images create` + `images publish` + `images build --account <lab-account> --wait`. The recipe is a `proxmox-clone` of template 7001 with an SSH communicator and an inline `shell` provisioner. The provisioner installs git and Node 22 (with a pinned checksum), authorizes the controller's public keys for `root`, writes a MAC-agnostic DHCP netplan, regenerates SSH host keys per clone, and cleans cloud-init and `/etc/machine-id`. The build record has outcome `succeeded`, Packer `1.16.1`, plugin `1.2.4`, and template `lab-base-7103` at VMID 7103, built in about 45 s. Three earlier attempts are recorded below; they fed #326 and #328.
2. **Promote.** `images promote <version>` set `promotedAt`.
3. **Template.** `lab template-create … --probe guest_agent --ttl 3600 --cleanup destroy`, then `lab publish`.
4. **Lease.** `lab create <template-version> --project <fleet-manager project> --account <lab-account> --wait`: `ready` 18 s after the request, VMID 900, an address, a Lab machine, and the project ID on the lease.
5. **Exec.** `lab exec … -- git clone --depth 1 https://github.com/Frogbyte-io/fleet-manager /tmp/fleet-projects/<project-id>` exited 0. Then the project's test command, `node --test .github/scripts/generate.test.mjs .github/scripts/load-toolchain-env.test.mjs` (the dependency-free part of the repository's policy suite), exited 0 with `tests 14`, `pass 14`, `fail 0`. `lab create --project` only links the lease; Fleet has no per-project test command, so the human supplies it.
6. **Collect.** `lab collect <lease> /tmp/fm742-test-report.txt /etc/os-release --wait` succeeded. `lab artifacts --lease` listed the two files and two `exec-log` artifacts. `lab artifact-get` downloaded the report with `"verified": true` (size and sha256 match).
7. **Destroy.** `lab destroy --wait` gave `released` with `cleanupAttempts: 0`. `machines list --tag lab` was then empty.
8. **Host check.** `/cluster/resources` on the cluster showed 0 `fm-lab-*` guests and 0 guests in 900-949. The 8.x node was the same after the Lab suite.
9. **Reservations.** No API or `fleetctl` command shows reservations yet (#319). By the documented rule (a reservation counts only while its lease is not `released`, and not `failed` without a VMID), the API showed 5 of 5 leases `released`. A read-only look at the controller's own `lab_capacity_reservations` table agreed: 5 rows, all `released`, 0 live.

**Workaround (#326).** With the guest image authorizing only the agent's key, the first ready lease's `lab exec` exited 255 with `Permission denied (publickey)`, and `lab collect` failed with `transfer_failed`. The SSH provider forces `IdentitiesOnly yes` without an identity file, so OpenSSH never offers an agent-only key. The lease itself was destroyed cleanly. The final image also authorizes the controller user's default `~/.ssh/id_ed25519.pub`, which OpenSSH does offer under `IdentitiesOnly`. Both the human leg and the Lab suite pass on that image.

**Failed attempts on the way.** All of these are recorded in the controller and cleaned up:

- **Image v1** (clone of 7000, SSH communicator): `build_failed` after the 15-minute SSH timeout, because the clone never got an address (#328). Packer deleted its VM. That VM was named `fm-lab-base-7101`, and the Lab sweeper correctly reported it as an orphan (`lab_orphan_guest`) and did not delete it. Recipes should not use Fleet's reserved `fm-lab-` prefix.
- **Image v2** (clone of 7001): built. Its lease failed at step `guest_ip` (`never_ready`), because the clone lost the cloud-init drive and the build VM's MAC-bound netplan kept the NIC down. Compensation moved the lease to `releasing`, one `lab.cleanup` destroyed VMID 900, and the lease ended `released`.
- **Image v3**: the lease became ready, then hit #326 as described above.

### Bootstrap project (supplement)

The gate says "prepare a project". `lab create --project` does not prepare anything. Only a template's `bootstrapProjectId` does, and only through `POST /api/v1/lab/templates`, because the CLI cannot set it (#291). A template with `bootstrapProjectId: <fleet-manager project>` and `readinessProbe: project_ready` failed its lease at step `project_ready` after 22 s:

- `projects.clone`: `git_failed`, `fatal: repository 'github.com/Frogbyte-io/fleet-manager' does not exist`. The clone step is given the stored normalized remote, not a URL (#329).
- `frogenv.status`: `status_failed`, `frogenv is not installed`. The workflow requires Frogenv, which no Lab image requirement mentions (#330).

The failed lease was compensated and cleaned up (`released`, guest destroyed).

### TTL leg

On the 9.x cluster, with a template version at `--ttl 60` and the default 60 s sweeper:

| UTC | Event |
|---|---|
| 13:09:37 | Controller started; template published |
| 13:09:46 | PVE `qmstart` of the Lab guest (VMID 900) |
| 13:09:56 | Lease `ready` (`expiresAt` 13:10:55); controller stopped (SIGTERM) |
| 13:10:55 | Lease expires; controller still down, guest still running |
| 13:11:35 | Controller restarted on the same data directory. From here on, only `lab status` polling |
| 13:12:25-27 | Sweeper released the lease; PVE `qmstop` + `qmdestroy` of VMID 900 |
| 13:12:30 | Lease `released`, `cleanupAttempts: 0`, 55 s after the restart; no guest in 900-949 |

`lab-acceptance`'s `ttl-expiry-restart` passed the same check on both targets.

### Agent leg

> **Pending: FM-723 ([#265](https://github.com/Frogbyte-io/fleet-manager/issues/265)) has not merged.** Once it has, an agent session that has only the `fleet` skill performs the human leg from a one-line instruction against a fresh isolated controller and template 7103. The redacted transcript excerpt goes here. The #326 workaround (the controller user's default key in the image) still applies until #326 is fixed.

### Fixture changes

Made on the nested fixtures only; the physical host's configuration was not changed. All are kept for the next run unless noted.

| Change | Where | Why |
|---|---|---|
| `pvesh set /cluster/options --next-id lower=900,upper=950` (`upper` is exclusive) | `<pve8>`, the cluster | Lab takes VMIDs from `nextid`; before this it answered about 103, outside the scratch range. There was no previous `next-id` setting. |
| New template **7001** `fleet-agent-template-dhcp` (tag `fleet-acceptance`): a full clone of 7000 with an empty `/etc/machine-id` and `cloud-init clean`. 7000 is unchanged | both | 7000 has no `/etc/machine-id`, so clones never get DHCP (#328) |
| Fleet-built templates **7101** (v2, no working network), **7102** (v3, agent key only), **7103** (v4, the working image) | both | Built and promoted through the human leg. Fleet never deletes templates, and none was removed. 7101 and 7102 are superseded and can be removed by hand. |
| A throwaway ed25519 public key authorized for `root` in 7102/7103, and the controller user's default public key in 7103 | both | Lab exec authentication (#326). The throwaway private key was deleted after the run, so its entry is inert. |
| Probe guests 947, 948, 949 (clones of 7000/7001/7101/7102) | cluster | Diagnosis. All destroyed. |
| All three nested VMs shut down again after the run | physical host | Left as found |

### Issues filed

| Issue | Agent | What |
|---|---|---|
| [#326](https://github.com/Frogbyte-io/fleet-manager/issues/326) | codex | Lab exec and collect ignore agent-only SSH keys: the SSH provider forces `IdentitiesOnly yes` |
| [#327](https://github.com/Frogbyte-io/fleet-manager/issues/327) | codex | Lab provision records stay `ready` after cleanup destroys the guest |
| [#328](https://github.com/Frogbyte-io/fleet-manager/issues/328) | claude | PVE test fixtures: template 7000 has no `/etc/machine-id`, so clones never get a DHCP address |
| [#329](https://github.com/Frogbyte-io/fleet-manager/issues/329) | codex | `ready.workflow` clones the normalized project remote, which git cannot fetch |
| [#330](https://github.com/Frogbyte-io/fleet-manager/issues/330) | claude | Lab bootstrap project needs Frogenv on the guest, and nothing documents it |

Already open and on the gate path: #301, #302, #303, #310 (the ignored failure-injection transitions), #291 (the CLI cannot set a bootstrap project), and #319 (reservations are not readable).
