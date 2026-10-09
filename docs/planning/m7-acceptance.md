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

Recorded by FM-742 ([#266](https://github.com/Frogbyte-io/fleet-manager/issues/266)). This is the second run, on 2026-10-09 against `dev` at `564a0b6`. The redacted JSON summaries are posted on #266. Hosts, addresses, node names, and token IDs are redacted here; `<node-a>` is the cluster node Fleet talks to, and `<pve8>` is the standalone 8.x node.

**Verdict: the exit gate passes.** The image suite, the Lab suite, the offline failure-injection suite (nothing ignored), the human leg without a workaround, the bootstrap-project leg, the TTL-after-restart leg, and the agent leg all pass on the PVE fixtures. The first live run of #372 (the template's cores, memory, and disk applied to the clone) also passes on both PVE versions. One documentation bug from the agent leg is filed ([#424](https://github.com/Frogbyte-io/fleet-manager/issues/424)). It does not block the gate.

**What the first run found (2026-10-08, `dev` at `6afb7a3`).** It failed on five bugs, #326 (agent-only SSH keys were never offered), #327, #328 (fixture template 7000 has no `/etc/machine-id`), #329 (the project clone step was given a normalized remote, not a URL), and #330 (bootstrap required Frogenv). It also ran with four failure-injection transitions ignored and pinned to #301, #302, #303, and #310, and the agent leg waited on FM-723 (#265). All of these are closed and are re-run below.

### Environment

| | |
|---|---|
| Fixtures | Nested PVE on the integration host: `<pve8>` (PVE 8.4.0) and the two-node cluster (PVE 9.2.2) from [the test-cluster runbook](../operations/proxmox-test-cluster.md). The physical host's own guests were not touched. All three nested VMs were stopped at the start; this run started them and shut them down at the end. |
| Accounts | The fixtures' privilege-separated `Administrator` test token (`<fixture admin token>`) for the suites and every leg. `fleetctl proxmox privileges` reports all four tiers `granted`, including the #372 privileges (`VM.Config.CPU`, `.Memory`, `.Disk`), because of Administrator. The least-privilege Lab roles were not exercised, so the `hardware_failed` path for a token without them was not run live. |
| Packer | 1.16.1, Proxmox plugin 1.2.4 |
| Controller (human, bootstrap, TTL, agent legs) | `fleet-controller serve` from this commit, on loopback, with a temporary data directory and master key, trusted-LAN mode, and a dedicated `ssh-agent` holding a throwaway key. Default sweeper interval (60 s). The `fleetctl` the agent used was a one-line wrapper that adds `--url` (the default port was taken on the integration host). |
| Scratch range | VMIDs 900-949 on both targets |

### Results

| Leg | Target | Result |
|---|---|---|
| `cargo xtask image-acceptance` | 9.x cluster, 8.x | **pass**: 16/16 (8 scenarios x 2 targets), 1262 s of scenario time |
| `cargo xtask lab-acceptance` (`FLEET_LAB_LIVE=1`) | 9.x cluster, 8.x | **pass**: 4/4 (`lease-exec-destroy`, `ttl-expiry-restart` x 2 targets), 372 s. Run with `FLEET_PVE_TARGET_<NAME>_TEMPLATE_VMID=7103`, the previous run's Fleet-built image |
| Failure injection, offline (`cargo test -p fleet-controller --test lab_failure_injection`) | | **pass**: 28 passed, **0 ignored** (the four transitions that were ignored last run now run). The two `live_` tests are the Lab suite's scenarios and ran as part of `lab-acceptance` |
| Human leg | 9.x cluster | **pass**, no workaround |
| #372 hardware, live | 9.x cluster, 8.x | **pass**, see [Template hardware](#template-hardware-372) |
| Bootstrap project (`project_ready`) | 9.x cluster | **pass**: ready in 42 s, project checked out |
| TTL leg | 9.x cluster | **pass** |
| Agent leg | 8.x | **pass**, with documentation gaps filed as #424 |

### Image and Lab suites

Both summaries report `"ok": true` with no skipped rows. The fixtures keep the two changes the first run made (the `next-id` range 900-949 on both targets, and template 7001, a DHCP-capable clone of 7000; see [Fixture changes](#fixture-changes)), so no fixture work was needed before the suites. The Lab suite ran against template 7103, built through Fleet's own image path in the first run.

### Human leg

On the 9.x cluster, through `fleetctl --output json` against the isolated controller:

1. **Build.** `images create` + `images publish` + `images build --account <lab-account> --wait`. The recipe is a `proxmox-clone` of template 7001 (SSH communicator, `full_clone: false`, `vm_id` 7201, name `lab-base-7201`, not the reserved `fm-lab-` prefix) with one inline `shell` provisioner, written from [the first-run recipe notes](../operations/lab.md#first-run). It waits for cloud-init, installs `git` and `nodejs` (v18.20.4) with `apt`, authorizes **only the agent's throwaway public key** for `root`, writes a MAC-agnostic DHCP netplan, enables a unit that regenerates SSH host keys, and then cleans cloud-init and `/etc/machine-id`. The build record has outcome `succeeded`, Packer `1.16.1`, template `lab-base-7201` on `<node-a>`, and took 69 s.
2. **Promote.** `images promote <version>` set `promotedAt`.
3. **Template.** `lab template-create --cores 2 --memory 2048 --disk 6 --probe guest_agent --ttl 3600 --cleanup destroy`, then `lab publish`. The image template has 1 core, 1024 MiB, and a 3 GiB disk, so the hardware step has work to do.
4. **Lease.** `lab create <template-version> --project <fleet-manager project> --account <lab-account> --wait`: `ready` 20 s after the request, VMID 900, an address, a Lab machine, the project ID, and a `held` reservation (2 cores, 2 GiB, 6 GiB on `local-lvm`) on the lease.
5. **Exec.** `lab exec … -- git clone --depth 1 https://github.com/Frogbyte-io/fleet-manager /tmp/fm-proj` exited 0, then `node --test .github/scripts/generate.test.mjs .github/scripts/load-toolchain-env.test.mjs` exited 0 with `tests 14`, `pass 14`, `fail 0`. Authentication used only the key in the controller's agent: #326 is fixed. `lab create --project` links the lease; the human supplies the test command.
6. **Collect.** `lab collect <lease> /tmp/test-report.txt /etc/os-release --wait` succeeded. `lab artifacts --lease` listed the two files and three `exec-log` artifacts. `lab artifact-get` downloaded the report with `"verified": true`.
7. **Destroy.** `lab destroy --wait` gave `released` with `cleanupAttempts: 0`, and the lease's reservation read `released`. `machines list --tag lab` was empty.
8. **Host check.** `/cluster/resources` on both targets, after all legs, showed no `fm-lab-*` guest and no guest in 900-949.
9. **Reservations.** `lab status` now shows a lease's `reservation` (#319). After all legs, every lease in the controller was `released` with a `released` reservation, except one lease that `failed` before it reserved anything and has `reservation: null`. No reservation is live. The sweeper reported no `lab_orphan_guest` audit event.

### Template hardware (#372)

Template version: 2 cores, 2048 MiB, 6 GiB disk, on an image template with 1 core, 1024 MiB, and a 3 GiB disk. Observed through the PVE API, after the lease reached `ready`, on the running clone (VMID 900), and from inside the guest with `lab exec`:

| | Requested | PVE config of the clone | PVE status | In the guest |
|---|---|---|---|---|
| 9.x cluster (PVE 9.2.2) | 2 cores, 2048 MiB, 6 GiB | `cores: 2`, `memory: 2048`, `scsi0 … size=6G`, 1 socket, no `protection` | running, 2 vCPUs, 2048 MiB max, 6 GiB max disk | `nproc` 2, 1979 MiB total, `sda` 6442450944 bytes, `/` 5.8G |
| 8.x (PVE 8.4.0) | 2 cores, 2048 MiB, 6 GiB | `cores: 2`, `memory: 2048`, `scsi0 … size=6G`, 1 socket, no `protection` | not read | `nproc` 2, 1979 MiB total, `/` 5.8G |

The PVE status call was read on the cluster only. The guest's filesystem followed the disk (`/` is 5.8G of 6G), because the image's cloud-init grows the root partition on first boot. The cluster and 8.x leases both became `ready` in about 20 s, so the extra `hardware` step adds no visible delay. The image template itself is unchanged (1 core, 1024 MiB, 3 GiB).

### Bootstrap project (supplement)

A template with `bootstrapProjectId: <fleet-manager project>` and `readinessProbe: project_ready` (created through `POST /api/v1/lab/templates`, the only way to set a bootstrap project; the CLI still cannot) reached `ready` in 42 s, with no failed step. The guest had the checkout at `/tmp/fleet-projects/<project-id>` (commit `78d4882`), and the project's test command exited 0 there with `pass 14`, `fail 0`. The guest has no Frogenv, so #329 and #330 are verified fixed. The lease was destroyed (`released`, `cleanupAttempts: 0`).

### TTL leg

On the 9.x cluster, with a template version at `--ttl 60` and the default 60 s sweeper:

| UTC | Event |
|---|---|
| 18:12:25 | Lease `ready` (`expiresAt` 18:13:25) |
| 18:12:27 | Controller stopped (SIGTERM) |
| 18:13:25 | Lease expires; controller still down |
| 18:13:37 | Guest (VMID 900) still `running` on PVE; controller restarted on the same data directory. From here on, only `lab status` polling |
| 18:14:40 | Lease `releasing` |
| 18:14:45 | Lease `released`, `cleanupAttempts: 0`, 68 s after the restart; no guest in 900-949 |

`lab-acceptance`'s `ttl-expiry-restart` passed the same check on both targets.

### Agent leg

A subagent, given only `skills/fleet/SKILL.md` and `fleetctl` and told not to read the source, docs, or tests, got the one-line task: "Use a disposable Fleet Lab environment (the `gate-bootstrap` template, for the `fleet-manager` project) to run `node --test .github/scripts/generate.test.mjs .github/scripts/load-toolchain-env.test.mjs` for that project, collect the test output as an artifact, then tell me the result." It worked against the same isolated controller, which now held two trusted accounts (one per nested host). Transcript excerpt, ids and addresses shortened, every command run as `fleetctl --output json …`:

```text
lab templates                      -> gate-bootstrap, readinessProbe project_ready
projects list                      -> fleet-manager
lab create <tv> --project <p> --purpose "run generate and load-toolchain-env tests" --wait
                                   -> exit 1: 2 trusted Proxmox accounts exist; pass --account <id>
proxmox accounts                   -> pve8, cluster          (not in the skill; found with --help)
lab lease <tv> --purpose "..."     -> state requested
lab provision-lease <lease>        -> operation pending; lab status: failed (placement_ambiguous)
lab provision-lease <lease> --account <id>  -> 409 not awaiting provisioning
lab destroy <lease> --wait         -> 400 already failed (no VM, no reservation)
lab create <tv> --project <p> --account <pve8> --purpose "..." --wait --timeout 900
                                   -> exit 0, state ready, vmid 900
lab exec <L> --wait --timeout 60 -- sh -c 'pwd; whoami; ...; node --version'  -> /root, root, v18.20.4
lab exec <L> --wait --timeout 60 -- sh -c 'ls -la /root; find / -name generate.test.mjs ...'
                                   -> checkout at /tmp/fleet-projects/<project-id>
lab exec <L> --wait --timeout 120 -- sh -c 'cd /tmp/fleet-projects/<project-id> && node --test ... > /root/test-output.txt 2>&1; echo rc=$?; tail -15 /root/test-output.txt'
                                   -> rc=0, # tests 14, # pass 14, # fail 0
lab collect <L> /root/test-output.txt --wait   -> succeeded, 2348 bytes
lab artifacts --lease <L>          -> the file and three exec-log artifacts
lab destroy <L> --wait             -> exit 0
lab status <L>                     -> released
```

The agent finished the task and left no live lease. The earlier `failed` lease owns no guest and no reservation. The agent also reported four gaps in the skill, filed as [#424](https://github.com/Frogbyte-io/fleet-manager/issues/424): no command to list accounts, no note that `failed` is terminal and `lab destroy` refuses it, no checkout path for a bootstrap template, and no note on terminal states when polling. The two-account ambiguity comes from the gate fixtures, which register both nested hosts with a Fleet-built template at VMID 7201.

### Fixture changes

Made on the nested fixtures only. The physical host's configuration, its apt repositories, and its guest 100 were not touched.

| Change | Where | Why |
|---|---|---|
| None to the token or its roles | | The fixture token is a privilege-separated `Administrator`, which already holds the #372 privileges. No upgrade note was needed. |
| New Fleet-built templates **7201** (`lab-base-7201`, built and promoted through the human leg and the 8.x repeat) | both | Kept for the next run. Fleet never deletes templates. 7101 and 7102 (first run) are superseded and can be removed by hand; 7103 is still used by `lab-acceptance` |
| A throwaway ed25519 public key authorized for `root` in 7201 | both | Lab exec authentication. The private key and the agent were deleted after the run, so the entry is inert |
| Scratch guest 900 (clones from the leases) | both | All destroyed by Lab |
| All three nested VMs started for this run and shut down again after it | physical host | They were stopped at the start; left as found |

### Issues filed

| Issue | Agent | What |
|---|---|---|
| [#424](https://github.com/Frogbyte-io/fleet-manager/issues/424) | glm | `fleet` skill: account discovery, failed-lease handling, and the project checkout path are undocumented |

The first run's bugs and gate-path issues (#326, #327, #328, #329, #330, #301, #302, #303, #310, #291, #319) are all closed, and this run re-verified their behavior.
