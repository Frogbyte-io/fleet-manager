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

Recorded by FM-742.
