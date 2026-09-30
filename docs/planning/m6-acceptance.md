# M6 acceptance — closing the Proxmox exit gate

Status: planned (2026-09-30)

M6 is code-complete: FM-600–FM-603 have merged, and every scope box on epics #9–#12 is ticked. The milestone is still open because its **exit gate** and the FM-000 compatibility criterion are not met:

- The gate asks for "recorded/simulated API tests plus a dedicated real-cluster suite" covering task polling, privilege failures, TLS mismatch, partial-node failure, and resource association. Versioned fixtures exist only for capacity. The only live test is `pin_live.rs`, and the FM-600–603 live checks were run by hand.
- PVE 8.x has not been validated live. This is the recorded FM-S08 deviation, and "passing one major is not a pass."
- Epic #9 promised privilege diagnostics and least-privilege token documentation. Neither landed.
- Windows guests are in M6 scope (lifecycle plus QGA health/IP), but nothing exercises Windows QGA shapes.
- The Proxmox console planned a tasks view (FM-941), but no task-history API exists.

## Branching and agent routing

All M6 acceptance PRs target the **`dev`** branch, not `main`. Each issue has an agent label:

| Label | Work |
|---|---|
| `agent:codex` | Logic, API, provider, storage, test harnesses |
| `agent:claude` | GUI and everything else (docs needing judgment, environment/runbooks, acceptance runs) |
| `agent:glm` | Simple, tightly specified tasks |

## Issues

| Planning ID | Issue | Epic | Agent | Depends on |
|---|---|---|---|---|
| FM-604 Token privilege diagnostics | [#206](https://github.com/Frogbyte-io/fleet-manager/issues/206) | #9 | codex | — |
| FM-605 Least-privilege token guide | [#212](https://github.com/Frogbyte-io/fleet-manager/issues/212) | #9 | claude | FM-604 |
| FM-606 PVE endpoint inventory doc | [#207](https://github.com/Frogbyte-io/fleet-manager/issues/207) | #9 | glm | — |
| FM-607 Recorded 8.x/9.x contract fixtures | [#208](https://github.com/Frogbyte-io/fleet-manager/issues/208) | #10 | codex | — |
| FM-608 Windows guest QGA observations | [#209](https://github.com/Frogbyte-io/fleet-manager/issues/209) | #10 | codex | — (coordinate with FM-607) |
| FM-609 Task history read API | [#210](https://github.com/Frogbyte-io/fleet-manager/issues/210) | #11 | codex | — |
| FM-610 Proxmox console: privileges, compatibility, tasks | [#213](https://github.com/Frogbyte-io/fleet-manager/issues/213) | #11 | claude | FM-604, FM-609 |
| FM-611 Real-cluster acceptance suite | [#214](https://github.com/Frogbyte-io/fleet-manager/issues/214) | #12 | codex | FM-604 (FM-612 soft) |
| FM-612 PVE 8.x host + two-node test cluster | [#211](https://github.com/Frogbyte-io/fleet-manager/issues/211) | #9 | claude | maintainer host access |
| FM-613 Run suite on 8.x/9.x, retire deviation | [#215](https://github.com/Frogbyte-io/fleet-manager/issues/215) | #12 | claude | FM-606, FM-611, FM-612 |
| FM-614 M6 close-out | [#216](https://github.com/Frogbyte-io/fleet-manager/issues/216) | #12 | glm | all of the above |

## Waves

```text
wave 1   FM-604 codex   FM-606 glm   FM-607 codex   FM-609 codex   FM-612 claude
                                     FM-608 codex
            |                                          |               |
wave 2   FM-605 claude   FM-610 claude (604+609)   FM-611 codex (604)
                                                          |
wave 3                                   FM-613 claude (606+611+612)
                                                          |
wave 4                                          FM-614 glm
```

Path conflicts to watch:

- FM-604, FM-607, FM-608, and FM-609 all touch `crates/providers/fleet-provider-proxmox/src/lib.rs`. Each issue names the region it owns. Merge them into `dev` one at a time, and rebase or merge `dev` before opening the next PR.
- FM-604 and FM-609 both add Proxmox API routes and regenerate the OpenAPI/TS client. Regenerate after merging `dev`; never resolve generated files by hand.
- FM-605, FM-612, and FM-613 add docs under `docs/operations/` and `docs/research/` with disjoint files.

## Exit

M6 is complete when FM-613 records a passing suite on PVE 8.x and 9.x (including the two-node partial-failure scenario) and FM-614 closes epics #9–#12. `dev` then merges to `main` through a normal reviewed PR.
