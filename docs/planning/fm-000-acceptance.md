# FM-000 — Master plan and ADR acceptance

Status: Accepted
Decided: 2026-08-25
Decided by: repository maintainers
Supersedes: the `proposed for review` status of `docs/PLAN.md` and the `Proposed` status of `docs/adr/0001`–`0008`

This record is the maintainer decision log for [FM-000](initial-issues.md#fm-000--review-and-accept-the-master-plan-and-adr-set). It records what was decided, not what was implemented. Implementation begins at FM-001.

## Decisions

### 1. Project license — Apache-2.0

The repository is licensed under Apache License 2.0. A root `LICENSE` file and a `NOTICE` file were added, and `package.json` declares `"license": "Apache-2.0"`.

Rationale: Apache-2.0 carries an explicit patent grant, which MIT does not, and it is inbound-compatible with the MIT, MPL-2.0, and Apache-2.0 terms of every reuse candidate in the research log. Copyleft was rejected because it would complicate the hosted Fleet Controller option listed under **Later** in the plan.

Consequences:

- Third-party source copied into this repository must be recorded in `NOTICE` with its own terms. Reusing MIT code from Purple (see FM-S05) requires attribution, not relicensing.
- FM-001 must add dependency and license scanning that fails on a license outside the approved inbound set.
- Contributions are accepted under Apache-2.0 §5 without a separate CLA.

### 2. ADR set — all eight accepted, with named spikes

ADRs 0001 through 0008 are `Accepted` as written, dated 2026-08-25. No ADR was modified as a condition of acceptance.

Acceptance does not close the implementation questions inside them. The eight unresolved choices are now named spikes in [spikes.md](spikes.md) and must be created as `type:spike` issues under their owning milestones. FM-S02 is expected to produce ADR-0009 because no existing ADR scopes the authorization engine choice.

Consequences:

- Reversing an accepted decision requires a superseding ADR, not an implementation pull request.
- A spike that fails its preferred option falls back to the recorded alternative without reopening its parent ADR.

### 3. Initial supported platform baseline — Linux x86_64 and Windows

| Platform | Initial scope | Notes |
|---|---|---|
| Linux x86_64 (Debian/Ubuntu) | Primary | Full support: agentless SSH, `fleetd` service, Docker, real integration tests, the controller image |
| Windows | Supported | `fleetd` service, named-pipe local broker, agentless SSH and inventory. Gated on FM-S04 |
| Linux aarch64 | Deferred | Not in the M2 exit gate. Revisit alongside FM-S06, which flags Skills Manager release coverage on non-x86 Linux |
| macOS | Deferred | Remains a design goal in the architecture documents; it is not an M2 acceptance requirement |

Rationale: Windows carries the highest per-platform cost (service model, named pipes instead of Unix sockets, process trees, filesystem permissions), so it is committed deliberately rather than assumed. macOS was deferred because it adds a third service model and a third CI runner class without a current target host.

Consequences:

- The M2 exit gate in `docs/PLAN.md` covers Linux and Windows. This is a scope reduction against the plan as originally written, which named macOS.
- FM-214 is added to M2 for Windows service packaging. Without it the chosen baseline cannot meet its own exit gate.
- Architecture documents still describe macOS as a supported target. That is intentional: cross-platform assumptions must not be designed out of the protocol, config, and filesystem layers just because macOS ships later.
- Deferred does not mean rejected. Adding a platform later needs a plan update, not an ADR.

### 4. Proxmox VE compatibility target — 8.x and 9.x

The M6 compatibility matrix and the real-cluster test suite target PVE 8.x and 9.x.

Rationale: 9.x is current and 8.x is still widely deployed. Two majors is the smallest matrix that does not force an operator upgrade as a precondition for adopting Fleet.

Consequences:

- FM-S08 must produce evidence against both majors before the Proxmox client choice is made. Passing on one major is not a pass.
- Version-specific API differences belong behind the provider boundary and must not leak into `fleet-core`.

### 5. Issue triage

- Issues #2 and #3 are superseded by this plan. Milestones M0–M8 were created first, then the twelve replacement epics that link back to them, then both issues were closed as superseded on 2026-08-25:
  - #2 (declarative fleet/machine/agent environment) → #5, #6, #7, #8 (M4) and #13 (M7).
  - #3 (Proxmox lifecycle and USB passthrough) → #9, #10, #11, #12 (M6) and #13, #14, #15, #16 (M7).
  - Merged PR #4 implemented the proof of concept described by #2. That code is legacy migration input, not the target architecture.
- Closed issue #1 described the correct Skills Manager boundary. It stays closed; FM-S06 and the M3 Skills Manager epic carry its intent forward against the current public CLI contract.

### 6. Milestone and epic ownership

Milestones M0–M8 and their epics follow `docs/PLAN.md#recommended-github-milestones-and-epic-issues` without change. Each epic is a tracking issue holding only dependency and status checklists; implementation stays in narrow linked issues.

Only the twelve epics needed to supersede #2 and #3 were created (M4, M6, M7). The M0–M3, M5, and M8 epics are created when their milestone starts, so they reflect what the preceding milestones taught rather than what was guessed on day one. The M0–M2 implementation issues already exist in [initial-issues.md](initial-issues.md) and are copied to GitHub at that point.

## Open items not decided here

These were out of FM-000's scope and are decided by the issues that consume them:

- Rust MSRV and pinned toolchain versions — FM-001.
- Whether the legacy `agents-registry` executable name is preserved for existing installs — FM-003.
- Hosted Fleet Cloud licensing and any dual-licensing arrangement — deferred until that product is real.

## Acceptance criteria evidence

| Criterion | Evidence |
|---|---|
| Maintainer decisions are recorded | This document |
| ADR statuses match decisions | `docs/adr/0001`–`0008` are `Accepted`; `docs/adr/README.md` table matches |
| A root project license is selected and added | `LICENSE` (Apache-2.0), `NOTICE`, `package.json` |
| Unresolved choices have named spike issues | [spikes.md](spikes.md), FM-S01 through FM-S08 |
| #2/#3 closed as superseded after replacement epics link back | Milestones M0–M8 and epics #5–#16 created, then #2 and #3 closed as superseded on 2026-08-25 |
| Documentation links and Markdown checks | `npm run check:docs` |
