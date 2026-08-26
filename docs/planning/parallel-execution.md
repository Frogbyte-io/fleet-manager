# Parallel execution

Fleet Manager issues are written so several agents or contributors can work at once. Concurrency is limited by two things: the dependency graph, and which files an issue is allowed to write. This document defines both.

An issue is safe to start when every issue in its **Depends on** list is merged, and no other in-flight issue owns the paths it needs to write.

## M0 execution waves

M0 is front-loaded and serial: FM-001 and the workspace scaffolds gate everything else. Maximum useful concurrency is three agents, reached in waves 3 and 4.

```text
wave 1   FM-001 toolchains/CI          FM-S01 OpenAPI spike
             |                              |
wave 2   FM-002 Cargo ---- FM-002B pnpm/Vue |
             |     \            |     \      |
wave 3   FM-003   FM-004      FM-002C  |    |
          legacy   core          verify |    |
                     |                  |    |
wave 4   FM-005 schemas   FM-007 proto   FM-006 API <-+
                                            |
wave 5                                   FM-008 image/Compose
```

| Wave | Issues | Concurrency | Notes |
|---|---|---|---|
| 1 | FM-001, FM-S01 | 2 | FM-S01 needs nothing; it can run from a throwaway project |
| 2 | FM-002, FM-002B | 2 | Disjoint file sets; the split exists to make this wave parallel |
| 3 | FM-003, FM-004, FM-002C | 3 | FM-002C needs both scaffolds; FM-003 and FM-004 need only FM-002 |
| 4 | FM-005, FM-006, FM-007 | 3 | All need FM-004; FM-006 additionally needs FM-S01 and FM-002B |
| 5 | FM-008 | 1 | Needs FM-006 and a host with Docker |

FM-002 was split from a single issue precisely because five issues waited on it and its two halves share no files.

## Path ownership

Every issue declares the paths it owns. Only the owning issue creates or edits files under them while it is in flight.

| Owned path | Owner |
|---|---|
| `.github/`, `rust-toolchain.toml`, `deny.toml`, lockfile policy | FM-001 |
| `Cargo.toml` (root), `crates/**` skeletons | FM-002 |
| `pnpm-workspace.yaml`, `apps/web/**`, `packages/ui/**` | FM-002B |
| `xtask/**`, the root verification command | FM-002C |
| `legacy/**`, and the move of `src/`, `bin/`, `test/` | FM-003 |
| `crates/fleet-core/**` | FM-004 |
| `schemas/**` | FM-005 |
| `crates/fleet-api/**`, `packages/api-client/**` | FM-006 |
| `proto/**`, `crates/fleet-protocol/**` | FM-007 |
| `deploy/**`, controller `Dockerfile` | FM-008 |

Paths not listed are unowned. Claim one in the issue before writing to it.

## Shared files

Three files are edited by many issues and cannot be exclusively owned:

- Root `Cargo.toml` `[workspace] members`
- `pnpm-workspace.yaml` package globs
- `package.json` `scripts`

The protocol for all three: **append your own line, change nothing else.** A one-line addition merges cleanly. Reordering, reformatting, or "tidying while I'm here" turns every concurrent branch into a conflict. If an issue needs to restructure one of these files, it says so explicitly and runs alone.

## Handoff contracts

An issue that unblocks others states what it guarantees on completion, so downstream work can be written against the guarantee rather than against the implementation:

- **FM-001** guarantees pinned toolchain versions and a CI entry point that later jobs extend.
- **FM-002** guarantees every crate in the layout exists, compiles, and has its dependency direction declared.
- **FM-002B** guarantees the Vue workspace builds and emits a static shell to a documented output directory.
- **FM-004** guarantees the ID, time, error, and secret-reference types that every later crate imports.
- **FM-S01** guarantees a named OpenAPI toolchain and TypeScript generator, with the rejected options recorded.

## Rules for concurrent agents

- Work on one issue per branch. Branch from current `main`, not from another agent's branch.
- Do not fix problems you notice outside your owned paths. Open an issue or leave a note on the relevant one. An unrelated drive-by fix in a shared file is the most common cause of a conflicted merge.
- If your issue turns out to need a file another in-flight issue owns, stop and coordinate rather than editing it. Overlapping ownership is a planning error worth surfacing.
- Re-read `AGENTS.md` before implementing. It constrains every issue and is not repeated in issue bodies.
- A blocked issue reports as blocked. Do not substitute adjacent work to appear productive; that produces changes nobody reviewed against an acceptance criterion.
