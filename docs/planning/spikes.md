# Named spikes

[FM-000](fm-000-acceptance.md) accepted the master plan and ADR set. Accepting an ADR fixes a boundary; it does not choose every library, protocol detail, or upstream contract inside that boundary. This register names each unresolved choice so it is tracked work rather than an implicit assumption in a later pull request.

A spike ends with an evidence package and a recorded decision — a section in `docs/research/ecosystem.md`, an ADR, or an update to the issue that consumes it. A spike never merges production code disguised as research.

Each spike must be created as a GitHub issue with the `type:spike` label under its owning milestone. IDs are stable planning references, not GitHub issue numbers.

| ID | Question | Milestone | Constrained by | Consumed by | Fallback if the preferred option fails |
|---|---|---|---|---|---|
| FM-S01 | Which Rust OpenAPI toolchain and TypeScript generator produce a reproducible spec and a compiling client from Axum handlers? | M0 | ADR-0002 | FM-006 | Hand-maintained OpenAPI document with a generated client and a spec-drift guard in CI |
| FM-S02 | When authenticated deployment is introduced, is Cedar the right embedded authorization engine for Fleet's permission, resource, tag, and project policies? | M8 | — (expected to produce ADR-0009) | Authenticated deployment epic | Native Rust permission catalog with deny-by-default checks and no external policy language |
| FM-S03 | Can Effectum execute durable operations without owning Fleet's Operation domain records? | M1 | ADR-0008 | FM-109 | Purpose-built SQLite-backed worker over the existing Operation table |

Spike outcomes:

- **FM-S03 (resolved 2026-09-03, fallback chosen).** Effectum 0.7.0 embeds its
  own SQLite database with its own schema, migrations, connection pool
  (rusqlite/deadpool), and job-state records. Using it for durable operations
  would put every operation's lifecycle in two places — Effectum's job rows and
  Fleet's `operations` rows — with no shared transaction to keep them
  consistent, which is the ownership split ADR-0008 forbids. What it offers in
  exchange (exponential retries, cron/recurring schedules) is either classified
  unsafe for Fleet semantics or an explicit non-goal of the first release. The
  purpose-built claim/complete loop over the existing table keeps one database,
  one transaction boundary, and one state machine.
| FM-S04 | How does `fleetd` install as a Windows service, expose a named pipe, and authenticate a local peer at least as strictly as Unix socket peer credentials? | Later Windows in-guest slice | ADR-0003 | Windows `fleetd`/project-readiness epic | Keep Windows support at Proxmox lifecycle and QEMU Guest Agent observation until the broker can be secured |
| FM-S05 | Is `purple_ssh` reusable as a dependency, as extracted MIT code with attribution, or only as a reference implementation? | M2 | ADR-0005 | FM-201, FM-202 | Direct system OpenSSH invocation using Purple's tested behaviour as a reference only |
| FM-S06 | Does `skills-manager-cli --json` cover agents, skills, presets, deploy/undeploy, and update status on both supported platforms, and which version range is pinned? | M3 | ADR-0005 | M3 Skills Manager epic | Degrade to detection and status only, and open an upstream contract request |
| FM-S07 | Which Frogenv commands can run non-interactively with machine-readable output, and which approval ceremonies must stay manual? | M3 | ADR-0005 | M3 Frogenv epic | Report `blocked: manual approval required` and hand off to the operator |
| FM-S08 | Does the experimental `proxmox-client` crate satisfy authentication, UPID task polling, custom TLS trust and pinning, unknown-field tolerance, and cancellation against PVE 8.x and 9.x? | M6 | ADR-0005 | M6 Proxmox epic | Small `reqwest` transport plus typed provider DTOs, borrowing Purple's parsing patterns |
| FM-S09 | Which Packer/Proxmox-plugin version range supports modern `.pkr.json`, required template builds, stable machine-readable diagnostics, cancellation, and acceptable redistribution/deployment terms? | M7 | ADR-0005 | Image recipe/build/version epic | Require an operator-installed supported CLI and keep the image-build port available for another implementation |

## Rules

- A spike is blocking only for the issues in its **Consumed by** column. Unrelated work in the same milestone proceeds.
- Every spike must record the fallback it rejected and why, so a later reviewer can see the option was tested rather than forgotten.
- Never accept invalid TLS certificates, an unauthenticated local broker, or a bypassed approval ceremony as a spike outcome. Those are fallbacks that reduce scope, not fallbacks that reduce security.
- Refresh the relevant section of [../research/ecosystem.md](../research/ecosystem.md) at the start of each spike; the research log records versions and commits that go stale.
