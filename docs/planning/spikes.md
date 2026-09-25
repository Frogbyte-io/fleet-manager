# Named spikes

[FM-000](fm-000-acceptance.md) accepted the master plan and ADR set. Accepting an ADR fixes a boundary; it does not choose every library, protocol detail, or upstream contract inside that boundary. This register names each unresolved choice so it is tracked work rather than an implicit assumption in a later pull request.

A spike ends with an evidence package and a recorded decision — a section in `docs/research/ecosystem.md`, an ADR, or an update to the issue that consumes it. A spike never merges production code disguised as research.

Each spike must be created as a GitHub issue with the `type:spike` label under its owning milestone. IDs are stable planning references, not GitHub issue numbers.

| ID | Question | Milestone | Constrained by | Consumed by | Fallback if the preferred option fails |
|---|---|---|---|---|---|
| FM-S01 | Which Rust OpenAPI toolchain and TypeScript generator produce a reproducible spec and a compiling client from Axum handlers? | M0 | ADR-0002 | FM-006 | Hand-maintained OpenAPI document with a generated client and a spec-drift guard in CI |
| FM-S02 | When authenticated deployment is introduced, is Cedar the right embedded authorization engine for Fleet's permission, resource, tag, and project policies? | M8 | — (expected to produce ADR-0011) | Authenticated deployment epic | Native Rust permission catalog with deny-by-default checks and no external policy language |
| FM-S03 | Can Effectum execute durable operations without owning Fleet's Operation domain records? | M1 | ADR-0008 | FM-109 | Purpose-built SQLite-backed worker over the existing Operation table |

Spike outcomes:

- **FM-S05 (resolved 2026-09-03, fallback chosen).** \`purple-ssh\` on crates.io
  (3.23.0, MIT) is a bin+lib TUI application — roughly 154K lines, 190
  releases of fast churn, zero dependents — whose module surface includes the
  whole terminal UI (tui, tui_loop, animation, fuzzy, clipboard, demo, 18
  cloud providers). Depending on it would pull the application, not an SSH
  library, into the controller. Its own \`ssh_launcher\` module confirms the
  approach Fleet already planned: it runs the system \`ssh\` binary rather
  than implementing SSH in Rust. Fleet therefore invokes system OpenSSH
  directly with an isolated config/known-hosts directory, using Purple's
  round-trip config handling and cancellation behaviour as a reference only.
  No code was extracted; MIT attribution in NOTICE remains open if specific
  modules are later borrowed.

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
| FM-S10 | What changed in the Skills Manager v1.34.2→v1.40.0 public CLI contract, and can Fleet roll out authored content or read local skills without a new upstream API? | M3 | ADR-0005 | FM-920–923 | Pin one tested release; keep Fleet-authored content in Fleet storage and use only documented local install/update operations |

- **FM-S09 (resolved 2026-09-22, fallback confirmed).** Packer 1.16.1 with the
  MPL-2.0 `packer-plugin-proxmox` v1.2.4 covers everything Fleet needs — modern
  HCL2 templates, every builder field the recipes require, stable
  `-machine-readable` output, and self-cleaning interrupted builds (verified
  live: a timed-out clone build stopped and deleted its own VM, no orphan on
  the host). Packer is BUSL 1.1: production use is granted to a self-hosted
  controller invoking an operator-installed binary, but Fleet must never
  bundle or redistribute the binary — that would be embedding. The fallback is
  therefore confirmed, not merely chosen: **operator-installed Packer, pinned
  `packer >= 1.15 < 2` and `proxmox >= 1.2.4 < 2`, checksum-verified, and the
  image-build port kept open.** One integration trap recorded: `proxmox_url`
  must include `/api2/json`, or the Telmate client paths break with a
  misleading `500 no such file` error. Evidence and the rejected options:
  [research/ecosystem.md](../research/ecosystem.md#image-building-packer-and-the-proxmox-plugin).

- **FM-S08 (resolved 2026-09-20, fallback chosen).** The typed
  `proxmox-client` crate (crates.io, `landrzejewski`, 0.9.2) failed the
  spike's security gate: its entire TLS surface is
  `accept_invalid_certs(bool)` — no fingerprint-pinning hook and no custom
  trust store — while PVE hosts present their own cluster CA, so every
  working configuration either disables verification (forbidden) or pins
  outside the crate. Everything else passed: token auth, UPID status/log/stop,
  broad QEMU/LXC/cluster/storage coverage, and genuinely tolerant decoding of
  loose/null shapes. Supply-chain weight told the same story: 3 commits, 3
  releases in one week, zero stars, 591 downloads, one maintainer, and a
  reqwest 0.13 + aws-lc-rs TLS stack duplicating the workspace's reqwest 0.12
  + ring. The fallback — a small `reqwest` transport with a custom rustls
  verifier that pins the leaf certificate's SHA-256 fingerprint and refuses
  mismatched hosts at the handshake — was proven live against the PVE 9.2
  integration host, positive and negative case, using the same TLS stack
  Fleet already standardizes on. Evidence and the rejected alternatives:
  [research/ecosystem.md](../research/ecosystem.md#fm-s08-proxmox-client-compatibility-spike).
  The PVE 8.x leg of the both-majors acceptance criterion is a recorded
  deviation: no 8.x host is reachable in the integration environment, so 8.x
  evidence is the endpoint/auth/task-shape documentation from the PVE 8.x API
  archive, and the live 8.x validation moves to the M6 real-cluster suite.
  The spike's decisive evidence is TLS behavior, which is client-side and
  version-independent.

- **FM-S10 (resolved 2026-09-25, existing CLI contract is sufficient).** The
  v1.34.2 and v1.40.0 Linux x64 binaries both expose the required `skills`
  and `presets` command groups, including local install/update, show/export,
  explicit deployment, status, and machine-readable errors. v1.40.0's
  `skills update` re-imports `local`/`import` skills from their recorded source
  directory while preserving the skill's identity and deployment metadata;
  removal of paths absent from the new source is reported as
  `held_back_removals` and cannot be approved through the CLI. Same-path edits
  can still be replaced, so Fleet must own the staged source and treat it as
  authoritative. `skills show --json` returns the SKILL.md body (`markdown`),
  file lists, and absolute paths; `skills export --dest` exports content to a
  caller-selected directory. Fleet's current reads do not need either path:
  FM-920 explicitly excludes reading machine-local skill content, while
  FM-922 owns its source content in Fleet storage. No upstream content API
  request is needed now. A future read requirement should first define a
  bounded, path-neutral response rather than consuming absolute machine paths.

  Both investigated releases are MIT. v1.40.0 publishes Linux x64 and Linux
  arm64 CLI assets; the earlier v1.34.2 release had Linux x64 but no Linux
  arm64 CLI asset. The spike executed the x64 binaries only. Start Fleet's
  provider at the exact verified `=1.40.0` release, verify its published
  SHA-256, and refresh the fixtures before expanding the accepted version
  range. Raw help and invalid-argument JSON captures are in
  [the candidate CLI fixtures](../research/fixtures/skills-manager-cli-v1.40.0-help.txt)
  and the sibling v1.34.2 files. See the
  [full evidence and decision](../research/ecosystem.md#fm-s10-skills-manager-v140-contract-refresh).

## Rules

- A spike is blocking only for the issues in its **Consumed by** column. Unrelated work in the same milestone proceeds.
- Every spike must record the fallback it rejected and why, so a later reviewer can see the option was tested rather than forgotten.
- Never accept invalid TLS certificates, an unauthenticated local broker, or a bypassed approval ceremony as a spike outcome. Those are fallbacks that reduce scope, not fallbacks that reduce security.
- Refresh the relevant section of [../research/ecosystem.md](../research/ecosystem.md) at the start of each spike; the research log records versions and commits that go stale.
