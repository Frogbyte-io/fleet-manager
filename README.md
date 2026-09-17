# fleet-manager

A persistent, controller-first **developer fleet control plane**: one controller
manages your development machines — onboarding, identity, operations, skills,
secrets, and projects — through a web UI, a CLI (`fleetctl`), and an MCP server.

> **Status:** the controller-first architecture is under active development.
> The canonical roadmap is [docs/PLAN.md](docs/PLAN.md), accepted on 2026-08-25
> along with [the ADR set](docs/adr/README.md). The Node.js `agents-registry`
> package preserved under [`legacy/agents-registry/`](legacy/agents-registry/) is
> the **legacy** proof of concept and migration input, not the target
> architecture.

## What it does

- **Onboarding** — enroll a machine with a one-shot install token; the node
  installs `fleetd`, joins the tailnet, and reports its facts.
- **Operations** — audit-authorized, idempotent operations (install node
  packages, run guarded exec, apply recipes) executed by a worker with lease
  renewal, CAS-based claim safety, and drain-on-shutdown semantics.
- **Projects** — per-machine Git checkouts keyed by a normalized remote with a
  documented grammar that refuses credential-bearing remotes.
- **Secrets** — encrypted secret sharing across machines via
  [frogenv](https://github.com/Frogbyte-io/frogenv); secrets never appear in
  Fleet Git, logs, audit metadata, job payloads, or command output.
- **Auth** — every mutation flows through a centralized authorization catalog
  (23 permission entries) and produces an audit event.

## How it's wired up

- **`crates/`** — the Rust workspace: `fleet-core` (domain), `fleet-application`
  (use cases), `fleet-api` (HTTP surface), `fleetctl` (CLI), `fleet-controller`
  (worker + onboarding controllers), `fleetd` (node agent), `fleet-auth`,
  `fleet-config`, `fleet-protocol`, `fleet-secrets`, `fleet-storage-sqlite`, and
  provider adapters under `crates/providers/`.
- **`apps/web`** — the Vue web UI.
- **A data repo you own** — your fleet's machine/role/project data lives in a
  separate repo you point Fleet Manager at, not in this one.
- **A secrets store you own** — credentials live in frogenv or another secret
  manager, never in the data repo or this one.

## Building and verifying

After installing the pinned tools described in
[`.github/toolchain-policy.md`](.github/toolchain-policy.md), run the same root
verification command used by CI:

```bash
cargo xtask verify
```

It checks Rust formatting, linting, and tests, then installs the pnpm workspace
from its lockfile and runs every package's lint, type-check, test, and build
scripts, plus the policy scripts and a Compose smoke check. The command stops at
the first failed step and prints the exact failing command.

## Repository map

- Product direction and milestones: [`docs/PLAN.md`](docs/PLAN.md)
- Architecture boundaries and invariants: [`docs/architecture/`](docs/architecture/)
- Decisions requiring explicit review: [`docs/adr/`](docs/adr/)
- Issue-ready work: [`docs/planning/initial-issues.md`](docs/planning/initial-issues.md)
- Agent working rules: [`AGENTS.md`](AGENTS.md)
- Web GUI design system: [`DESIGN.md`](DESIGN.md)

## Security

Fleet Manager treats remote execution, Docker access, hypervisor changes,
recipes, skills, and project scripts as privileged or untrusted operations. All
mutations require centralized authorization and emit an audit event. See
[`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE). Third-party
source copied into this repository must be attributed in `NOTICE` under its own
terms.
