# Toolchain policy

Every version this repository builds with is pinned, and each version appears in
exactly one place. Bumping one is a one-line edit.

## Where each version lives

| Tool | Pinned in | Current | How CI gets it |
|---|---|---|---|
| Rust (rustc, cargo, rustfmt, clippy) | [`rust-toolchain.toml`](../rust-toolchain.toml) `channel` | 1.98.0 | rustup reads the file automatically; the composite action runs `rustup toolchain install` with no toolchain argument |
| Node.js | [`toolchain.env`](toolchain.env) `NODE_VERSION` | 24.19.0 | `actions/setup-node` |
| pnpm | [`toolchain.env`](toolchain.env) `PNPM_VERSION` | 9.15.9 | `corepack prepare` |
| Corepack | [`toolchain.env`](toolchain.env) `COREPACK_VERSION` | 0.35.0 | installed explicitly, not taken from the Node bundle |
| cargo-deny | [`toolchain.env`](toolchain.env) `CARGO_DENY_VERSION` | 0.20.2 | `cargo install --locked` |
| gitleaks | [`toolchain.env`](toolchain.env) `GITLEAKS_VERSION` and `GITLEAKS_SHA256` | 8.30.1 | pinned release archive, checksum verified |

`.github/actions/setup-toolchain` is the only place CI installs any of them. A
job that needs a toolchain uses that action; it never names a version.

## The Rust MSRV

**The MSRV is the `channel` value in `rust-toolchain.toml`. There is no second
copy of it.**

- The MSRV tracks current stable. Fleet Manager ships binaries and a controller
  image rather than a library other people compile against, so there is no
  downstream compiler to accommodate and no reason to hold back.
- Crates do not set `rust-version` in `Cargo.toml`. A second declaration of the
  same number is a second thing to forget; if a published library later needs
  one, add a check that it equals the toolchain file rather than a copy that can
  drift.
- Bumping it is its own pull request: change `channel`, fix whatever new clippy
  lints appear, and land nothing else. A bump bundled into a feature branch
  makes an unrelated review argue about lint churn.
- A bump is deliberate, not automatic. Nothing here follows `stable`.

## Runner images

Jobs run on `ubuntu-latest` and `windows-latest`, which float. This is
intentional: the *toolchains* determine what gets built, and they are pinned;
the runner image determines which kernel and preinstalled utilities are around
it. Pinning to a dated image would trade a rare, visible breakage for a slow
slide into an unsupported image that GitHub eventually removes anyway.

macOS is deliberately absent. The supported baseline in
[docs/PLAN.md](../docs/PLAN.md#supported-platform-baseline) is Linux x86_64
(full checks) and Windows (binary and library compatibility). macOS is deferred,
and a runner for a deferred target produces maintenance without a promise.

## What CI runs, and when it starts running it

CI is one workflow, [`ci.yml`](workflows/ci.yml). Jobs for a workspace are gated
on that workspace existing, detected by a file-existence probe rather than a
glob, so the pipeline is correct on a repository that has neither workspace yet
and starts exercising each one the moment it lands.

| Job | Platform | Gate |
|---|---|---|
| Repository policy | Linux | always |
| Secret scan | Linux | always |
| Legacy Node suite | Linux | a `package-lock.json` at the root or under `legacy/` |
| Rust full checks | Linux x86_64 | a root `Cargo.toml` |
| Rust compatibility checks | Windows | a root `Cargo.toml` |
| Cargo dependency policy | Linux | a root `Cargo.toml` |
| Web workspace | Linux | a `pnpm-workspace.yaml` |
| CI | — | aggregates the above into one required status |

Extending it means adding a step to an existing job, or a job with its own gate.
It should not mean a second pipeline.

## Local use

There are no hidden local steps: every command in CI is a command you can run.

```sh
npm ci                              # install from the lockfile
npm test                            # the legacy Node suite
npm run check:docs                  # documentation links
npm run check:policy                # generated artifacts, licences, CI credentials
npm run test:policy                 # tests for the checks themselves
node .github/scripts/generate.mjs   # refresh a stale generated artifact
```

`check:policy` is the same three commands CI runs as separate steps; it is one
script locally so that it is one thing to remember, and three steps in CI so
that a failure names itself.

One test is quarantined in CI and only there: `waitForTask rejects on timeout`
asserts against a 2 ms wall-clock deadline and fails most runs. `npm test`
locally still runs it, which is the point — it is a real defect, owned by
[#23](https://github.com/Frogbyte-io/fleet-manager/issues/23), not a test to
delete.

Rust and pnpm commands become runnable as their workspaces land; the pinned
toolchains are already in place for them.
