# Inbound dependency policy

Fleet Manager is distributed under [Apache-2.0](../LICENSE). Every dependency we
take on must be redistributable inside an Apache-2.0 work without adding
obligations to downstream users beyond attribution.

This file is the **source of truth** for the allowed license set. The
`[licenses] allow` list in [`deny.toml`](../deny.toml) is generated from the
table below — edit the table, then run:

```sh
node .github/scripts/generate.mjs
```

CI fails if the two disagree, so the machine-enforced list can never drift from
the documented one.

## Allowed inbound licenses

Anything not in this table is denied. There is no "probably fine" tier.

| SPDX identifier | Why it is acceptable inbound |
|---|---|
| `0BSD` | Public-domain-equivalent; no attribution obligation at all. |
| `Apache-2.0` | The project's own license. |
| `Apache-2.0 WITH LLVM-exception` | Apache-2.0 plus an extra grant; strictly more permissive. Used by parts of the Rust standard toolchain ecosystem. |
| `BlueOak-1.0.0` | Permissive with an explicit patent grant; the license npm's own tooling ships under. Enters the graph with the web toolchain (`minimatch`), reviewed in [#34](https://github.com/Frogbyte-io/fleet-manager/issues/34). |
| `BSD-2-Clause` | Permissive; attribution only. |
| `BSD-3-Clause` | Permissive; attribution plus a no-endorsement clause we already honour. |
| `BSL-1.0` | Boost license; permissive and imposes no obligation on binary distribution. |
| `CC0-1.0` | Public-domain dedication. |
| `ISC` | Permissive; attribution only. Used by the current `yaml` dependency of the legacy Node package. |
| `MIT` | Permissive; attribution only. |
| `MPL-2.0` | File-level copyleft. Allowed for **unmodified** upstream files only: modifying an MPL-2.0 file obliges us to publish that file under MPL-2.0. Forking one is a decision, not a drive-by edit. |
| `Python-2.0` | Permissive, attribution-only PSF license. Enters the graph transitively under the pinned `orval` generator (`argparse`), reviewed in [#34](https://github.com/Frogbyte-io/fleet-manager/issues/34). |
| `Unicode-3.0` | Unicode data license used by ICU-derived crates; permissive for both source and binary distribution. |
| `Unicode-DFS-2016` | The older Unicode data license still declared by some crates. |
| `Zlib` | Permissive; no attribution required for binary distribution. |

## Denied, with the usual offenders named

Denial is the default, so this list is documentation rather than configuration.
It exists so that a rejection during review is predictable.

| License family | Why it is rejected |
|---|---|
| `GPL-2.0`, `GPL-3.0` and variants | Strong copyleft. Linking one into `fleetd` or the controller binary would relicense our distribution. `GPL-2.0` is additionally incompatible with Apache-2.0 in both directions. |
| `LGPL-2.1`, `LGPL-3.0` | Weak copyleft with relinking obligations that static Rust binaries cannot satisfy cleanly. |
| `AGPL-3.0` | Adds a network-use source obligation to anyone who operates a controller. |
| `SSPL-1.0`, `BUSL-1.1`, `Elastic-2.0` | Source-available, not open source; field-of-use restrictions. |
| `CDDL-1.0`, `EPL-1.0`, `EPL-2.0` | File- or module-level copyleft whose combination terms with Apache-2.0 are unsettled. |
| `CC-BY-NC-*` and other non-commercial terms | Field-of-use restriction. |
| `OpenSSL` | Advertising-clause lineage and a C dependency we do not want; use `rustls`. |
| No license, `NOASSERTION`, or an unparseable expression | Absence of a grant is not a permissive grant. |

## Exceptions

A per-crate exception is a deliberate, reviewed act, not a workaround for a red
build. To add one:

1. Open an issue describing the crate, the license, the obligation it creates,
   and why no allowed-license alternative exists.
2. Record the decision — including the obligation — in that issue.
3. Add the crate to `[licenses] exceptions` in `deny.toml` with a `reason`.

Exceptions are per-crate and never widen the table above.

## Lockfile policy

Every dependency graph in this repository is committed and installed from a
lockfile. CI installs in frozen mode and never resolves fresh versions:

| Workspace | Lockfile | CI install command | Added by |
|---|---|---|---|
| Repository Node tooling | `package-lock.json` | `npm ci` | present today |
| Legacy Node package | `legacy/agents-registry/package-lock.json` | `npm ci` from that directory | [#23](https://github.com/Frogbyte-io/fleet-manager/issues/23) |
| Cargo workspace | `Cargo.lock` | `cargo build --locked` etc. | [#22](https://github.com/Frogbyte-io/fleet-manager/issues/22) |
| pnpm workspace | `pnpm-lock.yaml` | `pnpm install --frozen-lockfile` | [#30](https://github.com/Frogbyte-io/fleet-manager/issues/30) |

Rules:

- Lockfiles are committed, including `Cargo.lock` for the workspace's binaries
  and libraries alike. This repository ships binaries; a reproducible build
  matters more than the library convention of omitting it.
- CI must fail, not silently update, when a lockfile does not match its
  manifest. `npm ci`, `pnpm install --frozen-lockfile`, and `cargo --locked` all
  do this by default; CI additionally asserts that no install step left a
  lockfile modified.
- A dependency change and the lockfile update that follows from it belong in the
  same commit.

## Dependency and license scanning

| Check | Tool | Scope | Runs |
|---|---|---|---|
| Rust licenses, advisories, banned crates, and source registries | `cargo-deny` (version pinned in [`toolchain.env`](toolchain.env)) | Cargo workspace | Once the Cargo workspace exists ([#22](https://github.com/Frogbyte-io/fleet-manager/issues/22)) |
| npm licenses | `.github/scripts/check-licenses.mjs` | every entry in both committed npm lockfiles | Today |
| pnpm licenses | `.github/scripts/check-licenses.mjs` via `pnpm licenses list --json` | every package in the pnpm workspace graph, devDependencies included ([#34](https://github.com/Frogbyte-io/fleet-manager/issues/34)) | [#34](https://github.com/Frogbyte-io/fleet-manager/issues/34) |
| Secrets | `gitleaks` | full working tree, and full history on `main` | Today |

`cargo-deny` also enforces the non-license halves of this policy: security
advisories from RustSec, banned crates, wildcard version requirements, and
crates sourced from anywhere other than crates.io.

The Node license check reads the `license` field that npm records for every
package in the lockfile. A package with no recorded license fails; see
[Denied, with the usual offenders named](#denied-with-the-usual-offenders-named).

The pnpm graph has no lockfile license fields, so its half of the check runs
`pnpm licenses list --json` against an installed store; the policy job installs
from the frozen lockfile first. devDependencies are in scope on purpose: the
build-time distinction was reviewed in [#34](https://github.com/Frogbyte-io/fleet-manager/issues/34)
and rejected — one global table, no "probably fine" tier.
