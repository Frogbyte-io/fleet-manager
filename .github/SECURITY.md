# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's
[security advisory](https://github.com/Frogbyte-io/fleet-manager/security/advisories/new)
form. Do not open a public issue, and do not include live credentials in the
report — a description of where the credential came from is enough.

Fleet Manager controls machines and holds the credentials used to reach them, so
a report about credential handling, authorization, or the node protocol is
in scope even when it needs an existing foothold to exploit.

## Secrets never enter this repository

`AGENTS.md` states the rule for the product: no secrets in Fleet Git, logs,
audit metadata, job payloads, fixtures, or command output. This file covers the
repository and its pipeline.

- **Scanning.** Every CI run scans both the working tree and the full commit
  history with `gitleaks`. History is scanned on every run rather than only on
  `main`, because the commit that introduces a credential is the one worth
  catching, not the merge that buries it. The configuration is
  [`gitleaks.toml`](gitleaks.toml); it extends the upstream ruleset instead of
  replacing it, and narrows exactly one rule in exactly one directory, with the
  reason written next to it.
- **If the scan finds a real credential:** rotate it first. A commit that
  removed it is not a fix — it is still in the history and in every clone and
  fork. Removing it from history comes after rotation, if at all.
- **Push protection.** Repository-level secret scanning and push protection are
  GitHub settings, not files, so they cannot be enforced from this repository.
  They are expected to be on; the CI scan is the backstop for what slips past.

## CI holds no deployment credentials

This pipeline builds and checks. It does not publish, sign, or deploy — those
are explicit non-goals of [#21](https://github.com/Frogbyte-io/fleet-manager/issues/21),
and when release automation arrives it gets its own workflow, its own trigger,
and its own scoped credentials rather than a secret added to this one.

The property is enforced, not just stated, by
[`scripts/check-workflows.mjs`](scripts/check-workflows.mjs), which fails the
build if a workflow:

- references any secret other than `secrets.GITHUB_TOKEN`, the ephemeral
  per-run token;
- omits a top-level `permissions` block, which would silently inherit the
  repository default;
- grants a write permission other than `contents`, at the workflow level or
  on any single job — `packages: write` and `id-token: write` are how a
  publish or a cloud deploy gets its credentials, and neither leaves a
  stored secret behind to grep for;
- uses the `pull_request_target` trigger, which runs with a writable token
  against code a fork controls;
- or refers to a third-party action by a mutable tag.

`ci.yml` declares `permissions: contents: read` and asks for nothing more.

## Third-party actions are pinned to commits

Actions published by `actions/` and `github/` are used by major tag. Everything
else must be pinned to a full 40-character commit SHA, because a tag can be
moved to point at different code after review.

Tools that are not actions — `gitleaks`, `cargo-deny` — are pinned by version in
[`toolchain.env`](toolchain.env). `gitleaks` is additionally verified against a
recorded SHA-256 of its release archive, since it is downloaded rather than
built from a registry that records its own hashes.

## Dependencies

The inbound license set, the lockfile rules, and the scanning tools are in
[`dependency-policy.md`](dependency-policy.md).
