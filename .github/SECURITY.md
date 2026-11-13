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
  replacing it. Each exception narrows named rules to named paths or to exact
  placeholder values used by tests, with the reason written next to it; no rule
  is turned off for the whole tree.
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
  stored secret behind to grep for (the one exception is below);
- uses the `pull_request_target` trigger, which runs with a writable token
  against code a fork controls;
- or refers to a third-party action by a mutable tag.

`ci.yml` declares `permissions: contents: read` and asks for nothing more.

### The release provenance exception

[`workflows/release.yml`](workflows/release.yml) is the release automation
this section anticipated: its own workflow, triggered by a push to `main`,
holding only the per-run `GITHUB_TOKEN`. Its `publish` job, and only that job,
also holds `id-token: write` and `attestations: write` (approved by the
maintainer on 2026-11-07). It uses them to sign a
[build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)
for each `fleetctl` binary and `SHA256SUMS` before it publishes them:

- `id-token: write` lets the job request a GitHub OIDC token, which Sigstore
  exchanges for a short-lived signing certificate naming this repository,
  workflow, and commit. No key is stored anywhere.
- `attestations: write` stores the signed attestation on this repository, where
  `gh attestation verify` finds it.

The attestation lets someone who downloaded a binary check that this
workflow built it from a commit on `main`, which `SHA256SUMS` alone cannot
show: the checksum file comes from the same release as the binary. That
claim holds only when the check pins the signer and the ref, with `gh`
2.102.0 or newer (older versions match both flags loosely; see
[Verifying a release](../SECURITY.md#verifying-a-release)):

```sh
gh attestation verify fleetctl-linux-x86_64 --repo Frogbyte-io/fleet-manager \
  --signer-workflow Frogbyte-io/fleet-manager/.github/workflows/release.yml \
  --source-ref refs/heads/main
```

`--repo` alone accepts an attestation signed by any workflow in this
repository, on any branch, so it does not show that this workflow built the
file.

`check-workflows.mjs` lists the exception by workflow path and job id
(`JOB_WRITE_EXCEPTIONS`). The same two scopes in any other workflow, in
another job of `release.yml`, or at its workflow level still fail the build,
and the exception grants no other scope. Widening it needs the same explicit
approval. Because the action that signs runs with that OIDC token,
`actions/attest-build-provenance` is pinned to a full commit SHA, although
`actions/` actions may otherwise be used by major tag.

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
