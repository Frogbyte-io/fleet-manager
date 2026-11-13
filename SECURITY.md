# Security Policy

## Reporting a vulnerability

Do **not** open a public GitHub issue for security problems.

Report privately via [GitHub Security Advisories](https://github.com/Frogbyte-io/fleet-manager/security/advisories/new)
("Report a vulnerability"). Include a description, reproduction steps, and the
affected version or commit if you can.

You can expect an initial response within 7 days. We will credit reporters in
the fix release unless you ask to stay anonymous.

## Scope

Fleet Manager treats the following as **privileged or untrusted operations**:
remote execution on managed machines, Docker access, hypervisor (Proxmox)
changes, recipes, skills, and project scripts. Issues in how these are
authorized, sandboxed, or audited are high priority.

In scope:

- Authorization bypasses (mutations must flow through the centralized authz
  catalog and emit audit events)
- Secret leakage into Fleet Git, logs, audit metadata, job payloads, or command
  output
- The node agent (`fleetd`) trust model: install tokens, enrollment, and
  command execution boundaries
- The API and CLI surfaces (`fleet-api`, `fleetctl`), including injection via
  job payloads or project remotes
- The worker lease/claim machinery (`fleet-controller`)

Out of scope:

- Vulnerabilities in third-party dependencies that are not exploitable through
  Fleet Manager (report those upstream; we track them via `cargo deny`)
- The legacy `legacy/agents-registry/` package (it is migration input, not the
  target architecture) — reports are still welcome, but fixes are best-effort
- Your own deployment misconfiguration (e.g. exposing the controller to the
  internet without transport authentication)

## Verifying a release

Releases published after build provenance was added carry a signed
attestation for each `fleetctl` asset from the release workflow. Earlier
releases, such as `v0.1.0-482fd9c`, have none; for those, the `SHA256SUMS`
check is the only one. Check a download with the GitHub CLI:

```sh
gh attestation verify fleetctl-linux-x86_64 --repo Frogbyte-io/fleet-manager \
  --signer-workflow Frogbyte-io/fleet-manager/.github/workflows/release.yml \
  --source-ref refs/heads/main
```

`--signer-workflow` and `--source-ref` require the release workflow running
on `main`; `--repo` alone accepts an attestation from any workflow in the
repository. They need `gh` 2.102.0 or newer: the flags arrived in 2.51.0
(`--signer-workflow`) and 2.68.0 (`--source-ref`), but before 2.97.0 the
signer value was matched as an unescaped regular expression
([GHSA-mm27-mwq9-fr5g](https://github.com/cli/cli/security/advisories/GHSA-mm27-mwq9-fr5g)),
and before 2.102.0 `--signer-workflow` matched only the start of the signing
workflow's identity and `--source-ref` ignored case
([GHSA-wjmr-j3rp-mh2g](https://github.com/cli/cli/security/advisories/GHSA-wjmr-j3rp-mh2g),
[GHSA-4mq3-hpgx-9cx8](https://github.com/cli/cli/security/advisories/GHSA-4mq3-hpgx-9cx8)),
so an older `gh` can accept an attestation from another workflow or branch.

The full install and verification steps are in
[`deploy/README.md`](deploy/README.md#install-fleetctl). Why the release job
holds the extra permissions this needs is in
[`.github/SECURITY.md`](.github/SECURITY.md#the-release-provenance-exception).

## Supported versions

Only the latest `main` branch is supported; releases are cut from it.
