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

## Supported versions

Only the latest `main` branch is supported; releases are cut from it.
