# ADR 0017: Agents reach machines through a brokered SSH session with Fleet-held keys

Status: Proposed

Proposed: 2026-10-22 (tracking issue [#493](https://github.com/Frogbyte-io/fleet-manager/issues/493)). Proposed for maintainer review. It extends the SSH transport of [ADR 0005](0005-provider-and-external-cli-boundaries.md) and the Windows guest shell of [ADR 0015](0015-windows-lab-guest-transport.md), and uses the encrypted secret store of [ADR 0004](0004-state-and-secret-ownership.md); it reverses none of them. It is the access model [#489](https://github.com/Frogbyte-io/fleet-manager/issues/489) (persistent VMs with a Fleet-generated key) builds on.

## Context

Fleet can create a VM and keep its private SSH key in the encrypted secret store, never returned by the API. An agent still cannot work on that VM:

- SSH endpoints authenticate with `--auth agent` (the controller's `SSH_AUTH_SOCK` and default key files) or `--auth identity-file --identity <path>` (a file on the controller). Neither can use a key held as a Fleet secret.
- There is no general command execution on a non-Lab machine. `lab exec` works on leases, and `mise exec` and `frogenv run` are scoped to a project root.

The question is how an agent or operator reaches a machine with a credential Fleet holds, without ever receiving the private key.

## Options

### (a) Brokered: the controller holds the key and runs the session

The caller asks the controller to run a command, put a file, or collect a file. The controller resolves the stored key just in time, runs `ssh` itself over the verified endpoint, and returns bounded, redacted output.

- Every command passes centralized authorization (`machines.exec`, `machines.put`, `machines.collect`, scoped to the machine) and is audited, with the command digest and never the command text, which may carry secrets.
- Revocation takes effect on the next command: deleting the secret record stops every use of the key (the executor re-resolves it for each session), clearing the endpoint's default auth stops callers that rely on the default, and taking `machines.exec` away from a principal stops that principal. Nothing persists on the caller's machine.
- A restricted agent "cannot read secrets" (the M8 goal, [security.md](../architecture/security.md)) holds by construction: the key never leaves the controller process and a 0600 file that lives for one session.
- It reuses what exists: the verified-endpoint trust gate and `known_hosts` pinning, the bounded exec path (output caps, deadline, cancellation, scrubber), the Lab put and collect implementations, and the ADR 0015 PowerShell layer for Windows.
- Cost: every byte and every command crosses the controller, and there is no interactive terminal. Heavy interactive use (an editor over SSH, port forwarding) is not served.

### (b) Short-lived credentials: Fleet signs an SSH user certificate

Fleet runs an SSH certificate authority and issues a certificate (or a temporary key pair) with a principal and a TTL, so the agent's own machine connects directly. OpenSSH supports this with `ssh-keygen -s` and the server's `TrustedUserCAKeys` and `AuthorizedPrincipalsFile` ([ssh-keygen(1) CERTIFICATES](https://man.openbsd.org/ssh-keygen#CERTIFICATES), [sshd_config(5)](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)).

- Faster for heavy interactive use, and the controller is not in the data path.
- Needs the CA public key and an authorized-principals mapping on every guest (image changes, plus a rollout for existing machines), moves trust off the controller (a leaked certificate works until it expires, and OpenSSH revocation needs a `RevokedKeys` file on every guest), and requires writing a credential into the agent's own `~/.ssh`, which is a different trust and consent decision.
- The CA private key becomes the most valuable secret Fleet holds.

## Decision

1. **Option (a) ships first.** Agents and operators reach machines through the controller. The private key is never returned by any API, CLI output, operation payload, result, log, or audit event.
2. **Option (b) is a possible later addition, not rejected.** If heavy interactive use justifies a CA on every guest, it gets its own issue and ADR and keeps (a) as the default path. Writing into the agent's `~/.ssh` belongs to that issue only.
3. **Stored-key authentication.** An SSH endpoint can authenticate with a Fleet secret: `EndpointAuth::Secret { credential }`. The reference is a secret-record id in the `machines/ssh/` namespace (created by #489) or in the `git/` namespace (the existing Fleet SSH credential references of `desired source credential`). Any other record never resolves, so a reference cannot reach a Proxmox token or another integration's secret.
4. **Just-in-time key delivery.** The executor resolves the key at the moment of the session, and the SSH provider writes it to a mode-0600 file in a mode-0700 directory under its work directory, offered with `IdentitiesOnly yes`. A guard removes the file after success, failure, deadline kill, and cancellation, and the directory is emptied when the provider starts. The key type's `Debug` and the operation payload never contain the key; a payload carries the reference only. An agent socket was considered and not chosen: a per-session `ssh-agent` adds a process lifecycle without protecting against anything the private directory does not. Passphrase-protected keys are unsupported (the session is non-interactive).
5. **Default auth per endpoint.** An endpoint can record its default auth, so callers do not repeat `--auth` and the credential. The application layer exposes `set_endpoint_default_auth(machine, endpoint, auth | none)`, authorized by `machine.update` and audited; #489 calls it when it switches an endpoint to the new key. A caller's explicit auth overrides the default. With neither, a machine command is refused: there is no implicit fall back to the controller's agent, because the controller's ambient keys are not the machine's credential.
6. **A distinct privileged command kind.** `machine.exec`, `machine.put`, and `machine.collect` are durable operations created only through their dedicated routes, behind their own machine-scoped catalog entries. Delegated Lab credentials (ADR 0011) are never granted them. The audit event records the machine, endpoint, auth kind, timeout, and the SHA-256 of the command (or the path, size, and digest of a file), never the command text or file bytes.
7. **Bounds are the existing ones.** Exec shares the `ssh.exec` limits (script size, 900 s ceiling, per-stream output cap with a truncation flag, concurrency limiter, scrubber). Put shares the Lab upload staging and cap; collect shares the Lab per-file cap and deadline. Windows machines use the PowerShell shell layer of ADR 0015; the guest OS is chosen by the caller (default Linux) because a non-Lab machine has no template to declare it.
8. **Collected files** are kept in the content-addressed artifact blob store and recorded per machine with a retention deadline. Blob garbage collection counts references from both Lab artifacts and machine files, so deduplication can never delete a blob another record still needs.

9. **Who may name a credential.** A caller with only `machines.exec` uses the endpoint's default auth. Naming any other auth for one request (a stored key, an identity file on the controller, the controller's agent) chooses which credential the controller uses and so needs `machine.update` on the machine. Identity files under the controller's data directory or master key are refused, because the SSH work directory holds other sessions' key files. A key stored for a machine (`machines/ssh/<machine>/...`) resolves for that machine only, checked when a default is set and again when a session starts; an unbound `machines/ssh/` key and an existing `git/` repository SSH key (the unbound legacy namespace) work on any machine for a caller allowed to set its credentials. Only `machines/ssh/` and `git/` records resolve, and a value that is not an unencrypted private key is refused.
10. **What the permissions mean.** `machines.put` is exec-equivalent: a file written to a machine can be a script, a cron entry, or `authorized_keys`, so granting put grants command execution as the endpoint's user. `machines.collect` reads any file the login can read, including that user's own secrets. The permissions stay separate so a grant can be audited and narrowed per kind, but none of them is a sandbox, and `exec` has no privilege-elevation policy. Reading a `machine.*` operation (its payload and result) needs that kind's permission on its machine.
11. **The command is in the payload.** The audit event holds the digest, but the operation record keeps the plaintext command, arguments and output of a `machine.exec` until operations are pruned, because the executor needs them. They are readable only with `machines.exec` on that machine. Do not put secrets in a command.
12. **Windows argv.** Windows PowerShell 5.1 builds a native command's line itself and does not escape embedded double quotes, so an argv argument containing `"` may be split or merged differently than given; use script mode for those. Key files need Unix file modes: the controller that serves stored keys is Linux (Unix) only.

## Consequences

- A new auth kind touches every payload that carries `auth`; this ADR adds it to the `ssh.exec` family and the machine file operations only. The other SSH-driven kinds (`mise`, `frogenv`, `skills`, `projects`) keep `agent` and `identity-file` until a later issue extends them, so no existing contract changes.
- The catalog gains three entries and the delegated-credential tests gain refusal rows.
- The controller is on the data path for agent work on machines: its concurrency limiter and output caps are the throttle, and large transfers are bounded by the Lab upload and artifact caps.
- Interactive terminals, bulk fan-out, privilege-elevation policy, and certificate-based access are explicit non-goals of this decision.
