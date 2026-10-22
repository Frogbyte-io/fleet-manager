# Machine access with Fleet-held keys

How an operator lets agents run commands on, and copy files to and from, a Fleet machine without ever handing them its SSH key. The decision is [ADR 0017](../adr/0017-agent-ssh-access.md); the principals and audit rules are in [security.md](../architecture/security.md#brokered-machine-access-proposed-adr-0017). This is the brokered model: the controller holds the key and runs the session, so every command is authorized and audited and revoking access is immediate.

## Set up a machine

1. The machine is registered and its SSH host key is confirmed (the Add Machine flow, `fleetctl machines onboard ...`). A command on an endpoint whose host key was never confirmed is refused.
2. Store the machine's private key. It must be an unencrypted OpenSSH or PEM key whose public half the machine accepts. The controller needs its secret store (`FLEET_MASTER_KEY_FILE`).

   ```sh
   fleetctl machines ssh-key store < ~/.ssh/id_ed25519_for_this_machine
   ```

   Add `--machine <machine-id>` to bind the key to one machine; it then resolves for that machine only (an unbound key works on any machine for a caller allowed to change its credentials). It prints a `credentialRef` and nothing else. The key is read once from stdin and is never shown again by any command. A key that Fleet generated for a machine (issue #489) is stored the same way by its use case.
3. Make it the endpoint's default, so callers pass no credential:

   ```sh
   fleetctl machines endpoint-auth set <machine-id> <endpoint-id> --auth secret --credential <credentialRef>
   fleetctl machines endpoint-auth get <machine-id> <endpoint-id>
   ```

   `--auth identity-file --identity <path>` and `--auth agent` record the other two kinds. Deleting the endpoint (or replacing the machine's endpoints) removes its default.

## Use it

```sh
fleetctl --output json machines exec <machine-id> -- systemctl is-active nginx
fleetctl --output json machines put <machine-id> ./app.tar.gz /opt/app/app.tar.gz
fleetctl --output json machines collect <machine-id> /var/log/nginx/error.log
fleetctl --output json machines file-get <file-id> --out ./error.log
```

`exec` exits with the command's exit code; `--os windows` selects the PowerShell layer of [ADR 0015](../adr/0015-windows-lab-guest-transport.md) and drive-absolute paths. Output is capped at 1 MiB per stream with a truncation flag. A put verifies its SHA-256 inside the machine. Collected files are stored in the controller's artifact directory and removed after the retention period (`FLEET_LAB_ARTIFACT_RETENTION_SECONDS`, seven days by default), by the next collection after they expire.

## Permissions and audit

`machines.put` is exec-equivalent: a file written to a machine can be a script, a cron entry, or `authorized_keys`, so granting put grants command execution as the endpoint's user. `machines.collect` reads any file the login can read. A caller with only `machines.exec` uses the endpoint's default auth; naming another auth for a request needs `machine.update`. The operation record keeps the plaintext command and output of an exec (readable only with `machines.exec` on that machine), so never put a secret in a command.

`machines.exec`, `machines.put` and `machines.collect` are separate catalog entries scoped to the machine; `machine.update` sets a default. A delegated Lab credential holds none of them. Each request writes an audit event (`machine_exec_requested`, `machine_put_requested`, `machine_collect_requested`, `machine_file_downloaded`, `machine_endpoint_auth_set`, `machine_ssh_key_stored`) with the machine, endpoint, auth kind and, for an exec, the SHA-256 of the command, never the command, the key, or file content.

## Revoke access

Delete the endpoint's default (`machines endpoint-auth clear`) to stop callers that rely on it; delete the secret record, or remove the key from the machine's `authorized_keys`, to stop every use of that key. Taking `machines.exec` from a principal stops that principal. The next command re-resolves the key, so a revoked secret fails a queued operation with "no longer exists" and no key file is written.

## Known limits

- The `machines onboard test` connection check, run again after the host key is confirmed, reported `connected: false` for a Windows machine in the live check (its probe runs `true`, which PowerShell does not have), and the draft then needed a new test and confirm. Confirm the host key, then add the machine without repeating that probe. The onboarding probe may also observe a different host key type on each run (RSA, ECDSA, ED25519): confirm the fingerprint it shows, and start a new draft if it reports a changed key.
- Passphrase-protected keys are refused; the session is non-interactive. Key files need Unix modes, so the controller must run on Linux (or another Unix).
- On Windows (PowerShell 5.1) an argv argument containing a double quote may be split or merged differently than given; use `--script` for such arguments.
- One command at a time per request: no interactive terminal, port forwarding, or fan-out across machines.
