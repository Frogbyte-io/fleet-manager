# Interactive machine terminal

A shell on a Fleet machine, in the console (the machine page's **Terminal** tab) or in `fleetctl`. It builds on [brokered machine access](machine-access.md) ([ADR 0017](../adr/0017-agent-ssh-access.md)): the controller holds the machine's key and runs `ssh -tt` under a PTY, so the person at the keyboard never receives the key and every session is authorized, audited and time-limited.

## Use it

Set up the machine as in [machine-access.md](machine-access.md#set-up-a-machine) (confirmed host key, a stored key, the endpoint's default auth). Then:

- Console: open the machine, choose **Terminal**, **Connect**. The tab shows the connection state, why a session ended, and **Reconnect**.
- CLI: `fleetctl machines terminal <machine-id> [--endpoint <id>] [--auth ...]` attaches the local terminal (raw mode, restored on every way out, window changes followed). The shell's exit status is the command's exit code. It needs an interactive terminal on standard input and output; scripts use `machines exec`.

When the shell ends, the controller sends a text message `{"type":"exit","code":N}` just before closing, and `fleetctl` and the console read the status from it (never from the close reason). Linux guests start the login's shell. Windows OpenSSH starts its configured default shell (PowerShell when the operator set `DefaultShell`), so no remote command is sent.

## Permissions

`machines.terminal` is a separate catalog entry, scoped to the machine and checked twice: when the session is created and again when its socket attaches. Read access implies nothing, `machines.exec` is not a substitute, and delegated Lab credentials never hold it. As for exec, naming an explicit auth (instead of the endpoint's default) needs `machine.update`.

## Bounds

| Bound | Default | Setting |
|---|---|---|
| Idle (no keyboard input; output, resizes and pings do not count) | 10 min | `FLEET_TERMINAL_IDLE_SECONDS` |
| Maximum duration | 1 h (at most 6 h) | `FLEET_TERMINAL_MAX_DURATION_SECONDS` |
| Sessions on the controller (waiting or attached) | 16 | `FLEET_TERMINAL_MAX_SESSIONS` |
| Sessions per principal | 4 | `FLEET_TERMINAL_MAX_SESSIONS_PER_PRINCIPAL` |

Other bounds are fixed: a session token lives 120 s and works once; a stalled peer is dropped after a 10 s send timeout; the controller pings every 20 s and closes a connection that is silent for 60 s; a controller shutdown closes every terminal cleanly. A set variable that is not a positive whole number (or a duration above the ceiling) disables terminals with a startup warning instead of silently ignoring the bound. Terminals need the secret store (`FLEET_MASTER_KEY_FILE`) and a Unix controller.

## Audit

`terminal_session_created`, `terminal_session_started` and `terminal_session_ended` carry the principal, machine, endpoint, auth kind, the session id, and at the end the duration (`elapsedMs`), the close reason (`client`, `exited`, `idle`, `max_duration`, `shutdown`, `peer_lost`, `error`) and the shell's exit code. Keystrokes and output are **not** recorded, logged or kept anywhere by default. If recording is ever added it needs its own retention and redaction rule first.

## Threat note

- **Cross-site WebSocket hijacking.** Browsers send cookies and reachability automatically, so a malicious page could try to open the socket. The relay refuses an upgrade whose `Origin` does not name the host it connected to, and it authenticates with a single-use token created by a separate request (which the browser origin guard also covers), never with ambient credentials. A client without `Origin` (the CLI) still needs the token.
- **Token replay.** The token is random (256 bits), valid for 120 s, spent by the first attach, and stored only as a SHA-256 digest. It travels in a WebSocket subprotocol, never in a URL, so it is not in access logs or browser history. A different principal presenting a valid token gets the same refusal as an unknown one and does not spend it.
- **Trusted-LAN mode.** The controller has no accounts: every client that can reach it is the same principal and holds every permission, so **every LAN caller can open a shell on every machine with a stored key**. The console says so on the tab itself. Restrict who can reach the listener (or use the Tailscale Serve listener) until accounts exist.
- **Caps count attaching sessions.** Creating and attaching move a session between the waiting and attached sets under one lock, so concurrent requests cannot exceed a cap. An unattached token holds a slot for its 120 s lifetime, so a burst of creates can exhaust the caps for two minutes. On a trusted LAN every caller is the same principal, so the per-principal cap is shared by everyone and is effectively a second controller-wide cap.
- **Shutdown.** Once the controller began shutting down no new terminal attaches (the refusal is audited as a `shutdown` end), and every attached terminal is closed and audited.
- **Re-checks at attach.** A session created with an explicit auth also needs `machine.update` again when it attaches.
- **The terminal is a shell as the endpoint's user.** It is arbitrary command execution, exactly as `machines.exec` is; the separate permission only lets an operator grant one without the other.
- **Content security policy.** The policy is unchanged. xterm.js renders with its WebGL addon (a canvas, so no injected row styles; it falls back to the DOM renderer without WebGL or after a context loss) and gives its one `<style>` element (scrollbar colours) the page's CSP nonce, so a browser reports no violations.

## Known limits

- Without WebGL (or after a lost WebGL context) xterm falls back to its DOM renderer. Under the nonce-only content security policy that renderer shows truecolor cells in the default colours and the browser logs CSP violations for them; the terminal stays usable.
- No session recording or playback, no shared sessions, no file browser, no port forwarding (`ssh` runs with all forwarding disabled).
- Passphrase-protected keys are refused, as for exec.
- On Windows the shell's exit status did not reach `fleetctl` in the first live check (the session ended with 0). The status is the local `ssh` client's exit status, so this is most likely an upstream Windows OpenSSH / ConPTY limitation (the server does not report the PowerShell exit code for an interactive session); it was not re-checked against plain `ssh -tt` after the test VM was destroyed.
- `fleetctl`: a first interrupt (`SIGINT`, `SIGTERM`, `SIGHUP`) closes the session politely; a second one gives up without waiting for the controller. A write to a stalled controller times out after 2 s, and the terminal is restored on every path.
