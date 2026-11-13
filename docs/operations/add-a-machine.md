# Add a machine to Fleet (guide for an agent on that machine)

This page is written to be followed by a coding agent (or a person) **on the
machine being added**. It turns a Linux or Windows 11 developer machine into a
Fleet machine:

- the controller can reach it over SSH,
- Skills Manager is installed and the built-in `fleet` skill is deployed to the
  machine's coding agents,
- `fleetctl` on the machine talks to the controller, so agents there can see
  the other machines.

After installing `fleetctl`, one command does it: **`fleetctl machines
join`**. The [manual path](#manual-path-fallback) is kept at the end for when
the command cannot be used. When something fails, the full runbooks explain
why: [fleet-pilot.md](fleet-pilot.md) (Linux) and
[windows-workstations.md](windows-workstations.md) (Windows).

## Rules for the agent

- **Ask, don't guess, the controller URL.** It comes from the operator.
- **Never print, copy or ask for a private key.** The join only uses the
  controller's *public* key, and reads this machine's *public* host key.
- **Do not work around a refusal.** The join refuses when the controller sees
  a host key that is not this machine's own, when the SSH server is not set
  up, or when the account is a Windows administrator. Report it; do not
  enable password login, add the key to another account, or pass a different
  `--host-key-file` to make a mismatch go away.
- **Never run the elevated blocks yourself** unless the operator gave you an
  elevated session for that purpose. The join prints them for the operator.
- **Read the warning first:** until authentication (M8) lands, anyone who can
  reach the controller can run commands on every enrolled machine, and so can
  every agent on them. Only add machines whose compromise the operator accepts.
  See [restrict access first](fleet-pilot.md#restrict-access-first).

## Before you start

This machine must be **on the controller's tailnet** (`tailscale status`
shows it, and `tailscale ip -4` prints its address), and the tailnet policy
must let the controller reach it on TCP 22. If it is not, stop and ask the
operator to add it; joining a tailnet is not something to do on their behalf.

The join checks this itself, from the controller's side, before it changes
anything here: after it fetches the controller's public key, its next step
against the controller is an onboarding test that connects to the address
(`--host`, by default the tailnet IPv4) and reads the host key, and the join goes on only when that key is this machine's own
(see [step 2](#2-join)). A local `tailscale` check could not prove the
controller's container can route to the address; this does, for an explicit
`--host` too.

## Inputs from the operator

| Input | Example | Where it comes from |
|---|---|---|
| Controller URL | `http://controller.example.ts.net:8080` | The operator's Fleet deployment. On a Coolify host whose proxy already holds ports 80/443/8080, it is the HTTP port Tailscale Serve publishes instead ([COOLIFY.md](../../deploy/COOLIFY.md)). |
| Controller release tag (optional) | `v0.1.0-48f6043` | The `fleetctl` release built from the commit the controller runs: `v<version>-<short commit>`. Default: the newest release, which matches a controller deployed from `main`'s head. Only needed on Windows; Linux takes the controller's own copy. |

The controller's SSH key no longer has to be handed over: the controller
generates it on its first start and publishes the public half
(`fleetctl system ssh-public-key`), and the join fetches it.

The controller URL only has to work from this machine, so a tailnet name is
fine there. The address the **controller** connects to is this machine's
**tailnet IPv4** (`tailscale ip -4`), which the join uses by default: the
controller runs in a container that may not resolve tailnet (MagicDNS) names.

## 1. Install `fleetctl` and point it at the controller

### Linux (Debian/Ubuntu x86_64)

Run as the account the coding agents use (not root).

Install the `fleetctl` built from the same commit as the controller: the
controller serves its own copy, so it matches by construction (and serves the
`ssh-public-key` endpoint the join needs). Fetch it through the controller's
**HTTPS** (Tailscale Serve) URL when there is one: over plain HTTP the binary
and its checksum come from the same unauthenticated origin, so the check only
catches corruption.

```sh
mkdir -p ~/.local/bin && cd "$(mktemp -d)"
u='<controller URL>/downloads/fleetctl/linux-x86_64'
# One chain: a failed download, checksum or test run installs nothing.
curl -fsSLo fleetctl "$u" && curl -fsSLo fleetctl.sha256 "$u.sha256" \
  && [ "$(cut -d' ' -f1 fleetctl.sha256)" = "$(sha256sum fleetctl | cut -d' ' -f1)" ] \
  && chmod +x fleetctl && ./fleetctl --version \
  && install -m 0755 fleetctl ~/.local/bin/fleetctl \
  || { echo 'fleetctl NOT installed: download, checksum or test run failed' >&2; false; }
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac

case "${XDG_CONFIG_HOME:-}" in /*) cfg="$XDG_CONFIG_HOME/fleet" ;; *) cfg="$HOME/.config/fleet" ;; esac
mkdir -p "$cfg"
printf 'url = "%s"\n' '<controller URL>' > "$cfg/config.toml"
fleetctl --output json system   # storageOk: true, client.urlSource: "config"
```

That copy needs glibc 2.36 or newer (Debian 12, Ubuntu 23.04 or later). On
older systems use the static release binary for the controller's release tag
instead, checked against the release's `SHA256SUMS`, as in
[deploy/README.md](../../deploy/README.md#install-fleetctl).

The SSH server must be installed and running. The join checks it but never
runs `sudo`; this is the one step that needs it:

```sh
command -v sshd >/dev/null || sudo apt-get install -y openssh-server
sudo systemctl enable --now ssh
```

### Windows 11 (x64)

**Once, elevated** (Windows PowerShell *as Administrator*). The join checks
each of these and prints this block when one is missing; it never runs it:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd
# Accept SSH only on the tailnet.
Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -InterfaceAlias Tailscale
# Fleet's scripts need Windows PowerShell 5.1 as the SSH login shell.
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
  -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -PropertyType String -Force
# Key login only.
# OpenSSH uses the first value it reads, so line 1 decides for every user.
$c = "$env:ProgramData\ssh\sshd_config"
$t = @(Get-Content $c)
if ($t[0] -ne 'PasswordAuthentication no') { Set-Content $c (@('PasswordAuthentication no') + $t) }
Restart-Service sshd
```

**Then as the developer's own, standard account:**

```powershell
# Stop at the first failed command. Both files are staged in a fresh
# temporary directory; only a binary whose checksum matches and that runs is
# moved into place, and the staging directory is removed either way.
$ErrorActionPreference = 'Stop'
$bin = "$env:LOCALAPPDATA\fleet\bin"; New-Item -ItemType Directory -Force $bin | Out-Null
# The controller's release tag when the operator gave one, else the newest.
$tag = ''   # e.g. 'v0.1.0-48f6043'
$base = if ($tag) { "https://github.com/Frogbyte-io/fleet-manager/releases/download/$tag" } else { 'https://github.com/Frogbyte-io/fleet-manager/releases/latest/download' }
$stage = Join-Path $env:TEMP ("fleetctl-" + [guid]::NewGuid())
New-Item -ItemType Directory $stage | Out-Null
try {
  Invoke-WebRequest "$base/fleetctl-windows-x86_64.exe" -OutFile "$stage\fleetctl.exe"
  Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$stage\SHA256SUMS"
  $line = @(@(Get-Content "$stage\SHA256SUMS") -match ' fleetctl-windows-x86_64\.exe$')
  if ($line.Count -ne 1) { throw 'SHA256SUMS has no single entry for fleetctl-windows-x86_64.exe' }
  $want = $line[0].Split(' ')[0].ToLower()
  if ((Get-FileHash "$stage\fleetctl.exe" -Algorithm SHA256).Hash.ToLower() -ne $want) { throw 'checksum mismatch' }
  & "$stage\fleetctl.exe" --version
  if ($LASTEXITCODE -ne 0) { throw 'the downloaded fleetctl does not run' }
  Move-Item -Force "$stage\fleetctl.exe" "$bin\fleetctl.exe"
} finally {
  Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $bin) { [Environment]::SetEnvironmentVariable('Path', "$userPath;$bin", 'User') }
if (($env:Path -split ';') -notcontains $bin) { $env:Path += ";$bin" }

New-Item -ItemType Directory -Force "$env:APPDATA\fleet" | Out-Null
Set-Content -Path "$env:APPDATA\fleet\config.toml" -Value 'url = "<controller URL>"' -Encoding ascii
fleetctl --output json system
```

**Keep the PowerShell profile quiet.** If `$PROFILE` exists and prints
anything, onboarding refuses the machine; remove the output.

## 2. Join

As the account the coding agents use:

```sh
fleetctl --output json machines join
```

It runs these steps and stops at the first refusal, before changing anything
it has not reached yet:

1. **Fetches the controller's SSH public key** and refuses if the controller
   has none (see [the controller has no key](#the-controller-has-no-key)).
2. **Checks this machine, read-only:** an SSH server answers on the port; on
   Windows, `DefaultShell` is Windows PowerShell 5.1 and password login is
   off (otherwise it prints the elevated block above and exits non-zero); on
   Linux, no stand-in `skills-manager-cli` (a script, or one whose
   `--version` does not print `skills-manager-cli <version>`) sits on `PATH`
   or in `~/.local/bin`. A stand-in is reported, never deleted: remove it
   yourself (Fleet installs the real, pinned binary).
3. **Has the controller look at this machine**, before changing anything
   here: it creates the onboarding draft (at the `--host` address, by
   default this machine's tailnet IPv4, as this account, named after the
   hostname) and runs the onboarding test, which,
   before a host key is confirmed, only connects and reads the host key (no
   login). That proves the controller reaches this address, `--host`
   included. The join compares the fingerprint the controller saw with
   **this machine's own key file** (`/etc/ssh/ssh_host_ed25519_key.pub`, or
   `%ProgramData%\ssh\ssh_host_ed25519_key.pub`) and goes on **only if
   identical**. Otherwise (or when the controller cannot reach the address)
   it cancels the draft and refuses loudly, with nothing changed on this
   machine: the controller is not talking to this machine.
4. **Adds the controller's key to this account**, once, and secured
   before the key is in it: `~/.ssh/authorized_keys` (directory 0700, file
   0600 before anything is appended) on Linux;
   `%USERPROFILE%\.ssh\authorized_keys` on Windows, where the new content
   is written to a file beside it that gets the protected ACL (this
   account, SYSTEM and Administrators, granted by SID so localized Windows
   works) and only then replaces `authorized_keys`; if `icacls` fails,
   `authorized_keys` is left as it was. A key already there (compared by
   key type and key, whatever its options or comment) is left alone.
   A Windows **administrator** is refused instead (see
   [Windows administrators](#windows-administrators)). Then it **confirms**
   the verified host key, tests the login, discovers and adds. A failure
   before the add cancels the draft.
5. **Deploys the `fleet` skill:** follows the Skills Manager install the add
   queued (`skills.probe`) to completion, reads which coding agents Skills
   Manager found installed, and rolls out the newest built-in `fleet` skill
   version to them. Each attempt is a new rollout, so a re-run after a
   failure runs again ([#644](https://github.com/Frogbyte-io/fleet-manager/issues/644)).
6. **Prints a summary**; `--output json` prints the same as a document.

Progress lines go to stderr; stdout is only the result:

```json
{
  "machineId": "01…",
  "name": "dev-box",
  "endpointId": "01…",
  "endpoint": { "user": "developer", "host": "100.64.0.9", "port": 22 },
  "resumed": false,
  "hostKey": { "fingerprint": "SHA256:…", "file": "/etc/ssh/ssh_host_ed25519_key.pub" },
  "controllerKey": { "fingerprint": "SHA256:…", "authorizedKeys": "added", "file": "/home/developer/.ssh/authorized_keys" },
  "skillsManager": { "followUp": { "status": "queued", "operationId": "01…" }, "operationId": "01…", "state": "succeeded" },
  "skills": { "status": "deployed", "versionId": "01…", "agents": ["claude_code", "codex"], "operationId": "01…" },
  "warnings": []
}
```

The exit code is `0` when the machine is enrolled and the skill step deployed
or had nothing to deploy to (`skills.status` `skipped`: no coding agent is
installed yet), and `1` on any refusal or when the skill step `failed` (the
machine is enrolled then; fix the cause and [resume](#re-running-and---resume)).

### Options

| Option | Default | Use |
|---|---|---|
| `--host <address>` | `tailscale ip -4` | The address the controller connects to. |
| `--port <n>` | `22` | The SSH port. |
| `--user <login>` | this account | Must name this account (the key is installed for the account the join runs as); another login is refused. Run the join as the account whose agents should get the skill. |
| `--name <name>` | the hostname | The machine name in Fleet. |
| `--host-key-file <path>` | the ed25519 host key | Only when sshd uses a non-default `HostKey`. |
| `--agents <id,...>` | the installed agents | Deploy the skill to these agents (Skills Manager ids, e.g. `claude_code`, `codex`). |
| `--no-skills` | | Enroll only; skip Skills Manager and the skill. |
| `--resume` | | Continue with the machine already enrolled at this address. |
| `--admin-key-installed` | | Windows administrators only, see below. |
| `--timeout <s>` | `600` | Bound on each operation the join waits for. |

### Re-running and `--resume`

The join is safe to run again. If a machine is already enrolled at this
address it says so and stops, naming it. `--resume` continues with that
machine instead, after the same check as a first join: the controller must
see **this machine's own host key** at the address (an address can be
reused by another machine), or the join refuses. It then re-checks the key in
`authorized_keys` and runs the skill step again through that machine's SSH
endpoint for **this login at this address** (never another endpoint of the
machine), for example after installing a coding agent or after a failed
rollout:

```sh
fleetctl --output json machines join --resume
```

To enroll it from scratch instead, remove it first (`fleetctl machines remove
<machine-id>`).

### Windows administrators

For a member of Administrators, sshd ignores the account's own
`authorized_keys` and reads `%ProgramData%\ssh\administrators_authorized_keys`,
which only an elevated session can change. **A key there logs in as any
administrator on the machine, with the full elevated token and no UAC prompt**,
so holding `machines.exec` on that machine is full control of it
([ADR 0021](../adr/0021-windows-workstations.md)). The join therefore refuses
and prints the exact elevated commands for this controller key. Prefer a
standard account. If the operator accepts the risk, they run the printed block
in Windows PowerShell as Administrator, and the join continues with:

```powershell
fleetctl --output json machines join --admin-key-installed
```

The onboarding test then proves the key works; nothing else is skipped.

**Done when:**

- the join exits `0` with `skills.status` `deployed`,
- `fleetctl --output json skills list <machine-id>` shows `fleet` with
  `deployedTo` listing those agents,
- `fleetctl --output json machines list` shows this machine and the others.

### When it fails

| Symptom | Cause | Fix |
|---|---|---|
| `the controller has no usable SSH key (none)` | Key generation is off on the controller | [The controller has no key](#the-controller-has-no-key) |
| `the controller has no usable SSH key (unusable)`, or `lastTest.detail` `Load key ".../id_ed25519": Permission denied` | A key created by hand that the controller user cannot use (unreadable by it, readable by others, passphrase-protected, corrupt) | Apply the fix the `detail` names (`chown -R` on the `.ssh` directory, `chmod 600`); when it names none, move the key away and restart the controller to generate a new one |
| `no SSH server answers on port 22` | sshd is not installed or not running | Linux: `sudo systemctl enable --now ssh`; Windows: the elevated block |
| `REFUSED: the host key the controller saw ... is not this machine's own key` | `--host` reaches another machine, or something intercepts the connection | Check the address; never override the host key file to make it match |
| `the controller could not log in ... Permission denied (publickey)` | sshd does not read the file the key went to (Windows administrators: the wrong file) | [Windows administrators](#windows-administrators); on Linux check `AuthorizedKeysFile` |
| `the controller could not reach ... to read its host key. Nothing was changed on this machine.` | The controller cannot route to the address | Use the tailnet IPv4; check the tailnet policy lets the controller reach port 22 |
| `icacls could not secure ... so the controller key was not added` (Windows) | The ACL could not be applied | `authorized_keys` is unchanged; fix the cause (`icacls` names it) and join again |
| `cannot resume with machine ...: the machine has no SSH endpoint for ...` | The enrolled machine reaches this address only under another login, or not by SSH | Join as the account that machine's endpoint uses, or remove the machine and join again |
| `the login shell is refused` (Windows) | `DefaultShell` is not Windows PowerShell 5.1, or the profile prints | The elevated block; keep the profile quiet |
| `... is not the real Skills Manager CLI` | A stand-in `skills-manager-cli` on `PATH` or in `~/.local/bin` | Remove it yourself, then join again |
| `is already enrolled as ...` | This address is already a Fleet machine | `--resume`, or `fleetctl machines remove` first |
| `skills.status: failed` | The Skills Manager probe or the rollout failed (the reason is in the summary) | Fix the cause, then `--resume` |

## The controller has no key

The controller generates `~/.ssh/id_ed25519` for its own user at startup
unless `FLEET_SSH_KEY_GENERATE` is `false`
([deploy/README.md](../../deploy/README.md#configuration)); in the image that
is `/var/lib/fleet/.ssh/id_ed25519` on the data volume. Check what it reports:

```sh
fleetctl --output json system ssh-public-key   # state: present | none | unusable
```

`none`: turn generation back on and restart the controller. `unusable`: the
`detail` says why (for example a key created as root inside the container that
the controller user cannot read) and how to fix it.

## Manual path (fallback)

Use this only when `fleetctl machines join` cannot run here. It is the same
sequence, by hand.

1. **The controller's public key:** `fleetctl --output json system
   ssh-public-key` prints the line (`publicKey`) and its `fingerprint`. If
   generation is off and you must create the key by hand, do it on
   the controller host inside the container, owned by the controller user
   (paste the whole block as one command):

   ```sh
   c="$(docker ps -qf name=<application uuid or name> | head -1)"
   docker exec -u 0 "$c" sh -c 'd=/var/lib/fleet/.ssh
     mkdir -p "$d" && [ -f "$d/id_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -C fleet-controller -f "$d/id_ed25519"
     chown -R "$(stat -c %u:%g /var/lib/fleet)" "$d" && chmod 700 "$d" && chmod 600 "$d/id_ed25519"
     cat "$d/id_ed25519.pub"; ssh-keygen -lf "$d/id_ed25519.pub"'
   ```

2. **Let the controller in.** The file is secured first, and the key is
   compared the way sshd reads the file, not as a whole line:
   `ssh-keygen -lf` lists the fingerprint of every key in it, past options
   and comments, so a copy with options or another comment is not added
   again. Linux (sshd installed and running as in
   [step 1](#1-install-fleetctl-and-point-it-at-the-controller)):

   ```sh
   key='<controller public key>'
   want='<controller key fingerprint>'   # SHA256:...
   f=~/.ssh/authorized_keys
   mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch "$f" && chmod 600 "$f"
   if ! ssh-keygen -lf "$f" 2>/dev/null | cut -d' ' -f2 | grep -qxF "$want"; then
     [ -s "$f" ] && [ -n "$(tail -c1 "$f")" ] && echo >> "$f"
     printf '%s\n' "$key" >> "$f"
   fi
   ```

   Windows, standard account:

   ```powershell
   $key = '<controller public key>'
   $want = '<controller key fingerprint>'   # SHA256:...
   New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null
   $k = "$env:USERPROFILE\.ssh\authorized_keys"
   if (-not (Test-Path $k)) { New-Item -ItemType File -Path $k | Out-Null }
   icacls $k /inheritance:r /grant "${env:USERNAME}:F" /grant "*S-1-5-18:F" /grant "*S-1-5-32-544:F" | Out-Null
   if ($LASTEXITCODE -ne 0) { throw 'icacls failed; the key was not added' }
   $have = @(ssh-keygen -lf $k 2>$null | ForEach-Object { ($_ -split ' ')[1] })
   if ($have -notcontains $want) {
     $b = [IO.File]::ReadAllBytes($k)
     if ($b.Length -gt 0 -and $b[-1] -ne 10) { Add-Content -Path $k -Value '' -Encoding ascii }
     Add-Content -Path $k -Value $key -Encoding ascii
   }
   ```

3. **Remove a stale Skills Manager stand-in** (Linux): if `skills-manager-cli`
   on `PATH` is a script or `skills-manager-cli --version` does not print
   `skills-manager-cli <version>`, it makes Fleet report fake skills:

   ```sh
   p="$(command -v skills-manager-cli)" && file "$p" | grep -q 'script' && rm -f "$p"
   ```

   Remove only a script. Leave a real binary in place, and stop and tell the
   operator if it is not the version Fleet pins.

4. **Onboard.** `<fingerprint>` is this machine's own, from
   `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` (Windows:
   `ssh-keygen -lf "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"`):

   ```sh
   fleetctl --output json machines onboard create --user <user> --host <tailnet IPv4> --name <machine name> --auth agent
   fleetctl --output json machines onboard test <draft-id> --wait
   fleetctl --output json machines onboard get <draft-id>          # hostKey.fingerprint
   ```

   Only if `hostKey.fingerprint` is **identical** to `<fingerprint>`:

   ```sh
   fleetctl --output json machines onboard confirm <draft-id> --fingerprint <fingerprint>
   fleetctl --output json machines onboard test <draft-id> --wait      # lastTest.connected: true
   fleetctl --output json machines onboard discover <draft-id> --wait
   fleetctl --output json machines onboard add <draft-id>              # skillsManager.operationId
   ```

5. **Deploy the skill.** Follow the `skills.probe` operation the add reports
   (`fleetctl --output json operations get <operation-id>`) until it
   succeeds, then:

   ```sh
   fleetctl --output json skills list <machine-id>               # data.agents[].installed
   fleetctl --output json skills catalog versions builtin-fleet   # take the newest version's id
   fleetctl --output json skills catalog rollout --request-json \
     '{"versionId":"<version id>","machineId":"<machine-id>","endpointId":"<endpoint-id>","auth":{"type":"agent"},"agents":["claude_code","codex"],"timeoutSeconds":300}'
   ```

   `<endpoint-id>` is the `id` of the endpoint in `fleetctl --output json
   machines get <machine-id>` whose `kind` is `ssh` and whose `reference` is
   `<user>@<tailnet IPv4>:22` (not simply the first endpoint: a machine can
   have others); list only agents that show `installed: true`. A rollout that
   fails cannot be retried with the identical request
   ([#644](https://github.com/Frogbyte-io/fleet-manager/issues/644)); change
   the agent list or `timeoutSeconds`.
