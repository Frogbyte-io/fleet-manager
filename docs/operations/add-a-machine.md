# Add a machine to Fleet (guide for an agent on that machine)

This page is written to be followed by a coding agent (or a person) **on the
machine being added**. It turns a Linux or Windows 11 developer machine into a
Fleet machine:

- the controller can reach it over SSH,
- Skills Manager is installed and the built-in `fleet` skill is deployed to the
  machine's coding agents,
- `fleetctl` on the machine talks to the controller, so agents there can see
  the other machines.

It is the short path through the full runbooks:
[fleet-pilot.md](fleet-pilot.md) (Linux) and
[windows-workstations.md](windows-workstations.md) (Windows). When something
here fails, those pages explain why.

## Rules for the agent

- **Ask, don't guess, the two inputs below.** They come from the operator.
- **Never print, copy or ask for a private key.** Only the controller's
  *public* key line is used here.
- **Check the host key fingerprint against this machine's own key file**
  before confirming it. Never confirm a fingerprint you did not compare.
- **Stop and report** if a step fails in a way this page does not cover; do
  not work around a refusal (for example by enabling password login or adding
  a key to another account).
- **Read the warning first:** until authentication (M8) lands, anyone who can
  reach the controller can run commands on every enrolled machine, and so can
  every agent on them. Only add machines whose compromise the operator accepts.
  See [restrict access first](fleet-pilot.md#restrict-access-first).

## Before you start

This machine must be **on the controller's tailnet** (`tailscale status`
shows it, and `tailscale ip -4` prints its address), and the tailnet policy
must let the controller reach it on TCP 22. If it is not, stop and ask the
operator to add it; joining a tailnet is not something to do on their behalf.

## Inputs from the operator

| Input | Example | Where it comes from |
|---|---|---|
| Controller URL | `http://controller.example.ts.net:8080` | The operator's Fleet deployment. On a Coolify host whose proxy already holds ports 80/443/8080, it is the HTTP port Tailscale Serve publishes instead ([COOLIFY.md](../../deploy/COOLIFY.md)). |
| Controller release tag (optional) | `v0.1.0-48f6043` | The `fleetctl` release built from the commit the controller runs: `v<version>-<short commit>`. Default: the newest release, which matches a controller deployed from `main`'s head. Only needed on Windows; Linux takes the controller's own copy. |
| Controller SSH public key | `ssh-ed25519 AAAA... fleet-controller@controller` | `cat /var/lib/fleet/.ssh/id_ed25519.pub` inside the controller container. See [give the controller an SSH key](#once-per-controller-give-it-an-ssh-key) if it has none. |

The controller URL only has to work from this machine, so a tailnet name is
fine there. The address the **controller** connects to (`--host` below) must be
this machine's **tailnet IPv4** (`tailscale ip -4`): the controller runs in a
container that may not resolve tailnet (MagicDNS) names.

## Linux (Debian/Ubuntu x86_64)

Run as the account the coding agents use (not root).

1. **Install `fleetctl`** built from the same commit as the controller. The
   controller serves its own copy, so it matches by construction. Fetch it
   through the controller's **HTTPS** (Tailscale Serve) URL when there is one:
   over plain HTTP the binary and its checksum come from the same
   unauthenticated origin, so the check only catches corruption.

   ```sh
   mkdir -p ~/.local/bin && cd "$(mktemp -d)"
   u='<controller URL>/downloads/fleetctl/linux-x86_64'
   # One chain: a failed download, checksum or test run installs nothing.
   curl -fsSLo fleetctl "$u" && curl -fsSLo fleetctl.sha256 "$u.sha256" \
     && [ "$(cut -d' ' -f1 fleetctl.sha256)" = "$(sha256sum fleetctl | cut -d' ' -f1)" ] \
     && chmod +x fleetctl && ./fleetctl --version \
     && install -m 0755 fleetctl ~/.local/bin/fleetctl \
     || echo 'fleetctl NOT installed: download, checksum or test run failed' >&2
   case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH" ;; esac
   ```

   That copy needs glibc 2.36 or newer (Debian 12, Ubuntu 23.04 or later). On
   older systems use the static release binary for the controller's release
   tag instead, checked against the release's `SHA256SUMS`, as in
   [deploy/README.md](../../deploy/README.md#install-fleetctl).

2. **Point it at the controller:**

   ```sh
   case "${XDG_CONFIG_HOME:-}" in /*) cfg="$XDG_CONFIG_HOME/fleet" ;; *) cfg="$HOME/.config/fleet" ;; esac
   mkdir -p "$cfg"
   printf 'url = "%s"\n' '<controller URL>' > "$cfg/config.toml"
   fleetctl --output json system   # storageOk: true, client.urlSource: "config"
   ```

3. **Let the controller in.** SSH server running, then add the controller's
   public key to this account:

   ```sh
   command -v sshd >/dev/null || sudo apt-get install -y openssh-server
   sudo systemctl enable --now ssh
   mkdir -p ~/.ssh && chmod 700 ~/.ssh
   grep -qxF '<controller public key>' ~/.ssh/authorized_keys 2>/dev/null \
     || echo '<controller public key>' >> ~/.ssh/authorized_keys
   chmod 600 ~/.ssh/authorized_keys
   ```

4. **Remove a stale Skills Manager stand-in.** If `skills-manager-cli` is on
   `PATH` but is not the real binary (`file "$(command -v skills-manager-cli)"`
   says it is a script, or `skills-manager-cli --version` prints JSON instead of
   `skills-manager-cli 1.40.0`), remove it; a test stub left there makes Fleet
   report fake skills. Fleet installs the real, pinned binary itself.

   ```sh
   p="$(command -v skills-manager-cli)" && file "$p" | grep -q 'script' && rm -f "$p"
   ```

   Remove only a script. Leave a real binary in place, and stop and tell the
   operator if it is not the version Fleet pins.

5. **Onboard this machine** (see [Onboard and verify](#onboard-and-verify)) with
   `--user "$USER" --host "$(tailscale ip -4)"` and the fingerprint from:

   ```sh
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

## Windows 11 (x64)

Two kinds of steps: **elevated** ones (Windows PowerShell *as Administrator*,
once per machine) and the rest as the **developer's own, standard account**.
An agent without an elevated session prints the elevated block for the
operator to run and waits. The why of each step is in
[windows-workstations.md](windows-workstations.md#one-time-setup-on-the-workstation).

1. **Elevated, once:**

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
   $c = "$env:ProgramData\ssh\sshd_config"
   (Get-Content $c) -replace '^#?\s*PasswordAuthentication\s+\S+', 'PasswordAuthentication no' | Set-Content $c
   Restart-Service sshd
   ```

   If the account is an **administrator**, its key goes in
   `%ProgramData%\ssh\administrators_authorized_keys` instead (step 3 of
   [the runbook](windows-workstations.md#one-time-setup-on-the-workstation)),
   and that key logs in elevated as any administrator. Prefer a standard
   account.

2. **Install `fleetctl`** (as the developer):

   ```powershell
   $bin = "$env:LOCALAPPDATA\fleet\bin"; New-Item -ItemType Directory -Force $bin | Out-Null
   # The controller's release tag when the operator gave one, else the newest.
   $tag = ''   # e.g. 'v0.1.0-48f6043'
   $base = if ($tag) { "https://github.com/Frogbyte-io/fleet-manager/releases/download/$tag" } else { 'https://github.com/Frogbyte-io/fleet-manager/releases/latest/download' }
   Invoke-WebRequest "$base/fleetctl-windows-x86_64.exe" -OutFile "$bin\fleetctl.exe"
   Invoke-WebRequest "$base/SHA256SUMS" -OutFile "$env:TEMP\SHA256SUMS"
   $want = ((Get-Content "$env:TEMP\SHA256SUMS") -match ' fleetctl-windows-x86_64\.exe$').Split(' ')[0]
   if ((Get-FileHash "$bin\fleetctl.exe" -Algorithm SHA256).Hash.ToLower() -ne $want) { throw 'checksum mismatch' }
   [Environment]::SetEnvironmentVariable('Path', "$([Environment]::GetEnvironmentVariable('Path','User'));$bin", 'User')
   $env:Path += ";$bin"
   ```

3. **Point it at the controller:**

   ```powershell
   New-Item -ItemType Directory -Force "$env:APPDATA\fleet" | Out-Null
   Set-Content -Path "$env:APPDATA\fleet\config.toml" -Value 'url = "<controller URL>"' -Encoding ascii
   fleetctl --output json system
   ```

4. **Let the controller in** (standard account, not elevated):

   ```powershell
   New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null
   $k = "$env:USERPROFILE\.ssh\authorized_keys"
   if (-not ((Test-Path $k) -and (Select-String -Path $k -SimpleMatch '<controller public key>' -Quiet))) {
     Add-Content -Path $k -Value '<controller public key>' -Encoding ascii
   }
   icacls $k /inheritance:r /grant "${env:USERNAME}:F" /grant "SYSTEM:F" /grant "*S-1-5-32-544:F" | Out-Null
   ```

5. **Keep the PowerShell profile quiet.** If `$PROFILE` exists and prints
   anything, onboarding refuses the machine; remove the output.

6. **Onboard this machine** (next section) with
   `--user $env:USERNAME --host (tailscale ip -4)` and the fingerprint from:

   ```powershell
   ssh-keygen -lf "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
   ```

## Onboard and verify

The same on both platforms. `<user>`, `<host>` and `<fingerprint>` come from
the platform section; `--auth agent` means the controller's own key.

```sh
fleetctl --output json machines onboard create --user <user> --host <host> --name <machine name> --auth agent
fleetctl --output json machines onboard test <draft-id> --wait
fleetctl --output json machines onboard get <draft-id>          # hostKey.fingerprint
```

Compare `hostKey.fingerprint` with this machine's `<fingerprint>`. Only if
they are **identical**:

```sh
fleetctl --output json machines onboard confirm <draft-id> --fingerprint <fingerprint>
fleetctl --output json machines onboard test <draft-id> --wait      # lastTest.connected: true
fleetctl --output json machines onboard discover <draft-id> --wait
fleetctl --output json machines onboard add <draft-id>
```

`add` queues the Skills Manager install (`skills.probe`). Follow it until it
succeeds:

```sh
fleetctl --output json operations list --limit 5
fleetctl --output json operations get <operation-id>
```

Then deploy the `fleet` skill to the agents Skills Manager found installed:

```sh
fleetctl --output json skills list <machine-id>               # data.agents[].installed
fleetctl --output json skills catalog versions builtin-fleet   # take the newest version's id
fleetctl --output json skills catalog rollout --request-json \
  '{"versionId":"<version id>","machineId":"<machine-id>","endpointId":"<endpoint-id>","auth":{"type":"agent"},"agents":["claude_code","codex"],"timeoutSeconds":300}'
```

`<endpoint-id>` is `endpoints[0].id` in `fleetctl --output json machines get
<machine-id>`; list only agents that show `installed: true`. A rollout that
fails because an agent is not installed cannot be retried with the identical
request ([#644](https://github.com/Frogbyte-io/fleet-manager/issues/644));
change the agent list or `timeoutSeconds`.

**Done when:**

- `fleetctl --output json skills list <machine-id>` shows `fleet` with
  `deployedTo` listing those agents,
- `fleetctl --output json machines list` shows this machine and the others.

### When it fails

| Symptom | Cause | Fix |
|---|---|---|
| `lastTest.detail`: `Load key ".../id_ed25519": Permission denied` | The controller's key file is not owned by the controller user | See [give the controller an SSH key](#once-per-controller-give-it-an-ssh-key), the `chown` line |
| `lastTest.connected: false`, `Permission denied (publickey)` | The public key is not in the account's `authorized_keys` (Windows administrators: the wrong file) | Step "let the controller in" |
| `onboard test` never connects | The controller cannot route to `<host>` | Use the tailnet IPv4, check tailnet policy allows the controller to reach port 22 |
| `shellCheck.refusalReason` set (Windows) | `DefaultShell` is not Windows PowerShell 5.1, or the profile prints | Windows steps 1 and 5 |
| `skills.probe` fails with `unsupported_version` | A stand-in `skills-manager-cli` on `PATH` | Linux step 4 |

## Once per controller: give it an SSH key

The controller connects with the default key of its own user. A fresh
deployment has none, and then no machine can be reached. On the controller
host, create one inside the container, on the data volume (it survives
redeploys), owned by the controller user:

```sh
c="$(docker ps -qf name=<application uuid or name> | head -1)"
docker exec -u 0 "$c" sh -c 'd=/var/lib/fleet/.ssh
  mkdir -p "$d" && [ -f "$d/id_ed25519" ] || ssh-keygen -q -t ed25519 -N "" -C fleet-controller -f "$d/id_ed25519"
  chown -R "$(stat -c %u:%g /var/lib/fleet)" "$d" && chmod 700 "$d" && chmod 600 "$d/id_ed25519"
  cat "$d/id_ed25519.pub"'
```

The printed line is the **controller SSH public key** input above. Paste the
whole block as one command: run line by line on the host, the variables are
unset there and the key lands in the wrong place.
