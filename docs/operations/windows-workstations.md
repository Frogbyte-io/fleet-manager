# Windows workstations over OpenSSH

How to prepare a Windows developer workstation so the controller can onboard it and read its inventory, agentless, over the in-box OpenSSH Server ([ADR 0021](../adr/0021-windows-workstations.md), issue [#608](https://github.com/Frogbyte-io/fleet-manager/issues/608)). The transport is the one Lab uses for Windows guests ([ADR 0015](../adr/0015-windows-lab-guest-transport.md), [lab.md](lab.md#windows-guests)): fixed scripts, caller data on stdin, host-key pinning, authorization and audit unchanged.

Examples use placeholders: the controller is `controller.example.ts.net` (tailnet address `100.64.0.1`), the workstation is `workstation-1.example.ts.net`, and the developer's Windows account is `developer`.

## Scope

- **Supported:** Windows 11 x64, Pro, Enterprise or Education, on a feature update Microsoft still services, with the in-box OpenSSH Server. Fleet approximates "still serviced" with one threshold, build 26100 (24H2), the oldest feature update serviced for Enterprise and Education as of 2026-11 (`MIN_SERVICED_WINDOWS_11_BUILD` in `fleet-provider-ssh`, raised as Microsoft ends servicing).
- **Allowed, not tested:** Windows 10 22H2 (out of mainstream support since 2025-10-14), Windows 11 Home, an older Windows 11 build, and arm64. Fleet refuses none of them; the inventory reports `os.support` = `untested`.
- **Not a workstation target:** Windows Server (it is a Lab guest).
- **What works after this guide:** onboarding (create, test, confirm, discover, add), agentless inventory, `machines exec|put|collect` (which take the OS recorded on the endpoint) and the terminal. The operations that only have a Bash script so far (fleetd install, skills, checkout, frogenv, mise, project readiness, removal with `--uninstall`) refuse an endpoint recorded as `windows` with `unsupported_guest_os` instead of sending it Bash. Skills Manager on Windows is [#609](https://github.com/Frogbyte-io/fleet-manager/issues/609); the terminal's exit status on Windows is [#610](https://github.com/Frogbyte-io/fleet-manager/issues/610); `fleetctl` on Windows is [#614](https://github.com/Frogbyte-io/fleet-manager/issues/614) and [#615](https://github.com/Frogbyte-io/fleet-manager/issues/615).

## Which account Fleet logs in as

Use **the developer's own account**: the skills, the Skills Manager library and the agent directories live in that profile, so a dedicated Fleet account would install skills the developer's agents never see.

- **A standard user is recommended.** Its key goes in `%USERPROFILE%\.ssh\authorized_keys`. Sessions are not elevated, and everything Fleet does on a workstation works.
- **An administrator is allowed, with a warning.** For any member of the Administrators group the default `sshd_config` reads `%ProgramData%\ssh\administrators_authorized_keys` instead of the user's own file ([Microsoft: OpenSSH server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)). **A key in that file logs in as any administrator on the machine**, and a key-authenticated session gets the full elevated token with no UAC prompt. Holding `machines.exec` on such a machine is full control of it. The inventory reports `session.administrator` = `true` for such a login. Work as a standard user where you can.

## One-time setup on the workstation

Run these in **Windows PowerShell as Administrator** on the workstation. Fleet does not run them: it has no channel to the machine until this is done.

1. **Install and start OpenSSH Server.**

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service -Name sshd -StartupType Automatic
   Start-Service sshd
   ```

2. **Scope the firewall rule** the capability created (`OpenSSH-Server-In-TCP`) to the controller, or to the tailnet interface:

   ```powershell
   Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -RemoteAddress 100.64.0.1
   # or, to accept SSH only on the tailnet:
   # Set-NetFirewallRule -Name OpenSSH-Server-In-TCP -InterfaceAlias Tailscale
   ```

3. **Make Windows PowerShell 5.1 the login shell (`DefaultShell`).** The Windows OpenSSH default is `cmd.exe`, which Fleet refuses, and PowerShell 7 (`pwsh.exe`) is refused too: Fleet's scripts are verified on Windows PowerShell 5.1, which is in-box on every supported version. This changes the login shell for every SSH user of the machine.

   ```powershell
   New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
     -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
     -PropertyType String -Force
   ```

4. **Turn password authentication off.** In `%ProgramData%\ssh\sshd_config`, set `PasswordAuthentication no` (and keep `PubkeyAuthentication yes`), then `Restart-Service sshd`.

5. **Install the controller's public key** (the `.pub` line of the key the controller authenticates with; never a private key).

   For a **standard user**, as that user (not elevated):

   ```powershell
   New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null
   Add-Content -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value 'ssh-ed25519 AAAA... fleet-controller'
   icacls "$env:USERPROFILE\.ssh\authorized_keys" /inheritance:r /grant "${env:USERNAME}:F" /grant "SYSTEM:F" /grant "*S-1-5-32-544:F"
   ```

   For an **administrator** (read the warning above first), elevated:

   ```powershell
   Add-Content -Path "$env:ProgramData\ssh\administrators_authorized_keys" -Value 'ssh-ed25519 AAAA... fleet-controller'
   icacls "$env:ProgramData\ssh\administrators_authorized_keys" /inheritance:r /grant "*S-1-5-32-544:F" /grant "SYSTEM:F"
   ```

   sshd ignores a key file whose ACL grants anyone else write access.

6. **Keep the account's PowerShell profile quiet.** Windows OpenSSH starts `powershell.exe -c <command>` without `-NoProfile`. A profile that prints anything corrupts Fleet's framing, and onboarding refuses it (below). The Windows 11 default execution policy (`Restricted`) keeps profiles from loading; if you set `RemoteSigned`, remove the output from `$PROFILE`.

7. **Read the host key fingerprint** for the confirmation step:

   ```powershell
   ssh-keygen -lf "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
   ```

## Onboard it

The same flow as a Linux machine ([pilot guide](fleet-pilot.md#agentless-onboarding)):

```sh
fleetctl --output json machines onboard create --user developer --host workstation-1.example.ts.net --name workstation-1 --auth agent
fleetctl --output json machines onboard test <draft-id> --wait
fleetctl --output json machines onboard get <draft-id>
fleetctl --output json machines onboard confirm <draft-id> --fingerprint SHA256:<fingerprint>
fleetctl --output json machines onboard test <draft-id> --wait      # connects and checks the login shell
fleetctl --output json machines onboard discover <draft-id> --wait  # checks the shell again, then probes
fleetctl --output json machines onboard add <draft-id>
```

Confirm the fingerprint only when it matches the one you read on the workstation. Once the fingerprint is confirmed, a test (and every discover) runs one fixed command with no caller data in it:

```text
echo fleet-shell %OS% $PSVersionTable.PSEdition $PSVersionTable.PSVersion.Major $ExecutionContext.SessionState.LanguageMode $PSVersionTable.Platform
```

Each shell answers it differently, so the controller knows which one it reached. After a POSIX answer it also runs `uname -s`, because Git Bash, MSYS2 and Cygwin answer like any POSIX shell. A test whose connection or authentication fails still completes, with `connected: false` and the failure in its detail, as on Linux; the shell is not checked then. When the connection succeeds but the shell check itself cannot complete (its session fails or times out), the test fails with `shell_check_failed` and leaves no answer on the draft. A login shell that answers without the marker (csh, `set -u`, a forced `command=` in `authorized_keys`) is `unrecognized`, never a failure. The result is the draft's `shellCheck` (`shell`, `guestOs`, and a refusal when there is one), shown by `onboard get`. `add` records `guestOs` on the new SSH endpoint: the machine reads back with `endpoints[].guestOs` = `windows` in `fleetctl --output json machines get <id>` and the API.

| The login shell | Result |
|---|---|
| Windows PowerShell 5.1, `FullLanguage`, no profile output | `shell` = `windows_powershell`, `guestOs` = `windows` |
| Bash or another POSIX shell | `shell` = `posix`, `guestOs` = `linux` (unchanged Linux behaviour) |
| `cmd.exe` | refused, `unsupported_shell`: set `DefaultShell` (step 3) |
| PowerShell 7 (`pwsh`) on Windows | refused, `unsupported_shell`: set `DefaultShell` to Windows PowerShell 5.1 (step 3) |
| Git Bash, MSYS2 or Cygwin as `DefaultShell` (`uname -s` is `MINGW*`, `MSYS*` or `CYGWIN*`) | refused, `unsupported_shell`: set `DefaultShell` to Windows PowerShell 5.1 (step 3) |
| PowerShell 7 as a Linux login shell | `shell` = `unrecognized` (not refused; the endpoint stays unknown) |
| Windows PowerShell in `ConstrainedLanguage` mode | refused, `constrained_language`: an App Control for Business or AppLocker policy applies to the account; Fleet's scripts need `FullLanguage` |
| Windows PowerShell with any output before the marker, whitespace included | refused, `profile_output`: remove the output from the profile (step 6) |
| Anything else | `shell` = `unrecognized`; nothing is recorded and the endpoint stays unknown |

A refused test fails with that reason and a detail naming the setting; `discover` fails the same way, and `add` refuses the draft (`409`) until a new test passes. Fix the setting on the workstation and run `onboard test` again.

Confirming a host key (the first time, or again after the key changed) drops the draft's shell answer and the facts discover collected, and a test that sees an unconfirmed or changed key drops the shell answer too: what answered behind another key says nothing about this one, so run discover again after a re-confirmation. `add` refuses a shell answer older than the latest confirmation and asks for a new test. The same holds for a registered machine: confirming an endpoint's host key clears its recorded OS.

## What the inventory reports

Discover, and every later `agentless.inventory` operation, runs the Windows probe under Windows PowerShell 5.1. The facts are the Linux set plus:

| Fact | Meaning |
|---|---|
| `os.family` = `Windows`, `os.distribution` = `windows` | The OS, as the console's machine list shows it (`windows 11`) |
| `os.windows_release` | `11` or `10`, from the build number (Windows 11 kept version 10.0); absent on a server build |
| `os.distribution_version` | The release (`11`), or the product name on a server |
| `os.edition`, `os.display_version`, `os.build`, `os.product_name`, `os.product_type` | `EditionID` (`Professional`, `Core` for Home, ...), `24H2`, `26100.2314`, the caption, `workstation` or `server` |
| `os.support` | `supported` (Windows 11 x64 Pro/Enterprise/Education, build 26100 or later) or `untested` (Windows 10, Home, arm64, an older build). Never a refusal |
| `host.architecture`, `host.hostname` | `x86_64` or `aarch64`; the computer name |
| `session.user` | The account Fleet logged in as |
| `session.administrator` | `true` when the session holds the Administrators role (a warning, see above) |
| `shell.powershell_version`, `shell.language_mode`, `shell.default_shell` | The login shell's version and language mode, and the OpenSSH `DefaultShell` value |
| `tool.<name>`, `tool-version.<name>` | Git, Docker, Tailscale, mise, Frogenv, `skills-manager-cli`, Claude and Codex: present or unavailable, and the first line of `--version` (`unknown` when the session is an administrator, below) |

**Sources, and standard users.** The probe asks CIM first, but a standard user's OpenSSH session is a network logon, and WMI refuses it (`Access denied`, for CIM and `Get-WmiObject` alike), so every fact CIM would give also has a source that account can read: the build, kernel version (`10.0.<build>`), product type and product name from the registry (`ProductName` still says `Windows 10` on Windows 11, so the probe names the release from the build, as the CIM caption does: `Microsoft Windows 11 Pro`), memory from `GlobalMemoryStatusEx` (through the in-box `Microsoft.VisualBasic` `ComputerInfo`), the maker, model and CPU from the SMBIOS and processor strings in `HKLM:\HARDWARE\DESCRIPTION\System`. A fact has the same value whichever source answered, so a standard user's inventory reads like an administrator's. The one difference: on physical hardware, `host.virtualization` = `hypervisor` (Hyper-V or virtualization-based security running) comes only from CIM, so a standard user's session reports it unavailable there. A fact no source answered is unavailable, never a guessed value such as a zero memory size. `network.ipv4` comes from .NET's interface list in every session, administrator or not, so it never depends on privilege: the first address, by IPv4 interface index, of an interface that is up and not loopback, skipping loopback and link-local (`169.254.*`) addresses.

Tools are found as `<name>.exe` on `PATH` with `Get-Command -CommandType Application`; a `.cmd` or `.bat` shim is never matched or run. Each match runs with the fixed argument `--version`, no stdin and its own 10-second bound. **When the session holds the Administrators role, nothing is run**: the inventory reports presence only and `tool-version` as `unknown`, because `PATH` folders are often user-writable and an elevated token must not execute what a user dropped there. Checkout discovery is still Linux-only.

## The endpoint's OS and `--os`

The guest OS is recorded **per SSH endpoint**, not per machine: a Windows PC that also runs an `sshd` in WSL has a `windows` endpoint and a `linux` endpoint. Once an endpoint's OS is recorded, `--os` (API `guestOs`) on `machines exec|put|collect` and on an inventory operation is a check, not a choice ([ADR 0021](../adr/0021-windows-workstations.md) decision 4, amending ADR 0017 decision 7): leave it out and the recorded OS is used; a different value is refused with `guest_os_mismatch`.

Endpoints that existed before this change are **unknown**, not `linux`. For them `--os` still chooses, and absent still means `linux`, so Windows Lab and persistent machines that work today keep working. The next inventory operation on an unknown endpoint runs the same login-shell check first and records what it finds: a refused shell fails the inventory with its reason, and an unrecognized answer or a check that cannot run leaves the endpoint unknown and probes with the caller's choice (an unrecognized endpoint is checked again on each inventory, one short extra session).

The rules for an `agentless.inventory` operation are checked when it is created: a `guestOs` that contradicts a recorded OS is refused with HTTP 409 and error code `guest_os_mismatch`, and on an endpoint whose OS is unknown, creating the operation also needs `machine.update` on the machine, because the operation may record the OS. A recorded OS is written under the principal who created the operation, together with an `endpoint_os_recorded` audit event naming the operation (one transaction), and only while the endpoint still has the host key the inventory verified: a key confirmed meanwhile wins. `machines exec|put|collect` answer a contradiction with the same `409 guest_os_mismatch`.

### Recovering from a wrong record

A recorded OS is not re-checked on every use. If it is wrong (for example `linux` recorded through an endpoint that now reaches a Windows PC, or after `DefaultShell` changed), clear it:

```sh
fleetctl --output json machines endpoint-os clear <machine-id> <endpoint-id>
```

It needs `machine.update`, writes an `endpoint_os_cleared` audit event, and leaves the endpoint unknown: `--os` chooses again, and the next inventory detects and records it afresh. Re-confirming the endpoint's host key clears it as well.

## Not verified yet

The detection, refusals and probe are covered by fixture and parser tests, a real POSIX `sshd`, and a `pwsh` run of the Windows probe on Linux, but not yet against a real Windows workstation: [#611](https://github.com/Frogbyte-io/fleet-manager/issues/611) runs that live validation, as a standard user and as an administrator. Until then, treat the Windows-specific fact values (edition, build, `session.administrator`, `shell.default_shell`, tool versions) and the exact sniff output of each Windows shell as expected, not observed.
