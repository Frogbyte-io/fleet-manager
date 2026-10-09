# ADR 0015: Windows Lab guests use OpenSSH Server in the image

Status: Proposed

Proposed: 2026-10-09 (tracking issue [#396](https://github.com/Frogbyte-io/fleet-manager/issues/396), first checklist item). Proposed for maintainer review. It refines the SSH transport of [ADR 0005](0005-provider-and-external-cli-boundaries.md) and the Lab flow of [ADR 0008](0008-durable-operations-and-lab-leases.md); it reverses neither. Accepting it ticks the first box of #396.

## Context

A Lab lease reaches its guest through `fleet-provider-ssh`: readiness registers a temporary SSH Fleet machine and pins its host key, and `lab exec`, `lab collect` and the proposed `lab put` ([#393](https://github.com/Frogbyte-io/fleet-manager/issues/393)) all run over that endpoint. The QEMU Guest Agent (FM-608, [#209](https://github.com/Frogbyte-io/fleet-manager/issues/209)) already reports a Windows guest's health, OS and IP, and nothing more. The first consumer of Windows leases is Release QA testing a Windows Tauri app. [#397](https://github.com/Frogbyte-io/fleet-manager/issues/397) additionally needs commands to run in the guest's interactive desktop session.

The question is which channel carries exec, put and collect for a Windows guest, so that the image recipe, readiness and the provider can be designed against one answer.

### What the code assumes today

- **A POSIX shell.** `fleet-provider-ssh` sends one command string, `bash -s -- <base64 blob>`, and the script on stdin. The caller's directory, environment and arguments travel in the blob so no remote shell ever parses caller text (`crates/providers/fleet-provider-ssh/src/exec.rs`). The prologue, the inventory and discovery probes, and the file fetch are Bash scripts using `base64 -d`/`-w0`, `read -d`, `export`, `uname`, `nproc`, `/proc/meminfo` and `hostname -I` (`exec.rs`, `fetch.rs`, `inventory.rs`, `discovery.rs`). None of these exist on a stock Windows guest (`cd` and `hostname` do, with different semantics).
- **POSIX guest paths.** `validate_collect_paths` in `crates/fleet-application/src/lab_artifacts.rs` requires a leading `/`, splits on `/`, and treats paths as case-sensitive when it rejects duplicates. #393 adopts the same rules for `lab put`. A Windows path (`C:\Users\...`, `C:/Users/...`) fails the first check.
- **Cloud-init and an SSH key already in the image.** The clone is configured through Proxmox cloud-init settings, and authentication uses controller keys that "must already be installed in the pinned image" ([lab.md](../architecture/lab.md#provisioning-saga), steps 4 and 8).
- **Per-lease host-key pinning.** Readiness establishes trust on first use (or against a template-declared fingerprint) and every later connection must match; a changed key fails the provision. Clones of one image therefore need distinct host keys, or at least a key that is stable per guest.
- **Windows is explicitly out of the first Lab release** ([PLAN.md](../PLAN.md), M7 and M8 notes; [#341](https://github.com/Frogbyte-io/fleet-manager/issues/341)).

## Options

### A. Windows OpenSSH Server in the image; keep `fleet-provider-ssh`

- OpenSSH Server ships as a Windows optional feature (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`) on Windows Server 2019 and Windows 10 1809 and later, and is installed but not enabled on Windows Server 2025. Microsoft calls the in-box feature "the recommended option for most users" and services it through Windows Update; installing it creates the `OpenSSH-Server-In-TCP` firewall rule on port 22. [Get started](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse), [overview](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview).
- Server configuration is `%programdata%\ssh\sshd_config`. The default shell is `cmd.exe`; `HKLM\SOFTWARE\OpenSSH\DefaultShell` selects another (for example `powershell.exe`). Only `password` and `publickey` authentication exist. [Server configuration](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration).
- Key authentication for a member of Administrators reads `%programdata%\ssh\administrators_authorized_keys` instead of the user's own file, and that file's ACL must contain only `SYSTEM` and `Administrators` (`icacls ... /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F"`). Same page.
- Host keys are `%programdata%\ssh\ssh_host_*_key`; "if the defaults aren't present, sshd automatically generates them on a service start." Same page. This is the hook for per-clone host keys.
- `scp`, `sftp` and `ssh-keyscan` ship with the feature ([overview](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-overview)), so the controller's existing `ssh`, `ssh-keyscan` and `ssh-keygen` host-key trust flow works unchanged.
- Licensing: the Windows port is Microsoft's fork of OpenSSH ([PowerShell/openssh-portable](https://github.com/PowerShell/openssh-portable)); its [LICENCE](https://raw.githubusercontent.com/PowerShell/openssh-portable/latestw_all/LICENCE) states that all components are under a BSD licence or one more free, with no GPL code. Fleet bundles nothing: the controller runs its own system `ssh`, and the guest's sshd is part of the image the operator builds.
- Unavailable options that matter here: `AcceptEnv`, `PermitUserEnvironment`, `StrictModes`, `AuthorizedKeysCommand` are not supported by the in-box build. Fleet does not rely on them (the environment already travels in the blob).
- Packer can already build Windows images over either communicator; the recipe rules in [the Lab runbook](../operations/lab.md) accept the literal `winrm_port` values 5985/5986 and `ssh_port` 22. That is the build-time channel and is independent of this decision.

### B. WinRM / PowerShell Remoting

- PowerShell Remoting uses WinRM on 5985 (HTTP) and 5986 (HTTPS); by default only Administrators may connect. WinRM encrypts everything after authentication, with message-level encryption over HTTP and TLS over HTTPS. [WinRM security](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security).
- A workgroup guest (assuming no domain join, which a Lab clone does not have) cannot use Kerberos. It falls back to NTLM, which is "disabled by default" and is enabled only by configuring SSL on the target or by adding the target to the client's `TrustedHosts`. NTLM "doesn't guarantee server identity"; only an SSL certificate the client trusts does. Same page. For a disposable fleet of clones, either every clone needs its own certificate (the same per-clone identity problem as an SSH host key, with a CA or pinning scheme on top) or `TrustedHosts` switches server verification off.
- The controller is Linux. A client needs either PowerShell with the WSMan/PSRP stack or a third-party library; neither is a documented, versioned CLI contract of the kind ADR 0005 requires, and neither is in the Rust stack. [pywinrm](https://pypi.org/project/pywinrm/) (MIT) would add a Python runtime. Evaluating and pinning that dependency is the cost this option adds.
- PowerShell can also remote over SSH ([docs](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ssh-remoting-in-powershell)), which needs PowerShell 6 or later and OpenSSH Server on the guest anyway, and does not support JEA or remote endpoint configuration. It adds nothing over option A for Fleet.

### C. QEMU Guest Agent exec through the Proxmox API

- PVE exposes `agent/exec`, `agent/exec-status`, `agent/file-write` and `agent/file-read` ([API viewer](https://pve.proxmox.com/pve-docs/api-viewer/index.html)). `exec` requires the `VM.GuestAgent.Unrestricted` privilege on the VM; `file-write` accepts `VM.GuestAgent.FileWrite` or Unrestricted. `file-write` content is limited to 61,440 characters per call, `file-read` to 16,777,216 bytes, and exec output is fetched by polling `exec-status`. Candidate-sized installers (the #393 use case: Electron and Tauri packages above 100 MB) would take well over a thousand calls (about 1,700 for 100 MB).
- It needs no guest network, and the agent is already part of every Windows template for FM-608. The cost is a privilege that is arbitrary command execution on every guest in the PVE account, not scoped to Lab guests, plus a second exec path to authorise, audit and bound (output caps, deadlines and cancellation semantics differ from `ssh`).
- The agent is QEMU's `qemu-ga`, GPL-2.0-or-later ([qga/main.c](https://github.com/qemu/qemu/blob/master/qga/main.c), [COPYING](https://github.com/qemu/qemu/blob/master/COPYING)); Windows builds are distributed with the virtio-win guest tools ([Fedora virtio-win ISO page](https://docs.fedoraproject.org/en-US/quick-docs/creating-windows-virtual-machines-using-virtio-drivers/), [virtio-win-pkg-scripts](https://github.com/virtio-win/virtio-win-pkg-scripts); the drivers repository [kvm-guest-drivers-windows](https://github.com/virtio-win/kvm-guest-drivers-windows) is BSD-3-Clause). Fleet calls it only through the Proxmox HTTP API as a separate process, so the licence does not reach Fleet's code.
- Its role in the current design is observation. That does not change here.

## Decision

1. **The Lab transport for Windows guests is OpenSSH Server baked into the image (option A).** Exec, put and collect keep going through `fleet-provider-ssh` against a verified SSH endpoint, with the same host-key pinning, authz, audit and operation machinery as Linux. WinRM is not adopted. A WinRM-based provider can be proposed later by a superseding ADR if a concrete need appears that OpenSSH cannot meet.
2. **The QEMU Guest Agent stays the observation and readiness-gating channel, not an exec transport.** Readiness still requires an online agent and a usable IPv4 address (the existing `guest_agent` probe) before the SSH endpoint is trusted. Agent exec is not wired into Lab exec, put or collect. It may be reconsidered as an out-of-band repair channel (for example, restarting a broken `sshd` on a stuck guest) under its own privilege review.
3. **Fleet learns the guest's OS from the template, not from guessing.** A Lab template gains a `guestOs` of `linux` (default) or `windows`. Everything OS-specific below keys off it. The template, not the SSH banner, is the source because a path or a shell must be chosen before the guest has proven anything.
4. **The SSH provider gets a guest-shell abstraction with the existing invariant intact:** caller data never passes through a remote shell. On Windows the remote shell is Windows PowerShell 5.1 (in-box, no extra install), set as `DefaultShell` by the image. The provider sends fixed text plus the same inert base64 metadata blob and the script on stdin; it never builds a command line from caller strings. The prologue is reimplemented for PowerShell (decode the blob, `Set-Location`, set environment variables, bind arguments), and the inventory, discovery and fetch probes are ported or declared unsupported per OS. Output decoding (UTF-8 versus the console code page) and exit-code propagation are part of that design and are tested on a real Windows guest.
5. **Guest paths are validated by guest OS.** For `windows` guests, `lab collect` and `lab put` accept an absolute drive-letter path with either separator (`C:\...` or `C:/...`), compared case-insensitively for the duplicate check. They refuse UNC and `\\?\` prefixes, alternate data streams (`:` after the drive), trailing dots or spaces in a component, reserved device names (`CON`, `NUL`, `COM1`, ...), empty, `.` and `..` components, and control characters, keeping the existing length and count bounds. The Linux rules are unchanged. The validator stays in `fleet-application`; the SSH provider receives a normalized path and never interprets caller text.
6. **The Windows image recipe and template requirements are in the Consequences below and are part of this decision.** The recipe issue documents them step by step.

## Consequences

### For `fleet-provider-ssh`

- The `bash -s --` command string, the Bash prologue, the probes and the fetch script move behind a per-OS guest-shell trait. The Linux implementation must stay byte-for-byte what it is now, covered by the existing tests, so this is a refactor with no Linux behaviour change.
- A PowerShell guest shell needs its own metadata framing test (hostile working directory, environment values and arguments including quotes, backticks, `$`, newlines and non-ASCII) mirroring the existing Bash tests. The bootstrap is delivered in a form the remote shell cannot misparse, for example a fixed `-EncodedCommand` string; the implementation issue chooses and proves it.
- File bytes: a PowerShell pipeline is not binary-safe on stdout. Collect on Windows must write raw bytes through the standard-output stream (or use SFTP). The size cap and SHA-256 verification inside the guest apply equally. This ADR proposes (#393 does not prescribe it) that `lab put` stream the file on stdin like collect does, rather than use `scp`, to keep one bounded, cancellable code path; it computes the hash in the guest with `Get-FileHash`.
- Cancellation and deadlines are unchanged: the controller kills its local `ssh`. Killing it does not stop the guest-side process tree on Windows. The documented "remote fate unknown" semantics already cover this, and the Windows executor should additionally run the script under a job-object-style wrapper only if the fixture shows orphaned processes (open question).

### For the image recipe and template

Each of these is verified on a real fixture before a Windows template is promotable.

- **Install and enable OpenSSH Server**, set the `sshd` service to Automatic, keep the `OpenSSH-Server-In-TCP` rule, and set `DefaultShell` to Windows PowerShell.
- **Controller key.** Install the Lab controller public key in `administrators_authorized_keys` with the ACL above, for a dedicated local administrator account (a non-administrator account would use `.ssh\authorized_keys` in its profile). Password authentication stays off. No private key or password enters the image or Git.
- **Host keys must not be baked in.** Sysprep generalize removes the computer SID and machine-specific device state ([Sysprep generalize](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation)); the page says nothing about SSH host keys, so the recipe must delete `%programdata%\ssh\ssh_host_*` after stopping `sshd` and before generalize. With `sshd` Automatic, each clone then generates its own keys at first start, and Fleet's trust-on-first-use or template-pinned flow applies per clone. A template that pins `sshFingerprint` is not usable for a cloned image whose keys are regenerated; Windows templates use `tofu`, unless the pool issue pins per pool member.
- **Unique identity on clone.** Generalize so each clone gets a new SID, and let specialize pick a unique computer name (not a fixed name in the answer file). Clones must receive new MAC addresses so DHCP leases and the guest agent's IP are distinct, and the controller already depends on the agent's address. The Sysprep limit is 1001 runs per Windows image, so templates are rebuilt from a fresh install, not re-sysprepped indefinitely. Microsoft Store apps updated by a user make generalize fail; the recipe must not update them.
- **Guest agent.** Install `qemu-ga` and the VirtIO drivers from the virtio-win ISO, with the agent service Automatic, so the existing readiness gate and FM-608 observation work.
- **First-boot configuration without cloud-init.** The clone step applies Proxmox cloud-init settings, which a stock Windows image ignores. The image either uses an unattend file for what is static or adds [Cloudbase-Init](https://github.com/cloudbase/cloudbase-init) (Apache-2.0) for what Fleet sets at clone time. Which is chosen is the recipe issue's call; this ADR requires only that no per-lease secret is baked in.
- **Windows licensing and activation** are runbook content, not part of this decision.

### For readiness, pools and revert

- The SSH readiness step and TOFU pinning are unchanged. Windows boot plus specialize is slow, so readiness deadlines are per template.
- A pool member reverted to a snapshot restores that snapshot's host keys. A snapshot taken before first boot regenerates keys on every revert, which would trip the pinned-key check; a snapshot taken after first boot gives a stable key per pool member. The pool issue must choose and document one.

### How this interacts with #397 (interactive-session exec)

- Windows services run in session 0 and cannot display UI on a user's desktop; Microsoft documents `CreateProcessAsUser` into the user's session as one technique for a service to reach a user's desktop ([Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)). `sshd` is a service, so the commands it launches are expected to run in session 0. This is also the premise of #397, and the fixture test in #397 (a command that reports its own session id) is what confirms it for OpenSSH specifically.
- Whether a guest-agent exec or a WinRM session would be any different is not sourced here (see "Evidence not yet gathered"); this ADR does not rely on either being interactive.
- This decision means #397's mechanism is one in-guest step started by an SSH exec: the SSH exec (session 0, administrator) starts a scheduled task or helper that runs as the designated test user in the interactive session and returns the exit code and bounded output through the same blob/stdout framing. #397 owns that mechanism and the autologon requirement (configured by the image, credentials never in job payloads, logs or audit). The long-exec pattern of [#394](https://github.com/Frogbyte-io/fleet-manager/issues/394) composes because the outer transport is the same SSH exec.
- Readiness for #397 adds a second condition to the transport's: the interactive user is logged in. That does not change this ADR.

## Alternatives rejected

- **WinRM (B).** No documented cross-platform client contract for a Linux controller; NTLM against workgroup clones needs a per-clone TLS certificate or switching off server verification, which is the identity problem of option A without the existing trust flow, tests, audit and endpoint model; a second provider to authorise, audit and keep bounded.
- **Guest-agent exec as the transport (C).** Requires a VM-wide arbitrary-exec privilege on the PVE account, is limited to 60 KiB writes and 16 MiB reads per call, polls for output, and creates a second exec path beside SSH. Kept only as a possible out-of-band repair channel.
- **A Fleet-owned in-guest agent (`fleetd` on Windows).** Deferred by the master plan; it is a larger Windows service-hosting commitment than this epic needs, and may later subsume this transport.

## Open questions

1. **Account model.** One dedicated local administrator for exec, or an administrator for exec plus a separate unprivileged interactive test user (the #397 user)? Installers that need elevation favour the first; Release QA's "intended user's environment" favours the second.
2. **Image build channel.** Packer can build over WinRM or SSH. Using the SSH communicator end to end gives one tested path; WinRM during build is the more common Windows recipe pattern. This only concerns the build and is a recipe-issue choice.
3. **Per-pool-member host keys and snapshot timing** (above).
4. **Orphaned process trees after a deadline kill** on Windows, and whether the executor needs a wrapper.
5. **Guest OS field.** `guestOs` on the template is proposed; whether it is also derived from the image recipe, and how a mismatch with the agent's `get-osinfo` is reported, needs a small design.
6. **Windows Server Core or Server image versus Windows 11 client.** Release QA's desktop tests need a desktop session, so Server Core is out for them, but the ADR does not fix an edition. Windows 11 licensing for disposable guests is a runbook matter.
7. **Out-of-band repair.** Whether Lab ever uses guest-agent exec for `sshd` recovery, and under which scoped PVE privilege, is left to a later issue.

## Evidence not yet gathered

These claims rest on Microsoft's documentation and on reading the code, not on a Windows guest in the fixture lab. The recipe and readiness issues must confirm them on a real guest before this ADR moves to Accepted:

- PowerShell 5.1 as `DefaultShell` accepts a stdin-delivered script with the fixed bootstrap, preserves the exit code, and is binary-safe for collect.
- `sshd` regenerates host keys at first start after generalize when the key files were removed.
- A Proxmox clone of a generalized Windows image gets a new MAC, SID and computer name.
- Guest-agent exec and WinRM sessions are also non-interactive (expected, as both run under services; not sourced).
- A command started by `sshd` reports a non-interactive session id, and the #397 mechanism reaches the interactive one.
