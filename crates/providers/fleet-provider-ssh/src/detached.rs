//! Detached commands on a Lab guest (#394): start one so it outlives the
//! SSH session, and read its state later.
//!
//! The transport rule is the one [`crate::exec`] states: **caller data never
//! reaches a remote shell as shell text.** The scripts here are fixed text
//! owned by this crate. The command rides as base64 inside a quoted heredoc
//! (its alphabet cannot contain a shell metacharacter or the heredoc's
//! delimiter), and the handle, the timeout, and the tail window ride in the
//! metadata blob as `$1..$3`. Both are validated again in the guest.
//!
//! # Guest layout
//!
//! One directory per handle, `<base>/<handle>/`, mode 0700, where `<base>` is
//! `/var/lib/fleet-lab/exec` for root and `$HOME/.local/state/fleet-lab/exec`
//! for any other SSH user:
//!
//! - `cmd.sh` the command, run by `bash`; `run.sh` the fixed wrapper.
//! - `pid` (`<pid> <start time>`), `boot_id`, `started`, written by the
//!   wrapper once it runs. `start` returns only after `pid` exists.
//! - `stdout`, `stderr` the command's output.
//! - `exit`, `finished` written last and atomically (temporary file, then
//!   rename). `exit` is the command's exit status; `124` means the
//!   `timeout` bound ended it.
//!
//! The command runs in its own session (`setsid`) with stdio detached, so
//! the SSH session ends as soon as it has started. Like `lab exec`, it
//! starts in the SSH user's login directory. Only coreutils and
//! util-linux are used (`setsid`, `timeout`, `base64`, `tail`, `stat`).
//!
//! # States
//!
//! The status script reports `absent` (no directory), `starting` (directory
//! without a `pid` yet), `running` (`pid` names a live process with the
//! recorded start time and the same boot id), `exited` (`exit` exists), or
//! `lost` with a reason: `guest_rebooted` (boot id differs), `process_gone`
//! (the wrapper died without writing `exit`, for example it was killed),
//! `never_started` (the directory never got a `pid`, or the start gave up
//! and wrote `abandoned`, which makes a late wrapper exit without running).
//! Status reads only regular files, never symlinks, and bounds each read.

use std::time::Duration;

use base64::Engine as _;

use crate::exec::{ExecutionLimiter, ScriptMetadata, execute_script};
use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// How much of each stream the status script returns, before Fleet scrubs
/// the text and keeps its own last bytes. It is larger than the bytes Fleet
/// keeps so that a credential straddling the cut is scrubbed whole.
pub const TAIL_WINDOW_BYTES: usize = 16 * 1024;

/// How long the start session may take.
pub const SESSION_DEADLINE: Duration = Duration::from_secs(60);

/// How long a status read may take. The guest script bounds each file read
/// with `timeout 5`, so a command that swaps its output for a FIFO cannot
/// hold the session.
pub const STATUS_DEADLINE: Duration = Duration::from_secs(15);

/// The longest handle the guest accepts.
pub const MAX_HANDLE_LEN: usize = 64;

/// Whether `handle` is safe to name a guest directory: 1 to
/// [`MAX_HANDLE_LEN`] characters of `[A-Za-z0-9_-]`.
#[must_use]
pub fn is_valid_handle(handle: &str) -> bool {
    !handle.is_empty()
        && handle.len() <= MAX_HANDLE_LEN
        && handle
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// The guest-side wrapper (`run.sh`), written verbatim by the start script.
/// `$1` the handle directory, `$2` the timeout in seconds.
const WRAPPER: &str = r#"umask 077
fleet_dir=$1; fleet_secs=$2
[ ! -e "$fleet_dir/abandoned" ] || exit 0
fleet_stat=$(cat /proc/$$/stat) || exit 1
fleet_rest=${fleet_stat##*) }
set -- $fleet_rest
fleet_start=${20}
cat /proc/sys/kernel/random/boot_id > "$fleet_dir/boot_id" 2>/dev/null
date +%s > "$fleet_dir/started"
printf '%s %s\n' "$$" "$fleet_start" > "$fleet_dir/pid.tmp" && mv -f "$fleet_dir/pid.tmp" "$fleet_dir/pid"
timeout -k 10 "$fleet_secs" bash "$fleet_dir/cmd.sh" > "$fleet_dir/stdout" 2> "$fleet_dir/stderr" < /dev/null
fleet_code=$?
date +%s > "$fleet_dir/finished"
printf '%s\n' "$fleet_code" > "$fleet_dir/exit.tmp" && mv -f "$fleet_dir/exit.tmp" "$fleet_dir/exit"
"#;

/// The guest-side shared prologue: validates the handle and resolves the
/// directory. `$1` handle, `$2` number, optional `$3` base directory
/// override (tests only; Fleet never sets it).
const RESOLVE: &str = r#"fleet_handle=$1; fleet_num=$2; fleet_base=${3:-}
case $fleet_handle in ''|*[!A-Za-z0-9_-]*) exit 64;; esac
[ "${#fleet_handle}" -le 64 ] || exit 64
case $fleet_num in ''|*[!0-9]*) exit 64;; esac
if [ -z "$fleet_base" ]; then
  if [ "$(id -u)" = 0 ]; then
    fleet_base=/var/lib/fleet-lab/exec
  else
    [ -n "${HOME:-}" ] || exit 71
    fleet_base=$HOME/.local/state/fleet-lab/exec
  fi
fi
fleet_dir=$fleet_base/$fleet_handle
"#;

const START_BODY: &str = r#"umask 077
mkdir -p -- "$fleet_base" || exit 71
if ! mkdir -- "$fleet_dir" 2>/dev/null; then
  [ -d "$fleet_dir" ] && [ ! -L "$fleet_dir" ] || exit 71
  echo exists
  exit 0
fi
printf '%s' "$fleet_cmd_b64" | base64 -d > "$fleet_dir/cmd.sh" || exit 72
cat > "$fleet_dir/run.sh" <<'FLEET_RUN_END'
"#;

const START_TAIL: &str = r#"FLEET_RUN_END
setsid bash "$fleet_dir/run.sh" "$fleet_dir" "$fleet_num" </dev/null >/dev/null 2>&1 &
fleet_n=0
while [ ! -f "$fleet_dir/pid" ] && [ "$fleet_n" -lt 100 ]; do
  sleep 0.1
  fleet_n=$((fleet_n + 1))
done
[ -f "$fleet_dir/pid" ] || { : > "$fleet_dir/abandoned"; exit 75; }
echo started
exit 0
"#;

/// The script that starts `command` detached. Run it with the metadata
/// arguments `[handle, timeout_seconds]` (see [`start_metadata`]).
///
/// Starting is idempotent: when the handle's directory already exists the
/// script prints `exists` and exits 0 without starting anything, so a
/// retried operation never runs the command twice. Exit codes: 64 invalid
/// handle or timeout, 71 the directory cannot be prepared, 72 the command
/// cannot be written, 75 the wrapper never started.
#[must_use]
pub fn start_script(command: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(command.as_bytes());
    format!(
        "fleet_cmd_b64=$(cat <<'FLEET_CMD_END'\n{encoded}\nFLEET_CMD_END\n)\n{RESOLVE}{START_BODY}{WRAPPER}{START_TAIL}"
    )
}

// ---------------------------------------------------------------------------
// Windows (PowerShell 5.1) twins of the scripts above. Same layout, same
// states, same `key=value` status protocol, so `parse_status` reads both.
//
// Guest layout: `<base>\<handle>\` where `<base>` is
// `%LOCALAPPDATA%\fleet-lab\exec` of the SSH user (every directory's ACL is
// protected: SYSTEM, Administrators and the SSH user only). Files: `body.ps1` (the
// command, verbatim UTF-8), `run.ps1` (the fixed wrapper), `pid`
// (`<pid> <start time ticks>`), `boot_id`, `started`, `stdout`, `stderr`,
// `exit` and `finished` (written last, temporary file then rename), and
// `abandoned` (a start that gave up: a late wrapper exits without running).
//
// The command runs as a child of the wrapper under a timeout (`124` is the
// bound ending it; its process tree is killed), with stdio redirected to
// files. The wrapper is launched with CreateProcess and
// `CREATE_BREAKAWAY_FROM_JOB` so it is outside the OpenSSH session's job
// object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` in `w32-doexec.c`). WMI's
// `Win32_Process.Create` was tried first and is refused for a standard
// account ("Access denied"); breakaway works for both account types (live
// Windows run).
// ---------------------------------------------------------------------------

/// The Windows prologue shared by start and status: validates the handle and
/// the number, resolves the directories, and defines the trust check.
/// `$args`: handle, number, optional base directory override (tests only;
/// Fleet never sets it).
///
/// Directories: always under the SSH user's `%LOCALAPPDATA%\fleet-lab\exec`
/// (never `C:\ProgramData`, where any local user can create folders and could
/// pre-create `fleet-lab` or a junction to plant the `run.ps1` the supervisor
/// runs). Even there, the base directories and the handle directory are only
/// used when each is a real directory (not a reparse point), owned by SYSTEM,
/// Administrators or the SSH user, and grants
/// write-class access to nobody else. They are created with a protected ACL in
/// the same call (the creator is the owner; nothing sets it), then checked
/// again: a directory someone else created first fails the check.
const WINDOWS_RESOLVE: &str = r"$ErrorActionPreference = 'Stop'
$fleetHandle = $args[0]
$fleetNum = $args[1]
$fleetBase = $args[2]
if ($fleetHandle -cnotmatch '^[A-Za-z0-9_-]{1,64}\z' -or $fleetNum -cnotmatch '^[0-9]{1,18}\z') { exit 64 }
$fleetWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
$fleetOverride = [bool]$fleetBase
$fleetSystem = $null
$fleetAdmins = $null
$fleetMe = $null
if ($fleetWindows) {
  $fleetSystem = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
  $fleetAdmins = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'
  $fleetMe = [Security.Principal.WindowsIdentity]::GetCurrent().User
}
if (-not $fleetBase) {
  if ($fleetWindows) {
    if (-not $env:LOCALAPPDATA) { exit 71 }
    $fleetBase = [IO.Path]::Combine($env:LOCALAPPDATA, 'fleet-lab', 'exec')
  } else {
    if (-not $env:HOME) { exit 71 }
    $fleetBase = [IO.Path]::Combine($env:HOME, '.local', 'state', 'fleet-lab', 'exec')
  }
}
$fleetParent = [IO.Path]::GetDirectoryName($fleetBase)
$fleetDir = [IO.Path]::Combine($fleetBase, $fleetHandle)
# Who may own or write: SYSTEM, Administrators and the SSH user, always, so
# an elevation change between start and status (or a profile whose ACL
# already names them) neither locks the user out nor fails the check.
$fleetTrusted = @()
if ($fleetWindows) { $fleetTrusted = @($fleetSystem, $fleetAdmins, $fleetMe) }
function fleetIn($sid) { foreach ($t in $fleetTrusted) { if ($t.Equals($sid)) { return $true } }; return $false }
function fleetSecure($path) {
  if (-not $fleetWindows) { return $true }
  try {
    $info = New-Object IO.DirectoryInfo $path
    if (-not $info.Exists -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
    $acl = $info.GetAccessControl()
    if (-not (fleetIn ($acl.GetOwner([Security.Principal.SecurityIdentifier])))) { return $false }
    # Write-class bits, including the raw generic rights an ACE can carry
    # (GENERIC_ALL 0x10000000, GENERIC_WRITE 0x40000000) that the enum names miss.
    $writes = [int64]0x500D0156
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
      if ($rule.AccessControlType -eq 'Allow' -and ((([int64]$rule.FileSystemRights) -band $writes) -ne 0) -and -not (fleetIn $rule.IdentityReference)) { return $false }
    }
    return $true
  } catch { return $false }
}
function fleetMakeDir($path) {
  if (-not [IO.Directory]::Exists($path)) {
    try {
      if ($fleetWindows) {
        $sec = New-Object Security.AccessControl.DirectorySecurity
        $sec.SetAccessRuleProtection($true, $false)
        foreach ($sid in $fleetTrusted) {
          $sec.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
        }
        [void][IO.Directory]::CreateDirectory($path, $sec)
      } else {
        [void][IO.Directory]::CreateDirectory($path)
      }
    } catch { [Console]::Error.WriteLine('fleet: cannot create a guest directory (' + $_.Exception.GetType().Name + $(if ($_.Exception.InnerException) { ' / ' + $_.Exception.InnerException.GetType().Name } else { '' }) + ')') }
  }
  return (fleetSecure $path)
}
function fleetChainSecure {
  if (-not $fleetWindows -or $fleetOverride) { return $true }
  foreach ($d in @($fleetParent, $fleetBase)) { if ([IO.Directory]::Exists($d) -and -not (fleetSecure $d)) { return $false } }
  return $true
}
function fleetReg($path) {
  try { $i = New-Object IO.FileInfo $path; return ($i.Exists -and -not ($i.Attributes -band [IO.FileAttributes]::ReparsePoint)) } catch { return $false }
}
function fleetBoot {
  if ($fleetWindows) {
    # The boot counter, unlike the last-boot time, does not move when the
    # clock is stepped. Empty means unknown, never a mismatch.
    try { return ([string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name BootId -ErrorAction Stop).BootId) } catch { return '' }
  }
  try { return (Get-Content -LiteralPath '/proc/sys/kernel/random/boot_id' -TotalCount 1) } catch { return '' }
}
";

/// The wrapper (`run.ps1`), written verbatim by the start script. With
/// `-Mode body` it is the child that runs the command; otherwise it is the
/// supervisor: it takes the `gate` (a start that gave up and a wrapper that
/// runs cannot both win), records its pid first, runs the child under the
/// timeout with output in files, and writes `exit` last.
const WINDOWS_WRAPPER: &str = r#"param([string]$Dir, [string]$Secs, [string]$Mode)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
if ($Mode -eq 'body') {
  try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
  $fleetText = [IO.File]::ReadAllText([IO.Path]::Combine($Dir, 'body.ps1'), [Text.Encoding]::UTF8)
  $fleetBlock = [scriptblock]::Create($fleetText + [Environment]::NewLine + [Environment]::NewLine + '$global:fleetOk=$?')
  $ErrorActionPreference = 'Continue'
  $global:fleetOk = $null
  $global:LASTEXITCODE = $null
  Invoke-Command -ScriptBlock $fleetBlock
  if ($global:fleetOk -eq $false) {
    # The code goes to a file, not through ssh: keep any nonzero code as it is.
    $fleetC = 1
    if ($global:LASTEXITCODE) { $fleetC = [int]$global:LASTEXITCODE }
    exit $fleetC
  }
  exit 0
}
function fleetPath($name) { return [IO.Path]::Combine($Dir, $name) }
try {
  $fleetGate = New-Object IO.FileStream((fleetPath 'gate'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
  $fleetGate.Dispose()
} catch { exit 0 }
if ([IO.File]::Exists((fleetPath 'abandoned'))) { exit 0 }
$fleetWindows = [Environment]::OSVersion.Platform -eq 'Win32NT'
$fleetMe = [Diagnostics.Process]::GetCurrentProcess()
[IO.File]::WriteAllText((fleetPath 'pid.tmp'), ('{0} {1}' -f $fleetMe.Id, $fleetMe.StartTime.ToUniversalTime().Ticks) + "`n")
[IO.File]::Move((fleetPath 'pid.tmp'), (fleetPath 'pid'))
$fleetBoot = ''
if ($fleetWindows) {
  try { $fleetBoot = [string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -Name BootId -ErrorAction Stop).BootId } catch { }
} else {
  try { $fleetBoot = (Get-Content -LiteralPath '/proc/sys/kernel/random/boot_id' -TotalCount 1) } catch { }
}
[IO.File]::WriteAllText((fleetPath 'boot_id'), $fleetBoot + "`n")
[IO.File]::WriteAllText((fleetPath 'started'), [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() + "`n")
[IO.File]::WriteAllBytes((fleetPath 'stdin'), [byte[]]@())
if ($fleetWindows) { $fleetExe = [IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe') } else { $fleetExe = [IO.Path]::Combine($PSHOME, 'pwsh') }
$fleetArgs = @('-NoProfile', '-NonInteractive')
if ($fleetWindows) { $fleetArgs += @('-ExecutionPolicy', 'Bypass') }
$fleetArgs += @('-File', ('"{0}"' -f (fleetPath 'run.ps1')), '-Dir', ('"{0}"' -f $Dir), '-Secs', $Secs, '-Mode', 'body')
# The command runs where the start session was (the supervisor's working
# directory), not in its own control directory.
$fleetCwd = (Get-Location).ProviderPath
$fleetChild = Start-Process -FilePath $fleetExe -ArgumentList $fleetArgs -WorkingDirectory $fleetCwd -RedirectStandardOutput (fleetPath 'stdout') -RedirectStandardError (fleetPath 'stderr') -RedirectStandardInput (fleetPath 'stdin') -NoNewWindow -PassThru
$null = $fleetChild.Handle
$fleetMs = [int][Math]::Min([int64]$Secs * 1000, 2000000000)
if ($fleetChild.WaitForExit($fleetMs)) {
  $fleetChild.WaitForExit()
  $fleetCode = $fleetChild.ExitCode
} else {
  $fleetKilled = $false
  if ($fleetWindows) {
    try {
      # Process.Start keeps the handle, so ExitCode is reliable (Windows
      # PowerShell 5.1's Start-Process -PassThru can lose it for a process
      # that exits quickly).
      $fleetPsi = New-Object Diagnostics.ProcessStartInfo
      $fleetPsi.FileName = [IO.Path]::Combine($env:SystemRoot, 'System32', 'taskkill.exe')
      $fleetPsi.Arguments = '/T /F /PID ' + [string]$fleetChild.Id
      $fleetPsi.UseShellExecute = $false
      $fleetPsi.CreateNoWindow = $true
      $fleetKill = [Diagnostics.Process]::Start($fleetPsi)
      if ($fleetKill.WaitForExit(10000) -and $fleetKill.ExitCode -eq 0) { $fleetKilled = $true }
    } catch { }
  }
  if (-not $fleetKilled) { try { if ($fleetWindows) { $fleetChild.Kill() } else { $fleetChild.Kill($true) } } catch { } }
  [void]$fleetChild.WaitForExit(30000)
  $fleetCode = 124
}
[IO.File]::WriteAllText((fleetPath 'finished'), [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString() + "`n")
[IO.File]::WriteAllText((fleetPath 'exit.tmp'), ([string]$fleetCode) + "`n")
[IO.File]::Move((fleetPath 'exit.tmp'), (fleetPath 'exit'))
"#;

/// The Windows start body: `$fleetCmd64` (the command as base64 UTF-8) and
/// `$fleetWrapper` are set by the caller's prefix.
const WINDOWS_START_BODY: &str = r#"$fleetBegan = [DateTime]::UtcNow
if ($fleetWindows -and -not $fleetOverride) {
  if (-not (fleetMakeDir $fleetParent)) { exit 71 }
  if (-not (fleetMakeDir $fleetBase)) { exit 71 }
} else {
  try { [void][IO.Directory]::CreateDirectory($fleetBase) } catch { exit 71 }
}
if ([IO.Directory]::Exists($fleetDir)) {
  if (-not (fleetSecure $fleetDir)) { exit 71 }
  [Console]::Out.Write("exists`n")
  exit 0
}
if (-not (fleetMakeDir $fleetDir)) { exit 71 }
try {
  [IO.File]::WriteAllBytes([IO.Path]::Combine($fleetDir, 'body.ps1'), [Convert]::FromBase64String($fleetCmd64))
  [IO.File]::WriteAllText([IO.Path]::Combine($fleetDir, 'run.ps1'), $fleetWrapper)
} catch { exit 72 }
# A start that gives up and a wrapper that runs race for the gate: whoever
# creates it first decides. The loser of the start's side only reports; the
# marker keeps a late wrapper from running.
function fleetGiveUp {
  $won = $false
  try {
    $g = New-Object IO.FileStream([IO.Path]::Combine($fleetDir, 'gate'), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $g.Dispose()
    $won = $true
  } catch { }
  if ($won) { try { [IO.File]::WriteAllText([IO.Path]::Combine($fleetDir, 'abandoned'), '') } catch { } }
  return $won
}
$fleetRun = [IO.Path]::Combine($fleetDir, 'run.ps1')
$fleetCwd = (Get-Location).ProviderPath
$fleetLaunched = $true
if ($fleetWindows) {
  $fleetPs = [IO.Path]::Combine($env:SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  $fleetLine = '"{0}" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{1}" -Dir "{2}" -Secs {3}' -f $fleetPs, $fleetRun, $fleetDir, $fleetNum
  try {
    # CreateProcess with CREATE_BREAKAWAY_FROM_JOB: Windows OpenSSH puts the
    # session's processes in a job that is killed when the session ends, and
    # allows breakaway from it. Unlike WMI process creation this works
    # for a standard (non-administrator) account, and the child keeps the
    # session's user, token and environment.
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FleetLaunch {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct STARTUPINFO { public int cb; public string lpReserved; public string lpDesktop; public string lpTitle; public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
  [StructLayout(LayoutKind.Sequential)]
  public struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
  [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags, IntPtr env, string cwd, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  public static int Start(string cmd, string cwd) {
    STARTUPINFO si = new STARTUPINFO(); si.cb = Marshal.SizeOf(typeof(STARTUPINFO)); PROCESS_INFORMATION pi;
    // CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW (a hidden console: powershell.exe does not start under DETACHED_PROCESS)
    uint flags = 0x01000000 | 0x00000200 | 0x08000000;
    if (!CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, cwd, ref si, out pi)) return -Marshal.GetLastWin32Error();
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return pi.dwProcessId;
  }
}
'@
    # Compiling the helper can be slow on a cold guest. A start that has used
    # more than 30 s of its 60 s session gives up here, before launching: sshd
    # does not end the session when the client disappears, so a late launch
    # after the controller has already read `never_started` would run anyway.
    if (([DateTime]::UtcNow - $fleetBegan).TotalSeconds -gt 30) { $fleetLaunched = $false }
    elseif ([FleetLaunch]::Start($fleetLine, $fleetCwd) -le 0) { $fleetLaunched = $false }
  } catch { $fleetLaunched = $false }
} else {
  $fleetInfo = New-Object Diagnostics.ProcessStartInfo
  $fleetInfo.FileName = [IO.Path]::Combine($PSHOME, 'pwsh')
  foreach ($fleetPart in @('-NoProfile', '-NonInteractive', '-File', $fleetRun, '-Dir', $fleetDir, '-Secs', $fleetNum)) { [void]$fleetInfo.ArgumentList.Add($fleetPart) }
  $fleetInfo.UseShellExecute = $false
  # Only so the child holds none of this session's pipes (tests, non-Windows).
  $fleetInfo.RedirectStandardInput = $true
  $fleetInfo.RedirectStandardOutput = $true
  $fleetInfo.RedirectStandardError = $true
  $fleetInfo.WorkingDirectory = $fleetCwd
  [void][Diagnostics.Process]::Start($fleetInfo)
}
# A launch that failed (a launch error) never started a wrapper unless one slipped
# in: take the gate to say so, and if the gate is already taken, wait for the
# wrapper like any other start.
if (-not $fleetLaunched -and (fleetGiveUp)) { exit 75 }
# Worst case in this session: a few seconds to compile the launch helper, 25 s
# here, 5 s below,
# inside the 60 s session deadline together with ssh setup and PowerShell's
# own cold start.
$fleetPidFile = [IO.Path]::Combine($fleetDir, 'pid')
$fleetWaited = 0
while (-not [IO.File]::Exists($fleetPidFile) -and $fleetWaited -lt 250) { Start-Sleep -Milliseconds 100; $fleetWaited++ }
if (-not [IO.File]::Exists($fleetPidFile)) {
  if (fleetGiveUp) { exit 75 }
  # The wrapper holds the gate, so it is running (or about to). Give it a
  # little longer; if its pid is still not there the outcome is unknown, which
  # is not the same as failed: status decides.
  $fleetWaited = 0
  while (-not [IO.File]::Exists($fleetPidFile) -and $fleetWaited -lt 50) { Start-Sleep -Milliseconds 100; $fleetWaited++ }
  if (-not [IO.File]::Exists($fleetPidFile)) { exit 76 }
}
[Console]::Out.Write("started`n")
exit 0
"#;

/// The Windows status body: prints the same `key=value` lines as the Bash
/// one. Only regular files that are not reparse points are read, each
/// bounded; the tails are the last `$fleetNum` bytes. The directories are
/// trusted only as `WINDOWS_RESOLVE` describes (exit 71 otherwise).
const WINDOWS_STATUS_BODY: &str = r#"function fleetNumOf($path, $signed) {
  if (-not (fleetReg $path)) { return '' }
  try {
    $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
    try { $buf = New-Object byte[] 20; $n = $fs.Read($buf, 0, 20) } finally { $fs.Dispose() }
    $text = [Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim()
    if ($signed) { if ($text -cmatch '^-?[0-9]{1,11}\z') { return $text } }
    elseif ($text -cmatch '^[0-9]{1,19}\z') { return $text }
  } catch { }
  return ''
}
function fleetSmall($path) {
  if (-not (fleetReg $path)) { return '' }
  try {
    $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
    try { $buf = New-Object byte[] 64; $n = $fs.Read($buf, 0, 64) } finally { $fs.Dispose() }
    return [Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim()
  } catch { return '' }
}
function fleetAlive {
  $line = fleetSmall ([IO.Path]::Combine($fleetDir, 'pid'))
  $parts = $line.Split(' ')
  if ($parts.Length -ne 2 -or $parts[0] -cnotmatch '^[0-9]{1,10}\z' -or $parts[1] -cnotmatch '^[0-9]{1,19}\z') { return $false }
  try {
    $p = Get-Process -Id ([int]$parts[0]) -ErrorAction Stop
    if ($p.HasExited) { return $false }
    # Within a second: Windows reports the exact creation time, but other
    # platforms estimate it, and a reused pid is never a second younger.
    return ([Math]::Abs($p.StartTime.ToUniversalTime().Ticks - [int64]$parts[1]) -lt 10000000)
  } catch { return $false }
}
$fleetExit = [IO.Path]::Combine($fleetDir, 'exit')
$fleetPid = [IO.Path]::Combine($fleetDir, 'pid')
if (-not (fleetChainSecure)) { exit 71 }
if (-not [IO.Directory]::Exists($fleetDir)) {
  [Console]::Out.Write("state=absent`n")
  exit 0
}
if (-not (fleetSecure $fleetDir)) { exit 71 }
$fleetState = ''
$fleetReason = ''
if (fleetReg $fleetExit) {
  $fleetState = 'exited'
} elseif (fleetReg $fleetPid) {
  # A boot counter that is unknown on either side is not evidence of a
  # reboot: the pid and its start time decide.
  $fleetThen = fleetSmall ([IO.Path]::Combine($fleetDir, 'boot_id'))
  $fleetNow = fleetBoot
  if ($fleetThen -ne '' -and $fleetNow -ne '' -and $fleetThen -ne $fleetNow) { $fleetState = 'lost'; $fleetReason = 'guest_rebooted' }
  elseif (fleetAlive) { $fleetState = 'running' }
  elseif (fleetReg $fleetExit) { $fleetState = 'exited' }
  else { $fleetState = 'lost'; $fleetReason = 'process_gone' }
} elseif ([IO.File]::Exists([IO.Path]::Combine($fleetDir, 'abandoned'))) {
  $fleetState = 'lost'; $fleetReason = 'never_started'
} elseif ([IO.File]::Exists([IO.Path]::Combine($fleetDir, 'gate')) -and (([DateTime]::UtcNow - (New-Object IO.DirectoryInfo $fleetDir).CreationTimeUtc).TotalSeconds -lt 180)) {
  # A wrapper holds the gate but has not recorded its pid yet: the start is
  # unconfirmed, not failed.
  $fleetState = 'starting'; $fleetReason = 'start_unconfirmed'
} elseif (([DateTime]::UtcNow - (New-Object IO.DirectoryInfo $fleetDir).CreationTimeUtc).TotalSeconds -lt 60) {
  $fleetState = 'starting'
} else {
  $fleetState = 'lost'; $fleetReason = 'never_started'
}
$fleetOut = New-Object Text.StringBuilder
[void]$fleetOut.Append("state=$fleetState`n")
if ($fleetReason -ne '') { [void]$fleetOut.Append("reason=$fleetReason`n") }
if ($fleetState -eq 'exited') { [void]$fleetOut.Append('exit=' + (fleetNumOf $fleetExit $true) + "`n") }
[void]$fleetOut.Append('started=' + (fleetNumOf ([IO.Path]::Combine($fleetDir, 'started')) $false) + "`n")
if ($fleetState -eq 'exited') { [void]$fleetOut.Append('finished=' + (fleetNumOf ([IO.Path]::Combine($fleetDir, 'finished')) $false) + "`n") }
$fleetWant = [int64][Math]::Min([int64]$fleetNum, 1048576)
foreach ($fleetStream in 'stdout', 'stderr') {
  $fleetFile = [IO.Path]::Combine($fleetDir, $fleetStream)
  $fleetBytes = 0
  $fleetB64 = ''
  if (fleetReg $fleetFile) {
    try {
      $fs = New-Object IO.FileStream($fleetFile, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]'ReadWrite,Delete')
      try {
        $fleetBytes = $fs.Length
        $take = [int][Math]::Min($fleetBytes, $fleetWant)
        $buf = New-Object byte[] $take
        [void]$fs.Seek($fleetBytes - $take, [IO.SeekOrigin]::Begin)
        $got = 0
        while ($got -lt $take) { $n = $fs.Read($buf, $got, $take - $got); if ($n -le 0) { break }; $got += $n }
        $fleetB64 = [Convert]::ToBase64String($buf, 0, $got)
      } finally { $fs.Dispose() }
    } catch { $fleetBytes = 0; $fleetB64 = '' }
  }
  [void]$fleetOut.Append("${fleetStream}_bytes=$fleetBytes`n")
  [void]$fleetOut.Append("${fleetStream}_b64=$fleetB64`n")
}
[Console]::Out.Write($fleetOut.ToString())
exit 0
"#;

/// The script that starts `command` detached on a guest with `shell`; see
/// [`start_script`] for the semantics, which are the same.
#[must_use]
pub fn start_script_for(shell: crate::shell::GuestShell, command: &str) -> String {
    match shell {
        crate::shell::GuestShell::Posix => start_script(command),
        crate::shell::GuestShell::PowerShell => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(command.as_bytes());
            format!(
                "$fleetCmd64 = '{encoded}'\n$fleetWrapper = @'\n{WINDOWS_WRAPPER}'@\n{WINDOWS_RESOLVE}{WINDOWS_START_BODY}"
            )
        }
    }
}

/// The script that reads a handle's state on a guest with `shell`.
#[must_use]
pub fn status_script_for(shell: crate::shell::GuestShell) -> String {
    match shell {
        crate::shell::GuestShell::Posix => status_script(),
        crate::shell::GuestShell::PowerShell => format!("{WINDOWS_RESOLVE}{WINDOWS_STATUS_BODY}"),
    }
}

/// The metadata for [`start_script`].
#[must_use]
pub fn start_metadata(handle: &str, timeout_seconds: u64) -> ScriptMetadata {
    ScriptMetadata {
        working_directory: String::new(),
        environment: Vec::new(),
        arguments: vec![handle.to_owned(), timeout_seconds.to_string()],
    }
}

const STATUS_BODY: &str = r#"[ -d "$fleet_dir" ] && [ ! -L "$fleet_dir" ] || { echo state=absent; exit 0; }
fleet_reg() { [ -f "$1" ] && [ ! -L "$1" ]; }
fleet_alive() {
  local pid start stat rest
  fleet_reg "$fleet_dir/pid" || return 1
  read -r pid start < "$fleet_dir/pid" 2>/dev/null || return 1
  case $pid in ''|*[!0-9]*) return 1;; esac
  stat=$(timeout 5 cat "/proc/$pid/stat" 2>/dev/null) || return 1
  rest=${stat##*) }
  set -- $rest
  [ "$1" != Z ] && [ "${20}" = "$start" ]
}
fleet_state=; fleet_reason=
if fleet_reg "$fleet_dir/exit"; then
  fleet_state=exited
elif fleet_reg "$fleet_dir/pid"; then
  fleet_boot=$(fleet_reg "$fleet_dir/boot_id" && timeout 5 cat "$fleet_dir/boot_id" 2>/dev/null)
  fleet_now=$(timeout 5 cat /proc/sys/kernel/random/boot_id 2>/dev/null)
  if [ "$fleet_boot" != "$fleet_now" ]; then
    fleet_state=lost; fleet_reason=guest_rebooted
  elif fleet_alive; then
    fleet_state=running
  elif fleet_reg "$fleet_dir/exit"; then
    fleet_state=exited
  else
    fleet_state=lost; fleet_reason=process_gone
  fi
elif [ -e "$fleet_dir/abandoned" ]; then
  fleet_state=lost; fleet_reason=never_started
elif [ -n "$(find "$fleet_dir" -maxdepth 0 -mmin -1 2>/dev/null)" ]; then
  fleet_state=starting
else
  fleet_state=lost; fleet_reason=never_started
fi
fleet_num_of() {
  local value
  fleet_reg "$1" || return 0
  value=$(timeout 5 head -c 20 "$1" 2>/dev/null)
  case $value in ''|*[!0-9]*) ;; *) printf '%s' "$value";; esac
}
echo "state=$fleet_state"
[ -z "$fleet_reason" ] || echo "reason=$fleet_reason"
[ "$fleet_state" != exited ] || echo "exit=$(fleet_num_of "$fleet_dir/exit")"
echo "started=$(fleet_num_of "$fleet_dir/started")"
[ "$fleet_state" != exited ] || echo "finished=$(fleet_num_of "$fleet_dir/finished")"
for fleet_stream in stdout stderr; do
  if fleet_reg "$fleet_dir/$fleet_stream"; then
    echo "${fleet_stream}_bytes=$(timeout 5 stat -c %s -- "$fleet_dir/$fleet_stream" 2>/dev/null || echo 0)"
    echo "${fleet_stream}_b64=$(timeout 5 tail -c "$fleet_num" -- "$fleet_dir/$fleet_stream" 2>/dev/null | base64 -w0)"
  else
    echo "${fleet_stream}_bytes=0"
    echo "${fleet_stream}_b64="
  fi
done
exit 0
"#;

/// The script that reads a handle's state. Run it with the metadata
/// arguments `[handle, tail_window_bytes]` (see [`status_metadata`]); it
/// prints `key=value` lines that [`parse_status`] reads. Exit 64 means an
/// invalid handle or number.
#[must_use]
pub fn status_script() -> String {
    format!("{RESOLVE}{STATUS_BODY}")
}

/// The metadata for [`status_script`].
#[must_use]
pub fn status_metadata(handle: &str, tail_window: usize) -> ScriptMetadata {
    ScriptMetadata {
        working_directory: String::new(),
        environment: Vec::new(),
        arguments: vec![handle.to_owned(), tail_window.to_string()],
    }
}

/// What the guest says about one handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestState {
    /// The guest has no directory for the handle.
    Absent,
    /// The directory exists and the wrapper has not recorded its process.
    Starting,
    /// The process is alive.
    Running,
    /// The wrapper wrote an exit status.
    Exited,
    /// The process is gone and wrote no exit status.
    Lost,
}

/// The status script's answer, before any scrubbing or bounding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuestReport {
    /// The state.
    pub state: GuestState,
    /// Why a lost process is lost (`guest_rebooted`, `process_gone`,
    /// `never_started`).
    pub reason: Option<String>,
    /// The exit status, once exited.
    pub exit_code: Option<i32>,
    /// When the wrapper started (guest epoch seconds).
    pub started_at: Option<i64>,
    /// When the command finished (guest epoch seconds).
    pub finished_at: Option<i64>,
    /// The size of stdout in the guest, in bytes.
    pub stdout_bytes: u64,
    /// The size of stderr in the guest, in bytes.
    pub stderr_bytes: u64,
    /// The last bytes of stdout, at most [`TAIL_WINDOW_BYTES`].
    pub stdout_tail: Vec<u8>,
    /// The last bytes of stderr, at most [`TAIL_WINDOW_BYTES`].
    pub stderr_tail: Vec<u8>,
}

/// Parses the status script's output.
///
/// # Errors
///
/// Fails when the output names no known state, or a tail is not base64 or
/// exceeds [`TAIL_WINDOW_BYTES`].
pub fn parse_status(output: &str) -> Result<GuestReport, String> {
    let mut report = GuestReport {
        state: GuestState::Absent,
        reason: None,
        exit_code: None,
        started_at: None,
        finished_at: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: Vec::new(),
        stderr_tail: Vec::new(),
    };
    let mut state = None;
    let decode = |value: &str| -> Result<Vec<u8>, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(value.trim())
            .map_err(|_| "a stream tail is not base64".to_owned())?;
        if bytes.len() > TAIL_WINDOW_BYTES {
            return Err("a stream tail is larger than the window".to_owned());
        }
        Ok(bytes)
    };
    for line in output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "state" => {
                state = Some(match value.trim() {
                    "absent" => GuestState::Absent,
                    "starting" => GuestState::Starting,
                    "running" => GuestState::Running,
                    "exited" => GuestState::Exited,
                    "lost" => GuestState::Lost,
                    other => return Err(format!("the guest reported an unknown state {other:?}")),
                });
            }
            "reason" => {
                report.reason = Some(
                    match value.trim() {
                        reason @ ("guest_rebooted" | "process_gone" | "never_started"
                        | "start_unconfirmed") => reason,
                        _ => "unknown",
                    }
                    .to_owned(),
                );
            }
            "exit" => report.exit_code = value.trim().parse().ok(),
            "started" => report.started_at = value.trim().parse().ok(),
            "finished" => report.finished_at = value.trim().parse().ok(),
            "stdout_bytes" => report.stdout_bytes = value.trim().parse().unwrap_or(0),
            "stderr_bytes" => report.stderr_bytes = value.trim().parse().unwrap_or(0),
            "stdout_b64" => report.stdout_tail = decode(value)?,
            "stderr_b64" => report.stderr_tail = decode(value)?,
            _ => {}
        }
    }
    report.state = state.ok_or_else(|| "the guest reported no state".to_owned())?;
    Ok(report)
}

/// Reads one handle's state from the guest.
///
/// # Errors
///
/// Fails on setup/tool errors, a connection failure, a deadline kill, a
/// script refusal, or output that does not parse. The error text is safe to
/// log: it names no command output.
pub fn probe_detached(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    handle: &str,
) -> Result<GuestReport, SshProviderError> {
    if !is_valid_handle(handle) {
        return Err(SshProviderError::Setup {
            detail: "the handle is not a valid detached-exec handle".to_owned(),
        });
    }
    let shell = crate::shell::GuestShell::for_os(endpoint.guest_os)?;
    let result = execute_script(
        provider,
        limiter,
        endpoint,
        &status_script_for(shell),
        &status_metadata(handle, TAIL_WINDOW_BYTES),
        STATUS_DEADLINE,
    )?;
    if result.killed_by_deadline {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: "the status read hit its deadline".to_owned(),
        });
    }
    if result.exit_code != Some(0) {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!(
                "the status read failed (exit {})",
                result
                    .exit_code
                    .map_or_else(|| "none".to_owned(), |code| code.to_string())
            ),
        });
    }
    parse_status(&result.stdout).map_err(|detail| SshProviderError::Tool {
        tool: "ssh",
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::Path;
    use std::process::{Command, Output, Stdio};
    use std::time::Instant;

    /// Runs a script under real bash the way the SSH session feeds it: the
    /// script on stdin, the metadata arguments after `--`.
    fn bash(script: &str, args: &[&str]) -> Output {
        // The session's directory is the guest base directory (the last
        // argument, when it is one), so a test never writes to the crate.
        let mut command = Command::new("bash");
        if let Some(dir) = args.last().filter(|last| Path::new(last).is_dir()) {
            command.current_dir(dir);
        }
        let mut child = command
            .arg("-s")
            .arg("--")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(script.as_bytes()).unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    }

    fn start(base: &Path, handle: &str, secs: u64, command: &str) -> Output {
        bash(
            &start_script(command),
            &[handle, &secs.to_string(), &base.display().to_string()],
        )
    }

    fn status(base: &Path, handle: &str) -> GuestReport {
        let out = bash(
            &status_script(),
            &[
                handle,
                &TAIL_WINDOW_BYTES.to_string(),
                &base.display().to_string(),
            ],
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        parse_status(&String::from_utf8(out.stdout).unwrap()).unwrap()
    }

    fn wait_for(base: &Path, handle: &str, state: GuestState) -> GuestReport {
        let started = Instant::now();
        loop {
            let report = status(base, handle);
            if report.state == state {
                return report;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "waited for {state:?}, last {report:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn handles_are_validated() {
        assert!(is_valid_handle("0199-abc_DEF"));
        for bad in ["", "a/b", "../x", "a b", "a;b", "é", &"x".repeat(65)] {
            assert!(!is_valid_handle(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_command_runs_detached_and_exits_with_its_code_and_output() {
        let base = tempfile::tempdir().unwrap();
        let out = start(
            base.path(),
            "h1",
            60,
            "echo out-line; echo err-line >&2; sleep 1; exit 7",
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "started");
        // The start returned while the command still ran.
        let running = status(base.path(), "h1");
        assert_eq!(running.state, GuestState::Running, "{running:?}");
        assert!(running.exit_code.is_none());
        let exited = wait_for(base.path(), "h1", GuestState::Exited);
        assert_eq!(exited.exit_code, Some(7));
        assert_eq!(exited.stdout_tail, b"out-line\n");
        assert_eq!(exited.stderr_tail, b"err-line\n");
        assert!(exited.started_at.is_some() && exited.finished_at.is_some());
        // The directory is private.
        let mode = std::fs::metadata(base.path().join("h1"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn the_command_starts_where_the_session_started() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "cwd1", 60, "pwd -P");
        let exited = wait_for(base.path(), "cwd1", GuestState::Exited);
        let here = base.path().canonicalize().unwrap();
        assert_eq!(
            String::from_utf8_lossy(&exited.stdout_tail).trim(),
            here.display().to_string()
        );
    }

    #[test]
    fn the_command_is_data_never_shell_text_of_the_start_script() {
        let base = tempfile::tempdir().unwrap();
        // Text that would break out of a heredoc, a quote, or a command
        // substitution if it were ever interpolated.
        let command = "cat <<'FLEET_CMD_END'\nFLEET_CMD_END\necho '\"'\"$(touch pwned)`touch pwned2`\"; echo $0; exit 0\n";
        let out = start(base.path(), "h2", 60, command);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let exited = wait_for(base.path(), "h2", GuestState::Exited);
        assert_eq!(exited.exit_code, Some(0));
        let written = std::fs::read_to_string(base.path().join("h2/cmd.sh")).unwrap();
        assert_eq!(written, command, "the command is stored byte for byte");
        let stdout = String::from_utf8_lossy(&exited.stdout_tail).into_owned();
        assert!(stdout.contains("cmd.sh"), "{stdout}");
        // The command itself ran, in the session's directory, and the start
        // script never expanded it.
        assert!(base.path().join("pwned").exists());
        assert!(base.path().join("pwned2").exists());
    }

    #[test]
    fn a_bad_handle_or_number_is_refused_before_anything_is_created() {
        let base = tempfile::tempdir().unwrap();
        for (handle, secs) in [
            ("../escape", "60"),
            ("a b", "60"),
            ("ok", "6x"),
            ("ok", ""),
            ("", "60"),
        ] {
            let out = bash(
                &start_script("true"),
                &[handle, secs, &base.path().display().to_string()],
            );
            assert_eq!(out.status.code(), Some(64), "{handle:?} {secs:?}: {out:?}");
        }
        assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
        let out = bash(
            &status_script(),
            &["../x", "10", &base.path().display().to_string()],
        );
        assert_eq!(out.status.code(), Some(64));
    }

    #[test]
    fn starting_twice_runs_the_command_once() {
        let base = tempfile::tempdir().unwrap();
        let marker = base.path().join("runs");
        let command = format!("echo x >> {}; sleep 1", marker.display());
        assert_eq!(
            start(base.path(), "h3", 60, &command).status.code(),
            Some(0)
        );
        let again = start(base.path(), "h3", 60, &command);
        assert_eq!(again.status.code(), Some(0));
        assert_eq!(String::from_utf8_lossy(&again.stdout).trim(), "exists");
        wait_for(base.path(), "h3", GuestState::Exited);
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "x\n");
    }

    #[test]
    fn an_unknown_handle_is_absent() {
        let base = tempfile::tempdir().unwrap();
        assert_eq!(status(base.path(), "nothing").state, GuestState::Absent);
    }

    #[test]
    fn the_timeout_ends_the_command_with_124() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "h4", 1, "sleep 30");
        let exited = wait_for(base.path(), "h4", GuestState::Exited);
        assert_eq!(exited.exit_code, Some(124));
    }

    #[test]
    fn a_killed_wrapper_is_lost_and_a_reboot_is_lost_too() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "h5", 60, "sleep 29.17");
        let pid_text = std::fs::read_to_string(base.path().join("h5/pid")).unwrap();
        let pid = pid_text.split_whitespace().next().unwrap().to_owned();
        // Kill the wrapper and everything under it before it writes `exit`.
        Command::new("kill").args(["-9", &pid]).status().unwrap();
        let lost = wait_for(base.path(), "h5", GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("process_gone"));
        // Kill the orphaned `sleep` too so the test leaves nothing behind.
        let _ = Command::new("pkill").args(["-f", "sleep 29.17"]).status();

        // A different boot id reads as a reboot, even though the pid lives.
        start(base.path(), "h6", 60, "sleep 30");
        std::fs::write(base.path().join("h6/boot_id"), "not-this-boot\n").unwrap();
        let lost = status(base.path(), "h6");
        assert_eq!(lost.state, GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("guest_rebooted"));
        let pid_text = std::fs::read_to_string(base.path().join("h6/pid")).unwrap();
        let pid = pid_text.split_whitespace().next().unwrap().to_owned();
        Command::new("pkill").args(["-P", &pid]).status().unwrap();
        wait_for_exit_file(base.path(), "h6");
    }

    fn wait_for_exit_file(base: &Path, handle: &str) {
        let started = Instant::now();
        while !base.join(handle).join("exit").exists() {
            assert!(started.elapsed() < Duration::from_secs(20));
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn a_command_cannot_hang_status_by_swapping_its_files_for_a_fifo() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "f1", 60, "sleep 29.61");
        let dir = base.path().join("f1");
        std::fs::remove_file(dir.join("stdout")).unwrap();
        Command::new("mkfifo")
            .arg(dir.join("stdout"))
            .status()
            .unwrap();
        std::fs::remove_file(dir.join("stderr")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.join("stderr")).unwrap();
        let begun = Instant::now();
        let report = status(base.path(), "f1");
        assert!(
            begun.elapsed() < Duration::from_secs(5),
            "{:?}",
            begun.elapsed()
        );
        assert_eq!(report.state, GuestState::Running);
        assert!(report.stdout_tail.is_empty() && report.stderr_tail.is_empty());
        let pid_text = std::fs::read_to_string(dir.join("pid")).unwrap();
        let pid = pid_text.split_whitespace().next().unwrap();
        Command::new("pkill").args(["-P", pid]).status().unwrap();
    }

    #[test]
    fn an_abandoned_start_never_runs_late() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("ab");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("abandoned"), "").unwrap();
        std::fs::write(dir.join("cmd.sh"), "touch ran\n").unwrap();
        let wrapper = dir.join("run.sh");
        std::fs::write(&wrapper, WRAPPER).unwrap();
        let out = Command::new("bash")
            .arg(&wrapper)
            .arg(&dir)
            .arg("60")
            .current_dir(base.path())
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0));
        assert!(!dir.join("ran").exists() && !dir.join("pid").exists());
        let lost = status(base.path(), "ab");
        assert_eq!(lost.state, GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("never_started"));
    }

    #[test]
    fn a_reused_pid_is_not_mistaken_for_the_wrapper() {
        let base = tempfile::tempdir().unwrap();
        start(base.path(), "h7", 60, "sleep 30");
        let pid_path = base.path().join("h7/pid");
        let pid_text = std::fs::read_to_string(&pid_path).unwrap();
        let (pid, _) = pid_text.trim().split_once(' ').unwrap();
        // The same pid with another start time is another process.
        std::fs::write(&pid_path, format!("{pid} 1\n")).unwrap();
        let lost = status(base.path(), "h7");
        assert_eq!(lost.state, GuestState::Lost, "{lost:?}");
        std::fs::write(&pid_path, &pid_text).unwrap();
        Command::new("pkill").args(["-P", pid]).status().unwrap();
        wait_for(base.path(), "h7", GuestState::Exited);
    }

    #[test]
    fn a_directory_that_never_got_a_pid_is_starting_then_lost() {
        let base = tempfile::tempdir().unwrap();
        let dir = base.path().join("h8");
        std::fs::create_dir(&dir).unwrap();
        assert_eq!(status(base.path(), "h8").state, GuestState::Starting);
        // Age it past the starting grace.
        Command::new("touch")
            .args(["-d", "10 minutes ago"])
            .arg(&dir)
            .status()
            .unwrap();
        let lost = status(base.path(), "h8");
        assert_eq!(lost.state, GuestState::Lost);
        assert_eq!(lost.reason.as_deref(), Some("never_started"));
    }

    #[test]
    fn the_status_returns_a_bounded_tail_and_the_true_size() {
        let base = tempfile::tempdir().unwrap();
        start(
            base.path(),
            "h9",
            60,
            "head -c 100000 /dev/zero | tr '\\0' 'a'; printf 'THE-END'",
        );
        let exited = wait_for(base.path(), "h9", GuestState::Exited);
        assert_eq!(exited.stdout_bytes, 100_007);
        assert_eq!(exited.stdout_tail.len(), TAIL_WINDOW_BYTES);
        assert!(exited.stdout_tail.ends_with(b"THE-END"));
    }

    #[test]
    fn binary_output_survives_the_transport() {
        let base = tempfile::tempdir().unwrap();
        start(
            base.path(),
            "h10",
            60,
            "printf '\\000\\033[1m\\377\\n=x\\n'",
        );
        let exited = wait_for(base.path(), "h10", GuestState::Exited);
        assert_eq!(exited.stdout_tail, b"\0\x1b[1m\xff\n=x\n");
    }

    #[test]
    fn parse_status_refuses_nonsense() {
        assert!(parse_status("").is_err());
        assert!(parse_status("state=maybe\n").is_err());
        assert!(parse_status("state=exited\nstdout_b64=!!!\n").is_err());
        let huge =
            base64::engine::general_purpose::STANDARD.encode(vec![0_u8; TAIL_WINDOW_BYTES + 1]);
        assert!(parse_status(&format!("state=running\nstdout_b64={huge}\n")).is_err());
        let ok = parse_status("state=lost\nreason=anything else\n").unwrap();
        assert_eq!(ok.reason.as_deref(), Some("unknown"));
    }

    /// The Windows scripts under a real PowerShell (see `pwsh_support`).
    mod windows {
        use super::*;
        use crate::exec::ScriptMetadata;
        use crate::pwsh_support::{require_pwsh, run_ps};
        use crate::shell::GuestShell;

        fn run(pwsh: &str, script: &str, args: &[&str]) -> std::process::Output {
            let metadata = ScriptMetadata {
                arguments: args.iter().map(|arg| (*arg).to_owned()).collect(),
                ..ScriptMetadata::default()
            };
            // The session starts in the guest directory the arguments name (the
            // last one), like an SSH session in a login directory.
            let cwd = args.last().map(Path::new).filter(|path| path.is_dir());
            run_ps(pwsh, script, &metadata, b"", cwd)
        }

        fn start(
            pwsh: &str,
            base: &Path,
            handle: &str,
            secs: u64,
            command: &str,
        ) -> std::process::Output {
            run(
                pwsh,
                &start_script_for(GuestShell::PowerShell, command),
                &[handle, &secs.to_string(), &base.display().to_string()],
            )
        }

        fn status(pwsh: &str, base: &Path, handle: &str) -> GuestReport {
            let out = run(
                pwsh,
                &status_script_for(GuestShell::PowerShell),
                &[
                    handle,
                    &TAIL_WINDOW_BYTES.to_string(),
                    &base.display().to_string(),
                ],
            );
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            parse_status(&String::from_utf8(out.stdout).unwrap()).unwrap()
        }

        fn wait_for(pwsh: &str, base: &Path, handle: &str, state: GuestState) -> GuestReport {
            let started = Instant::now();
            loop {
                let report = status(pwsh, base, handle);
                if report.state == state {
                    return report;
                }
                assert!(
                    started.elapsed() < Duration::from_secs(40),
                    "waited for {state:?}, last {report:?}"
                );
                std::thread::sleep(Duration::from_millis(200));
            }
        }

        fn pid_of(base: &Path, handle: &str) -> String {
            std::fs::read_to_string(base.join(handle).join("pid"))
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .to_owned()
        }

        #[test]
        fn a_command_runs_detached_and_exits_with_its_code_and_output() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            let out = start(
                &pwsh,
                base.path(),
                "w1",
                60,
                "Write-Output 'out-line'\n[Console]::Error.WriteLine('err-line')\nStart-Sleep -Seconds 2\nexit 7\n",
            );
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "started");
            let running = status(&pwsh, base.path(), "w1");
            assert_eq!(running.state, GuestState::Running, "{running:?}");
            let exited = wait_for(&pwsh, base.path(), "w1", GuestState::Exited);
            assert_eq!(exited.exit_code, Some(7), "{exited:?}");
            assert_eq!(
                String::from_utf8_lossy(&exited.stdout_tail).trim(),
                "out-line"
            );
            assert_eq!(
                String::from_utf8_lossy(&exited.stderr_tail).trim(),
                "err-line"
            );
            assert!(exited.started_at.is_some() && exited.finished_at.is_some());
        }

        #[test]
        fn the_command_is_data_never_shell_text_of_the_start_script() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            // Text that would break out of a single-quoted literal, a
            // here-string, or an expandable string if it were interpolated.
            let command =
                "Write-Output '@'\n'@\n\"`$(New-Item pwned2)\"\n'; New-Item pwned3; '\nexit 0\n";
            let out = start(&pwsh, base.path(), "w2", 60, command);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            wait_for(&pwsh, base.path(), "w2", GuestState::Exited);
            let written = std::fs::read(base.path().join("w2/body.ps1")).unwrap();
            assert_eq!(written, command.as_bytes(), "stored byte for byte");
            // The start script never expanded it (the session started in the
            // base directory, where any expansion would have left a file).
            assert!(!base.path().join("pwned2").exists());
            assert!(!base.path().join("pwned3").exists());
            assert!(!base.path().join("w2/pwned3").exists());
        }

        #[test]
        fn a_bad_handle_or_number_is_refused_before_anything_is_created() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            for (handle, secs) in [
                ("../escape", "60"),
                ("a b", "60"),
                ("ok", "6x"),
                ("ok", "-1"),
                ("x;y", "60"),
            ] {
                let out = run(
                    &pwsh,
                    &start_script_for(GuestShell::PowerShell, "exit 0"),
                    &[handle, secs, &base.path().display().to_string()],
                );
                assert_eq!(out.status.code(), Some(64), "{handle:?} {secs:?}: {out:?}");
            }
            assert_eq!(std::fs::read_dir(base.path()).unwrap().count(), 0);
            let out = run(
                &pwsh,
                &status_script_for(GuestShell::PowerShell),
                &["../x", "10", &base.path().display().to_string()],
            );
            assert_eq!(out.status.code(), Some(64));
        }

        #[test]
        fn starting_twice_runs_the_command_once_and_unknown_handles_are_absent() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            let marker = base.path().join("runs");
            let command = format!(
                "Add-Content -LiteralPath '{}' x\nStart-Sleep -Seconds 1\n",
                marker.display()
            );
            assert_eq!(
                start(&pwsh, base.path(), "w3", 60, &command).status.code(),
                Some(0)
            );
            let again = start(&pwsh, base.path(), "w3", 60, &command);
            assert_eq!(String::from_utf8_lossy(&again.stdout).trim(), "exists");
            wait_for(&pwsh, base.path(), "w3", GuestState::Exited);
            assert_eq!(std::fs::read_to_string(&marker).unwrap().trim(), "x");
            assert_eq!(
                status(&pwsh, base.path(), "nothing").state,
                GuestState::Absent
            );
        }

        #[test]
        fn the_timeout_ends_the_command_and_its_tree_with_124() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            start(&pwsh, base.path(), "w4", 2, "Start-Sleep -Seconds 60\n");
            let exited = wait_for(&pwsh, base.path(), "w4", GuestState::Exited);
            assert_eq!(exited.exit_code, Some(124));
        }

        #[test]
        fn a_killed_wrapper_is_lost_and_a_reboot_is_lost_too() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            start(&pwsh, base.path(), "w5", 60, "Start-Sleep -Seconds 29\n");
            let pid = pid_of(base.path(), "w5");
            Command::new("kill").args(["-9", &pid]).status().unwrap();
            let lost = wait_for(&pwsh, base.path(), "w5", GuestState::Lost);
            assert_eq!(lost.reason.as_deref(), Some("process_gone"));
            let _ = Command::new("pkill")
                .args(["-f", &base.path().display().to_string()])
                .status();

            start(&pwsh, base.path(), "w6", 60, "Start-Sleep -Seconds 29\n");
            std::fs::write(base.path().join("w6/boot_id"), "not-this-boot\n").unwrap();
            let lost = status(&pwsh, base.path(), "w6");
            assert_eq!(lost.state, GuestState::Lost);
            assert_eq!(lost.reason.as_deref(), Some("guest_rebooted"));
            let pid = pid_of(base.path(), "w6");
            let _ = Command::new("pkill").args(["-P", &pid]).status();
            let _ = Command::new("kill").args(["-9", &pid]).status();
        }

        #[test]
        fn a_reused_pid_is_not_mistaken_for_the_wrapper() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            start(&pwsh, base.path(), "w7", 60, "Start-Sleep -Seconds 29\n");
            let pid_path = base.path().join("w7/pid");
            let text = std::fs::read_to_string(&pid_path).unwrap();
            let (pid, _) = text.trim().split_once(' ').unwrap();
            std::fs::write(&pid_path, format!("{pid} 1\n")).unwrap();
            assert_eq!(status(&pwsh, base.path(), "w7").state, GuestState::Lost);
            let _ = Command::new("pkill").args(["-P", pid]).status();
            let _ = Command::new("kill").args(["-9", pid]).status();
        }

        #[test]
        fn an_abandoned_start_never_runs_late_and_an_unstarted_directory_ages_to_lost() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            let dir = base.path().join("ab");
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("abandoned"), "").unwrap();
            std::fs::write(dir.join("body.ps1"), "New-Item ran | Out-Null\n").unwrap();
            std::fs::write(dir.join("run.ps1"), WINDOWS_WRAPPER).unwrap();
            let out = Command::new(&pwsh)
                .args(["-NoProfile", "-File"])
                .arg(dir.join("run.ps1"))
                .args(["-Dir"])
                .arg(&dir)
                .args(["-Secs", "60"])
                .current_dir(&dir)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert!(!dir.join("ran").exists() && !dir.join("pid").exists());
            let lost = status(&pwsh, base.path(), "ab");
            assert_eq!(lost.reason.as_deref(), Some("never_started"));

            let fresh = base.path().join("fresh");
            std::fs::create_dir(&fresh).unwrap();
            assert_eq!(
                status(&pwsh, base.path(), "fresh").state,
                GuestState::Starting
            );
            Command::new("touch")
                .args(["-d", "10 minutes ago"])
                .arg(&fresh)
                .status()
                .unwrap();
            // CreationTime is not settable with touch on Linux; the birth time
            // is what the script reads, so only the abandoned path is asserted
            // above and the fresh directory must at least read as starting.
        }

        #[test]
        fn status_reads_only_regular_files_and_returns_a_bounded_tail() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            start(
                &pwsh,
                base.path(),
                "w8",
                60,
                "[Console]::Out.Write(('a' * 100000) + 'THE-END \u{e9}\u{4e2d}')\n",
            );
            let report = wait_for(&pwsh, base.path(), "w8", GuestState::Exited);
            assert!(report.stdout_bytes >= 100_000 + "THE-END \u{e9}\u{4e2d}".len() as u64);
            assert_eq!(report.stdout_tail.len(), TAIL_WINDOW_BYTES);
            assert!(
                String::from_utf8_lossy(&report.stdout_tail)
                    .trim_end()
                    .ends_with("THE-END \u{e9}\u{4e2d}")
            );
            // A command that swaps its output for a symlink is not followed.
            let dir = base.path().join("w8");
            let _ = std::fs::remove_file(dir.join("stdout"));
            std::os::unix::fs::symlink("/dev/zero", dir.join("stdout")).unwrap();
            let begun = Instant::now();
            let report = status(&pwsh, base.path(), "w8");
            assert!(begun.elapsed() < Duration::from_secs(10));
            assert!(report.stdout_tail.is_empty());
        }

        #[test]
        fn a_wrapper_that_loses_the_gate_never_runs_and_negative_exit_codes_survive() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            let dir = base.path().join("g1");
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("gate"), "").unwrap();
            std::fs::write(dir.join("body.ps1"), "New-Item ran | Out-Null\n").unwrap();
            std::fs::write(dir.join("run.ps1"), WINDOWS_WRAPPER).unwrap();
            let out = Command::new(&pwsh)
                .args(["-NoProfile", "-File"])
                .arg(dir.join("run.ps1"))
                .arg("-Dir")
                .arg(&dir)
                .args(["-Secs", "60"])
                .current_dir(&dir)
                .output()
                .unwrap();
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert!(!dir.join("ran").exists() && !dir.join("pid").exists());

            // An NTSTATUS-style negative exit code is reported, not blanked.
            let done = base.path().join("g2");
            std::fs::create_dir(&done).unwrap();
            std::fs::write(done.join("exit"), "-1073741819\n").unwrap();
            std::fs::write(done.join("finished"), "1790000000\n").unwrap();
            let report = status(&pwsh, base.path(), "g2");
            assert_eq!(report.state, GuestState::Exited);
            assert_eq!(report.exit_code, Some(-1_073_741_819));
            // Garbage in a control file is not a number.
            std::fs::write(done.join("exit"), "12abc\n").unwrap();
            assert_eq!(status(&pwsh, base.path(), "g2").exit_code, None);
            std::fs::write(done.join("exit"), "5\n\n").unwrap();
            assert_eq!(status(&pwsh, base.path(), "g2").exit_code, Some(5));
        }

        #[test]
        fn an_unknown_boot_counter_is_not_a_reboot() {
            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            start(&pwsh, base.path(), "g3", 60, "Start-Sleep -Seconds 25\n");
            std::fs::write(base.path().join("g3/boot_id"), "\n").unwrap();
            let report = status(&pwsh, base.path(), "g3");
            assert_eq!(report.state, GuestState::Running, "{report:?}");
            let pid = pid_of(base.path(), "g3");
            let _ = Command::new("pkill").args(["-P", &pid]).status();
            let _ = Command::new("kill").args(["-9", &pid]).status();
        }

        #[test]
        fn the_directories_are_trust_checked_before_use_and_created_protected() {
            // Off Windows the ACL calls cannot run, so the script's shape is
            // what is checked here; the fixture exercises it (a base that a
            // local user pre-created, a junction in its place, a foreign
            // owner, an extra write ACE).
            let start = start_script_for(GuestShell::PowerShell, "exit 0");
            let status = status_script_for(GuestShell::PowerShell);
            for text in [&start, &status] {
                assert!(text.contains("function fleetSecure"));
                assert!(text.contains("ReparsePoint"));
                assert!(text.contains("GetOwner("));
                assert!(text.contains("0x500D0156"));
            }
            assert!(start.contains("CreateDirectory($path, $sec)"));
            // The creator is the owner: setting Administrators fails for a
            // non-admin token. And only the user's own profile is used.
            assert!(!start.contains("SetOwner") && !start.contains("ProgramData"));
            assert!(start.contains("LOCALAPPDATA") && start.contains("0x500D0156"));
            assert!(start.contains("SetAccessRuleProtection($true, $false)"));
            assert!(
                start.contains("fleetMakeDir $fleetParent")
                    && start.contains("fleetMakeDir $fleetBase")
            );
            assert!(status.contains("fleetChainSecure") && status.contains("exit 71"));
            // Anchors that a trailing newline cannot slip past.
            assert!(!start.contains("}$'") && start.contains("\\z"));
        }

        #[test]
        fn the_start_session_fits_its_deadline_and_a_held_gate_is_unconfirmed_not_failed() {
            let start = start_script_for(GuestShell::PowerShell, "exit 0");
            // helper compile + 25 s + 5 s of waiting, plus ssh setup and a
            // cold PowerShell, inside SESSION_DEADLINE (60 s).
            assert!(
                start.contains("CREATE_BREAKAWAY_FROM_JOB") && !start.contains("Win32_Process")
            );
            assert!(
                start.contains("$fleetWaited -lt 250") && start.contains("$fleetWaited -lt 50")
            );
            assert!(10 + 25 + 5 < SESSION_DEADLINE.as_secs());
            assert!(start.contains("exit 76"));

            let Some(pwsh) = require_pwsh() else { return };
            let base = tempfile::tempdir().unwrap();
            let dir = base.path().join("g4");
            std::fs::create_dir(&dir).unwrap();
            std::fs::write(dir.join("gate"), "").unwrap();
            let report = status(&pwsh, base.path(), "g4");
            assert_eq!(report.state, GuestState::Starting, "{report:?}");
            assert_eq!(report.reason.as_deref(), Some("start_unconfirmed"));
        }

        #[test]
        fn the_windows_launch_helper_compiles_and_runs_before_it_is_launched() {
            let Some(pwsh) = require_pwsh() else { return };
            // The C# helper is the one piece of the start script no Linux
            // test executes (it calls kernel32). It must at least compile, so
            // a typo does not wait for a Windows guest to be found.
            let start = start_script_for(GuestShell::PowerShell, "exit 0");
            let from = start.find("Add-Type -TypeDefinition @'\n").unwrap();
            let end = from + start[from..].find("\n'@\n").unwrap() + 4;
            let snippet = format!(
                "{}\n[Console]::Out.Write([FleetLaunch]::Start.GetType().Name + ' ' + [FleetLaunch].FullName)\n",
                &start[from..end]
            );
            let out = run_ps(&pwsh, &snippet, &ScriptMetadata::default(), b"", None);
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("FleetLaunch"),
                "{out:?}"
            );
            // And the give-up-late guard is in front of the launch.
            let guard = start.find("TotalSeconds -gt 30").unwrap();
            let launch = start.find("[FleetLaunch]::Start($fleetLine").unwrap();
            assert!(guard < launch);
        }
    }
}
