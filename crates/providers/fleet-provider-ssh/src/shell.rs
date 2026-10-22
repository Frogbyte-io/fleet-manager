//! The guest shell: how a fixed script and its inert metadata reach a guest.
//!
//! One transport rule holds for every guest OS: **caller data never reaches a
//! remote shell as shell text.** What differs is how the fixed text and the
//! data are framed. [`GuestShell::Posix`] sends `bash -s -- <blob>` as the
//! command and the prologue plus script on stdin. The framing for each OS is
//! owned here, so the executors (`exec`, `fetch`, `put`, `detached`) never
//! build a command line themselves.
//!
//! # The PowerShell framing (Windows guests)
//!
//! Windows OpenSSH hands the command string to the account's default shell
//! (`powershell.exe -c <command>`, see `w32-doexec.c` in PowerShell/openssh-portable;
//! Windows PowerShell 5.1 is the shell the image sets, per ADR 0015).
//! [`POWERSHELL_BOOTSTRAP`] is that command: fixed text with **no caller data
//! in it at all** (not even the inert blob), restricted to an alphabet that
//! no layer between sshd and PowerShell treats specially (no double quote,
//! backslash, backtick, `%`, `^`, `&`, `|`, `<`, `>`). Everything the caller
//! controls rides stdin as two ASCII lines and is read with
//! `[Console]::OpenStandardInput()`, so no console code page touches it:
//!
//! 1. the metadata blob (the same NUL-framed base64 as Bash),
//! 2. the script, as base64 of its UTF-8 bytes.
//!
//! Any payload (`lab put`) follows the second line byte for byte; the
//! bootstrap reads the two lines one byte at a time so nothing is consumed
//! ahead.

use std::io::Write as _;

use base64::Engine as _;
use std::time::Duration;

use fleet_core::GuestOs;

use crate::exec::{ScriptMetadata, encode_metadata, remote_prologue};
use crate::{SshConnectionSpec, SshProvider, SshProviderError};

/// The remote shell a guest is driven through.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuestShell {
    /// Bash on a Linux guest.
    Posix,
    /// Windows PowerShell 5.1 (or newer) on a Windows guest.
    PowerShell,
}

impl GuestShell {
    /// The shell for a guest OS.
    ///
    /// # Errors
    ///
    /// Fails for a guest OS this build has no shell for.
    pub fn for_os(os: GuestOs) -> Result<Self, SshProviderError> {
        match os {
            GuestOs::Linux => Ok(Self::Posix),
            GuestOs::Windows => Ok(Self::PowerShell),
        }
    }

    /// The one command string handed to the remote login shell: fixed text,
    /// plus for Bash the shell-inert metadata blob.
    pub(crate) fn command_line(self, metadata: &ScriptMetadata) -> String {
        match self {
            Self::Posix => format!("bash -s -- {}", encode_metadata(metadata)),
            Self::PowerShell => POWERSHELL_BOOTSTRAP.to_owned(),
        }
    }

    /// The command string for a synchronous exec: the same as
    /// [`Self::command_line`] on Linux, and [`POWERSHELL_EXEC_BOOTSTRAP`]
    /// (which runs the script under a guest-side watchdog) on Windows.
    pub(crate) fn exec_command_line(self, metadata: &ScriptMetadata) -> String {
        match self {
            Self::Posix => self.command_line(metadata),
            Self::PowerShell => POWERSHELL_EXEC_BOOTSTRAP.to_owned(),
        }
    }

    /// The session input for a synchronous exec: unchanged on Linux; on
    /// Windows the usual two lines, then the watchdog and the guest-side
    /// limit in seconds for `deadline`.
    pub(crate) fn exec_session_input(
        self,
        script: &str,
        metadata: &ScriptMetadata,
        deadline: Duration,
    ) -> Vec<u8> {
        match self {
            Self::Posix => self.session_input(script, metadata),
            Self::PowerShell => {
                let mut input = self.session_input(script, metadata);
                input.extend_from_slice(
                    format!(
                        "{}\n{}\n",
                        watchdog_base64(),
                        guest_deadline_seconds(deadline)
                    )
                    .as_bytes(),
                );
                input
            }
        }
    }

    /// The command string and session input for a session: the exec forms
    /// when `watched`, the plain ones otherwise. Only a synchronous exec on
    /// a Windows guest is ever watched.
    pub(crate) fn session_parts(
        self,
        watched: bool,
        metadata: &ScriptMetadata,
        script: &str,
        deadline: Duration,
    ) -> (String, Vec<u8>) {
        if watched {
            (
                self.exec_command_line(metadata),
                self.exec_session_input(script, metadata, deadline),
            )
        } else {
            (
                self.command_line(metadata),
                self.session_input(script, metadata),
            )
        }
    }

    /// The bytes written to the session's stdin before any payload: the
    /// prologue and the script.
    pub(crate) fn session_input(self, script: &str, metadata: &ScriptMetadata) -> Vec<u8> {
        match self {
            Self::Posix => format!("{}{script}", remote_prologue()).into_bytes(),
            Self::PowerShell => format!(
                "{}\n{}\n",
                encode_metadata(metadata),
                base64::engine::general_purpose::STANDARD.encode(script.as_bytes())
            )
            .into_bytes(),
        }
    }
}

/// The fixed PowerShell bootstrap: the whole command string for a Windows
/// guest. It reads the metadata line and the script line from stdin, applies
/// the working directory, environment and arguments, runs the script as a
/// script block, and maps the outcome to an exit code the way a POSIX shell
/// would: `exit N` in the script exits N; otherwise the exit code is 0 when
/// the script's last statement succeeded, else the last native command's
/// exit code, else 1 (a native code whose low byte is 0 also reports 1:
/// `ssh` truncates the remote exit status to 8 bits, and a failure must not
/// read as success). A header that is truncated or malformed, a working
/// directory that is not an existing local directory, or an environment
/// entry that cannot be applied exits 90 without echoing any caller text.
/// Syntax is Windows PowerShell 5.1.
macro_rules! powershell_bootstrap {
    ($read:expr, $open:expr, $close:expr) => {
        concat!(
    "$ErrorActionPreference='Stop';",
    "$ProgressPreference='SilentlyContinue';",
    "try{[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)}catch{};",
    "$fleetIn=[Console]::OpenStandardInput();",
    "function fleetLine{",
    "$m=New-Object System.IO.MemoryStream;",
    "while(($b=$fleetIn.ReadByte()) -ge 0 -and $b -ne 10){$m.WriteByte($b)};",
    "if($b -lt 0){throw 'header'};",
    "[System.Text.Encoding]::ASCII.GetString($m.ToArray()).Trim()};",
    "try{",
    "$fleetMeta=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((fleetLine))).Split([char]0);",
    "$fleetText=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((fleetLine)));",
    $read,
    "$i=1;$fleetEnv=@();",
    "while($i -lt $fleetMeta.Length -and $fleetMeta[$i] -ne ''){$fleetEnv+=$fleetMeta[$i];$i++};",
    "$i++;$fleetArgs=@();",
    "while($i -lt $fleetMeta.Length){if($fleetMeta[$i] -ne ''){$fleetArgs+=$fleetMeta[$i]};$i++};",
    "$d=$fleetMeta[0];",
    "if($d -ne ''){",
    "if($d.Length -ge 2 -and ($d[0] -eq [char]92 -or $d[0] -eq [char]47) -and ($d[1] -eq [char]92 -or $d[1] -eq [char]47)){throw 'unc'};",
    "if(-not [System.IO.Directory]::Exists($d)){throw 'dir'};",
    "Set-Location -LiteralPath $d;",
    "[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath};",
    "foreach($e in $fleetEnv){$k=$e.IndexOf('=');",
    "[Environment]::SetEnvironmentVariable($e.Substring(0,$k),$e.Substring($k+1),'Process')}",
    "}catch{[Console]::Error.WriteLine('fleet: the session header, working directory or environment cannot be applied');exit 90};",
    "$fleetBlock=[scriptblock]::Create($fleetText+[Environment]::NewLine+[Environment]::NewLine+'$global:fleetOk=$?');",
    "Remove-Variable i,d,e,k,m,b,fleetMeta,fleetEnv,fleetText -ErrorAction SilentlyContinue;",
    "$ErrorActionPreference='Continue';$global:fleetOk=$null;$global:LASTEXITCODE=$null;",
    $open,
    "Invoke-Command -ScriptBlock $fleetBlock -ArgumentList $fleetArgs;",
    $close,
    "if($global:fleetOk -eq $false){$fleetC=1;",
    "if($global:LASTEXITCODE){$fleetC=[int]$global:LASTEXITCODE;if(($fleetC -band 255) -eq 0){$fleetC=1}};",
    "exit $fleetC}else{exit 0}"
)
    };
}

/// The bootstrap for everything except a synchronous exec; see the macro.
pub const POWERSHELL_BOOTSTRAP: &str = powershell_bootstrap!("", "", "");

/// The bootstrap for a synchronous `exec` (see [`WATCHDOG_SCRIPT`]): the
/// same as [`POWERSHELL_BOOTSTRAP`], plus two more stdin lines after the
/// script (the watchdog, and the limit in seconds) and a guest-side
/// watchdog started before the script runs. The limit must be 1 to 5 ASCII
/// digits with a value of 1 to 86400, and the watchdog text must be base64;
/// anything else exits 90 without running the script, as does a watchdog that
/// cannot be started. After the script ends the watchdog is stopped. The
/// script runs exactly as under [`POWERSHELL_BOOTSTRAP`] (no `try` around
/// it), so error and exit-code behaviour is identical.
pub const POWERSHELL_EXEC_BOOTSTRAP: &str = powershell_bootstrap!(
    concat!(
        "$fleetWdText=[Convert]::ToBase64String([Convert]::FromBase64String((fleetLine)));",
        "$fleetLimitText=fleetLine;",
        "if($fleetLimitText.Length -lt 1 -or $fleetLimitText.Length -gt 5){throw 'limit'};",
        "foreach($c in $fleetLimitText.ToCharArray()){if([int]$c -lt 48 -or [int]$c -gt 57){throw 'limit'}};",
        "$fleetLimit=[int]::Parse($fleetLimitText,[Globalization.CultureInfo]::InvariantCulture);",
        "if($fleetLimit -lt 1 -or $fleetLimit -gt 86400){throw 'limit'};",
        // The watchdog starts before the caller's environment is applied, so
        // it never sees a caller-set SystemRoot, PSModulePath and the like.
        "try{",
        "$fleetPsi=New-Object System.Diagnostics.ProcessStartInfo;",
        "$fleetPsi.FileName=[System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName;",
        "$fleetPsi.Arguments='-NoProfile -NonInteractive -EncodedCommand '+$fleetWdText;",
        "$fleetPsi.UseShellExecute=$false;$fleetPsi.CreateNoWindow=$true;",
        "$fleetPsi.RedirectStandardInput=$true;$fleetPsi.RedirectStandardOutput=$true;$fleetPsi.RedirectStandardError=$true;",
        "$fleetPsi.EnvironmentVariables['FLEET_WD_PID']=[string]$PID;",
        "$fleetPsi.EnvironmentVariables['FLEET_WD_SECONDS']=[string]$fleetLimit;",
        "$fleetWd=[System.Diagnostics.Process]::Start($fleetPsi);",
        "$fleetWd.StandardInput.Close()",
        "}catch{[Console]::Error.WriteLine('fleet: the deadline watchdog cannot be started');exit 90};",
    ),
    "",
    // Straight-line, not try/finally: a try block would make a
    // statement-terminating error end the whole script. The watchdog also
    // ends by itself when this process does.
    "try{$fleetWd.Kill()}catch{};"
);

/// The watchdog the exec bootstrap starts as a separate PowerShell process
/// (fixed text, sent as base64 of its UTF-16 bytes for `-EncodedCommand`; no
/// caller data is in it). It reads the session PowerShell's pid and the limit
/// from `FLEET_WD_PID` and `FLEET_WD_SECONDS`, both integers the bootstrap
/// wrote itself. It waits for that process to end; if it is still running
/// when the limit is up, counted from the watchdog's own start so its
/// startup is not added, it stops the parent and then the parent's child
/// process trees with `taskkill /F /T`. It runs as its own process, so it
/// works when the script is blocked reading stdin or sleeping. It does
/// nothing unless the pid it was given started no later than itself (a
/// recycled pid is not the session), and it takes only children created
/// after the parent started (a stale parent pid is not a child). `taskkill
/// /T` walks parent pids the same way and has the same residual. A script
/// that deliberately kills the watchdog or exhausts the guest defeats it:
/// this is best effort against a cooperative script, not a sandbox.
pub const WATCHDOG_SCRIPT: &str = "$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
try {
  $fleetParentId = [int]$env:FLEET_WD_PID
  $fleetSeconds = [int]$env:FLEET_WD_SECONDS
  $fleetParent = [System.Diagnostics.Process]::GetProcessById($fleetParentId)
  $fleetMe = [System.Diagnostics.Process]::GetCurrentProcess()
  $fleetParentStart = $fleetParent.StartTime.ToUniversalTime()
  $fleetMeStart = $fleetMe.StartTime.ToUniversalTime()
  if ($fleetParentStart -gt $fleetMeStart) { exit 0 }
  $fleetUsed = [int64]([DateTime]::UtcNow - $fleetMeStart).TotalMilliseconds
  if ($fleetUsed -lt 0) { $fleetUsed = 0 }
  if ($fleetUsed -gt 10000) { $fleetUsed = 10000 }
  $fleetWait = [int64]$fleetSeconds * 1000 - $fleetUsed
  if ($fleetWait -lt 0) { $fleetWait = 0 }
  if ($fleetWait -gt 2000000000) { $fleetWait = 2000000000 }
  if ($fleetParent.WaitForExit([int]$fleetWait)) { exit 0 }
  $fleetKids = @()
  try {
    $fleetKids = @(Get-CimInstance -ClassName Win32_Process -Filter ('ParentProcessId=' + $fleetParentId) -OperationTimeoutSec 10 | Where-Object { $_.ProcessId -ne $fleetMe.Id -and $_.CreationDate -ne $null -and $_.CreationDate.ToUniversalTime() -ge $fleetParentStart })
  } catch { }
  try { $fleetParent.Kill() } catch { }
  $fleetTaskkill = [System.IO.Path]::Combine([Environment]::GetFolderPath('System'), 'taskkill.exe')
  foreach ($fleetKid in $fleetKids) {
    try {
      $fleetPsi = New-Object System.Diagnostics.ProcessStartInfo
      $fleetPsi.FileName = $fleetTaskkill
      $fleetPsi.Arguments = '/F /T /PID ' + [string][int]$fleetKid.ProcessId
      $fleetPsi.UseShellExecute = $false
      $fleetPsi.CreateNoWindow = $true
      $fleetK = [System.Diagnostics.Process]::Start($fleetPsi)
      [void]$fleetK.WaitForExit(10000)
    } catch { }
  }
} catch { }
";

/// The limit the exec bootstrap accepts, in seconds.
pub const MAX_GUEST_DEADLINE_SECS: u64 = 86_400;

/// The guest-side limit for a controller deadline: whole seconds, rounded
/// up (the guest never gives up before the controller), at least 1 and at
/// most [`MAX_GUEST_DEADLINE_SECS`].
#[must_use]
pub fn guest_deadline_seconds(deadline: Duration) -> u64 {
    let whole = deadline
        .as_secs()
        .saturating_add(u64::from(deadline.subsec_nanos() > 0));
    whole.clamp(1, MAX_GUEST_DEADLINE_SECS)
}

fn watchdog_base64() -> String {
    let utf16: Vec<u8> = WATCHDOG_SCRIPT
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

/// Refuses metadata the framing cannot carry faithfully. A NUL byte is the
/// framing's field separator, so one inside a field would shift every field
/// after it (nothing becomes shell text, but the script would see other
/// data); an environment name outside `[A-Za-z_][A-Za-z0-9_]*` is not a
/// variable either shell can set the same way.
fn validate_metadata(metadata: &ScriptMetadata) -> Result<(), SshProviderError> {
    let has_nul = |text: &str| text.contains('\0');
    if has_nul(&metadata.working_directory)
        || metadata
            .environment
            .iter()
            .any(|(name, value)| has_nul(name) || has_nul(value))
        || metadata.arguments.iter().any(|argument| has_nul(argument))
    {
        return Err(SshProviderError::Setup {
            detail: "the working directory, environment and arguments cannot contain a NUL byte"
                .to_owned(),
        });
    }
    let valid_name = |name: &str| {
        let mut chars = name.chars();
        chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some((name, _)) = metadata
        .environment
        .iter()
        .find(|(name, _)| !valid_name(name))
    {
        return Err(SshProviderError::Setup {
            detail: format!("the environment name {name:?} is not [A-Za-z_][A-Za-z0-9_]*"),
        });
    }
    Ok(())
}

/// Starts an `ssh` session running `script` with `metadata` through the
/// endpoint's guest shell. The script has been written to the session's
/// stdin, which stays open: a caller that streams a payload after the script
/// keeps writing to it, and everyone else drops it.
pub(crate) fn spawn_script_session(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    metadata: &ScriptMetadata,
    script: &str,
    deadline: Duration,
) -> Result<crate::key::SshChild, SshProviderError> {
    spawn_session(provider, endpoint, metadata, script, deadline, false)
}

/// Starts a session; `watched` runs the script under the Windows guest-side
/// watchdog (see [`POWERSHELL_EXEC_BOOTSTRAP`]), so its process tree ends at
/// `deadline` even though killing the local `ssh` does not.
pub(crate) fn spawn_session(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    metadata: &ScriptMetadata,
    script: &str,
    deadline: Duration,
    watched: bool,
) -> Result<crate::key::SshChild, SshProviderError> {
    let shell = GuestShell::for_os(endpoint.guest_os)?;
    validate_metadata(metadata)?;
    let config_path = provider.write_config(&endpoint.auth)?;
    // The guard travels with the child: dropping the session removes the file.
    let key_file = match &endpoint.auth {
        crate::SshAuth::StoredKey { key } => Some(provider.materialize_key(key)?),
        _ => None,
    };

    let (command_line, input) = shell.session_parts(watched, metadata, script, deadline);
    let mut command = std::process::Command::new("ssh");
    command
        .arg("-F")
        .arg(&config_path)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", deadline.as_secs().max(1)))
        .arg("-T")
        .arg("-p")
        .arg(endpoint.port.to_string());
    match &endpoint.auth {
        crate::SshAuth::IdentityFile { path } => {
            command.arg("-i").arg(path);
        }
        crate::SshAuth::StoredKey { .. } => {
            if let Some(file) = &key_file {
                command.arg("-i").arg(file.path());
            }
        }
        crate::SshAuth::Agent => {}
    }
    crate::add_ssh_destination(&mut command, endpoint);
    command
        .arg(&command_line)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let child = command.spawn().map_err(|error| SshProviderError::Tool {
        tool: "ssh",
        detail: format!("cannot start: {error}"),
    })?;
    let mut child = crate::key::SshChild::new(child, key_file);
    let stdin = child.stdin.as_mut().ok_or_else(|| SshProviderError::Tool {
        tool: "ssh",
        detail: "the ssh process has no stdin".to_owned(),
    })?;
    if let Err(error) = stdin.write_all(&input) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!("cannot send the script: {error}"),
        });
    }
    Ok(child)
}

/// Metadata that carries only positional arguments.
pub(crate) fn arguments_only(arguments: Vec<String>) -> ScriptMetadata {
    ScriptMetadata {
        working_directory: String::new(),
        environment: Vec::new(),
        arguments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pwsh_support::{
        require_pwsh, run_ps, run_ps_exec, run_ps_raw, run_ps_raw_exec, text,
    };

    #[test]
    fn the_posix_framing_is_the_bash_framing() {
        let metadata = ScriptMetadata {
            working_directory: "/tmp".to_owned(),
            environment: vec![("A".to_owned(), "b c".to_owned())],
            arguments: vec!["x".to_owned()],
        };
        let shell = GuestShell::for_os(GuestOs::Linux).unwrap();
        assert_eq!(
            shell.command_line(&metadata),
            format!("bash -s -- {}", encode_metadata(&metadata))
        );
        assert_eq!(
            shell.session_input("echo hi\n", &metadata),
            format!("{}echo hi\n", remote_prologue()).into_bytes()
        );
    }

    #[test]
    fn the_powershell_command_line_carries_no_caller_data_and_a_safe_alphabet() {
        let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
        let hostile = ScriptMetadata {
            working_directory: "C:\\x\" & calc; $(boom) `".to_owned(),
            environment: vec![("K".to_owned(), "\"; rm".to_owned())],
            arguments: vec!["'\"%PATH%\"".to_owned()],
        };
        // Identical for every caller: the line is a constant.
        assert_eq!(shell.command_line(&hostile), POWERSHELL_BOOTSTRAP);
        assert_eq!(
            shell.command_line(&ScriptMetadata::default()),
            POWERSHELL_BOOTSTRAP
        );
        // sshd, CreateProcess and PowerShell's command-line parsing see no
        // character they treat specially.
        let forbidden = [
            '"', '\\', '`', '%', '^', '&', '|', '<', '>', '\n', '\r', '\0',
        ];
        assert!(
            POWERSHELL_BOOTSTRAP
                .chars()
                .all(|c| c.is_ascii() && !forbidden.contains(&c)),
            "{POWERSHELL_BOOTSTRAP}"
        );
        assert!(POWERSHELL_BOOTSTRAP.len() < 4096);
    }

    #[test]
    fn the_powershell_session_input_is_two_ascii_lines() {
        let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
        let metadata = ScriptMetadata {
            working_directory: "C:\\Users\\\u{e9}".to_owned(),
            environment: vec![("A".to_owned(), "b\nc".to_owned())],
            arguments: vec!["x y".to_owned()],
        };
        let input = shell.session_input("Write-Output '\u{e9}'\n", &metadata);
        let text = String::from_utf8(input).unwrap();
        assert!(text.is_ascii());
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 3, "{text:?}");
        assert!(lines[2].is_empty());
        assert_eq!(lines[0], encode_metadata(&metadata));
        let script = base64::engine::general_purpose::STANDARD
            .decode(lines[1])
            .unwrap();
        assert_eq!(script, "Write-Output '\u{e9}'\n".as_bytes());
    }

    #[test]
    fn powershell_runs_the_script_and_keeps_stdout_and_stderr_apart() {
        let Some(pwsh) = require_pwsh() else { return };
        let out = run_ps(
            &pwsh,
            "Write-Output 'out-line'\n[Console]::Error.WriteLine('err-line')\n",
            &ScriptMetadata::default(),
            b"",
            None,
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(text(&out.stdout), "out-line\n");
        assert_eq!(text(&out.stderr), "err-line\n");
    }

    #[test]
    fn powershell_exit_codes_follow_the_posix_shape() {
        let Some(pwsh) = require_pwsh() else { return };
        let code = |script: &str| {
            run_ps(&pwsh, script, &ScriptMetadata::default(), b"", None)
                .status
                .code()
        };
        assert_eq!(code("exit 7\n"), Some(7));
        assert_eq!(code("exit 0\n"), Some(0));
        assert_eq!(code("Write-Output ok\n"), Some(0));
        // The last native command's code is the script's.
        assert_eq!(code("& /bin/sh -c 'exit 3'\n"), Some(3));
        // An earlier native failure does not taint a later success.
        assert_eq!(code("& /bin/sh -c 'exit 3'\nWrite-Output ok\n"), Some(0));
        // A failing cmdlet with no native code is 1.
        assert_eq!(code("Get-Item /definitely/not/here\n"), Some(1));
        // A terminating error and a syntax error are failures, not success.
        assert_eq!(code("throw 'x'\n"), Some(1));
        assert_ne!(code("if ($true {\n"), Some(0));
    }

    #[test]
    fn powershell_metadata_is_data_never_shell_text() {
        let Some(pwsh) = require_pwsh() else { return };
        let dir = tempfile::tempdir().unwrap();
        let hostile = dir.path().join("d $x 'q' \"dq\" `t & ; (x) é");
        std::fs::create_dir(&hostile).unwrap();
        let metadata = ScriptMetadata {
            working_directory: hostile.display().to_string(),
            environment: vec![
                (
                    "FLEET_T1".to_owned(),
                    "a=b \"c\" 'd' `e` $(touch pwned) $x\nline2 \u{e9}\u{1f600}".to_owned(),
                ),
                ("FLEET_T2".to_owned(), "; exit 9".to_owned()),
            ],
            arguments: vec![
                "-NoProfile".to_owned(),
                "'; touch pwned2; '".to_owned(),
                "\"$(touch pwned3)\"".to_owned(),
                "`n %PATH% ^&".to_owned(),
                "\u{e9}\u{4e2d}".to_owned(),
            ],
        };
        let script = "[Console]::Out.Write((Get-Location).ProviderPath + '|' + $env:FLEET_T1 + '|' + $env:FLEET_T2 + '|' + $args.Count + '|' + ($args -join '<>'))\n";
        let out = run_ps(&pwsh, script, &metadata, b"", Some(dir.path()));
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let expected = format!(
            "{}|{}|{}|5|{}",
            hostile.display(),
            "a=b \"c\" 'd' `e` $(touch pwned) $x\nline2 \u{e9}\u{1f600}",
            "; exit 9",
            metadata.arguments.join("<>")
        );
        assert_eq!(text(&out.stdout), expected);
        for marker in ["pwned", "pwned2", "pwned3"] {
            assert!(!dir.path().join(marker).exists(), "{marker}");
            assert!(!hostile.join(marker).exists(), "{marker}");
        }
    }

    #[test]
    fn powershell_refuses_an_unusable_working_directory_with_90() {
        let Some(pwsh) = require_pwsh() else { return };
        let metadata = ScriptMetadata {
            working_directory: "/definitely/not/a/directory".to_owned(),
            ..ScriptMetadata::default()
        };
        let out = run_ps(&pwsh, "Write-Output ran\n", &metadata, b"", None);
        assert_eq!(out.status.code(), Some(90), "{out:?}");
        assert!(!text(&out.stdout).contains("ran"));
        // The refusal names no caller text.
        assert!(!text(&out.stderr).contains("definitely"));
    }

    #[test]
    fn powershell_payload_after_the_header_arrives_byte_for_byte() {
        let Some(pwsh) = require_pwsh() else { return };
        let payload: Vec<u8> = (0..=255_u8).cycle().take(70_000).collect();
        let script = "$in=[Console]::OpenStandardInput();$ms=New-Object System.IO.MemoryStream;$in.CopyTo($ms);[Console]::Out.Write([Convert]::ToBase64String($ms.ToArray()))\n";
        let out = run_ps(&pwsh, script, &ScriptMetadata::default(), &payload, None);
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let got = base64::engine::general_purpose::STANDARD
            .decode(text(&out.stdout).trim())
            .unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn powershell_output_is_utf8() {
        let Some(pwsh) = require_pwsh() else { return };
        let out = run_ps(
            &pwsh,
            "Write-Output \"caf\u{e9} \u{4e2d}\u{6587} \u{1f600}\"\n",
            &ScriptMetadata::default(),
            b"",
            None,
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(text(&out.stdout), "caf\u{e9} \u{4e2d}\u{6587} \u{1f600}\n");
    }

    #[test]
    fn powershell_never_reports_a_failed_native_code_as_success() {
        let Some(pwsh) = require_pwsh() else { return };
        let code = |script: &str| {
            run_ps(&pwsh, script, &ScriptMetadata::default(), b"", None)
                .status
                .code()
        };
        // ssh truncates the remote status to 8 bits, so a code that is a
        // multiple of 256 would read as success.
        assert_eq!(
            code("$global:LASTEXITCODE = 512\nGet-Item /definitely/not/here\n"),
            Some(1)
        );
        assert_eq!(
            code("$global:LASTEXITCODE = 3\nGet-Item /definitely/not/here\n"),
            Some(3)
        );
    }

    #[test]
    fn a_trailing_line_continuation_cannot_swallow_the_status_probe() {
        let Some(pwsh) = require_pwsh() else { return };
        let run = |script: &str| run_ps(&pwsh, script, &ScriptMetadata::default(), b"", None);
        let failed = run("Get-Item /definitely/not/here `");
        assert_eq!(failed.status.code(), Some(1), "{failed:?}");
        let printed = run("Write-Output hi `");
        assert_eq!(printed.status.code(), Some(0));
        assert_eq!(text(&printed.stdout), "hi\n");
    }

    #[test]
    fn a_truncated_or_malformed_header_exits_90_and_runs_nothing() {
        let Some(pwsh) = require_pwsh() else { return };
        let b64 = |text: &str| base64::engine::general_purpose::STANDARD.encode(text);
        let script = b64("Write-Output ran");
        for input in [
            String::new(),
            "AAAA".to_owned(),
            format!("{}\n", encode_metadata(&ScriptMetadata::default())),
            "!!!\n!!!\n".to_owned(),
            format!("{}\n{script}", encode_metadata(&ScriptMetadata::default())),
        ] {
            let out = run_ps_raw(&pwsh, input.as_bytes());
            assert_eq!(out.status.code(), Some(90), "{input:?}: {out:?}");
            assert!(!text(&out.stdout).contains("ran"));
        }
    }

    #[test]
    fn the_working_directory_must_be_an_existing_local_directory() {
        let Some(pwsh) = require_pwsh() else { return };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-file");
        std::fs::write(&file, b"x").unwrap();
        for bad in [
            "//server/share".to_owned(),
            "\\\\server\\share".to_owned(),
            file.display().to_string(),
            "Env:".to_owned(),
        ] {
            let metadata = ScriptMetadata {
                working_directory: bad.clone(),
                ..ScriptMetadata::default()
            };
            let out = run_ps(&pwsh, "Write-Output ran\n", &metadata, b"", None);
            assert_eq!(out.status.code(), Some(90), "{bad}: {out:?}");
        }
    }

    #[test]
    fn the_bootstraps_own_variables_are_not_left_for_the_script() {
        let Some(pwsh) = require_pwsh() else { return };
        let metadata = ScriptMetadata {
            environment: vec![("FLEET_SECRETISH".to_owned(), "value".to_owned())],
            ..ScriptMetadata::default()
        };
        let out = run_ps(
            &pwsh,
            "[Console]::Out.Write([string]($null -eq (Get-Variable fleetMeta,fleetEnv,fleetText -ErrorAction SilentlyContinue)))\n",
            &metadata,
            b"",
            None,
        );
        assert_eq!(text(&out.stdout), "True");
    }

    #[test]
    fn the_exec_bootstrap_is_fixed_text_in_the_same_safe_alphabet() {
        let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
        let hostile = ScriptMetadata {
            working_directory: "C:\\x\" & calc".to_owned(),
            environment: vec![("K".to_owned(), "\"; rm".to_owned())],
            arguments: vec!["'\"%PATH%\"".to_owned()],
        };
        assert_eq!(shell.exec_command_line(&hostile), POWERSHELL_EXEC_BOOTSTRAP);
        assert_eq!(
            shell.exec_command_line(&ScriptMetadata::default()),
            POWERSHELL_EXEC_BOOTSTRAP
        );
        let forbidden = [
            '"', '\\', '`', '%', '^', '&', '|', '<', '>', '\n', '\r', '\0',
        ];
        assert!(
            POWERSHELL_EXEC_BOOTSTRAP
                .chars()
                .all(|c| c.is_ascii() && !forbidden.contains(&c)),
            "{POWERSHELL_EXEC_BOOTSTRAP}"
        );
        assert!(POWERSHELL_EXEC_BOOTSTRAP.len() < 4096);
        // Other transfers keep the bootstrap without a watchdog.
        assert!(!POWERSHELL_BOOTSTRAP.contains("fleetWd"));
        assert!(POWERSHELL_EXEC_BOOTSTRAP.contains("fleetWd"));
        // Linux is untouched.
        let posix = GuestShell::for_os(GuestOs::Linux).unwrap();
        let limit = Duration::from_secs(5);
        assert_eq!(
            posix.exec_command_line(&hostile),
            posix.command_line(&hostile)
        );
        assert_eq!(
            posix.exec_session_input("echo\n", &hostile, limit),
            posix.session_input("echo\n", &hostile)
        );
    }

    #[test]
    fn the_exec_session_input_adds_the_watchdog_and_a_validated_integer_limit() {
        let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
        let metadata = ScriptMetadata::default();
        let input = String::from_utf8(shell.exec_session_input(
            "Write-Output hi\n",
            &metadata,
            Duration::from_millis(1500),
        ))
        .unwrap();
        let lines: Vec<&str> = input.split('\n').collect();
        assert_eq!(lines.len(), 5, "{input:?}");
        assert!(lines[4].is_empty());
        let plain = String::from_utf8(shell.session_input("Write-Output hi\n", &metadata)).unwrap();
        assert!(input.starts_with(&plain));
        let watchdog = base64::engine::general_purpose::STANDARD
            .decode(lines[2])
            .unwrap();
        let units: Vec<u16> = watchdog
            .chunks(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(String::from_utf16(&units).unwrap(), WATCHDOG_SCRIPT);
        assert_eq!(lines[3], "2", "1.5 s rounds up to 2");
        // The fixed watchdog carries no caller data and uses taskkill's tree kill.
        assert!(WATCHDOG_SCRIPT.contains("taskkill.exe"));
        assert!(WATCHDOG_SCRIPT.contains("/F /T /PID"));
    }

    #[test]
    fn the_guest_limit_is_whole_seconds_rounded_up_and_clamped() {
        let secs = |ms: u64| guest_deadline_seconds(Duration::from_millis(ms));
        assert_eq!(secs(0), 1);
        assert_eq!(secs(1), 1);
        assert_eq!(secs(1000), 1);
        assert_eq!(secs(1001), 2);
        assert_eq!(secs(900_000), 900);
        assert_eq!(secs(u64::MAX / 2), MAX_GUEST_DEADLINE_SECS);
        assert_eq!(
            guest_deadline_seconds(Duration::MAX),
            MAX_GUEST_DEADLINE_SECS
        );
    }

    #[test]
    fn powershell_exec_runs_under_the_watchdog_and_keeps_its_exit_codes() {
        let Some(pwsh) = require_pwsh() else { return };
        let limit = Duration::from_secs(60);
        let out = run_ps_exec(
            &pwsh,
            "Write-Output 'out-line'\n[Console]::Error.WriteLine('err-line')\n",
            limit,
            None,
        );
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        assert_eq!(text(&out.stdout), "out-line\n");
        assert_eq!(text(&out.stderr), "err-line\n");
        for (script, want) in [
            ("exit 7\n", 7),
            ("& /bin/sh -c 'exit 3'\n", 3),
            ("throw 'x'\n", 1),
        ] {
            let out = run_ps_exec(&pwsh, script, limit, None);
            assert_eq!(out.status.code(), Some(want), "{script}: {out:?}");
        }
    }

    #[test]
    fn powershell_exec_refuses_a_bad_limit_or_watchdog_with_90_and_runs_nothing() {
        let Some(pwsh) = require_pwsh() else { return };
        let good = watchdog_base64();
        let limit = Duration::from_secs(60);
        for (watchdog, line) in [
            (good.as_str(), ""),
            (good.as_str(), "0"),
            (good.as_str(), "86401"),
            (good.as_str(), "100000"),
            (good.as_str(), "-5"),
            (good.as_str(), "+5"),
            (good.as_str(), "5.0"),
            (good.as_str(), "0x10"),
            (good.as_str(), "1e3"),
            (good.as_str(), "5 "),
            (good.as_str(), "5; exit 0"),
            (good.as_str(), "\u{663}"),
            (good.as_str(), "$(exit 0)"),
            ("!!!not base64!!!", "60"),
        ] {
            let out = run_ps_exec(&pwsh, "Write-Output ran\n", limit, Some((watchdog, line)));
            // A trailing space is trimmed by the line reader and is valid.
            if line == "5 " {
                assert_eq!(out.status.code(), Some(0), "{line:?}: {out:?}");
                continue;
            }
            assert_eq!(out.status.code(), Some(90), "{line:?}: {out:?}");
            assert!(!text(&out.stdout).contains("ran"), "{line:?}");
        }
        // The end of the input before the limit line is a refused header.
        let out = run_ps_raw(&pwsh, b"");
        assert_eq!(out.status.code(), Some(90));
    }

    #[test]
    fn only_a_watched_session_gets_the_exec_bootstrap_and_its_extra_lines() {
        let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
        let metadata = ScriptMetadata::default();
        let limit = Duration::from_secs(30);
        let (plain_line, plain_input) = shell.session_parts(false, &metadata, "echo\n", limit);
        assert_eq!(plain_line, POWERSHELL_BOOTSTRAP);
        assert_eq!(plain_input, shell.session_input("echo\n", &metadata));
        let (watched_line, watched_input) = shell.session_parts(true, &metadata, "echo\n", limit);
        assert_eq!(watched_line, POWERSHELL_EXEC_BOOTSTRAP);
        assert_eq!(
            watched_input,
            shell.exec_session_input("echo\n", &metadata, limit)
        );
        assert!(watched_input.len() > plain_input.len());
        // The Linux framing never changes.
        let posix = GuestShell::for_os(GuestOs::Linux).unwrap();
        for watched in [false, true] {
            assert_eq!(
                posix.session_parts(watched, &metadata, "echo\n", limit),
                posix.session_parts(false, &metadata, "echo\n", limit)
            );
        }
    }

    #[test]
    fn the_watchdog_guards_against_a_recycled_pid_and_stale_children() {
        // The text-level controls; the firing path runs under pwsh and live.
        assert!(WATCHDOG_SCRIPT.contains("$fleetParentStart -gt $fleetMeStart"));
        assert!(WATCHDOG_SCRIPT.contains(
            "$_.CreationDate -ne $null -and $_.CreationDate.ToUniversalTime() -ge $fleetParentStart"
        ));
        assert!(WATCHDOG_SCRIPT.contains("-OperationTimeoutSec 10"));
        assert!(WATCHDOG_SCRIPT.contains("GetFolderPath('System')"));
        assert!(!WATCHDOG_SCRIPT.contains("SystemRoot"));
        // It is started before the caller's environment is applied.
        let started = POWERSHELL_EXEC_BOOTSTRAP
            .find("Process]::Start($fleetPsi)")
            .unwrap();
        let applied = POWERSHELL_EXEC_BOOTSTRAP
            .find("SetEnvironmentVariable")
            .unwrap();
        assert!(started < applied);
    }

    #[test]
    fn powershell_exec_status_survives_the_watchdog_wrapper_for_exit_and_throw() {
        let Some(pwsh) = require_pwsh() else { return };
        let limit = Duration::from_secs(60);
        for (script, want) in [
            ("exit 5\n", 5),
            ("try { exit 6 } finally { }\n", 6),
            ("throw 'boom'\nWrite-Output after\n", 1),
            ("& /bin/sh -c 'exit 9'\n", 9),
        ] {
            let out = run_ps_exec(&pwsh, script, limit, None);
            assert_eq!(out.status.code(), Some(want), "{script}: {out:?}");
            assert!(!text(&out.stdout).contains("after"));
        }
    }

    #[test]
    fn powershell_exec_watchdog_stops_a_sleeping_or_stdin_blocked_script_at_the_limit() {
        let Some(pwsh) = require_pwsh() else { return };
        for script in [
            "Start-Sleep 60\nWrite-Output after\n",
            // Blocked reading stdin, which the session keeps open.
            "$null = [Console]::OpenStandardInput().ReadByte()\nWrite-Output after\n",
        ] {
            let started = std::time::Instant::now();
            let out =
                crate::pwsh_support::run_ps_exec_open_stdin(&pwsh, script, Duration::from_secs(2));
            let took = started.elapsed();
            assert!(took < Duration::from_secs(30), "{script}: {took:?}");
            assert_ne!(out.status.code(), Some(0), "{script}: {out:?}");
            assert!(!text(&out.stdout).contains("after"), "{script}");
        }
    }

    #[test]
    fn powershell_exec_refuses_truncated_exec_input_and_odd_whitespace_in_the_limit() {
        let Some(pwsh) = require_pwsh() else { return };
        let good = watchdog_base64();
        let limit = Duration::from_secs(60);
        let full = String::from_utf8(GuestShell::PowerShell.exec_session_input(
            "Write-Output ran\n",
            &ScriptMetadata::default(),
            limit,
        ))
        .unwrap();
        let lines: Vec<&str> = full.split('\n').collect();
        // Input that ends after the script, the watchdog, or the limit's digits.
        for cut in [
            format!("{}\n{}\n", lines[0], lines[1]),
            format!("{}\n{}\n{}\n", lines[0], lines[1], lines[2]),
            format!("{}\n{}\n{}\n60", lines[0], lines[1], lines[2]),
        ] {
            let out = run_ps_raw_exec(&pwsh, cut.as_bytes());
            assert_eq!(out.status.code(), Some(90), "{cut:?}: {out:?}");
            assert!(!text(&out.stdout).contains("ran"));
        }
        for line in ["5\t5", "5 5", "\u{a0}5", "5\r5", " "] {
            let out = run_ps_exec(
                &pwsh,
                "Write-Output ran\n",
                limit,
                Some((good.as_str(), line)),
            );
            assert_eq!(out.status.code(), Some(90), "{line:?}: {out:?}");
            assert!(!text(&out.stdout).contains("ran"), "{line:?}");
        }
        // Surrounding whitespace is trimmed by the line reader and is accepted.
        for line in ["\t5", "5\t", " 5 "] {
            let out = run_ps_exec(
                &pwsh,
                "Write-Output ran\n",
                limit,
                Some((good.as_str(), line)),
            );
            assert_eq!(out.status.code(), Some(0), "{line:?}: {out:?}");
        }
    }

    #[test]
    fn the_watched_bootstrap_behaves_exactly_like_the_unwatched_one() {
        let Some(pwsh) = require_pwsh() else { return };
        let limit = Duration::from_secs(60);
        let scripts = [
            "[int]::Parse('x')\nWrite-Output after\n",
            "Write-Output before\n[int]::Parse('x')\n",
            "[int]::Parse('x')\nexit 3\n",
            "$x = 0\n1/$x\nWrite-Output after\n",
            "Get-Item -NoSuchParam\nWrite-Output after\n",
            "function f { [int]::Parse('x') }\nf\nWrite-Output after\n",
            "break\n",
            "while ($true) { break }\nWrite-Output after\n",
            "Write-Output ok\n",
            "exit 7\n",
            "throw 'boom'\nWrite-Output after\n",
            "Get-Item /definitely/not/here\n",
            "& /bin/sh -c 'exit 3'\n",
            "& /bin/sh -c 'exit 3'\nWrite-Output after\n",
            "[Console]::Error.WriteLine('err')\nexit 0\n",
            "Write-Error 'x'\n",
            "Write-Error 'x'\nWrite-Output after\n",
            "$ErrorActionPreference = 'Stop'\n[int]::Parse('x')\nWrite-Output after\n",
            "try { [int]::Parse('x') } catch { Write-Output caught }\nWrite-Output after\n",
            "exit 256\n",
        ];
        for script in scripts {
            let plain = run_ps(&pwsh, script, &ScriptMetadata::default(), b"", None);
            let watched = run_ps_exec(&pwsh, script, limit, None);
            assert_eq!(
                watched.status.code(),
                plain.status.code(),
                "{script:?}: {watched:?} vs {plain:?}"
            );
            assert_eq!(text(&watched.stdout), text(&plain.stdout), "{script:?}");
            assert_eq!(text(&watched.stderr), text(&plain.stderr), "{script:?}");
        }
        // The cases the comparison must actually cover.
        let code = |script: &str| run_ps_exec(&pwsh, script, limit, None).status.code();
        let out = run_ps_exec(&pwsh, scripts[0], limit, None);
        assert_eq!(out.status.code(), Some(0));
        assert_eq!(text(&out.stdout), "after\n");
        assert_eq!(code(scripts[1]), Some(1));
        assert_eq!(code(scripts[2]), Some(3));
        assert_eq!(code(scripts[6]), Some(1));
    }

    #[test]
    fn metadata_the_framing_cannot_carry_is_refused_before_a_session_starts() {
        for bad in [
            ScriptMetadata {
                working_directory: "/tmp\0X=1".to_owned(),
                ..ScriptMetadata::default()
            },
            ScriptMetadata {
                environment: vec![("A".to_owned(), "v\0\0-injected".to_owned())],
                ..ScriptMetadata::default()
            },
            ScriptMetadata {
                arguments: vec!["a\0b".to_owned()],
                ..ScriptMetadata::default()
            },
            ScriptMetadata {
                environment: vec![("1BAD".to_owned(), "v".to_owned())],
                ..ScriptMetadata::default()
            },
            ScriptMetadata {
                environment: vec![("A=B".to_owned(), "v".to_owned())],
                ..ScriptMetadata::default()
            },
            ScriptMetadata {
                environment: vec![(String::new(), "v".to_owned())],
                ..ScriptMetadata::default()
            },
        ] {
            assert!(validate_metadata(&bad).is_err(), "{bad:?}");
        }
        assert!(
            validate_metadata(&ScriptMetadata {
                environment: vec![("_OK_1".to_owned(), "a=b".to_owned())],
                ..ScriptMetadata::default()
            })
            .is_ok()
        );
    }
}
