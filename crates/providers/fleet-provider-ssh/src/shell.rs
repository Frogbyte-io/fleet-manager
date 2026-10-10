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
/// exit code, else 1. Syntax is Windows PowerShell 5.1.
pub const POWERSHELL_BOOTSTRAP: &str = concat!(
    "$ErrorActionPreference='Stop';",
    "$ProgressPreference='SilentlyContinue';",
    "[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);",
    "$fleetIn=[Console]::OpenStandardInput();",
    "function fleetLine{",
    "$m=New-Object System.IO.MemoryStream;",
    "while(($b=$fleetIn.ReadByte()) -ge 0 -and $b -ne 10){$m.WriteByte($b)};",
    "[System.Text.Encoding]::ASCII.GetString($m.ToArray()).Trim()};",
    "$fleetMeta=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((fleetLine))).Split([char]0);",
    "$fleetText=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((fleetLine)));",
    "$i=1;$fleetEnv=@();",
    "while($i -lt $fleetMeta.Length -and $fleetMeta[$i] -ne ''){$fleetEnv+=$fleetMeta[$i];$i++};",
    "$i++;$fleetArgs=@();",
    "while($i -lt $fleetMeta.Length){if($fleetMeta[$i] -ne ''){$fleetArgs+=$fleetMeta[$i]};$i++};",
    "try{",
    "if($fleetMeta[0] -ne ''){Set-Location -LiteralPath $fleetMeta[0];",
    "[Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath};",
    "foreach($e in $fleetEnv){$k=$e.IndexOf('=');",
    "[Environment]::SetEnvironmentVariable($e.Substring(0,$k),$e.Substring($k+1),'Process')}",
    "}catch{[Console]::Error.WriteLine('fleet: the working directory or environment cannot be applied');exit 90};",
    "$fleetBlock=[scriptblock]::Create($fleetText+[Environment]::NewLine+'$global:fleetOk=$?');",
    "$ErrorActionPreference='Continue';$global:fleetOk=$null;$global:LASTEXITCODE=$null;",
    "Invoke-Command -ScriptBlock $fleetBlock -ArgumentList $fleetArgs;",
    "if($global:fleetOk -eq $false){if($global:LASTEXITCODE){exit $global:LASTEXITCODE}else{exit 1}}else{exit 0}"
);

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
) -> Result<std::process::Child, SshProviderError> {
    let shell = GuestShell::for_os(endpoint.guest_os)?;
    let config_path = provider.write_config(&endpoint.auth)?;

    let mut command = std::process::Command::new("ssh");
    command
        .arg("-F")
        .arg(&config_path)
        .arg("-o")
        .arg(format!("ConnectTimeout={}", deadline.as_secs().max(1)))
        .arg("-T")
        .arg("-p")
        .arg(endpoint.port.to_string());
    if let crate::SshAuth::IdentityFile { path } = &endpoint.auth {
        command.arg("-i").arg(path);
    }
    crate::add_ssh_destination(&mut command, endpoint);
    command
        .arg(shell.command_line(metadata))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().map_err(|error| SshProviderError::Tool {
        tool: "ssh",
        detail: format!("cannot start: {error}"),
    })?;
    let stdin = child.stdin.as_mut().ok_or_else(|| SshProviderError::Tool {
        tool: "ssh",
        detail: "the ssh process has no stdin".to_owned(),
    })?;
    if let Err(error) = stdin.write_all(&shell.session_input(script, metadata)) {
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
    use crate::pwsh_support::{require_pwsh, run_ps, text};

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
}
