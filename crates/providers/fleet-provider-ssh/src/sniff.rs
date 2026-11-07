//! Login-shell detection (ADR 0021 decision 4): which shell answers on an
//! SSH endpoint, and so which guest OS Fleet should drive it as.
//!
//! The probe is one fixed command string with no caller data in it,
//! [`SNIFF_COMMAND`], written so every shell Fleet may meet parses it and
//! answers differently:
//!
//! | Login shell                | Output (whitespace-separated tokens)                         |
//! |----------------------------|--------------------------------------------------------------|
//! | Bash, dash, other POSIX    | `fleet-shell %OS% .PSEdition .PSVersion.Major .SessionState.LanguageMode` |
//! | `cmd.exe`                  | `fleet-shell Windows_NT $PSVersionTable.PSEdition ...` (literal) |
//! | Windows PowerShell 5.1     | `fleet-shell` `%OS%` `Desktop` `5` `FullLanguage`, one per line |
//! | PowerShell 7 (`pwsh`)      | `fleet-shell` `%OS%` `Core` `7` `FullLanguage`, one per line |
//!
//! `%OS%` is expanded only by `cmd.exe`; `$name.Member` is a property read
//! in PowerShell and an empty variable followed by literal text in a POSIX
//! shell. Only Windows PowerShell 5.1 in `FullLanguage` mode with nothing
//! printed ahead of the marker classifies as Windows; POSIX output keeps
//! today's Linux behaviour; anything else is refused with a reason that
//! names the setup step, or left unrecognized (and so unknown).
#![warn(missing_docs)]

use std::time::{Duration, Instant};

use fleet_core::GuestOs;

use crate::{ExecutionLimiter, SshConnectionSpec, SshProvider, SshProviderError};

/// The fixed shell-sniffing command. It carries no caller data, and only the
/// marker and the shell's own answers come back.
pub const SNIFF_COMMAND: &str = "echo fleet-shell %OS% $PSVersionTable.PSEdition $PSVersionTable.PSVersion.Major $ExecutionContext.SessionState.LanguageMode $PSVersionTable.Platform";

/// The second fixed command, run only after a POSIX answer: Git Bash, MSYS2
/// and Cygwin answer the sniff like any POSIX shell, and `uname -s` is what
/// tells them from Linux (`MINGW64_NT-...`, `MSYS_NT-...`, `CYGWIN_NT-...`).
pub const UNAME_COMMAND: &str = "uname -s";

/// The exit status `ssh` itself uses for a connection, authentication or
/// host-key failure; any other status came from the remote shell.
const SSH_FAILURE_STATUS: i32 = 255;

/// The marker token the sniff prints first.
const MARKER: &str = "fleet-shell";

/// How long the sniff may take, connection included.
pub const SNIFF_DEADLINE: Duration = Duration::from_secs(20);

/// The runbook section that every refusal points to.
pub const SETUP_GUIDE: &str = "docs/operations/windows-workstations.md";

/// The login shell an endpoint answered with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectedShell {
    /// A POSIX shell (Bash, dash, ...): today's Linux path.
    Posix,
    /// Windows PowerShell 5.1 (`Desktop` edition): the Windows path.
    WindowsPowerShell,
    /// PowerShell 6 or 7 (`Core` edition) as the login shell.
    PowerShellCore,
    /// `cmd.exe`, the Windows OpenSSH default.
    Cmd,
    /// A POSIX shell running on Windows (Git Bash, MSYS2, Cygwin) as the
    /// OpenSSH `DefaultShell`.
    WindowsPosix,
    /// The output matched none of the above.
    Unrecognized,
}

impl DetectedShell {
    /// The stable string used in results and the API.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Posix => "posix",
            Self::WindowsPowerShell => "windows_powershell",
            Self::PowerShellCore => "powershell_core",
            Self::Cmd => "cmd",
            Self::WindowsPosix => "windows_posix",
            Self::Unrecognized => "unrecognized",
        }
    }
}

/// Why a detected shell cannot be driven, with the setup step that fixes it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellRefusal {
    /// The stable reason code: `unsupported_shell`, `constrained_language`
    /// or `profile_output`.
    pub reason: &'static str,
    /// The operator-facing detail, naming the setting to change.
    pub detail: String,
}

/// The classified answer of one sniff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellSniff {
    /// The login shell.
    pub shell: DetectedShell,
    /// The PowerShell major version, when PowerShell answered.
    pub powershell_major: Option<u32>,
    /// The PowerShell language mode, when PowerShell answered.
    pub language_mode: Option<String>,
    /// Whether anything was printed before the marker (a profile or logon
    /// script writing to stdout).
    pub profile_output: bool,
}

impl ShellSniff {
    /// The guest OS this endpoint is driven as, when the shell is one Fleet
    /// drives and nothing refuses it: POSIX is Linux, Windows PowerShell 5.1
    /// is Windows. `None` means unknown (refused or unrecognized).
    #[must_use]
    pub fn guest_os(&self) -> Option<GuestOs> {
        if self.refusal().is_some() {
            return None;
        }
        match self.shell {
            DetectedShell::Posix => Some(GuestOs::Linux),
            DetectedShell::WindowsPowerShell => Some(GuestOs::Windows),
            DetectedShell::PowerShellCore
            | DetectedShell::Cmd
            | DetectedShell::WindowsPosix
            | DetectedShell::Unrecognized => None,
        }
    }

    /// Why this shell cannot be driven, when it cannot. POSIX and
    /// unrecognized output are never refused, so Linux behaviour does not
    /// change.
    #[must_use]
    pub fn refusal(&self) -> Option<ShellRefusal> {
        let default_shell = "set the OpenSSH DefaultShell registry value \
             (HKLM\\SOFTWARE\\OpenSSH, DefaultShell) to \
             C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe and test again";
        match self.shell {
            DetectedShell::Cmd => Some(ShellRefusal {
                reason: "unsupported_shell",
                detail: format!(
                    "the endpoint's login shell is cmd.exe (the Windows OpenSSH default); \
                     Fleet drives Windows through Windows PowerShell 5.1: {default_shell} \
                     (see {SETUP_GUIDE})"
                ),
            }),
            DetectedShell::WindowsPosix => Some(ShellRefusal {
                reason: "unsupported_shell",
                detail: format!(
                    "the endpoint's login shell is a POSIX shell on Windows (Git Bash, MSYS2 or \
                     Cygwin); Fleet drives Windows through Windows PowerShell 5.1: \
                     {default_shell} (see {SETUP_GUIDE})"
                ),
            }),
            DetectedShell::PowerShellCore => Some(ShellRefusal {
                reason: "unsupported_shell",
                detail: format!(
                    "the endpoint's login shell is PowerShell {} (pwsh); Fleet requires \
                     Windows PowerShell 5.1 as the login shell: {default_shell} \
                     (see {SETUP_GUIDE})",
                    self.powershell_major
                        .map_or_else(|| "6 or later".to_owned(), |major| major.to_string())
                ),
            }),
            DetectedShell::WindowsPowerShell => {
                if self.language_mode.as_deref() != Some("FullLanguage") {
                    return Some(ShellRefusal {
                        reason: "constrained_language",
                        detail: format!(
                            "Windows PowerShell runs in {} mode for this account (App Control \
                             for Business or AppLocker policy); Fleet's scripts need \
                             FullLanguage, which only the machine's policy can allow \
                             (see {SETUP_GUIDE})",
                            self.language_mode
                                .as_deref()
                                .unwrap_or("an unknown language")
                        ),
                    });
                }
                if self.profile_output {
                    return Some(ShellRefusal {
                        reason: "profile_output",
                        detail: format!(
                            "a PowerShell profile or logon script printed output before \
                             Fleet's command, which corrupts Fleet's framing; remove the \
                             output from the account's $PROFILE files (Windows OpenSSH \
                             starts powershell.exe without -NoProfile) and test again \
                             (see {SETUP_GUIDE})"
                        ),
                    });
                }
                None
            }
            DetectedShell::Posix | DetectedShell::Unrecognized => None,
        }
    }
}

/// Classifies the sniff's stdout. Pure: the contract fixtures in the tests
/// pin what each shell prints.
#[must_use]
pub fn parse_sniff(stdout: &str) -> ShellSniff {
    let unrecognized = ShellSniff {
        shell: DetectedShell::Unrecognized,
        powershell_major: None,
        language_mode: None,
        profile_output: false,
    };
    let Some(at) = find_marker(stdout) else {
        return unrecognized;
    };
    // Anything at all ahead of the marker, whitespace included, is output
    // something else wrote into the session before Fleet's command.
    let profile_output = !stdout[..at].is_empty();
    let tokens: Vec<&str> = stdout[at..].split_whitespace().skip(1).collect();
    let token = |index: usize| tokens.get(index).copied().unwrap_or("");
    let os = token(0);
    let edition = token(1);
    if os == "Windows_NT" && edition.starts_with('$') {
        return ShellSniff {
            shell: DetectedShell::Cmd,
            profile_output,
            ..unrecognized
        };
    }
    if os != "%OS%" {
        return ShellSniff {
            profile_output,
            ..unrecognized
        };
    }
    if edition == ".PSEdition" {
        return ShellSniff {
            shell: DetectedShell::Posix,
            profile_output,
            ..unrecognized
        };
    }
    let shell = match edition {
        "Desktop" => DetectedShell::WindowsPowerShell,
        // PowerShell 7 is refused only on Windows, where the advice to set
        // `DefaultShell` applies. `pwsh` as a Linux login shell answers
        // `Unix` and stays unrecognized (unknown), as before.
        "Core" if token(4) == "Win32NT" => DetectedShell::PowerShellCore,
        _ => DetectedShell::Unrecognized,
    };
    let powershell_major = token(2).parse().ok();
    let language_mode = Some(token(3))
        .filter(|mode| {
            !mode.is_empty() && mode.len() <= 64 && mode.bytes().all(|b| b.is_ascii_alphabetic())
        })
        .map(str::to_owned);
    // Windows PowerShell 5.1 is Desktop edition, major 5; anything else that
    // calls itself Desktop is not a version Fleet was verified on.
    let shell = if shell == DetectedShell::WindowsPowerShell && powershell_major != Some(5) {
        DetectedShell::Unrecognized
    } else {
        shell
    };
    ShellSniff {
        shell,
        powershell_major,
        language_mode,
        profile_output,
    }
}

/// Whether a `uname -s` answer names a POSIX layer on Windows (Git Bash or
/// MSYS2 report `MINGW*`/`MSYS*`, Cygwin `CYGWIN*`).
#[must_use]
pub fn is_windows_posix_uname(stdout: &str) -> bool {
    let first = stdout.trim().to_ascii_uppercase();
    ["MINGW", "MSYS", "CYGWIN"]
        .iter()
        .any(|prefix| first.starts_with(prefix))
}

/// The byte offset of the marker token at the start of a line, when any.
fn find_marker(stdout: &str) -> Option<usize> {
    let mut offset = 0;
    for line in stdout.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed
            .strip_prefix(MARKER)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return Some(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    None
}

/// Runs the sniff against a verified endpoint and classifies the answer.
/// The endpoint's `guest_os` is ignored: the command is the same for every
/// shell, and nothing rides stdin.
///
/// A remote shell that answers without the marker (csh, `set -u`, a forced
/// `command=` in `authorized_keys`) is `Unrecognized`, not an error, so a
/// Linux login that worked before keeps working.
///
/// # Errors
///
/// Fails on transport errors (`ssh` exiting 255: network, authentication,
/// host key) and on a deadline kill.
pub fn sniff_shell(
    provider: &SshProvider,
    limiter: &ExecutionLimiter,
    endpoint: &SshConnectionSpec,
    deadline: Duration,
) -> Result<ShellSniff, SshProviderError> {
    if !limiter.acquire() {
        return Err(SshProviderError::Tool {
            tool: "ssh",
            detail: format!(
                "the concurrency limit ({}) is saturated; no session slot is free",
                limiter.capacity()
            ),
        });
    }
    let result = sniff_inner(provider, endpoint, deadline);
    limiter.release();
    result
}

fn sniff_inner(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    deadline: Duration,
) -> Result<ShellSniff, SshProviderError> {
    let started = Instant::now();
    let result = run_fixed(provider, endpoint, SNIFF_COMMAND, started, deadline)?;
    let mut sniff = parse_sniff(&result.stdout);
    if sniff.shell == DetectedShell::Posix {
        // A POSIX answer may still be Windows. A failed `uname` keeps the
        // POSIX answer: nothing on Linux depends on it.
        if let Ok(uname) = run_fixed(provider, endpoint, UNAME_COMMAND, started, deadline)
            && is_windows_posix_uname(&uname.stdout)
        {
            sniff.shell = DetectedShell::WindowsPosix;
        }
    }
    Ok(sniff)
}

/// Runs one fixed command within what is left of `deadline`.
fn run_fixed(
    provider: &SshProvider,
    endpoint: &SshConnectionSpec,
    command: &str,
    started: Instant,
    deadline: Duration,
) -> Result<crate::ExecutionResult, SshProviderError> {
    let killed = || SshProviderError::Tool {
        tool: "ssh",
        detail: "the login-shell check was killed at its deadline".to_owned(),
    };
    let left = deadline.checked_sub(started.elapsed()).ok_or_else(killed)?;
    let mut child = crate::shell::spawn_fixed_command(provider, endpoint, command, b"", left)?;
    drop(child.stdin.take());
    let result = crate::exec::wait_bounded(&mut child, Instant::now(), left);
    if result.killed_by_deadline {
        return Err(killed());
    }
    if result
        .exit_code
        .is_none_or(|code| code == SSH_FAILURE_STATUS)
    {
        return Err(SshProviderError::Connect {
            detail: crate::redact_failure(&result.stderr),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What Bash, dash and other POSIX shells print.
    const POSIX: &str =
        "fleet-shell %OS% .PSEdition .PSVersion.Major .SessionState.LanguageMode .Platform\n";
    /// What `cmd.exe` prints: `%OS%` expanded, the rest literal, CRLF.
    const CMD: &str = "fleet-shell Windows_NT $PSVersionTable.PSEdition $PSVersionTable.PSVersion.Major $ExecutionContext.SessionState.LanguageMode $PSVersionTable.Platform\r\n";
    /// Windows PowerShell 5.1: Write-Output prints one argument per line.
    const POWERSHELL_51: &str = "fleet-shell\r\n%OS%\r\nDesktop\r\n5\r\nFullLanguage\r\n";
    /// PowerShell 7 as the login shell on Windows.
    const POWERSHELL_7: &str = "fleet-shell\r\n%OS%\r\nCore\r\n7\r\nFullLanguage\r\nWin32NT\r\n";
    /// PowerShell 7 as a Linux login shell.
    const POWERSHELL_7_LINUX: &str = "fleet-shell\n%OS%\nCore\n7\nFullLanguage\nUnix\n";
    /// Windows PowerShell 5.1 under an App Control or `AppLocker` policy.
    const POWERSHELL_51_CLM: &str =
        "fleet-shell\r\n%OS%\r\nDesktop\r\n5\r\nConstrainedLanguage\r\n";
    /// Windows PowerShell 5.1 with a profile that prints a greeting.
    const POWERSHELL_51_PROFILE: &str =
        "Hello from my profile\r\nfleet-shell\r\n%OS%\r\nDesktop\r\n5\r\nFullLanguage\r\n";

    #[test]
    fn a_posix_shell_is_linux_and_never_refused() {
        let sniff = parse_sniff(POSIX);
        assert_eq!(sniff.shell, DetectedShell::Posix);
        assert_eq!(sniff.guest_os(), Some(GuestOs::Linux));
        assert_eq!(sniff.refusal(), None);
        // A noisy .bashrc does not change Linux behaviour.
        let noisy = parse_sniff(&format!("welcome\n{POSIX}"));
        assert!(noisy.profile_output);
        assert_eq!(noisy.guest_os(), Some(GuestOs::Linux));
        assert_eq!(noisy.refusal(), None);
    }

    #[test]
    fn windows_powershell_5_1_is_windows() {
        let sniff = parse_sniff(POWERSHELL_51);
        assert_eq!(sniff.shell, DetectedShell::WindowsPowerShell);
        assert_eq!(sniff.powershell_major, Some(5));
        assert_eq!(sniff.language_mode.as_deref(), Some("FullLanguage"));
        assert!(!sniff.profile_output);
        assert_eq!(sniff.guest_os(), Some(GuestOs::Windows));
        assert_eq!(sniff.refusal(), None);
    }

    #[test]
    fn cmd_is_refused_naming_the_default_shell_setting() {
        let sniff = parse_sniff(CMD);
        assert_eq!(sniff.shell, DetectedShell::Cmd);
        assert_eq!(sniff.guest_os(), None);
        let refusal = sniff.refusal().expect("cmd is refused");
        assert_eq!(refusal.reason, "unsupported_shell");
        assert!(refusal.detail.contains("cmd.exe"), "{}", refusal.detail);
        assert!(
            refusal.detail.contains("DefaultShell"),
            "{}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("powershell.exe"),
            "{}",
            refusal.detail
        );
        assert!(refusal.detail.contains(SETUP_GUIDE), "{}", refusal.detail);
    }

    #[test]
    fn powershell_7_is_refused_naming_the_default_shell_setting() {
        let sniff = parse_sniff(POWERSHELL_7);
        assert_eq!(sniff.shell, DetectedShell::PowerShellCore);
        assert_eq!(sniff.powershell_major, Some(7));
        assert_eq!(sniff.guest_os(), None);
        let refusal = sniff.refusal().expect("pwsh is refused");
        assert_eq!(refusal.reason, "unsupported_shell");
        assert!(
            refusal.detail.contains("PowerShell 7"),
            "{}",
            refusal.detail
        );
        assert!(
            refusal.detail.contains("DefaultShell"),
            "{}",
            refusal.detail
        );
        assert!(refusal.detail.contains("Windows PowerShell 5.1"));
    }

    #[test]
    fn powershell_7_as_a_linux_login_shell_is_not_given_windows_advice() {
        let sniff = parse_sniff(POWERSHELL_7_LINUX);
        assert_eq!(sniff.shell, DetectedShell::Unrecognized);
        assert_eq!(sniff.refusal(), None);
        assert_eq!(sniff.guest_os(), None);
    }

    #[test]
    fn whitespace_before_the_marker_is_profile_output() {
        for noise in ["\r\n", " ", "\n\n"] {
            let sniff = parse_sniff(&format!("{noise}{POWERSHELL_51}"));
            assert!(sniff.profile_output, "{noise:?}");
            assert_eq!(sniff.refusal().map(|r| r.reason), Some("profile_output"));
        }
    }

    #[test]
    fn git_bash_msys_and_cygwin_are_windows_and_refused() {
        for uname in [
            "MINGW64_NT-10.0-22631\n",
            "MSYS_NT-10.0-22631\n",
            "CYGWIN_NT-10.0\n",
        ] {
            assert!(is_windows_posix_uname(uname), "{uname}");
        }
        for uname in ["Linux\n", "Darwin\n", "FreeBSD\n", ""] {
            assert!(!is_windows_posix_uname(uname), "{uname}");
        }
        let sniff = ShellSniff {
            shell: DetectedShell::WindowsPosix,
            ..parse_sniff(POSIX)
        };
        assert_eq!(sniff.guest_os(), None);
        let refusal = sniff.refusal().expect("Git Bash is refused");
        assert_eq!(refusal.reason, "unsupported_shell");
        assert!(refusal.detail.contains("Git Bash"), "{}", refusal.detail);
        assert!(
            refusal.detail.contains("DefaultShell"),
            "{}",
            refusal.detail
        );
    }

    #[test]
    fn constrained_language_mode_is_refused() {
        let sniff = parse_sniff(POWERSHELL_51_CLM);
        assert_eq!(sniff.shell, DetectedShell::WindowsPowerShell);
        assert_eq!(sniff.guest_os(), None);
        let refusal = sniff.refusal().expect("CLM is refused");
        assert_eq!(refusal.reason, "constrained_language");
        assert!(refusal.detail.contains("ConstrainedLanguage"));
    }

    #[test]
    fn profile_output_on_windows_is_refused_without_quoting_it() {
        let sniff = parse_sniff(POWERSHELL_51_PROFILE);
        assert!(sniff.profile_output);
        assert_eq!(sniff.guest_os(), None);
        let refusal = sniff.refusal().expect("profile output is refused");
        assert_eq!(refusal.reason, "profile_output");
        assert!(refusal.detail.contains("$PROFILE"));
        assert!(!refusal.detail.contains("Hello from my profile"));
    }

    #[test]
    fn anything_else_is_unrecognized_and_not_refused() {
        for output in [
            "",
            "garbage\n",
            "fleet-shellish %OS%\n",
            // Windows PowerShell 5.0 has no PSEdition: not a verified shell.
            "fleet-shell\r\n%OS%\r\n5\r\nFullLanguage\r\n",
            // Something calling itself Desktop with another major version.
            "fleet-shell\r\n%OS%\r\nDesktop\r\n4\r\nFullLanguage\r\n",
        ] {
            let sniff = parse_sniff(output);
            assert_eq!(sniff.shell, DetectedShell::Unrecognized, "{output:?}");
            assert_eq!(sniff.guest_os(), None, "{output:?}");
            assert_eq!(sniff.refusal(), None, "{output:?}");
        }
    }

    #[test]
    fn the_command_is_fixed_and_carries_no_quoting_metacharacters() {
        // No quote, backslash, backtick or redirection: every shell parses
        // it the same way up to the variable reads.
        for forbidden in ['"', '\'', '\\', '`', '|', '&', '<', '>', ';', '^'] {
            assert!(!SNIFF_COMMAND.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn a_real_posix_shell_answers_as_posix() {
        for shell in ["sh", "bash"] {
            let Ok(out) = std::process::Command::new(shell)
                .arg("-c")
                .arg(SNIFF_COMMAND)
                .output()
            else {
                continue;
            };
            let sniff = parse_sniff(&String::from_utf8_lossy(&out.stdout));
            assert_eq!(sniff.shell, DetectedShell::Posix, "{shell}: {out:?}");
        }
    }

    #[test]
    fn a_real_powershell_7_answers_by_its_platform() {
        let Some(pwsh) = crate::pwsh_support::require_pwsh() else {
            return;
        };
        // Windows OpenSSH runs `<DefaultShell> -c <command>` with no
        // -NoProfile; the test mirrors that.
        let out = std::process::Command::new(&pwsh)
            .arg("-Command")
            .arg(SNIFF_COMMAND)
            .output()
            .unwrap();
        let sniff = parse_sniff(&String::from_utf8_lossy(&out.stdout));
        // On a Linux test host pwsh answers `Unix`: unrecognized, never
        // refused with Windows advice. On Windows it is refused.
        let expected = if cfg!(windows) {
            DetectedShell::PowerShellCore
        } else {
            DetectedShell::Unrecognized
        };
        assert_eq!(sniff.shell, expected, "{out:?}");
        assert!(sniff.powershell_major.unwrap_or_default() >= 6);
        assert_eq!(sniff.language_mode.as_deref(), Some("FullLanguage"));
    }
}
