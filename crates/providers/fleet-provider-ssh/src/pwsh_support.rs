//! Test support: run the fixed Windows scripts under a real PowerShell.
use std::io::Write as _;

use fleet_core::GuestOs;

use crate::exec::ScriptMetadata;
use crate::shell::GuestShell;

/// The PowerShell used to run the Windows scripts under test: `pwsh`
/// (PowerShell 7) on PATH, or `$FLEET_PWSH`. These tests run the fixed
/// scripts for real, which is the next best thing to a Windows guest:
/// PowerShell 5.1 differences are checked on the fixture. They are
/// skipped (loudly) where no PowerShell is installed: callers use
/// [`require_pwsh`].
pub(crate) fn pwsh() -> Option<String> {
    let candidate = std::env::var("FLEET_PWSH").unwrap_or_else(|_| "pwsh".to_owned());
    std::process::Command::new(&candidate)
        .args(["-NoProfile", "-Command", "exit 0"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|_| candidate)
}

/// Runs `script` through the real bootstrap the way sshd would: the
/// fixed command line as `-Command`, the session input on stdin, then
/// `payload`.
pub(crate) fn run_ps(
    pwsh: &str,
    script: &str,
    metadata: &ScriptMetadata,
    payload: &[u8],
    cwd: Option<&std::path::Path>,
) -> std::process::Output {
    let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
    let mut command = std::process::Command::new(pwsh);
    command
        // Windows OpenSSH passes only `-c <command>`: no -NoProfile and no
        // -NonInteractive. The test mirrors that.
        .arg("-Command")
        .arg(shell.command_line(metadata))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut input = shell.session_input(script, metadata);
    input.extend_from_slice(payload);
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let out = child.wait_with_output().unwrap();
    let _ = writer.join();
    out
}

/// Runs the real bootstrap with exactly `stdin` as the session input.
pub(crate) fn run_ps_raw(pwsh: &str, stdin: &[u8]) -> std::process::Output {
    let shell = GuestShell::for_os(GuestOs::Windows).unwrap();
    let mut child = std::process::Command::new(pwsh)
        .arg("-Command")
        .arg(shell.command_line(&ScriptMetadata::default()))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut pipe = child.stdin.take().unwrap();
    let input = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = pipe.write_all(&input);
    });
    let out = child.wait_with_output().unwrap();
    let _ = writer.join();
    out
}

/// The captured text of a stream with Windows line endings normalized.
pub(crate) fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n")
}

/// The PowerShell to test with, or `None` after saying the test is skipped.
pub(crate) fn require_pwsh() -> Option<String> {
    let found = pwsh();
    assert!(
        found.is_some() || std::env::var_os("FLEET_REQUIRE_PWSH").is_none(),
        "FLEET_REQUIRE_PWSH is set but no PowerShell was found"
    );
    if found.is_none() {
        eprintln!("SKIPPED: no pwsh on PATH and FLEET_PWSH unset");
    }
    found
}
