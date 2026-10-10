//! The Windows guest shell end to end: the real `ssh` client, a real sshd,
//! and `pwsh` standing in for the guest's PowerShell. sshd's `ForceCommand`
//! hands the command string to `pwsh -Command`, which is exactly what
//! Windows OpenSSH does with `DefaultShell` set to `powershell.exe` (it runs
//! `powershell.exe -c <command>`). The scripts are the ones Fleet ships;
//! what this cannot prove is Windows PowerShell 5.1 itself, which the
//! fixture run covers. Tests skip (loudly) when `pwsh` is not installed.

#![allow(dead_code)]

use fleet_core::GuestOs;
use fleet_provider_ssh::{
    ExecutionLimiter, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider, execute_script,
};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

fn pwsh() -> Option<String> {
    let mut candidate = std::env::var("FLEET_PWSH").unwrap_or_else(|_| "pwsh".to_owned());
    if !candidate.contains('/') {
        // sshd's session has no PATH worth trusting: use the absolute path.
        candidate = std::env::var("PATH")
            .unwrap_or_default()
            .split(':')
            .map(|dir| std::path::Path::new(dir).join(&candidate))
            .find(|path| path.is_file())?
            .display()
            .to_string();
    }
    Command::new(&candidate)
        .args(["-NoProfile", "-NonInteractive", "-Command", "exit 0"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|_| candidate)
}

fn startup_lock() -> std::fs::File {
    let user = std::env::var("USER")
        .unwrap_or_else(|_| std::env::var("LOGNAME").unwrap_or_else(|_| "unknown".to_owned()));
    let path = std::env::temp_dir().join(format!("fleet-test-sshd-startup-{user}.lock"));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .expect("the startup lock file must open");
    file.lock().expect("the startup lock must acquire");
    file
}

/// A sshd whose every command runs through `pwsh -Command`.
struct PowerShellSshd {
    child: Child,
    port: u16,
    dir: tempfile::TempDir,
}

impl Drop for PowerShellSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl PowerShellSshd {
    fn start(pwsh: &str) -> Self {
        let _guard = startup_lock();
        let dir = tempfile::tempdir().unwrap();
        let host_key = dir.path().join("host_ed25519");
        let user_key = dir.path().join("user_ed25519");
        for key in [&host_key, &user_key] {
            let generated = Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-q", "-f"])
                .arg(key)
                .output()
                .unwrap();
            assert!(generated.status.success());
        }
        let authz = dir.path().join("authorized_keys");
        std::fs::write(
            &authz,
            std::fs::read_to_string(format!("{}.pub", user_key.display())).unwrap(),
        )
        .unwrap();
        let wrapper = dir.path().join("windows-default-shell.sh");
        std::fs::write(
            &wrapper,
            format!(
                "#!/bin/sh\nexec '{pwsh}' -NoProfile -NonInteractive -Command \"$SSH_ORIGINAL_COMMAND\"\n"
            ),
        )
        .unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let config = dir.path().join("sshd_config");
        std::fs::write(
            &config,
            format!(
                "Port {port}\nListenAddress 127.0.0.1\nHostKey {}\nAuthorizedKeysFile {}\n\
                 PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n\
                 StrictModes no\nMaxAuthTries 64\nPidFile {}/sshd.pid\n\
                 ForceCommand /bin/sh {}\n",
                host_key.display(),
                authz.display(),
                dir.path().display(),
                wrapper.display()
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&host_key, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::create_dir_all("/run/sshd").ok();
        }
        let child = Command::new("/usr/sbin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .spawn()
            .expect("sshd must start; these tests need a local OpenSSH server");
        for _ in 0..50 {
            if TcpListener::bind(("127.0.0.1", port)).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Self { child, port, dir }
    }

    fn spec(&self) -> SshConnectionSpec {
        SshConnectionSpec {
            guest_os: GuestOs::Windows,
            host: "127.0.0.1".to_owned(),
            port: self.port,
            user: std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| "nobody".to_owned()),
            auth: SshAuth::IdentityFile {
                path: format!("{}/user_ed25519", self.dir.path().display()),
            },
        }
    }

    fn provider(&self) -> SshProvider {
        let provider = SshProvider::new(self.dir.path().join("ssh")).unwrap();
        // Trust the test host key without TOFU ceremony.
        let key =
            std::fs::read_to_string(format!("{}/host_ed25519.pub", self.dir.path().display()))
                .unwrap();
        let mut parts = key.split_whitespace();
        let (kind, body) = (parts.next().unwrap(), parts.next().unwrap());
        std::fs::write(
            provider.known_hosts_path(),
            format!("[127.0.0.1]:{} {kind} {body}\n", self.port),
        )
        .unwrap();
        provider
    }
}

macro_rules! sshd_or_skip {
    () => {{
        let Some(pwsh) = pwsh() else {
            eprintln!("SKIPPED: no pwsh on PATH and FLEET_PWSH unset");
            return;
        };
        let sshd = PowerShellSshd::start(&pwsh);
        let provider = sshd.provider();
        (sshd, provider, ExecutionLimiter::new(4))
    }};
}

#[test]
fn exec_runs_a_powershell_script_over_ssh_with_exit_code_and_separate_streams() {
    let (sshd, provider, limiter) = sshd_or_skip!();
    let result = execute_script(
        &provider,
        &limiter,
        &sshd.spec(),
        "Write-Output 'to-stdout'\n[Console]::Error.WriteLine('to-stderr')\nexit 6\n",
        &ScriptMetadata::default(),
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(6), "{result:?}");
    assert_eq!(result.stdout.trim(), "to-stdout");
    assert_eq!(result.stderr.trim(), "to-stderr");
    assert!(!result.killed_by_deadline);
}

#[test]
fn exec_keeps_hostile_caller_data_out_of_the_remote_command() {
    let (sshd, provider, limiter) = sshd_or_skip!();
    let marker = sshd.dir.path().join("pwned");
    let hostile = format!("'; New-Item -ItemType File '{}'; '", marker.display());
    let metadata = ScriptMetadata {
        working_directory: sshd.dir.path().display().to_string(),
        environment: vec![("FLEET_X".to_owned(), format!("\"{hostile}\" `n $(1+1)"))],
        arguments: vec![hostile.clone(), "caf\u{e9} \u{4e2d}".to_owned()],
    };
    let result = execute_script(
        &provider,
        &limiter,
        &sshd.spec(),
        "[Console]::Out.Write($env:FLEET_X + '|' + ($args -join '<>') + '|' + (Get-Location).ProviderPath)\n",
        &metadata,
        Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(0), "{result:?}");
    assert_eq!(
        result.stdout,
        format!(
            "\"{hostile}\" `n $(1+1)|{hostile}<>caf\u{e9} \u{4e2d}|{}",
            sshd.dir.path().display()
        )
    );
    assert!(!marker.exists(), "caller text was executed");
}

#[test]
fn exec_kills_a_long_script_at_the_deadline() {
    let (sshd, provider, limiter) = sshd_or_skip!();
    let started = std::time::Instant::now();
    let result = execute_script(
        &provider,
        &limiter,
        &sshd.spec(),
        "Start-Sleep -Seconds 30\n",
        &ScriptMetadata::default(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(result.killed_by_deadline, "{result:?}");
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[test]
fn a_windows_probe_collects_facts_over_ssh() {
    let (sshd, provider, limiter) = sshd_or_skip!();
    let facts =
        fleet_provider_ssh::collect(&provider, &limiter, &sshd.spec(), Duration::from_secs(60))
            .unwrap();
    assert!(
        facts.iter().any(|fact| fact.namespace == "os"
            && fact.name == "family"
            && fact.value.as_deref() == Some("Windows")),
        "{facts:?}"
    );
}
