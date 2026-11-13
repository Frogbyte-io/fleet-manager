use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::json;

use super::*;

// Throwaway public keys generated for these tests only.
const CONTROLLER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9t4Xt9H44BCMC3Ab4ugXr+F9s8s/RCNEv6mkk3WHnV fleet-controller@test";
const OTHER_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJo/jP24EL5XlGpIRFkyYqRJ4VjG+odBnxXEwb/K0nYY other@test";

fn key(line: &str) -> fleet_core::SshPublicKey {
    fleet_core::parse_public_key(line).unwrap()
}

/// A scripted machine: environment, programs and their answers, and the
/// SSH banner. Records every program it was asked to run.
struct FakeHost {
    platform: Platform,
    env: BTreeMap<&'static str, String>,
    programs: BTreeMap<String, Result<ProgramOutput, String>>,
    on_path: BTreeMap<&'static str, PathBuf>,
    banner: Result<String, String>,
    ran: Mutex<Vec<String>>,
}

impl FakeHost {
    fn unix(home: &Path) -> Self {
        Self {
            platform: Platform::Unix,
            env: BTreeMap::from([
                ("HOME", home.display().to_string()),
                ("USER", "developer".to_owned()),
            ]),
            programs: BTreeMap::new(),
            on_path: BTreeMap::new(),
            banner: Ok("SSH-2.0-OpenSSH_9.6".to_owned()),
            ran: Mutex::new(Vec::new()),
        }
    }

    fn windows(home: &Path, program_data: &Path) -> Self {
        let mut host = Self::unix(home);
        host.platform = Platform::Windows;
        host.env = BTreeMap::from([
            ("USERPROFILE", home.display().to_string()),
            ("USERNAME", "developer".to_owned()),
            ("SystemRoot", r"C:\Windows".to_owned()),
            ("ProgramData", program_data.display().to_string()),
        ]);
        host
    }

    fn answer(mut self, program: &str, stdout: &str) -> Self {
        self.programs.insert(
            program.to_owned(),
            Ok(ProgramOutput {
                success: true,
                stdout: stdout.to_owned(),
                stderr: String::new(),
            }),
        );
        self
    }

    fn ran(&self) -> Vec<String> {
        self.ran.lock().unwrap().clone()
    }
}

impl JoinHost for FakeHost {
    fn platform(&self) -> Platform {
        self.platform
    }
    fn env(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }
    fn run(&self, program: &Path, args: &[&str]) -> Result<ProgramOutput, String> {
        let name = program.display().to_string();
        self.ran
            .lock()
            .unwrap()
            .push(format!("{name} {}", args.join(" ")));
        self.programs
            .get(&name)
            .cloned()
            .unwrap_or_else(|| Err(format!("{name} is not installed")))
    }
    fn find_on_path(&self, name: &str) -> Option<PathBuf> {
        self.on_path.get(name).cloned()
    }
    fn ssh_banner(&self, _host: &str, _port: u16) -> Result<String, String> {
        self.banner.clone()
    }
    fn hostname(&self) -> Option<String> {
        Some("dev-box".to_owned())
    }
}

#[test]
fn the_documented_grammar_parses() {
    let mut output = Output::Text;
    let Command::MachinesJoin(args) = parse_join(
        &[
            "--host", "100.64.0.9", "--port", "2222", "--user", "dev", "--name", "box",
            "--agents", "claude_code,codex", "--agent", "codex", "--resume", "--timeout", "900",
            "--output", "json",
        ],
        &mut output,
    )
    .unwrap() else {
        panic!("a join");
    };
    assert_eq!(output, Output::Json);
    assert_eq!(args.host.as_deref(), Some("100.64.0.9"));
    assert_eq!(args.port, 2222);
    assert_eq!(args.agents, ["claude_code", "codex"]);
    assert!(args.resume && !args.no_skills && !args.admin_key_installed);
    assert_eq!(args.timeout, 900);

    let Command::MachinesJoin(defaults) = parse_join(&[], &mut output).unwrap() else {
        panic!("a join");
    };
    assert_eq!(defaults, JoinArgs::default());
    assert_eq!(defaults.port, 22);

    for bad in [
        &["--port", "0"][..],
        &["--port", "x"],
        &["--timeout", "0"],
        &["--host"],
        &["--host", ""],
        &["--no-skills", "--agents", "codex"],
        &["positional"],
        &["--yes"],
    ] {
        assert!(parse_join(bad, &mut output).is_err(), "{bad:?}");
    }
    assert_eq!(
        parse_public_key(&["--output", "json"], &mut output).unwrap(),
        Command::SystemSshPublicKey
    );
    assert!(parse_public_key(&["extra"], &mut output).is_err());
}

#[test]
fn the_top_level_parser_routes_both_commands() {
    let words = |line: &str| line.split(' ').map(str::to_owned).collect::<Vec<_>>();
    let join = crate::parse(&words("--url http://127.0.0.1:9 machines join --no-skills")).unwrap();
    assert!(matches!(join.command, Command::MachinesJoin(ref args) if args.no_skills));
    let key = crate::parse(&words("--url http://127.0.0.1:9 system ssh-public-key")).unwrap();
    assert_eq!(key.command, Command::SystemSshPublicKey);
    let (method, path, _, body) = crate::request_for(&key.command).unwrap();
    assert_eq!((method, path.as_str()), (reqwest::Method::GET, SSH_PUBLIC_KEY_PATH));
    assert!(body.is_none());
}

#[test]
fn the_key_is_appended_once_whatever_the_comment_or_options() {
    let controller = key(CONTROLLER_KEY);
    assert_eq!(
        authorized_keys_addition("", &controller).as_deref(),
        Some(format!("{CONTROLLER_KEY}\n").as_str())
    );
    // A file without a final newline gets one before the new line.
    assert_eq!(
        authorized_keys_addition(OTHER_KEY, &controller).unwrap(),
        format!("\n{CONTROLLER_KEY}\n")
    );
    let blob = CONTROLLER_KEY.split(' ').nth(1).unwrap();
    for present in [
        format!("{OTHER_KEY}\n{CONTROLLER_KEY}\n"),
        format!("ssh-ed25519 {blob} renamed-comment\n"),
        format!("from=\"100.64.0.0/10\",no-pty ssh-ed25519 {blob}\n"),
    ] {
        assert_eq!(authorized_keys_addition(&present, &controller), None, "{present}");
    }
    // A commented-out key does not count.
    assert!(authorized_keys_addition(&format!("# {CONTROLLER_KEY}\n"), &controller).is_some());
}

#[cfg(unix)]
#[test]
fn installing_the_key_is_idempotent_and_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().unwrap();
    let ssh = home.path().join(".ssh");
    std::fs::create_dir_all(&ssh).unwrap();
    std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(ssh.join("authorized_keys"), OTHER_KEY).unwrap();
    std::fs::set_permissions(
        ssh.join("authorized_keys"),
        std::fs::Permissions::from_mode(0o664),
    )
    .unwrap();
    let host = FakeHost::unix(home.path());
    let controller = key(CONTROLLER_KEY);
    let (first, path) = install_authorized_key(&host, home.path(), &controller).unwrap();
    assert_eq!(first, KeyInstall::Added);
    let (second, _) = install_authorized_key(&host, home.path(), &controller).unwrap();
    assert_eq!(second, KeyInstall::Present);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{OTHER_KEY}\n{CONTROLLER_KEY}\n"),
        "the existing key is kept and the controller's added exactly once"
    );
    let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&ssh), 0o700);
    assert_eq!(mode(&path), 0o600);
    assert!(host.ran().is_empty(), "no icacls on Unix");

    // A fresh home gets the directory and the file.
    let fresh = tempfile::tempdir().unwrap();
    let (outcome, path) = install_authorized_key(&host, fresh.path(), &controller).unwrap();
    assert_eq!(outcome, KeyInstall::Added);
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(&fresh.path().join(".ssh")), 0o700);
}

#[test]
fn a_windows_standard_account_gets_the_protected_acl() {
    let home = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let host = FakeHost::windows(home.path(), data.path()).answer("icacls", "processed 1 file");
    let (outcome, path) = install_authorized_key(&host, home.path(), &key(CONTROLLER_KEY)).unwrap();
    assert_eq!(outcome, KeyInstall::Added);
    assert_eq!(path, home.path().join(".ssh").join("authorized_keys"));
    assert_eq!(
        host.ran(),
        [format!(
            "icacls {} /inheritance:r /grant developer:F /grant SYSTEM:F /grant *S-1-5-32-544:F",
            path.display()
        )]
    );
    // A failing icacls is a failure, not a silent open file.
    let mut broken = FakeHost::windows(home.path(), data.path());
    broken.programs.insert(
        "icacls".to_owned(),
        Ok(ProgramOutput {
            success: false,
            stdout: String::new(),
            stderr: "Access is denied.".to_owned(),
        }),
    );
    let error = install_authorized_key(&broken, home.path(), &key(CONTROLLER_KEY)).unwrap_err();
    assert!(error.message.contains("Access is denied"), "{}", error.message);
}

#[test]
fn administrators_are_recognized_from_whoami_groups() {
    let admin = "\"BUILTIN\\Administrators\",\"Alias\",\"S-1-5-32-544\",\"Group used for deny only\"\n\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"";
    let standard = "\"Everyone\",\"Well-known group\",\"S-1-1-0\",\"Mandatory group\"\n\"BUILTIN\\Users\",\"Alias\",\"S-1-5-32-545\",\"Mandatory group\"";
    assert!(is_administrator(admin));
    assert!(!is_administrator(standard));
}

#[test]
fn an_administrator_is_refused_with_the_elevated_commands_for_this_key() {
    let refusal = administrator_refusal(CONTROLLER_KEY);
    assert!(refusal.contains("administrators_authorized_keys"));
    assert!(refusal.contains("ANY administrator"));
    assert!(refusal.contains(&format!("'{CONTROLLER_KEY}'")));
    assert!(refusal.contains("icacls $k /inheritance:r /grant \"*S-1-5-32-544:F\" /grant \"SYSTEM:F\""));
    assert!(refusal.contains("--admin-key-installed"));
    // A quote in a comment cannot break out of the PowerShell literal.
    let block = administrators_key_block("ssh-ed25519 AAAA it's");
    assert!(block.contains("'ssh-ed25519 AAAA it''s'"), "{block}");
}

#[test]
fn the_default_shell_must_be_windows_powershell_5_1() {
    let reg = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH\r\n    DefaultShell    REG_SZ    C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\r\n\r\n";
    let value = parse_default_shell(reg).unwrap();
    assert!(is_windows_powershell_51(&value, r"C:\Windows"));
    assert!(is_windows_powershell_51(
        r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Windows"
    ));
    assert!(is_windows_powershell_51(
        r"c:\windows\system32\windowspowershell\v1.0\POWERSHELL.EXE",
        r"C:\Windows"
    ));
    for refused in [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\cmd.exe",
        r"D:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ] {
        assert!(!is_windows_powershell_51(refused, r"C:\Windows"), "{refused}");
    }
    assert_eq!(parse_default_shell("ERROR: The system was unable to find the specified registry key or value."), None);
}

#[test]
fn password_login_is_off_only_when_the_global_value_says_no() {
    assert!(password_auth_disabled("PasswordAuthentication no\n"));
    assert!(password_auth_disabled("#PasswordAuthentication yes\nPasswordAuthentication=no\n"));
    // The first value wins, as in OpenSSH.
    assert!(!password_auth_disabled("PasswordAuthentication yes\nPasswordAuthentication no\n"));
    // Absent means the default, yes.
    assert!(!password_auth_disabled("#PasswordAuthentication no\nPubkeyAuthentication yes\n"));
    // A value only inside a Match block is not the global one.
    assert!(!password_auth_disabled(
        "Match Group administrators\n  PasswordAuthentication no\n"
    ));
}

#[test]
fn a_stand_in_skills_manager_is_named() {
    let real = ProgramOutput {
        success: true,
        stdout: "skills-manager-cli 1.40.0\n".to_owned(),
        stderr: String::new(),
    };
    assert_eq!(stand_in_reason(b"\x7fE", Ok(&real)), None);
    assert!(stand_in_reason(b"#!", Ok(&real)).unwrap().contains("script"));
    let json = ProgramOutput {
        success: true,
        stdout: "{\"version\":\"1.40.0\"}\n".to_owned(),
        stderr: String::new(),
    };
    assert!(stand_in_reason(b"\x7fE", Ok(&json)).unwrap().contains("instead of"));
    let failed = ProgramOutput {
        success: false,
        ..ProgramOutput::default()
    };
    assert!(stand_in_reason(b"\x7fE", Ok(&failed)).is_some());
    assert!(stand_in_reason(b"\x7fE", Err("exec format error")).unwrap().contains("does not run"));
}

#[cfg(unix)]
#[test]
fn preflight_refuses_a_script_on_path_and_deletes_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join(".local/bin");
    std::fs::create_dir_all(&bin).unwrap();
    let stub = bin.join("skills-manager-cli");
    std::fs::write(&stub, "#!/bin/sh\necho '{\"version\":\"1.40.0\"}'\n").unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut host = FakeHost::unix(home.path());
    host.programs.insert(
        stub.display().to_string(),
        Ok(ProgramOutput {
            success: true,
            stdout: "{\"version\":\"1.40.0\"}".to_owned(),
            stderr: String::new(),
        }),
    );
    let found = preflight(&host, home.path(), "100.64.0.9", 22);
    assert_eq!(found.problems.len(), 1, "{:?}", found.problems);
    assert!(found.problems[0].contains("not the real Skills Manager CLI"));
    assert!(found.problems[0].contains("script"));
    assert!(stub.exists(), "the user's file is left alone");

    // The real binary passes.
    std::fs::write(&stub, b"\x7fELF").unwrap();
    host.programs.insert(
        stub.display().to_string(),
        Ok(ProgramOutput {
            success: true,
            stdout: "skills-manager-cli 1.40.0\n".to_owned(),
            stderr: String::new(),
        }),
    );
    assert!(preflight(&host, home.path(), "100.64.0.9", 22).problems.is_empty());
}

#[test]
fn preflight_needs_an_answering_ssh_server() {
    let home = tempfile::tempdir().unwrap();
    let mut host = FakeHost::unix(home.path());
    host.banner = Err("connection refused".to_owned());
    let found = preflight(&host, home.path(), "100.64.0.9", 22);
    assert!(found.problems[0].contains("no SSH server answers on port 22"));
    assert!(found.problems.iter().any(|problem| problem.contains("systemctl enable --now ssh")));
    assert!(!found.needs_elevated_setup);

    host.banner = Ok("HTTP/1.1 400 Bad Request".to_owned());
    assert!(preflight(&host, home.path(), "100.64.0.9", 22).problems[0].contains("not as an SSH server"));
}

#[test]
fn windows_preflight_reads_and_never_changes_and_asks_for_the_elevated_block() {
    let home = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(data.path().join("ssh")).unwrap();
    std::fs::write(
        data.path().join("ssh/sshd_config"),
        "#PasswordAuthentication yes\nMatch Group administrators\n  AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys\n",
    )
    .unwrap();
    let mut host = FakeHost::windows(home.path(), data.path());
    host.programs.insert(
        "reg".to_owned(),
        Ok(ProgramOutput {
            success: false,
            stdout: String::new(),
            stderr: "ERROR: The system was unable to find the specified registry key or value.".to_owned(),
        }),
    );
    let found = preflight(&host, home.path(), "100.64.0.9", 22);
    assert!(found.needs_elevated_setup);
    assert_eq!(found.problems.len(), 2, "{:?}", found.problems);
    assert!(found.problems[0].contains("cmd.exe"));
    assert!(found.problems[1].contains("PasswordAuthentication no"));
    assert_eq!(
        host.ran(),
        [r"reg query HKLM\SOFTWARE\OpenSSH /v DefaultShell"],
        "only reads"
    );

    // Set up correctly, it passes; an unreadable config is only a warning.
    let ready = FakeHost::windows(home.path(), data.path()).answer(
        "reg",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\OpenSSH\n    DefaultShell    REG_SZ    C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n",
    );
    std::fs::write(
        data.path().join("ssh/sshd_config"),
        "PasswordAuthentication no\n",
    )
    .unwrap();
    let found = preflight(&ready, home.path(), "100.64.0.9", 22);
    assert!(found.problems.is_empty(), "{:?}", found.problems);
    std::fs::remove_file(data.path().join("ssh/sshd_config")).unwrap();
    let found = preflight(&ready, home.path(), "100.64.0.9", 22);
    assert!(found.problems.is_empty());
    assert!(found.warnings[0].contains("PasswordAuthentication no"));
    assert!(WINDOWS_ELEVATED_SETUP.contains("DefaultShell"));
}

#[test]
fn the_address_comes_from_tailscale_unless_given() {
    assert_eq!(
        parse_tailscale_ipv4("100.101.102.103\n"),
        Some(std::net::Ipv4Addr::new(100, 101, 102, 103))
    );
    assert_eq!(parse_tailscale_ipv4("fd7a:115c::1\n100.64.0.9\n"), Some(std::net::Ipv4Addr::new(100, 64, 0, 9)));
    assert_eq!(parse_tailscale_ipv4("Tailscale is stopped.\n"), None);

    let home = tempfile::tempdir().unwrap();
    let host = FakeHost::unix(home.path()).answer("tailscale", "100.64.0.9\n");
    let target = resolve_target(&host, &JoinArgs::default()).unwrap();
    assert_eq!(
        (target.user.as_str(), target.host.as_str(), target.port, target.name.as_str()),
        ("developer", "100.64.0.9", 22, "dev-box")
    );
    let given = resolve_target(
        &host,
        &JoinArgs {
            host: Some("192.0.2.7".to_owned()),
            user: Some("agent".to_owned()),
            name: Some("named".to_owned()),
            ..JoinArgs::default()
        },
    )
    .unwrap();
    assert_eq!(
        (given.user.as_str(), given.host.as_str(), given.name.as_str()),
        ("agent", "192.0.2.7", "named")
    );
    let missing = FakeHost::unix(home.path());
    let error = resolve_target(&missing, &JoinArgs::default()).unwrap_err();
    assert!(error.message.contains("--host"), "{}", error.message);
}

#[test]
fn the_local_host_key_is_read_and_fingerprinted_like_ssh_keygen() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ssh_host_ed25519_key.pub");
    std::fs::write(&file, format!("{CONTROLLER_KEY}\n")).unwrap();
    let host = FakeHost::unix(dir.path());
    let (path, local) = local_host_key(
        &host,
        &JoinArgs {
            host_key_file: Some(file.display().to_string()),
            ..JoinArgs::default()
        },
    )
    .unwrap();
    assert_eq!(path, file);
    assert_eq!(local.fingerprint, "SHA256:2Mqm0WXnrxat1gQ/xKwNc1fp09Gh1IgfynaiOD4BH18");
    std::fs::write(&file, "not a key").unwrap();
    assert!(local_host_key(&host, &JoinArgs { host_key_file: Some(file.display().to_string()), ..JoinArgs::default() }).is_err());
}

#[test]
fn only_an_identical_fingerprint_is_confirmed() {
    let local = key(CONTROLLER_KEY).fingerprint;
    let other = key(OTHER_KEY).fingerprint;
    assert!(fleet_core::fingerprints_match(&local, &local));
    assert!(!fleet_core::fingerprints_match(&local, &other));
    assert!(!fleet_core::fingerprints_match(&local, &local.to_lowercase()));
    let message = fingerprint_mismatch(&local, &other, "100.64.0.9", 22);
    assert!(message.starts_with("REFUSED"));
    assert!(message.contains(&local) && message.contains(&other));
    assert!(message.contains("cancelled"));
}

#[test]
fn requests_carry_agent_auth_and_explicit_agents() {
    assert_eq!(
        draft_body("dev", "100.64.0.9", 22, "box"),
        json!({"user": "dev", "host": "100.64.0.9", "port": 22, "name": "box", "auth": {"type": "agent"}})
    );
    let rollout = rollout_body("v1", "m1", "e1", &["claude_code".to_owned()]);
    assert_eq!(rollout["auth"], json!({"type": "agent"}));
    assert_eq!(rollout["agents"], json!(["claude_code"]));
    assert_eq!(rollout["timeoutSeconds"], 300);
    let probe = probe_body("m1", "e1");
    assert!(probe.get("skillId").is_none() && probe.get("artifactUrl").is_none());
}

#[test]
fn the_newest_version_and_the_installed_agents_are_picked() {
    let page = json!({"items": [
        {"id": "old", "publishedAt": 1},
        {"id": "new", "publishedAt": 5},
    ]});
    assert_eq!(newest_version(&page).as_deref(), Some("new"));
    assert_eq!(newest_version(&json!({"items": []})), None);
    let snapshot = json!({"data": {"agents": [
        {"key": "claude_code", "installed": true, "enabled": true},
        {"key": "codex", "installed": false, "enabled": true},
        {"key": "cursor", "installed": true, "enabled": false},
        {"key": "gemini", "installed": true},
    ]}});
    assert_eq!(installed_agents(&snapshot), ["claude_code", "gemini"]);
    assert!(installed_agents(&json!({"data": {}})).is_empty());
}

#[test]
fn the_ssh_endpoint_at_this_address_is_chosen() {
    let machine = json!({"endpoints": [
        {"id": "node", "kind": "node", "reference": "n"},
        {"id": "other", "kind": "ssh", "reference": "dev@192.0.2.1:22"},
        {"id": "this", "kind": "ssh", "reference": "dev@100.64.0.9:22"},
    ]});
    assert_eq!(ssh_endpoint_id(&machine, "100.64.0.9", 22).as_deref(), Some("this"));
    assert_eq!(ssh_endpoint_id(&machine, "198.51.100.1", 22).as_deref(), Some("other"));
    assert_eq!(ssh_endpoint_id(&json!({"endpoints": []}), "x", 22), None);
}

#[test]
fn the_summary_names_the_machine_and_the_next_step_on_failure() {
    let summary = json!({
        "machineId": "m1", "name": "box", "endpointId": "e1", "resumed": false,
        "endpoint": {"user": "dev", "host": "100.64.0.9", "port": 22},
        "hostKey": {"fingerprint": "SHA256:h"},
        "controllerKey": {"fingerprint": "SHA256:c", "authorizedKeys": "added"},
        "skills": {"status": "deployed", "agents": ["claude_code", "codex"]},
        "warnings": [],
    });
    let text = render(&summary);
    assert!(text.starts_with("joined machine box (m1)"), "{text}");
    assert!(text.contains("fleet skill deployed to claude_code, codex"));
    let mut failed = summary;
    failed["skills"] = json!({"status": "failed", "reason": "probe failed"});
    assert!(render(&failed).contains("--resume"));
}
