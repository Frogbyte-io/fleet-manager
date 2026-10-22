//! #489: a Windows product key reaches the guest on the SSH session's stdin
//! and nowhere else. A recording fake `ssh` stands in for the real one: it
//! logs its arguments and environment, copies its stdin, and answers like
//! the activation script would. The key must be absent from the arguments
//! and the environment, present once on stdin, and absent from everything
//! the provider returns once the guest's own output has been parsed.
//!
//! Changing `PATH` of a running process is unsafe (and this workspace
//! forbids `unsafe`), so the test body runs in a child process of itself
//! whose `PATH` starts with the fake.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use fleet_core::GuestOs;
use fleet_provider_ssh::persistent::{
    ActivationMethod, parse_activation, windows_activation_script,
};
use fleet_provider_ssh::{
    ExecutionLimiter, PrivateKey, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider,
    execute_script,
};

const PRODUCT_KEY: &str = "AAAAA-BBBBB-CCCCC-DDDDD-EEEEE";
const FAKE_KEY: &str =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfake\n-----END OPENSSH PRIVATE KEY-----";

/// Runs inside the child, where `ssh` is the recording fake.
fn check(root: &std::path::Path) {
    let log = root.join("log");
    let provider = SshProvider::new(root.join("work")).unwrap();
    let spec = SshConnectionSpec {
        host: "192.0.2.10".to_owned(),
        port: 22,
        user: "fleetadmin".to_owned(),
        auth: SshAuth::StoredKey {
            key: PrivateKey::parse(FAKE_KEY).unwrap(),
        },
        guest_os: GuestOs::Windows,
    };
    let script = windows_activation_script(&ActivationMethod::ProductKey(PRODUCT_KEY));
    let result = execute_script(
        &provider,
        &ExecutionLimiter::new(1),
        &spec,
        &script,
        &ScriptMetadata::default(),
        Duration::from_secs(20),
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(0));

    let args = std::fs::read_to_string(log.join("args")).unwrap();
    let env = std::fs::read_to_string(log.join("env")).unwrap();
    let stdin = std::fs::read_to_string(log.join("stdin")).unwrap();
    assert!(!args.contains(PRODUCT_KEY), "the key is on the command line");
    assert!(!env.contains(PRODUCT_KEY), "the key is in the environment");
    // The Windows layer sends the script as one base64 line on stdin.
    use base64::Engine as _;
    let script_line = stdin.lines().nth(1).expect("the script line");
    let sent = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(script_line)
            .expect("base64"),
    )
    .unwrap();
    assert_eq!(
        sent.matches(PRODUCT_KEY).count(),
        1,
        "the key must be in the script on stdin, once"
    );
    assert!(sent.contains("/ipk $k *> $null"));
    // What comes back is the guest's result lines, parsed; no key.
    assert!(!result.stdout.contains(PRODUCT_KEY));
    let report = parse_activation(&result.stdout);
    assert!(report.activated());
    assert_eq!(report.xpr.as_deref(), Some("permanently activated"));
    // The private key file is gone, as ever.
    assert_eq!(
        std::fs::read_dir(root.join("work").join("keys"))
            .unwrap()
            .count(),
        0
    );
}

#[test]
fn the_product_key_travels_on_stdin_only() {
    if let Ok(root) = std::env::var("FLEET_ACTIVATION_CHILD") {
        check(std::path::Path::new(&root));
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let log = root.path().join("log");
    std::fs::create_dir_all(&log).unwrap();
    let fake = bin.join("ssh");
    std::fs::write(
        &fake,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}/args\nenv > {log}/env\ncat > {log}/stdin\nprintf 'FLEET_ATO=ok\\nFLEET_LICENSE_STATUS=1\\nFLEET_XPR=permanently activated\\n'\n",
            log = log.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "the_product_key_travels_on_stdin_only",
            "--nocapture",
        ])
        .env("PATH", path)
        .env("FLEET_ACTIVATION_CHILD", root.path())
        .status()
        .unwrap();
    assert!(status.success(), "the child run failed");
}
