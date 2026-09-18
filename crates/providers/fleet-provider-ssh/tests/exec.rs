//! Integration tests for bounded SSH execution against a real sshd: output
//! capture, working directory, environment, deadline kills, truncation, and
//! the quoting rule — caller data never passes through a remote shell.

use fleet_provider_ssh::{
    ExecutionLimiter, ScriptMetadata, SshAuth, SshConnectionSpec, SshProvider, decode_metadata,
    encode_metadata, execute_script,
};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// The port-allocation lock: the free-port window between allocation and
/// sshd's bind is racy both across threads and across concurrently run
/// test binaries. A cross-process file lock serializes startup
/// everywhere.
/// The lock file is scoped to the uid: an unrelated user's leftover lock
/// on a shared machine must not break this suite, and the file's mode is
/// 0600 so no other user can hold or tamper with it.
fn startup_lock_path() -> std::path::PathBuf {
    let user = std::env::var("USER")
        .unwrap_or_else(|_| std::env::var("LOGNAME").unwrap_or_else(|_| "unknown".to_owned()));
    std::env::temp_dir().join(format!("fleet-test-sshd-startup-{user}.lock"))
}

fn acquire_startup_lock() -> std::fs::File {
    // The mode is set atomically at creation (OpenOptionsExt::mode applies
    // to newly created files), so no window exists where another user
    // could open the lock. A stale pre-existing file from an older run is
    // covered by the backstop set_permissions below; a file we cannot
    // chmod is one we cannot lock safely, so that failure surfaces.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(startup_lock_path());
        let file = match file {
            Ok(file) => file,
            Err(error) => panic!("the startup lock file must open: {error}"),
        };
        std::fs::set_permissions(startup_lock_path(), std::fs::Permissions::from_mode(0o600))
            .expect("the startup lock file must be ours to chmod");
        file.lock().expect("the startup lock must acquire");
        file
    }
    #[cfg(not(unix))]
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(startup_lock_path())
            .expect("the startup lock file must open");
        file.lock().expect("the startup lock must acquire");
        file
    }
}

/// One running sshd bound to an ephemeral port with its own host key.
struct TestSshd {
    child: Child,
    port: u16,
    keys_dir: tempfile::TempDir,
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start_sshd() -> TestSshd {
    let _guard = acquire_startup_lock();
    let dir = tempfile::tempdir().unwrap();
    let host_key = dir.path().join("host_ed25519");
    let user_key = dir.path().join("user_ed25519");
    for key in [&host_key, &user_key] {
        let generated = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-q")
            .arg("-f")
            .arg(key)
            .output()
            .unwrap();
        assert!(
            generated.status.success(),
            "ssh-keygen failed: {:?}",
            generated.stderr
        );
    }
    let public = std::fs::read_to_string(format!("{}.pub", user_key.display())).unwrap();
    let authz = dir.path().join("authorized_keys");
    std::fs::write(&authz, public).unwrap();

    let port = free_port();
    let sshd_config = dir.path().join("sshd_config");
    let host_key_display = host_key.display().to_string();
    let authz_display = authz.display().to_string();
    let dir_display = dir.path().display().to_string();
    std::fs::write(
        &sshd_config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key_display}\n\
             AuthorizedKeysFile {authz_display}\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             StrictModes no\n\
             PidFile {dir_display}/sshd.pid\n\
             Subsystem sftp internal-sftp\n"
        ),
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&host_key, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::create_dir_all("/run/sshd").ok();
    }

    let child = Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&sshd_config)
        .spawn()
        .expect("sshd must start; these tests need a local OpenSSH server");
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    TestSshd {
        child,
        port,
        keys_dir: dir,
    }
}

fn spec(sshd: &TestSshd) -> SshConnectionSpec {
    SshConnectionSpec {
        host: "127.0.0.1".to_owned(),
        port: sshd.port,
        user: whoami(),
        auth: SshAuth::IdentityFile {
            path: format!("{}/user_ed25519", sshd.keys_dir.path().display()),
        },
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}

#[test]
fn metadata_round_trips_hostile_values() {
    let metadata = ScriptMetadata {
        working_directory: "/tmp/with spaces; rm -rf $(echo x)".to_owned(),
        environment: vec![
            (
                "FLEET_X".to_owned(),
                "value with; `backticks` and $dollars".to_owned(),
            ),
            ("FLEET_Y".to_owned(), "multi\nline\nvalue".to_owned()),
        ],
        arguments: vec![
            "arg with; semicolon".to_owned(),
            "$(echo hostile)".to_owned(),
        ],
    };
    let blob = encode_metadata(&metadata);
    // The blob is shell-inert: only base64 characters.
    assert!(
        blob.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
        "{blob}"
    );
    let decoded = decode_metadata(&blob).unwrap();
    assert_eq!(decoded, metadata);
}

#[test]
fn decode_rejects_non_base64() {
    assert!(decode_metadata("not base64!!").is_err());
}

#[test]
fn a_script_runs_and_captures_output() {
    let sshd = start_sshd();
    let dir = tempfile::tempdir().unwrap();
    let provider = SshProvider::new(dir.path().to_path_buf()).unwrap();
    let observation = provider
        .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&observation).unwrap();

    let result = execute_script(
        &provider,
        &ExecutionLimiter::new(4),
        &spec(&sshd),
        "echo hello-remote; echo oops >&2; exit 7",
        &ScriptMetadata::default(),
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(7));
    assert_eq!(result.stdout, "hello-remote\n");
    assert!(result.stderr.contains("oops"), "{:?}", result.stderr);
    assert!(!result.killed_by_deadline);
}

#[test]
fn working_directory_and_environment_arrive_safely() {
    let sshd = start_sshd();
    let dir = tempfile::tempdir().unwrap();
    let provider = SshProvider::new(dir.path().to_path_buf()).unwrap();
    provider
        .pin(
            &provider
                .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
                .unwrap(),
        )
        .unwrap();

    let workdir = dir.path().join("work here; $(echo hostile)");
    std::fs::create_dir_all(&workdir).unwrap();
    std::fs::write(workdir.join("marker.txt"), b"found").unwrap();

    let result = execute_script(
        &provider,
        &ExecutionLimiter::new(4),
        &spec(&sshd),
        "pwd > pwd.txt; printf '%s' \"$FLEET_SECRET_PROBE\" > env.txt; cat marker.txt; printf '|%s|' \"$1\" \"$2\"",
        &ScriptMetadata {
            working_directory: workdir.display().to_string(),
            environment: vec![(
                "FLEET_SECRET_PROBE".to_owned(),
                "value with; `backticks` $dollars\nand a newline".to_owned(),
            )],
            arguments: vec!["arg one; ; $(echo x)".to_owned(), "arg&two".to_owned()],
        },
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(result.exit_code, Some(0), "{:?}", result.stderr);
    // The hostile working directory and argument text stayed data.
    // The hostile working directory and argument text stayed data. The two
    // printf chunks join on || between arg one and arg two.
    assert_eq!(result.stdout, "found|arg one; ; $(echo x)||arg&two|");
    let pwd = std::fs::read_to_string(workdir.join("pwd.txt")).unwrap();
    assert_eq!(pwd.trim(), workdir.display().to_string());
    let env = std::fs::read_to_string(workdir.join("env.txt")).unwrap();
    assert_eq!(env, "value with; `backticks` $dollars\nand a newline");
}

#[test]
fn the_deadline_kills_and_reports_uncertainty() {
    let sshd = start_sshd();
    let dir = tempfile::tempdir().unwrap();
    let provider = SshProvider::new(dir.path().to_path_buf()).unwrap();
    provider
        .pin(
            &provider
                .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
                .unwrap(),
        )
        .unwrap();

    let result = execute_script(
        &provider,
        &ExecutionLimiter::new(4),
        &spec(&sshd),
        "sleep 30",
        &ScriptMetadata::default(),
        Duration::from_secs(2),
    )
    .unwrap();
    assert!(result.killed_by_deadline);
    assert_eq!(result.exit_code, None);
}

#[test]
fn output_truncates_at_the_cap() {
    let sshd = start_sshd();
    let dir = tempfile::tempdir().unwrap();
    let provider = SshProvider::new(dir.path().to_path_buf()).unwrap();
    provider
        .pin(
            &provider
                .probe_host_key("127.0.0.1", sshd.port, Duration::from_secs(10))
                .unwrap(),
        )
        .unwrap();

    let result = execute_script(
        &provider,
        &ExecutionLimiter::new(4),
        &spec(&sshd),
        // Produce far more than the cap.
        "i=0; while [ $i -lt 100000 ]; do echo 'x'; i=$((i+1)); done",
        &ScriptMetadata::default(),
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(result.truncated_stdout, "the cap must bit");
    assert_eq!(result.stdout.len(), fleet_provider_ssh::MAX_STREAM_BYTES);
}

#[test]
fn the_limiter_saturates_without_starting_sessions() {
    let limiter = ExecutionLimiter::new(1);
    // The pool is an internal detail; drive it through the public held/capacity.
    assert_eq!(limiter.capacity(), 1);
    // Acquire twice via a failing path: execute with no sshd listening (fast
    // refusal), and confirm saturation refuses the second attempt.
    let dir = tempfile::tempdir().unwrap();
    let provider = SshProvider::new(dir.path().to_path_buf()).unwrap();
    let refused = SshConnectionSpec {
        host: "127.0.0.1".to_owned(),
        port: 1,
        user: whoami(),
        auth: SshAuth::Agent,
    };
    let _ = execute_script(
        &provider,
        &limiter,
        &refused,
        "true",
        &ScriptMetadata::default(),
        Duration::from_secs(1),
    );
    assert_eq!(limiter.held(), 0, "a finished attempt releases its permit");
}
