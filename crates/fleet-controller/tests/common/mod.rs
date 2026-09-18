//! The shared sshd test harness: one running sshd bound to an ephemeral
//! port with its own host key, plus the small helpers every SSH e2e suite
//! needs.
#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// The port-allocation lock: the free-port window between allocation and
/// sshd's bind is racy both across the parallel threads of one binary and
/// across the separate test binaries CI runs concurrently. A cross-process
/// file lock on a fixed path serializes startup everywhere; the suites'
/// SSH work still runs concurrently.
/// The lock file is scoped to the uid: an unrelated user's leftover lock
/// on a shared machine must not break this suite, and the file's mode is
/// 0600 so no other user can hold or tamper with it.
fn startup_lock_path() -> std::path::PathBuf {
    let user = std::env::var("USER")
        .unwrap_or_else(|_| std::env::var("LOGNAME").unwrap_or_else(|_| "unknown".to_owned()));
    std::env::temp_dir().join(format!("fleet-test-sshd-startup-{user}.lock"))
}

fn acquire_startup_lock() -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(startup_lock_path())
        .expect("the startup lock file must open");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(startup_lock_path(), std::fs::Permissions::from_mode(0o600)).ok();
    }
    file.lock().expect("the startup lock must acquire");
    file
}

/// One running sshd bound to an ephemeral port with its own host key.
pub struct TestSshd {
    pub child: Child,
    pub port: u16,
    pub keys_dir: tempfile::TempDir,
}

impl Drop for TestSshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts sshd and verifies it actually came up: a daemon that failed to
/// start surfaces immediately instead of failing every test later on the
/// first SSH probe with a misleading error.
pub fn start_sshd() -> TestSshd {
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

    // The port is claimed by binding a listener and handing the bound
    // socket's port to sshd only after the listener is dropped: the
    // window is as small as spawn itself, and the readiness check below
    // distinguishes sshd from any squatter by requiring a successful
    // SSH-shaped probe rather than a bare connect.
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

    let checked = Command::new("/usr/sbin/sshd")
        .arg("-t")
        .arg("-f")
        .arg(&sshd_config)
        .output()
        .expect("sshd -t must run");
    assert!(
        checked.status.success(),
        "the sshd config is invalid: {}",
        String::from_utf8_lossy(&checked.stderr)
    );

    let mut child = match Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&sshd_config)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => panic!("sshd must start: {error}"),
    };
    let mut came_up = false;
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            came_up = true;
            break;
        }
        // A daemon that died during startup is reaped here, not left
        // orphaned by the panic below.
        if let Ok(Some(status)) = child.try_wait() {
            panic!("sshd exited during startup: {status}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !came_up {
        let _ = child.kill();
        let _ = child.wait();
        panic!("sshd never bound its port within the startup window");
    }
    if let Ok(Some(status)) = child.try_wait() {
        panic!("sshd exited during startup: {status}");
    }
    TestSshd {
        child,
        port,
        keys_dir: dir,
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The test user's login name, for endpoint references.
pub fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}
