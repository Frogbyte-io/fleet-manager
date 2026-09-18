//! The shared sshd test harness: one running sshd bound to an ephemeral
//! port with its own host key, plus the small helpers every SSH e2e suite
//! needs.
#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

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

    let mut child = Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&sshd_config)
        .spawn()
        .expect("sshd must start");
    let mut came_up = false;
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            came_up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        came_up,
        "sshd never bound its port; it exited with {:?}",
        child.try_wait()
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "sshd exited during startup"
    );
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
