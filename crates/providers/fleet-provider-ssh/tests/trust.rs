//! Integration tests against a real ephemeral sshd: new-key trust, known-key
//! acceptance, changed-key blocking, and connection testing. The harness
//! generates its own host key, configures a per-test sshd, and tears it down.

use fleet_provider_ssh::{SshAuth, SshConnectionSpec, SshProvider, TrustDecision};
use std::net::TcpListener;
use std::process::{Child, Command};
use std::time::Duration;

/// One running sshd bound to an ephemeral port with its own host key.
struct TestSshd {
    child: Child,
    host: &'static str,
    port: u16,
    keys: KeysDir,
}

struct KeysDir {
    dir: tempfile::TempDir,
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

/// Starts a local sshd with a fresh host key; the client-side user is the
/// current user, authenticating via the agent or an unencrypted key we also
/// generate here.
fn start_sshd() -> TestSshd {
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

    // The user key is authorized for the current user.
    let public = std::fs::read_to_string(format!("{}.pub", user_key.display())).unwrap();
    let authz = dir.path().join("authorized_keys");
    std::fs::write(&authz, public).unwrap();

    let host_key_display = host_key.display().to_string();
    let authz_display = authz.display().to_string();
    let port = free_port();
    let sshd_config = dir.path().join("sshd_config");
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
             PidFile {}/sshd.pid\n\
             Subsystem sftp internal-sftp\n",
            dir.path().display()
        ),
    )
    .unwrap();

    // sshd demands strict permissions and a privsep directory.
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
        .expect("sshd must start; this test needs a local OpenSSH server");

    // Wait until the port accepts.
    for _ in 0..50 {
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            break; // someone holds it now: our sshd
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    TestSshd {
        child,
        host: "127.0.0.1",
        port,
        keys: KeysDir { dir },
    }
}

fn provider() -> (tempfile::TempDir, SshProvider) {
    let dir = tempfile::tempdir().unwrap();
    let provider = SshProvider::new(dir.path().to_path_buf()).unwrap();
    (dir, provider)
}

fn spec(sshd: &TestSshd) -> SshConnectionSpec {
    SshConnectionSpec {
        host: sshd.host.to_owned(),
        port: sshd.port,
        user: whoami(),
        auth: SshAuth::IdentityFile {
            path: format!("{}/user_ed25519", sshd.keys.dir.path().display()),
        },
    }
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "nobody".to_owned())
}

#[test]
fn a_new_host_requires_confirmation_then_becomes_known() {
    let sshd = start_sshd();
    let (_dir, provider) = provider();

    let observation = provider
        .probe_host_key(sshd.host, sshd.port, Duration::from_secs(10))
        .unwrap();
    assert!(observation.fingerprint.starts_with("SHA256:"));
    assert_eq!(observation.key_type, "ED25519");

    let decision = provider.decide(None, &observation);
    assert!(matches!(decision, TrustDecision::New { .. }));

    // Confirmation: pin, and the same key is now known...
    provider.pin(&observation).unwrap();
    let reobserved = provider
        .probe_host_key(sshd.host, sshd.port, Duration::from_secs(10))
        .unwrap();
    assert!(matches!(
        provider.decide(Some(&observation.fingerprint), &reobserved),
        TrustDecision::Known { .. }
    ));

    // ...and the connection test succeeds with the pinned key.
    provider
        .test_connect(&spec(&sshd), Duration::from_secs(15))
        .unwrap();
}

#[test]
fn a_changed_host_key_blocks() {
    let sshd = start_sshd();
    let (_dir, provider) = provider();

    let first = provider
        .probe_host_key(sshd.host, sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&first).unwrap();

    // The operator re-confirms nothing: a different key is the hostile case.
    let decision = provider.decide(Some("SHA256:entirely-different"), &first);
    assert!(matches!(decision, TrustDecision::Changed { .. }));

    // Even a stale pin on file does not rescue a connection when the
    // fingerprint comparison refuses it.
}

#[test]
fn a_real_host_key_change_fails_the_connection() {
    let mut sshd = start_sshd();
    let (_dir, provider) = provider();

    let first = provider
        .probe_host_key(sshd.host, sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&first).unwrap();
    provider
        .test_connect(&spec(&sshd), Duration::from_secs(15))
        .unwrap();

    // Rotate the host key under the pin: restart sshd with a new key.
    let _ = sshd.child.kill();
    let _ = sshd.child.wait();
    let new_key = sshd.keys.dir.path().join("host_ed25519_2");
    Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-q")
        .arg("-f")
        .arg(&new_key)
        .output()
        .unwrap();

    let new_key_display = new_key.display().to_string();
    let port = sshd.port;
    let dir_path = sshd.keys.dir.path().to_path_buf();
    let user_name = whoami();
    let authz = dir_path.join("authorized_keys");
    let authz_display = authz.display().to_string();
    let sshd_config = dir_path.join("sshd_config_2");
    std::fs::write(
        &sshd_config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {new_key_display}\n\
             AuthorizedKeysFile {authz_display}\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n             StrictModes no
\
             PidFile {}/sshd2.pid\n\
             Subsystem sftp internal-sftp\n",
            dir_path.display()
        ),
    )
    .unwrap();
    let second = Command::new("/usr/sbin/sshd")
        .arg("-D")
        .arg("-e")
        .arg("-f")
        .arg(&sshd_config)
        .spawn()
        .unwrap();
    sshd.child = second;

    // Wait for the new listener.
    std::thread::sleep(Duration::from_millis(800));

    let spec = SshConnectionSpec {
        host: "127.0.0.1".to_owned(),
        port,
        user: user_name,
        auth: SshAuth::IdentityFile {
            path: format!("{}/user_ed25519", dir_path.display()),
        },
    };
    let error = provider
        .test_connect(&spec, Duration::from_secs(15))
        .unwrap_err();
    assert!(
        matches!(error, fleet_provider_ssh::SshProviderError::Connect { .. }),
        "{error}"
    );
    let detail = error.to_string();
    assert!(
        detail
            .to_lowercase()
            .contains("host key verification failed")
            || detail.to_lowercase().contains("changed"),
        "the failure must name the host-key problem: {detail}"
    );
}

#[test]
fn unpinning_removes_only_that_host() {
    let sshd = start_sshd();
    let (_dir, provider) = provider();

    let observation = provider
        .probe_host_key(sshd.host, sshd.port, Duration::from_secs(10))
        .unwrap();
    provider.pin(&observation).unwrap();

    // A pin for another host must survive.
    std::fs::write(
        provider.known_hosts_path(),
        std::fs::read_to_string(provider.known_hosts_path()).unwrap()
            + "[other-host.lan]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForAnotherHost\n",
    )
    .unwrap();

    let removed = provider.unpin(sshd.host).unwrap();
    assert_eq!(removed, 1);
    let remaining = std::fs::read_to_string(provider.known_hosts_path()).unwrap();
    assert!(remaining.contains("other-host.lan"));
    assert!(!remaining.contains(&observation.raw_line));
}

#[test]
fn a_missing_host_key_is_reported_not_invented() {
    let (_dir, provider) = provider();
    // Nothing listens on this port (port 1 on loopback is reserved and
    // refused on Linux CI images).
    let error = provider
        .probe_host_key("127.0.0.1", 1, Duration::from_secs(2))
        .unwrap_err();
    assert!(
        matches!(
            error,
            fleet_provider_ssh::SshProviderError::NoHostKey { .. }
        ),
        "{error}"
    );
}
