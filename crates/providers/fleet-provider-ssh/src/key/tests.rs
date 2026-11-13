use super::*;

const KEY: &str =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfake\n-----END OPENSSH PRIVATE KEY-----";

#[cfg(unix)]
#[test]
fn a_generated_key_round_trips_and_leaves_no_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    let generated = provider
        .generate_ed25519("fleet@build box")
        .expect("generated");
    assert!(generated.public.starts_with("ssh-ed25519 "));
    assert!(generated.public.ends_with("fleet@buildbox"));
    assert_eq!(
        provider.public_key_of(&generated.private).expect("derived"),
        generated.public
    );
    assert_eq!(
        std::fs::read_dir(provider.key_dir()).expect("dir").count(),
        0,
        "a key file outlived its call"
    );
    let other = provider.generate_ed25519("x").expect("generated");
    assert_ne!(
        other.public.split(' ').nth(1),
        generated.public.split(' ').nth(1)
    );
}

#[test]
fn debug_never_shows_the_key() {
    let key = PrivateKey::parse(KEY).expect("parses");
    assert_eq!(format!("{key:?}"), "PrivateKey([redacted])");
}

#[test]
fn only_a_single_unencrypted_pem_private_key_is_accepted() {
    assert!(PrivateKey::parse(KEY).is_ok());
    assert!(PrivateKey::parse("hunter2").is_err());
    assert!(PrivateKey::parse("ghp_abcdef").is_err());
    assert!(PrivateKey::parse(&format!("{KEY}\n{KEY}")).is_err());
    let encrypted =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----";
    assert!(PrivateKey::parse(encrypted).is_err());
    let legacy = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nAAAA\n-----END RSA PRIVATE KEY-----";
    assert!(PrivateKey::parse(legacy).is_err());
    assert!(PrivateKey::parse(&"A".repeat(MAX_KEY_BYTES + 1)).is_err());
}

#[test]
fn a_parse_error_never_echoes_the_content() {
    let error = PrivateKey::parse("not-a-key-but-secret-looking-hunter2").unwrap_err();
    assert!(!error.contains("hunter2"), "{error}");
}

#[cfg(unix)]
#[test]
fn the_key_file_is_private_and_removed_on_drop() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    let key = PrivateKey::parse(KEY).expect("parses");
    let file = provider.materialize_key(&key).expect("written");
    let path = file.path().to_path_buf();
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let dir_mode = std::fs::metadata(provider.key_dir())
        .expect("stat dir")
        .permissions()
        .mode();
    assert_eq!(dir_mode & 0o777, 0o700);
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .starts_with("-----BEGIN")
    );
    drop(file);
    assert!(!path.exists(), "the key file outlived its guard");
}

/// A real `ssh` that cannot connect (nothing listens on port 1): the key
/// file exists for the session and is gone after the failure.
#[test]
fn a_failed_session_removes_the_key_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    let spec = crate::SshConnectionSpec {
        host: "127.0.0.1".to_owned(),
        port: 1,
        user: "nobody".to_owned(),
        auth: crate::SshAuth::StoredKey {
            key: PrivateKey::parse(KEY).expect("parses"),
        },
        guest_os: fleet_core::GuestOs::Linux,
    };
    let limiter = crate::ExecutionLimiter::new(1);
    let _ = crate::execute_script(
        &provider,
        &limiter,
        &spec,
        "true",
        &crate::ScriptMetadata::default(),
        std::time::Duration::from_secs(10),
    );
    // ssh exits 255 on a refused connection; whether that surfaces as an
    // error or a result, no key file may remain.
    assert_eq!(
        std::fs::read_dir(provider.key_dir()).expect("dir").count(),
        0,
        "a failed session left its key file"
    );
    // test_connect cleans up too.
    let _ = provider.test_connect(&spec, std::time::Duration::from_secs(2));
    assert_eq!(
        std::fs::read_dir(provider.key_dir()).expect("dir").count(),
        0
    );
}

#[test]
fn the_start_sweep_removes_this_processs_leftovers_and_keeps_another_processs_live_keys() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = dir.path().join(KEY_DIR);
    std::fs::create_dir_all(&keys).expect("dir");
    let leftover = keys.join(format!("key-{}-0", std::process::id()));
    let other_live = keys.join("key-1-0");
    std::fs::write(&leftover, "left behind").expect("seed");
    std::fs::write(&other_live, "another process's session").expect("seed");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    assert!(!leftover.exists(), "this process's leftover survived");
    assert!(other_live.exists(), "another process's live key was swept");
    let mine = provider
        .materialize_key(&PrivateKey::parse(KEY).expect("parses"))
        .expect("written");
    let _second = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    assert!(mine.path().exists(), "a live session's key was swept");
}

#[test]
fn an_identity_file_in_the_provider_key_directory_is_refused_before_ssh_starts() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    let inside = provider.key_dir().join("key-9-9");
    assert!(
        provider
            .check_identity_file(&inside.display().to_string())
            .is_err()
    );
    let spec = crate::SshConnectionSpec {
        host: "127.0.0.1".to_owned(),
        port: 1,
        user: "nobody".to_owned(),
        auth: crate::SshAuth::IdentityFile {
            path: inside.display().to_string(),
        },
        guest_os: fleet_core::GuestOs::Linux,
    };
    assert!(
        provider
            .test_connect(&spec, std::time::Duration::from_secs(1))
            .is_err()
    );
    // The user's own key elsewhere, and the sibling known_hosts area, pass.
    let home_key = dir.path().join(".ssh").join("id_ed25519");
    assert!(
        provider
            .check_identity_file(&home_key.display().to_string())
            .is_ok()
    );
}

#[test]
fn materializing_a_key_sweeps_stale_key_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    let stale = provider.key_dir().join("key-1-1");
    std::fs::write(&stale, "old").expect("seed");
    let old = std::time::SystemTime::now() - std::time::Duration::from_hours(8);
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .expect("open")
        .set_modified(old)
        .expect("mtime");
    let _fresh = provider
        .materialize_key(&PrivateKey::parse(KEY).expect("parses"))
        .expect("written");
    assert!(!stale.exists(), "a stale key survived a new session");
}

#[test]
fn the_stored_key_config_offers_no_agent_and_no_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let provider = SshProvider::new(dir.path().to_path_buf()).expect("provider");
    let auth = crate::SshAuth::StoredKey {
        key: PrivateKey::parse(KEY).expect("parses"),
    };
    let config = provider.write_config(&auth).expect("config");
    let text = std::fs::read_to_string(config).expect("text");
    for line in [
        "IdentitiesOnly yes",
        "IdentityAgent none",
        "CertificateFile none",
    ] {
        assert!(text.contains(line), "{line} missing: {text}");
    }
}
