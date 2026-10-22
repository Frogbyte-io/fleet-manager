//! A Fleet-held private key, delivered to `ssh` for one session (ADR 0017).
//!
//! The key arrives as text from the encrypted secret store. This module never
//! logs or prints it: [`PrivateKey`]'s `Debug` is redacted, errors name the
//! problem and never the content, and the only place the bytes touch disk is
//! a mode-0600 file in a mode-0700 directory under the provider's work
//! directory. [`KeyFile`] removes that file when it drops, which covers the
//! success, failure, deadline-kill and cancellation paths alike (every one
//! drops the session that owns it; the owner-only modes are Unix modes, so key
//! files are supported on a Linux (Unix) controller only), and [`SshProvider::new`](crate::SshProvider::new)
//! removes what a crashed process left behind.

use std::io::Write as _;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::Child;

use crate::{SshProvider, SshProviderError};

/// The directory under the provider's work directory that holds key files.
pub(crate) const KEY_DIR: &str = "keys";
/// The largest private key accepted (a 16 KiB PEM is far beyond any real key).
pub const MAX_KEY_BYTES: usize = 16 * 1024;
/// A key file older than this belongs to no live session (the longest runs
/// six hours) and is removed at start.
const STALE_KEY_AGE: std::time::Duration = std::time::Duration::from_hours(7);

/// A private key in OpenSSH, PKCS#8 or PEM form, as plain unencrypted text.
#[derive(Clone, Eq, PartialEq)]
pub struct PrivateKey(String);

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateKey([redacted])")
    }
}

impl PrivateKey {
    /// Accepts a PEM-armored private key. A passphrase-protected key is
    /// refused: the session is non-interactive and there is nobody to ask.
    ///
    /// # Errors
    ///
    /// Fails, without echoing the content, when the text is not a single
    /// PEM private-key block, is too large, or is encrypted.
    pub fn parse(text: &str) -> Result<Self, String> {
        let trimmed = text.trim();
        if trimmed.len() > MAX_KEY_BYTES {
            return Err(format!("the key is larger than {MAX_KEY_BYTES} bytes"));
        }
        let first = trimmed.lines().next().unwrap_or("").trim();
        let last = trimmed.lines().next_back().unwrap_or("").trim();
        let begins = first.starts_with("-----BEGIN ") && first.ends_with("PRIVATE KEY-----");
        let ends = last.starts_with("-----END ") && last.ends_with("PRIVATE KEY-----");
        if !begins || !ends {
            return Err("the secret is not a PEM private key".to_owned());
        }
        if trimmed.matches("-----BEGIN ").count() != 1 {
            return Err("the secret must hold exactly one private key".to_owned());
        }
        if first.contains("ENCRYPTED") || trimmed.contains("ENCRYPTED") {
            return Err("the key is passphrase-protected; Fleet cannot prompt for it".to_owned());
        }
        // OpenSSH rejects a key file without a final newline.
        Ok(Self(format!("{trimmed}\n")))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

/// A key file that exists for one session and is removed when dropped.
#[derive(Debug)]
pub(crate) struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        // Best effort: a file that cannot be removed is reclaimed by the
        // next provider start, and its directory is owner-only meanwhile.
        let _ = std::fs::remove_file(&self.path);
    }
}

impl SshProvider {
    /// The owner-only directory holding session key files.
    pub(crate) fn key_dir(&self) -> PathBuf {
        self.work_dir.join(KEY_DIR)
    }

    /// Prepares the key directory and removes key files a previous run left
    /// (a crash between writing a key and dropping its guard).
    pub(crate) fn sweep_keys(&self) -> Result<(), SshProviderError> {
        // The directories swept so far in this process.
        static SWEPT: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());
        let dir = self.key_dir();
        std::fs::create_dir_all(&dir).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot create {}: {error}", dir.display()),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(
                |error| SshProviderError::Setup {
                    detail: format!("cannot secure {}: {error}", dir.display()),
                },
            )?;
        }
        // Once per directory and process: later providers over the same
        // directory (the controller builds several) must not remove a key
        // another provider's live session is using.
        let first = {
            let mut swept = SWEPT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if swept.contains(&dir) {
                false
            } else {
                swept.push(dir.clone());
                true
            }
        };
        if first && let Ok(entries) = std::fs::read_dir(&dir) {
            // Only what this process wrote, or what outlived any session
            // (the longest is a six-hour put): another process sharing the
            // directory keeps its live keys.
            let own = format!("key-{}-", std::process::id());
            for entry in entries.flatten() {
                let ours = entry.file_name().to_string_lossy().starts_with(&own);
                let stale = entry
                    .metadata()
                    .and_then(|meta| meta.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age >= STALE_KEY_AGE);
                if ours || stale {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        Ok(())
    }

    /// Writes `key` to a fresh 0600 file for one session.
    pub(crate) fn materialize_key(&self, key: &PrivateKey) -> Result<KeyFile, SshProviderError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = self.key_dir();
        std::fs::create_dir_all(&dir).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot create {}: {error}", dir.display()),
        })?;
        let path = dir.join(format!(
            "key-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|error| SshProviderError::Setup {
                detail: format!("cannot create a session key file: {error}"),
            })?;
        // From here the guard owns the path: any failure below removes it.
        let guard = KeyFile { path };
        file.write_all(key.expose().as_bytes())
            .and_then(|()| file.flush())
            .map_err(|error| SshProviderError::Setup {
                detail: format!("cannot write the session key file: {error}"),
            })?;
        Ok(guard)
    }
}

/// A started `ssh` process and the key file it was started with. Dropping it
/// removes the key file; the process is reaped by its owner as before.
#[derive(Debug)]
pub(crate) struct SshChild {
    child: Child,
    _key: Option<KeyFile>,
}

impl SshChild {
    pub(crate) fn new(child: Child, key: Option<KeyFile>) -> Self {
        Self { child, _key: key }
    }
}

impl Deref for SshChild {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for SshChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfake\n-----END OPENSSH PRIVATE KEY-----";

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
}
