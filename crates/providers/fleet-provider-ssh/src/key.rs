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

    /// The key text, for handing to the encrypted secret store and nowhere
    /// else. Callers must never log, return or serialize it.
    #[must_use]
    pub fn expose_for_store(&self) -> &str {
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

    /// Refuses an identity file inside this provider's own key directory:
    /// it holds other sessions' stored keys. Every SSH-driven kind passes
    /// through here before `ssh` starts.
    pub(crate) fn check_identity_file(&self, path: &str) -> Result<(), SshProviderError> {
        let given = Path::new(path);
        let keys = self.key_dir();
        let keys = std::fs::canonicalize(&keys).unwrap_or(keys);
        let resolved = std::fs::canonicalize(given).unwrap_or_else(|_| given.to_path_buf());
        if resolved.starts_with(&keys)
            || given.starts_with(&keys)
            || given
                .components()
                .any(|c| c == std::path::Component::ParentDir)
        {
            return Err(SshProviderError::Setup {
                detail: "the identity file is inside the SSH provider's own key directory"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Removes key files older than any session (bounded: one directory read).
    fn sweep_stale_keys(&self) {
        let Ok(entries) = std::fs::read_dir(self.key_dir()) else {
            return;
        };
        for entry in entries.flatten().take(1024) {
            let stale = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= STALE_KEY_AGE);
            if stale {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    /// Writes `key` to a fresh 0600 file for one session.
    pub(crate) fn materialize_key(&self, key: &PrivateKey) -> Result<KeyFile, SshProviderError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = self.key_dir();
        std::fs::create_dir_all(&dir).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot create {}: {error}", dir.display()),
        })?;
        self.sweep_stale_keys();
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

/// A freshly generated key pair: the private half as a [`PrivateKey`]
/// (redacted `Debug`) and the public half as one OpenSSH line.
#[derive(Clone, Debug)]
pub struct GeneratedKey {
    /// The private key, to be stored in the secret store and nowhere else.
    pub private: PrivateKey,
    /// The public key line (`ssh-ed25519 AAAA... comment`).
    pub public: String,
}

/// Removes a generated key's files when dropped, whatever path returns.
struct GeneratedFiles(PathBuf);

impl Drop for GeneratedFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let mut public = self.0.clone().into_os_string();
        public.push(".pub");
        let _ = std::fs::remove_file(PathBuf::from(public));
    }
}

impl SshProvider {
    /// Generates an unencrypted ed25519 key pair with `ssh-keygen` inside
    /// the private key directory. The files are removed before this
    /// returns, on every path.
    ///
    /// # Errors
    ///
    /// Fails, without any key text, when `ssh-keygen` is missing or fails.
    pub fn generate_ed25519(&self, comment: &str) -> Result<GeneratedKey, SshProviderError> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = self.key_dir();
        std::fs::create_dir_all(&dir).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot create {}: {error}", dir.display()),
        })?;
        let comment: String = comment
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-'))
            .take(64)
            .collect();
        let path = dir.join(format!(
            "gen-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _files = GeneratedFiles(path.clone());
        let output = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &comment, "-f"])
            .arg(&path)
            .output()
            .map_err(|error| SshProviderError::Tool {
                tool: "ssh-keygen",
                detail: format!("cannot run ssh-keygen: {error}"),
            })?;
        if !output.status.success() {
            return Err(SshProviderError::Tool {
                tool: "ssh-keygen",
                detail: "ssh-keygen could not generate a key".to_owned(),
            });
        }
        let private = std::fs::read_to_string(&path).map_err(|error| SshProviderError::Setup {
            detail: format!("cannot read the generated key: {error}"),
        })?;
        let mut public_path = path.clone().into_os_string();
        public_path.push(".pub");
        let public = std::fs::read_to_string(PathBuf::from(public_path))
            .map_err(|error| SshProviderError::Setup {
                detail: format!("cannot read the generated public key: {error}"),
            })?
            .trim()
            .to_owned();
        Ok(GeneratedKey {
            private: PrivateKey::parse(&private)
                .map_err(|detail| SshProviderError::Setup { detail })?,
            public,
        })
    }

    /// The public key line of a private key (`ssh-keygen -y`).
    ///
    /// # Errors
    ///
    /// Fails, without key text, when the key is unusable.
    pub fn public_key_of(&self, key: &PrivateKey) -> Result<String, SshProviderError> {
        let file = self.materialize_key(key)?;
        let output = std::process::Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(file.path())
            .output()
            .map_err(|error| SshProviderError::Tool {
                tool: "ssh-keygen",
                detail: format!("cannot run ssh-keygen: {error}"),
            })?;
        if !output.status.success() {
            return Err(SshProviderError::Tool {
                tool: "ssh-keygen",
                detail: "the key is not a usable private key".to_owned(),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
mod tests;
