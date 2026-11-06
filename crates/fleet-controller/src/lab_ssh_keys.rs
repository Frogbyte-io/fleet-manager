//! The controller's SSH public keys, for Lab clones that must be logged in to
//! without a key baked into the image (#561).
//!
//! Two sources:
//!
//! - **Explicit** (`FLEET_LAB_LOGIN_PUBLIC_KEY_FILE`): the key(s) in that
//!   `.pub` file are installed and nothing else. Recommended.
//! - **Discovery** (the setting unset): the public halves of what the
//!   controller authenticates with, the same set OpenSSH offers: the keys its
//!   ssh-agent holds (`ssh-add -L`), then `$HOME/.ssh/id_*.pub`. Every one of
//!   them becomes authorized on a Windows guest, so more than [`MAX_KEYS`] is
//!   refused rather than truncated.
//!
//! Nothing private is read. Comments are dropped, so a hostname or user in a
//! key comment never reaches PVE, the audit log or the startup log.
//! `$HOME` is used, not the passwd entry (the workspace has no passwd
//! lookup); a service whose `$HOME` differs from the user's home should set
//! the explicit key file.

use base64::Engine as _;
use sha2::Digest as _;
use std::path::PathBuf;
use std::time::Duration;

/// At most this many keys are installed: the guest's `sshd` limits attempts
/// (`MaxAuthTries`), and Lab needs one. More is refused, never truncated.
pub const MAX_KEYS: usize = 4;
/// The bound on key text that is read from a process or a file.
const MAX_OUTPUT: usize = 64 * 1024;
const AGENT_TIMEOUT: Duration = Duration::from_secs(5);
/// The default public key files OpenSSH tries, in its order.
const DEFAULT_KEY_FILES: [&str; 6] = [
    "id_rsa.pub",
    "id_ecdsa.pub",
    "id_ecdsa_sk.pub",
    "id_ed25519.pub",
    "id_ed25519_sk.pub",
    "id_dsa.pub",
];

/// Why the keys could not be provided; both parts are secret-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySourceError {
    /// The classified reason the provision fails with.
    pub reason: &'static str,
    /// What to tell the operator.
    pub detail: String,
}

/// Where Lab gets the public keys to install in a clone.
#[async_trait::async_trait]
pub trait LabKeySource: Send + Sync + std::fmt::Debug {
    /// The public keys, each a `type base64` line without a comment: at
    /// least one and at most [`MAX_KEYS`].
    ///
    /// # Errors
    /// `no_ssh_key`, `too_many_ssh_keys`, or an unreadable explicit file.
    async fn public_keys(&self) -> Result<Vec<String>, KeySourceError>;
}

/// The explicit key file when configured, else the controller user's agent
/// keys and default public key files.
#[derive(Debug, Default)]
pub struct ControllerKeys {
    explicit: Option<PathBuf>,
}

impl ControllerKeys {
    /// A source for the configured key file, or discovery when `None`.
    #[must_use]
    pub fn new(explicit: Option<PathBuf>) -> Self {
        Self { explicit }
    }

    /// The keys that would be installed, for the startup log: how many, and
    /// their SHA256 fingerprints. Never the keys. Errors are reported as
    /// their detail.
    pub async fn describe(&self) -> String {
        let source = match &self.explicit {
            Some(path) => format!("the key file {}", path.display()),
            None => "discovery (ssh-agent and default .pub files)".to_owned(),
        };
        match self.public_keys().await {
            Ok(keys) => format!(
                "Lab login keys for Windows clones from {source}: {} key(s) [{}]",
                keys.len(),
                keys.iter()
                    .map(|key| fingerprint(key))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Err(error) => format!(
                "Lab login keys for Windows clones from {source}: none usable ({}: {})",
                error.reason, error.detail
            ),
        }
    }
}

#[async_trait::async_trait]
impl LabKeySource for ControllerKeys {
    async fn public_keys(&self) -> Result<Vec<String>, KeySourceError> {
        let keys = match &self.explicit {
            Some(path) => {
                let text = read_bounded(path).await.map_err(|detail| KeySourceError {
                    reason: "no_ssh_key",
                    detail: format!(
                        "the Lab login public key file {} is unreadable: {detail}",
                        path.display()
                    ),
                })?;
                let keys = normalize_public_keys(&text);
                if keys.is_empty() {
                    return Err(KeySourceError {
                        reason: "no_ssh_key",
                        detail: format!(
                            "the Lab login public key file {} holds no public key",
                            path.display()
                        ),
                    });
                }
                keys
            }
            None => {
                let mut text = String::new();
                if std::env::var_os("SSH_AUTH_SOCK").is_some() {
                    text.push_str(&agent_keys().await);
                }
                if let Some(home) = std::env::var_os("HOME") {
                    let dir = std::path::Path::new(&home).join(".ssh");
                    for name in DEFAULT_KEY_FILES {
                        // Only the public half; the private file is never opened.
                        if let Ok(file) = read_bounded(&dir.join(name)).await {
                            text.push('\n');
                            text.push_str(&file);
                        }
                    }
                }
                let keys = normalize_public_keys(&text);
                if keys.is_empty() {
                    return Err(KeySourceError {
                        reason: "no_ssh_key",
                        detail: "the controller has no SSH public key to install in the Windows clone (its ssh-agent holds none and $HOME/.ssh has no default public key file); set FLEET_LAB_LOGIN_PUBLIC_KEY_FILE to the key Lab authenticates with".to_owned(),
                    });
                }
                keys
            }
        };
        if keys.len() > MAX_KEYS {
            return Err(KeySourceError {
                reason: "too_many_ssh_keys",
                detail: format!(
                    "{} SSH public keys were found and every one would be authorized on the Windows clone (at most {MAX_KEYS}); set FLEET_LAB_LOGIN_PUBLIC_KEY_FILE to the one key Lab authenticates with",
                    keys.len()
                ),
            });
        }
        Ok(keys)
    }
}

async fn read_bounded(path: &std::path::Path) -> Result<String, String> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| e.kind().to_string())?;
    Ok(String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT)]).into_owned())
}

/// `ssh-add -L`: one public key per line. No agent, no identities, a timeout
/// and any failure all read as no keys, so the default files still apply.
async fn agent_keys() -> String {
    let mut command = tokio::process::Command::new("ssh-add");
    command
        .arg("-L")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let Ok(Ok(output)) = tokio::time::timeout(AGENT_TIMEOUT, command.output()).await else {
        return String::new();
    };
    if !output.status.success() {
        return String::new();
    }
    let stdout = &output.stdout[..output.stdout.len().min(MAX_OUTPUT)];
    String::from_utf8_lossy(stdout).into_owned()
}

/// Reduces OpenSSH public key text (one key per line, optional comments,
/// blank lines) to distinct `type base64` lines, in order, dropping anything
/// that is not a public key. Authorized-keys options before the type are not
/// understood and make the line be skipped.
#[must_use]
pub fn normalize_public_keys(text: &str) -> Vec<String> {
    let mut keys: Vec<String> = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(kind), Some(blob)) = (fields.next(), fields.next()) else {
            continue;
        };
        let key = format!("{kind} {blob}");
        if fleet_provider_proxmox::is_public_key_line(&key) && !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

/// `SHA256:<unpadded base64>` of the key's blob, as `ssh-keygen -l` prints it.
#[must_use]
pub fn fingerprint(key: &str) -> String {
    let blob = key.split(' ').nth(1).unwrap_or_default();
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(blob) else {
        return "SHA256:<unreadable>".to_owned();
    };
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(sha2::Sha256::digest(raw))
    )
}

/// A fixed key list, for tests.
#[derive(Debug)]
pub struct FixedKeys(pub Vec<String>);

#[async_trait::async_trait]
impl LabKeySource for FixedKeys {
    async fn public_keys(&self) -> Result<Vec<String>, KeySourceError> {
        if self.0.is_empty() {
            return Err(KeySourceError {
                reason: "no_ssh_key",
                detail: "the controller has no SSH public key to install in the Windows clone (its ssh-agent holds none)".to_owned(),
            });
        }
        Ok(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_lose_their_comments_and_anything_that_is_not_a_public_key() {
        let text = "ssh-ed25519 AAAAC3Nza host@example comment\n\
                    \n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n\
                    ssh-ed25519 AAAAC3Nza again\n\
                    not-a-key AAAA\n\
                    ecdsa-sha2-nistp256 AAAAE2Vj\n\
                    no-blob-here\n";
        assert_eq!(
            normalize_public_keys(text),
            ["ssh-ed25519 AAAAC3Nza", "ecdsa-sha2-nistp256 AAAAE2Vj"]
        );
    }

    #[test]
    fn the_fingerprint_is_the_unpadded_sha256_of_the_blob() {
        // "hello" as the blob: sha256 = LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ
        assert_eq!(
            fingerprint("ssh-ed25519 aGVsbG8="),
            "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
        );
    }

    #[tokio::test]
    async fn an_explicit_file_is_the_only_source_and_more_than_four_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let one = dir.path().join("lab.pub");
        std::fs::write(&one, "ssh-ed25519 AAAAC3Nza lab@host\n").unwrap();
        assert_eq!(
            ControllerKeys::new(Some(one)).public_keys().await.unwrap(),
            ["ssh-ed25519 AAAAC3Nza"]
        );
        let many = dir.path().join("many.pub");
        let text = (0..5)
            .map(|n| format!("ssh-ed25519 AAAA{n}\n"))
            .collect::<String>();
        std::fs::write(&many, text).unwrap();
        let error = ControllerKeys::new(Some(many))
            .public_keys()
            .await
            .unwrap_err();
        assert_eq!(error.reason, "too_many_ssh_keys");
        assert!(error.detail.contains("FLEET_LAB_LOGIN_PUBLIC_KEY_FILE"));
        let empty = dir.path().join("empty.pub");
        std::fs::write(&empty, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
        let error = ControllerKeys::new(Some(empty))
            .public_keys()
            .await
            .unwrap_err();
        assert_eq!(error.reason, "no_ssh_key");
        let missing = ControllerKeys::new(Some(dir.path().join("absent.pub")))
            .public_keys()
            .await
            .unwrap_err();
        assert_eq!(missing.reason, "no_ssh_key");
    }

    #[tokio::test]
    async fn describe_names_fingerprints_never_keys() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lab.pub");
        std::fs::write(&file, "ssh-ed25519 aGVsbG8= secret-comment\n").unwrap();
        let line = ControllerKeys::new(Some(file)).describe().await;
        assert!(
            line.contains("1 key(s)") && line.contains("SHA256:LPJN"),
            "{line}"
        );
        assert!(!line.contains("aGVsbG8") && !line.contains("secret-comment"));
    }
}
