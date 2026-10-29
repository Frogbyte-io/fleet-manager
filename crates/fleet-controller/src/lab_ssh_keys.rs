//! The controller's SSH public keys, for Lab clones that must be logged in to
//! without a key baked into the image (#561).
//!
//! Lab has no key store: the controller authenticates with the keys its
//! SSH agent holds and then its default key files (see `docs/operations/lab.md`,
//! "Which keys the controller offers"). This reads the *public* halves of
//! exactly those keys, the same set OpenSSH offers, so a key that can log in
//! is the key that gets installed. Nothing private is read: the agent lists
//! public keys (`ssh-add -L`), and the fallback reads `~/.ssh/<name>.pub`.
//! Comments are dropped, so a hostname or user in a key comment never
//! reaches PVE or the audit log.

use std::time::Duration;

/// At most this many keys are installed: the guest's `sshd` limits attempts
/// (`MaxAuthTries`), and Lab needs one.
pub const MAX_KEYS: usize = 4;
/// The bound on `ssh-add -L` output that is read.
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

/// Where Lab gets the public keys to install in a clone.
#[async_trait::async_trait]
pub trait LabKeySource: Send + Sync + std::fmt::Debug {
    /// The public keys, each a `type base64` line without a comment, at most
    /// [`MAX_KEYS`].
    ///
    /// # Errors
    /// A short, secret-free reason the keys could not be read.
    async fn public_keys(&self) -> Result<Vec<String>, String>;
}

/// The controller user's agent keys, then its default public key files.
#[derive(Debug, Default)]
pub struct ControllerKeys;

#[async_trait::async_trait]
impl LabKeySource for ControllerKeys {
    async fn public_keys(&self) -> Result<Vec<String>, String> {
        let mut text = String::new();
        if std::env::var_os("SSH_AUTH_SOCK").is_some() {
            text.push_str(&agent_keys().await);
        }
        if let Some(home) = std::env::var_os("HOME") {
            let dir = std::path::Path::new(&home).join(".ssh");
            for name in DEFAULT_KEY_FILES {
                // Only the public half; the private file is never opened.
                if let Ok(file) = tokio::fs::read(dir.join(name)).await {
                    let file = &file[..file.len().min(MAX_OUTPUT)];
                    text.push('\n');
                    text.push_str(&String::from_utf8_lossy(file));
                }
            }
        }
        Ok(normalize_public_keys(&text))
    }
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

/// Reduces OpenSSH public key text (one key per line, optional options and
/// comments, blank lines) to distinct `type base64` lines, dropping anything
/// that is not a public key, in order, up to [`MAX_KEYS`].
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
            if keys.len() == MAX_KEYS {
                break;
            }
        }
    }
    keys
}

/// A fixed key list, for tests.
#[derive(Debug)]
pub struct FixedKeys(pub Vec<String>);

#[async_trait::async_trait]
impl LabKeySource for FixedKeys {
    async fn public_keys(&self) -> Result<Vec<String>, String> {
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
    fn at_most_four_keys_are_kept() {
        let text = (0..9)
            .map(|n| format!("ssh-ed25519 AAAA{n}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(normalize_public_keys(&text).len(), MAX_KEYS);
    }
}
