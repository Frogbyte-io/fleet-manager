//! The controller's own SSH identity at startup and on the read endpoint.
//!
//! `--auth agent` endpoints connect with the controller user's default key.
//! A fresh deployment has none, so at startup the controller generates
//! `~/.ssh/id_ed25519` for its own user (unless `FLEET_SSH_KEY_GENERATE` is
//! off), and reports an existing key that `ssh` could not use instead of
//! letting every connection fail later. `GET /api/v1/system/ssh-public-key`
//! publishes the public half so `fleetctl machines join` can install it.

use fleet_api::system::{SshKeyState, SshPublicKeyInfo};
use fleet_provider_ssh::identity::{
    ControllerIdentity, EnsureOutcome, IdentityStamp, IdentityState,
};

/// Prepares the identity at startup and answers the log line to print.
/// Never fails startup: a controller that reaches machines only through an
/// agent, or not at all, still serves.
#[must_use]
pub fn prepare_at_startup(generate: bool) -> String {
    let identity = match ControllerIdentity::for_current_user() {
        Ok(identity) => identity,
        Err(error) => return format!("warning: controller SSH key: {error}"),
    };
    describe(
        identity.ensure(
            generate,
            &fleet_provider_ssh::identity::controller_key_comment(),
        ),
        generate,
    )
}

/// The startup log line for an [`EnsureOutcome`].
#[must_use]
pub fn describe(outcome: Result<EnsureOutcome, String>, generate: bool) -> String {
    match outcome {
        Ok(EnsureOutcome::Generated(identity)) => format!(
            "controller SSH key generated at {} ({} {}); machines add its public key with `fleetctl machines join`",
            identity.path.display(),
            identity.key_type,
            identity.fingerprint
        ),
        Ok(EnsureOutcome::Existing(IdentityState::Present(identity))) => format!(
            "controller SSH key {} ({} {})",
            identity.path.display(),
            identity.key_type,
            identity.fingerprint
        ),
        Ok(EnsureOutcome::Existing(IdentityState::None { ssh_dir })) => {
            let why = if generate {
                "none was generated"
            } else {
                "generation is off (FLEET_SSH_KEY_GENERATE or the config file's ssh_key_generate is false)"
            };
            format!(
                "warning: the controller user has no SSH key in {} and {why}; `--auth agent` endpoints connect only with keys an ssh-agent supplies",
                ssh_dir.display()
            )
        }
        Ok(EnsureOutcome::Existing(IdentityState::Unusable { detail, .. })) => {
            format!("warning: the controller SSH key is unusable: {detail}")
        }
        Err(error) => format!("warning: the controller SSH key could not be generated: {error}"),
    }
}

/// How long a cached answer of the read endpoint is reused while the key
/// files look unchanged. A change to them (a new, replaced, re-owned or
/// re-moded key) is seen on the next read; the bound only covers what the
/// file metadata cannot show, such as the account database's home.
pub const PUBLIC_KEY_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// One remembered inspection.
#[derive(Clone, Debug)]
struct Cached {
    identity: ControllerIdentity,
    stamp: IdentityStamp,
    info: SshPublicKeyInfo,
    at: std::time::Instant,
}

/// The read endpoint's answers, remembered: an inspection runs `getent`
/// and `ssh-keygen -y`, so repeated reads reuse the last answer while it is
/// younger than the TTL and the key files' [`IdentityStamp`] is unchanged.
/// Inspections are serialized: concurrent reads wait for the one running
/// and then reuse its answer, so a burst of requests starts at most one
/// set of programs (each itself bounded by the provider's deadline).
#[derive(Debug)]
pub struct PublicKeyCache {
    ttl: std::time::Duration,
    entry: tokio::sync::Mutex<Option<Cached>>,
}

impl PublicKeyCache {
    /// An empty cache whose answers live at most `ttl`.
    #[must_use]
    pub const fn new(ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            entry: tokio::sync::Mutex::const_new(None),
        }
    }

    /// The answer for the identity `resolve` finds, from the cache when it
    /// still holds.
    ///
    /// # Errors
    ///
    /// Fails when `resolve` fails or the inspection does not finish.
    pub async fn get(
        &self,
        resolve: impl FnOnce() -> Result<ControllerIdentity, String> + Send + 'static,
    ) -> Result<SshPublicKeyInfo, String> {
        let mut entry = self.entry.lock().await;
        let previous = entry.take();
        let ttl = self.ttl;
        let cached = tokio::task::spawn_blocking(move || {
            let now = std::time::Instant::now();
            if let Some(cached) = previous
                && now.duration_since(cached.at) < ttl
                && cached.identity.stamp() == cached.stamp
            {
                return Ok::<_, String>(cached);
            }
            let identity = resolve()?;
            // Stamped before the inspection: a change during it is seen
            // as a change on the next read.
            let stamp = identity.stamp();
            let info = to_info(identity.inspect());
            Ok(Cached {
                identity,
                stamp,
                info,
                at: now,
            })
        })
        .await
        .map_err(|error| format!("the identity inspection did not finish: {error}"))??;
        let info = cached.info.clone();
        *entry = Some(cached);
        Ok(info)
    }
}

/// The read endpoint's answer for the current identity.
///
/// # Errors
///
/// Fails when the controller user has no home directory to look in.
pub async fn public_key_info() -> Result<SshPublicKeyInfo, String> {
    static CACHE: PublicKeyCache = PublicKeyCache::new(PUBLIC_KEY_CACHE_TTL);
    CACHE.get(ControllerIdentity::for_current_user).await
}

/// Maps an [`IdentityState`] to the public answer.
#[must_use]
pub fn to_info(state: IdentityState) -> SshPublicKeyInfo {
    match state {
        IdentityState::Present(identity) => SshPublicKeyInfo {
            state: SshKeyState::Present,
            public_key: Some(identity.public_key),
            key_type: Some(identity.key_type),
            fingerprint: Some(identity.fingerprint),
            path: Some(identity.path.display().to_string()),
            detail: None,
        },
        IdentityState::None { ssh_dir } => SshPublicKeyInfo {
            state: SshKeyState::None,
            public_key: None,
            key_type: None,
            fingerprint: None,
            path: Some(ssh_dir.display().to_string()),
            detail: Some(
                "the controller user has no default SSH key; if FLEET_SSH_KEY_GENERATE (or ssh_key_generate in the config file) is off, turn it on and restart the controller, otherwise its startup log says why generation failed".to_owned(),
            ),
        },
        IdentityState::Unusable { path, detail } => SshPublicKeyInfo {
            state: SshKeyState::Unusable,
            public_key: None,
            key_type: None,
            fingerprint: None,
            path: Some(path.display().to_string()),
            detail: Some(detail),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_lines_name_the_fingerprint_or_the_problem_and_never_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let identity = ControllerIdentity::at(dir.path().join(".ssh"));
        let off = describe(identity.ensure(false, "t"), false);
        assert!(off.contains("FLEET_SSH_KEY_GENERATE or"), "{off}");
        assert!(off.contains("ssh_key_generate"), "{off}");
        let generated = describe(identity.ensure(true, "t"), true);
        assert!(generated.contains("generated"), "{generated}");
        assert!(generated.contains("SHA256:"), "{generated}");
        let private = std::fs::read_to_string(dir.path().join(".ssh/id_ed25519")).unwrap();
        let body = private
            .lines()
            .nth(1)
            .expect("the key has a body line")
            .to_owned();
        assert!(!generated.contains(&body));
        let again = describe(identity.ensure(true, "t"), true);
        assert!(again.starts_with("controller SSH key "), "{again}");

        let info = to_info(identity.inspect());
        assert_eq!(info.state, SshKeyState::Present);
        assert!(info.public_key.unwrap().starts_with("ssh-ed25519 "));
        let json = serde_json::to_string(&to_info(identity.inspect())).unwrap();
        assert!(!json.contains(&body));
        assert!(json.contains("\"state\":\"present\""), "{json}");
    }

    #[tokio::test]
    async fn reads_reuse_the_inspection_until_the_files_change_or_it_expires() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        let resolved = Arc::new(AtomicUsize::new(0));
        let resolver = || {
            let resolved = resolved.clone();
            let ssh = ssh.clone();
            move || {
                resolved.fetch_add(1, Ordering::SeqCst);
                Ok(ControllerIdentity::at(ssh))
            }
        };
        let cache = PublicKeyCache::new(std::time::Duration::from_secs(3600));
        assert_eq!(
            cache.get(resolver()).await.unwrap().state,
            SshKeyState::None
        );
        assert_eq!(
            cache.get(resolver()).await.unwrap().state,
            SshKeyState::None
        );
        assert_eq!(
            resolved.load(Ordering::SeqCst),
            1,
            "the second read is cached"
        );
        // A new key is seen at once, without waiting for the TTL.
        ControllerIdentity::at(&ssh).ensure(true, "t").unwrap();
        assert_eq!(
            cache.get(resolver()).await.unwrap().state,
            SshKeyState::Present
        );
        assert_eq!(resolved.load(Ordering::SeqCst), 2);
        assert_eq!(
            cache.get(resolver()).await.unwrap().state,
            SshKeyState::Present
        );
        assert_eq!(resolved.load(Ordering::SeqCst), 2);
        // Concurrent reads share one inspection.
        let cache = Arc::new(PublicKeyCache::new(std::time::Duration::from_secs(3600)));
        let reads: Vec<_> = (0..8)
            .map(|_| {
                let cache = cache.clone();
                let resolver = resolver();
                tokio::spawn(async move { cache.get(resolver).await })
            })
            .collect();
        for read in reads {
            assert_eq!(read.await.unwrap().unwrap().state, SshKeyState::Present);
        }
        assert_eq!(resolved.load(Ordering::SeqCst), 3);
        // An expired answer is inspected again.
        let expired = PublicKeyCache::new(std::time::Duration::ZERO);
        expired.get(resolver()).await.unwrap();
        expired.get(resolver()).await.unwrap();
        assert_eq!(resolved.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn none_is_an_honest_answer() {
        let dir = tempfile::tempdir().unwrap();
        let info = to_info(ControllerIdentity::at(dir.path().join(".ssh")).inspect());
        assert_eq!(info.state, SshKeyState::None);
        assert!(info.public_key.is_none());
        let detail = info.detail.unwrap();
        assert!(detail.contains("if FLEET_SSH_KEY_GENERATE"), "{detail}");
        assert!(detail.contains("startup log"), "{detail}");
    }
}
