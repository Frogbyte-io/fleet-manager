//! The controller's own SSH identity at startup and on the read endpoint.
//!
//! `--auth agent` endpoints connect with the controller user's default key.
//! A fresh deployment has none, so at startup the controller generates
//! `~/.ssh/id_ed25519` for its own user (unless `FLEET_SSH_KEY_GENERATE` is
//! off), and reports an existing key that `ssh` could not use instead of
//! letting every connection fail later. `GET /api/v1/system/ssh-public-key`
//! publishes the public half so `fleetctl machines join` can install it.

use fleet_api::system::{SshKeyState, SshPublicKeyInfo};
use fleet_provider_ssh::identity::{ControllerIdentity, EnsureOutcome, IdentityState};

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
                "generation is off (FLEET_SSH_KEY_GENERATE=false)"
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

/// The read endpoint's answer for the current identity.
///
/// # Errors
///
/// Fails when the controller user has no home directory to look in.
pub async fn public_key_info() -> Result<SshPublicKeyInfo, String> {
    tokio::task::spawn_blocking(|| {
        ControllerIdentity::for_current_user().map(|identity| to_info(identity.inspect()))
    })
    .await
    .map_err(|error| format!("the identity inspection did not finish: {error}"))?
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
                "the controller user has no default SSH key; restart the controller with FLEET_SSH_KEY_GENERATE on (the default) to generate one".to_owned(),
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
        assert!(off.contains("FLEET_SSH_KEY_GENERATE=false"), "{off}");
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

    #[test]
    fn none_is_an_honest_answer() {
        let dir = tempfile::tempdir().unwrap();
        let info = to_info(ControllerIdentity::at(dir.path().join(".ssh")).inspect());
        assert_eq!(info.state, SshKeyState::None);
        assert!(info.public_key.is_none());
        assert!(info.detail.unwrap().contains("FLEET_SSH_KEY_GENERATE"));
    }
}
