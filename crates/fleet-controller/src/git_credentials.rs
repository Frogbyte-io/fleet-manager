//! The Git credential store over the encrypted secret store (FM-412).
//!
//! Each credential (an HTTPS token or an SSH private key) is one secret
//! record named `git/<uuid>`; the record id is the reference the desired
//! source's configuration holds. Only records under the `git/` prefix
//! resolve here, so a reference can never reach another integration's
//! secret (a Proxmox token, the Tailscale client). The value is resolved
//! just in time by the fetch executor and nowhere else.

use std::sync::Arc;

use fleet_application::source::GitCredentialStore;
use fleet_secrets::{SecretError, SecretStore, SecretValue};

/// The secret-record name prefix for Git credentials.
pub const SECRET_PREFIX: &str = "git/";

/// The credential store over the secret store.
#[derive(Debug)]
pub struct SecretBackedGitCredentials {
    secrets: Arc<SecretStore>,
}

impl SecretBackedGitCredentials {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    /// Whether `reference` names a live record inside the Git namespace.
    async fn live(&self, reference: &str) -> Result<bool, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .iter()
            .any(|record| record.id == reference && record.name.starts_with(SECRET_PREFIX)))
    }
}

#[async_trait::async_trait]
impl GitCredentialStore for SecretBackedGitCredentials {
    async fn create(&self, value: &str) -> Result<String, String> {
        let name = format!("{SECRET_PREFIX}{}", uuid::Uuid::now_v7());
        self.secrets
            .create(&name, SecretValue::new(value.as_bytes().to_vec()))
            .await
            .map(|record| record.id)
            .map_err(|error| format!("the credential could not be stored: {error}"))
    }

    async fn exists(&self, reference: &str) -> Result<bool, String> {
        self.live(reference).await
    }

    async fn resolve(&self, reference: &str) -> Result<Option<String>, String> {
        if !self.live(reference).await? {
            return Ok(None);
        }
        match self.secrets.resolve(reference).await {
            Ok(value) => String::from_utf8(value.expose().to_vec())
                .map(Some)
                .map_err(|_| "the stored Git credential is not UTF-8".to_owned()),
            // Deleted between the check and the read: revoked.
            Err(SecretError::NotFound { .. }) => Ok(None),
            Err(error) => Err(format!("the stored Git credential is unreadable: {error}")),
        }
    }
}
