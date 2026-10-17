//! The `images/<name>` build secrets over the encrypted secret store
//! (#520).
//!
//! The same records the image build executor resolves just in time for the
//! Packer var file. Only names inside the namespace are visible here, so
//! this surface can never list, overwrite, or delete another integration's
//! secret (a Proxmox token, a Git credential). Values go in; nothing here
//! reads one back.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::images::{ImageSecretPort, check_secret_reference};
use fleet_core::SensitiveString;
use fleet_secrets::{SecretError, SecretStore, SecretValue};

/// The image secret port over the secret store.
#[derive(Debug)]
pub struct SecretBackedImageSecrets {
    secrets: Arc<SecretStore>,
}

impl SecretBackedImageSecrets {
    /// Composes the port over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    async fn record_id(&self, reference: &str) -> Result<Option<String>, String> {
        if check_secret_reference(reference).is_err() {
            return Err("the record is outside the images/ namespace".to_owned());
        }
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .into_iter()
            .find(|record| record.name == reference)
            .map(|record| record.id))
    }
}

#[async_trait]
impl ImageSecretPort for SecretBackedImageSecrets {
    async fn list(&self) -> Result<Vec<String>, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .into_iter()
            .map(|record| record.name)
            .filter(|name| check_secret_reference(name).is_ok())
            .collect())
    }

    async fn set(&self, reference: &str, value: &SensitiveString) -> Result<bool, String> {
        let sealed = || SecretValue::new(value.expose().as_bytes().to_vec());
        // A concurrent delete or create can race either step, so the pair
        // retries a few times: replace when the record exists, else create.
        for _ in 0..3 {
            if let Some(id) = self.record_id(reference).await? {
                match self.secrets.update(&id, sealed()).await {
                    Ok(_) => return Ok(true),
                    // Deleted between the lookup and the update: create.
                    Err(SecretError::NotFound { .. }) => continue,
                    Err(error) => return Err(format!("the secret could not be replaced: {error}")),
                }
            }
            match self.secrets.create(reference, sealed()).await {
                Ok(_) => return Ok(false),
                // A concurrent writer won the create: replace its record.
                Err(SecretError::DuplicateName { .. }) => continue,
                Err(error) => return Err(format!("the secret could not be stored: {error}")),
            }
        }
        Err("the secret record kept changing during the write; retry".to_owned())
    }

    async fn delete(&self, reference: &str) -> Result<bool, String> {
        let Some(id) = self.record_id(reference).await? else {
            return Ok(false);
        };
        match self.secrets.delete(&id).await {
            Ok(()) => Ok(true),
            Err(SecretError::NotFound { .. }) => Ok(false),
            Err(error) => Err(format!("the secret could not be deleted: {error}")),
        }
    }
}
