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
use fleet_application::images::{ImageSecretPort, SECRET_NAMESPACE};
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
        if !reference.starts_with(SECRET_NAMESPACE) {
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
            .filter(|name| name.starts_with(SECRET_NAMESPACE))
            .collect())
    }

    async fn set(&self, reference: &str, value: &SensitiveString) -> Result<bool, String> {
        let sealed = || SecretValue::new(value.expose().as_bytes().to_vec());
        if let Some(id) = self.record_id(reference).await? {
            return match self.secrets.update(&id, sealed()).await {
                Ok(_) => Ok(true),
                Err(error) => Err(format!("the secret could not be replaced: {error}")),
            };
        }
        match self.secrets.create(reference, sealed()).await {
            Ok(_) => Ok(false),
            // A concurrent writer won the create: replace its record.
            Err(SecretError::DuplicateName { .. }) => {
                let id = self
                    .record_id(reference)
                    .await?
                    .ok_or_else(|| "the secret record vanished during the write".to_owned())?;
                self.secrets
                    .update(&id, sealed())
                    .await
                    .map(|_| true)
                    .map_err(|error| format!("the secret could not be replaced: {error}"))
            }
            Err(error) => Err(format!("the secret could not be stored: {error}")),
        }
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
