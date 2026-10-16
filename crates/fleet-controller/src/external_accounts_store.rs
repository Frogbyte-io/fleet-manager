//! The external accounts composition: the credential store over the
//! encrypted secret store, and the probe dispatch over the provider
//! crates (FM-1001).
//!
//! Each account's token is one secret record named `external/<account-id>`.
//! Only that namespace resolves here, so an account id can never reach a
//! Proxmox token or a Git credential.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::external_accounts::{ExternalCredentialStore, ExternalProbePort};
use fleet_application::proxmox::CredentialStoreError;
use fleet_core::{ExternalProviderKind, ProbeReport, SensitiveString};
use fleet_secrets::{SecretError, SecretStore, SecretValue};

/// The secret-record name prefix for external account tokens.
pub const SECRET_PREFIX: &str = "external/";

fn secret_name(account_id: &str) -> String {
    format!("{SECRET_PREFIX}{account_id}")
}

fn backend(detail: String) -> CredentialStoreError {
    CredentialStoreError::Backend { detail }
}

/// The credential store over the secret store.
#[derive(Debug)]
pub struct SecretBackedExternalCredentials {
    secrets: Arc<SecretStore>,
}

impl SecretBackedExternalCredentials {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    async fn record_id(&self, name: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| backend(format!("the secret store is unreadable: {error}")))?
            .into_iter()
            .find(|record| record.name == name)
            .map(|record| record.id))
    }
}

#[async_trait]
impl ExternalCredentialStore for SecretBackedExternalCredentials {
    async fn load(&self, account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        let name = secret_name(account_id);
        let Some(id) = self.record_id(&name).await? else {
            return Ok(None);
        };
        let value = self.secrets.resolve(&id).await.map_err(|error| {
            backend(format!("the secret record {name:?} is unreadable: {error}"))
        })?;
        String::from_utf8(value.expose().to_vec())
            .map(Some)
            .map_err(|_| backend(format!("the secret record {name:?} is not UTF-8")))
    }

    async fn store(&self, account_id: &str, secret: &str) -> Result<(), CredentialStoreError> {
        let name = secret_name(account_id);
        let value = || SecretValue::new(secret.as_bytes().to_vec());
        if let Some(id) = self.record_id(&name).await? {
            return self
                .secrets
                .update(&id, value())
                .await
                .map(|_| ())
                .map_err(|error| backend(format!("cannot update {name:?}: {error}")));
        }
        match self.secrets.create(&name, value()).await {
            Ok(_) => Ok(()),
            Err(SecretError::DuplicateName { .. }) => {
                let id = self.record_id(&name).await?.ok_or_else(|| {
                    backend(format!("cannot store {name:?}: vanished after the race"))
                })?;
                self.secrets
                    .update(&id, value())
                    .await
                    .map(|_| ())
                    .map_err(|error| backend(format!("cannot update {name:?}: {error}")))
            }
            Err(other) => Err(backend(format!("cannot store {name:?}: {other}"))),
        }
    }

    async fn clear(&self, account_id: &str) -> Result<(), CredentialStoreError> {
        let name = secret_name(account_id);
        if let Some(id) = self.record_id(&name).await? {
            self.secrets
                .delete(&id)
                .await
                .map_err(|error| backend(format!("cannot delete {name:?}: {error}")))?;
        }
        Ok(())
    }
}

/// The probe dispatch: one provider crate per kind.
#[derive(Debug, Default)]
pub struct ProviderExternalProbe;

#[async_trait]
impl ExternalProbePort for ProviderExternalProbe {
    async fn probe(
        &self,
        kind: ExternalProviderKind,
        base_url: &str,
        scope_id: Option<&str>,
        token: &SensitiveString,
    ) -> ProbeReport {
        match kind {
            ExternalProviderKind::Coolify => {
                fleet_provider_coolify::probe(base_url, token.expose()).await
            }
            ExternalProviderKind::Cloudflare => {
                fleet_provider_cloudflare::probe(base_url, scope_id, token.expose()).await
            }
        }
    }
}

/// Composes the use cases over the store pool and the secret store.
#[must_use]
pub fn compose_external_accounts(
    pool: &sqlx::SqlitePool,
    secrets: Arc<SecretStore>,
) -> Arc<fleet_application::external_accounts::ExternalAccounts> {
    Arc::new(fleet_application::external_accounts::ExternalAccounts::new(
        Arc::new(fleet_storage_sqlite::ExternalAccountRepository::new(
            pool.clone(),
        )),
        Arc::new(SecretBackedExternalCredentials::new(secrets)),
        Arc::new(ProviderExternalProbe),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ))
}

/// Composes the Coolify discovery use case over the same account table, the
/// same credential namespace, and the HTTP source (FM-1030).
#[must_use]
pub fn compose_coolify_discovery(
    pool: &sqlx::SqlitePool,
    secrets: Arc<SecretStore>,
) -> Arc<fleet_application::coolify::CoolifyDiscovery> {
    Arc::new(fleet_application::coolify::CoolifyDiscovery::new(
        Arc::new(fleet_storage_sqlite::ExternalAccountRepository::new(
            pool.clone(),
        )),
        Arc::new(SecretBackedExternalCredentials::new(secrets)),
        Arc::new(fleet_provider_coolify::CoolifyHttpSource),
        Arc::new(fleet_storage_sqlite::CoolifyObservationRepository::new(
            pool.clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ))
}
