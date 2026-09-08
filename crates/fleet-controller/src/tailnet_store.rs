//! The Tailscale integration's composition: the credential store over the
//! encrypted secret store, and the discovery service wiring (FM-213).
//!
//! The OAuth client id and secret live as two fixed-name secret records
//! (`tailscale/client-id`, `tailscale/client-secret`) inside Fleet's
//! encrypted store — the same store every controller credential uses. The
//! values are resolved just in time by the discovery source; nothing else
//! in the controller reads them, and clearing the integration deletes the
//! records. The store port reports `Some` only when both records exist.

use std::sync::Arc;

use fleet_application::tailnet::{TailnetCredentialStore, TailnetCredentials, TailnetIntegration};
use fleet_secrets::{SecretStore, SecretValue};

/// The fixed secret-record names. Fixed so the port can resolve without a
/// lookup table; the names carry no meaning beyond this module.
pub const CLIENT_ID_RECORD: &str = "tailscale/client-id";
/// The OAuth client secret's record name.
pub const CLIENT_SECRET_RECORD: &str = "tailscale/client-secret";

/// The credential store over the secret store.
#[derive(Debug)]
pub struct SecretBackedTailnetStore {
    secrets: Arc<SecretStore>,
}

impl SecretBackedTailnetStore {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    async fn record_id(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|error| format!("the secret store is unreadable: {error}"))?
            .into_iter()
            .find(|record| record.name == name)
            .map(|record| record.id))
    }

    async fn read_value(&self, name: &str) -> Result<Option<String>, String> {
        let Some(id) = self.record_id(name).await? else {
            return Ok(None);
        };
        let value = self
            .secrets
            .resolve(&id)
            .await
            .map_err(|error| format!("the secret record {name:?} is unreadable: {error}"))?;
        String::from_utf8(value.expose().to_vec())
            .map(Some)
            .map_err(|error| format!("the secret record {name:?} is not UTF-8: {error}"))
    }
}

#[async_trait::async_trait]
impl TailnetCredentialStore for SecretBackedTailnetStore {
    async fn load(&self) -> Result<Option<TailnetCredentials>, String> {
        let Some(client_id) = self.read_value(CLIENT_ID_RECORD).await? else {
            return Ok(None);
        };
        let Some(client_secret) = self.read_value(CLIENT_SECRET_RECORD).await? else {
            // A half-configured store is a configuration defect, not a
            // silent integration: report unconfigured rather than minting
            // calls that can only fail.
            return Ok(None);
        };
        Ok(Some(TailnetCredentials {
            client_id,
            client_secret: fleet_core::SensitiveString::new(client_secret),
        }))
    }

    async fn store(&self, client_id: &str, client_secret: &str) -> Result<(), String> {
        // Replace semantics: clear then create, in that order. The store is
        // the only writer of these two names.
        self.clear().await?;
        self.secrets
            .create(
                CLIENT_ID_RECORD,
                SecretValue::new(client_id.as_bytes().to_vec()),
            )
            .await
            .map_err(|error| format!("cannot store the client id: {error}"))?;
        self.secrets
            .create(
                CLIENT_SECRET_RECORD,
                SecretValue::new(client_secret.as_bytes().to_vec()),
            )
            .await
            .map_err(|error| format!("cannot store the client secret: {error}"))?;
        Ok(())
    }

    async fn clear(&self) -> Result<(), String> {
        for name in [CLIENT_ID_RECORD, CLIENT_SECRET_RECORD] {
            if let Some(id) = self.record_id(name).await? {
                self.secrets
                    .delete(&id)
                    .await
                    .map_err(|error| format!("cannot delete {name:?}: {error}"))?;
            }
        }
        Ok(())
    }
}

/// Composes the Tailscale discovery service over its ports: the provider
/// client (as the source), the secret-backed credential store, the
/// onboarding use cases (import), the machine use cases (correlation), and
/// the audit sink.
#[must_use]
pub fn compose_tailnet(
    secrets: Arc<SecretStore>,
    source: Arc<dyn fleet_application::tailnet::TailnetSource>,
    onboarding: Arc<fleet_application::onboarding::Onboarding>,
    machines: Arc<fleet_application::machine::Machines>,
    audit: Arc<dyn fleet_application::operation::AuditPort>,
) -> TailnetIntegration {
    TailnetIntegration::new(
        source,
        Arc::new(SecretBackedTailnetStore::new(secrets)),
        onboarding,
        machines,
        audit,
    )
}
