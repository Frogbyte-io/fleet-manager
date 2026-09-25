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
        // Replace semantics through upserts, never delete-then-create: a
        // failed second write must not leave one client's id paired with
        // another client's secret. The fixed names make this a two-row
        // upsert; a concurrent configure is a lost race retried once.
        self.upsert(CLIENT_ID_RECORD, client_id).await?;
        self.upsert(CLIENT_SECRET_RECORD, client_secret).await?;
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

impl SecretBackedTailnetStore {
    /// Creates the record or, when a concurrent configure created it first,
    /// updates the winner's row — either way the pair ends consistent.
    async fn upsert(&self, name: &'static str, value: &str) -> Result<(), String> {
        if let Some(id) = self.record_id(name).await? {
            return self
                .secrets
                .update(&id, SecretValue::new(value.as_bytes().to_vec()))
                .await
                .map(|_| ())
                .map_err(|error| format!("cannot update {name:?}: {error}"));
        }
        match self
            .secrets
            .create(name, SecretValue::new(value.as_bytes().to_vec()))
            .await
        {
            Ok(_) => Ok(()),
            Err(fleet_secrets::SecretError::DuplicateName { .. }) => {
                let id = self
                    .record_id(name)
                    .await?
                    .ok_or_else(|| format!("cannot store {name:?}: vanished after the race"))?;
                self.secrets
                    .update(&id, SecretValue::new(value.as_bytes().to_vec()))
                    .await
                    .map(|_| ())
                    .map_err(|error| format!("cannot update {name:?}: {error}"))
            }
            Err(other) => Err(format!("cannot store {name:?}: {other}")),
        }
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
    compose_tailnet_with_events(secrets, source, onboarding, machines, audit, None)
}

/// Composes Tailscale discovery with the process event hub.
#[must_use]
pub fn compose_tailnet_with_events(
    secrets: Arc<SecretStore>,
    source: Arc<dyn fleet_application::tailnet::TailnetSource>,
    onboarding: Arc<fleet_application::onboarding::Onboarding>,
    machines: Arc<fleet_application::machine::Machines>,
    audit: Arc<dyn fleet_application::operation::AuditPort>,
    events: Option<Arc<fleet_application::events::EventHub>>,
) -> TailnetIntegration {
    let tailnet = TailnetIntegration::new(
        source,
        Arc::new(SecretBackedTailnetStore::new(secrets)),
        onboarding,
        machines,
        audit,
    );
    match events {
        Some(hub) => tailnet.with_events(hub),
        None => tailnet,
    }
}
