//! The DNS composition and executor (FM-1042).
//!
//! [`compose_dns`] wires the application's DNS use cases to the Cloudflare
//! gateway, the external accounts' credential store, the observation table,
//! and the Registry read model. [`DnsDispatch`] sends the two brokered DNS
//! operation kinds to [`DnsExecutor`] and everything else down the chain.
//! The executor decides nothing: it hands the payload to
//! [`Dns::execute`], which re-reads, refuses a stale preview, applies, and
//! verifies.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::dns::{DELETE_ACTION, Dns, UPSERT_ACTION};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_secrets::SecretStore;

/// Composes the DNS use cases over the store pool and the secret store.
#[must_use]
pub fn compose_dns(pool: &sqlx::SqlitePool, secrets: Arc<SecretStore>) -> Arc<Dns> {
    let dns = Dns::new(
        Arc::new(fleet_storage_sqlite::ExternalAccountRepository::new(
            pool.clone(),
        )),
        Arc::new(crate::external_accounts_store::SecretBackedExternalCredentials::new(secrets)),
        Arc::new(fleet_provider_cloudflare::CloudflareDns),
        Arc::new(fleet_storage_sqlite::DnsObservationRepository::new(
            pool.clone(),
        )),
    );
    Arc::new(match crate::compose_desired_source(pool).registry() {
        Some(registry) => dns.with_registry(registry.clone()),
        None => dns,
    })
}

/// Runs an approved DNS change as a durable operation.
#[derive(Debug)]
pub struct DnsExecutor {
    dns: Arc<Dns>,
}

impl DnsExecutor {
    /// Composes the executor over the DNS use cases.
    #[must_use]
    pub fn new(dns: Arc<Dns>) -> Self {
        Self { dns }
    }
}

#[async_trait]
impl OperationExecutor for DnsExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload = operation
            .payload_json
            .as_deref()
            .ok_or_else(|| "the DNS operation has no payload".to_owned())?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("applying the change"))
            .await
            .map_err(|error| error.to_string())?;
        let outcome = self.dns.execute(&operation.kind, payload).await?;
        let result = serde_json::to_string(&outcome)
            .map_err(|_| "the outcome could not be recorded".to_owned())?;
        operations
            .record_progress(&operation.id, Some(1), Some(1), Some("verified"))
            .await
            .map_err(|error| error.to_string())?;
        operations
            .complete(&operation.id, "succeeded", Some(&result), None)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

/// Routes the DNS kinds to the DNS executor and everything else onward.
#[derive(Debug)]
pub struct DnsDispatch {
    fallback: Arc<dyn OperationExecutor>,
    dns: Arc<dyn OperationExecutor>,
}

impl DnsDispatch {
    /// Composes the dispatch from the fallback chain and the DNS executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, dns: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, dns }
    }
}

#[async_trait]
impl OperationExecutor for DnsDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        match operation.kind.as_str() {
            UPSERT_ACTION | DELETE_ACTION => self.dns.execute(operations, operation).await,
            _ => self.fallback.execute(operations, operation).await,
        }
    }
}
