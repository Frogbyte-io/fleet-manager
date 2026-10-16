//! The Coolify lifecycle composition and executor (FM-1033).
//!
//! [`compose_coolify_lifecycle`] wires the application's lifecycle use cases
//! to the HTTP client (a separate surface from read discovery), the external
//! accounts' credential store, and the observation table.
//! [`CoolifyLifecycleDispatch`] sends the `coolify.lifecycle` operation kind
//! to [`CoolifyLifecycleExecutor`] and everything else down the chain. The
//! executor decides nothing: it hands the payload to
//! [`CoolifyLifecycle::execute`], which checks the version, acts, and
//! re-reads the resource.

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::coolify::lifecycle::{CoolifyLifecycle, LIFECYCLE_KIND};
use fleet_application::operation::{Operation, Operations};
use fleet_application::worker::OperationExecutor;
use fleet_secrets::SecretStore;

/// Composes the lifecycle use cases over the store pool and the secret store.
#[must_use]
pub fn compose_coolify_lifecycle(
    pool: &sqlx::SqlitePool,
    secrets: Arc<SecretStore>,
) -> Arc<CoolifyLifecycle> {
    Arc::new(CoolifyLifecycle::new(
        Arc::new(fleet_storage_sqlite::ExternalAccountRepository::new(
            pool.clone(),
        )),
        Arc::new(crate::external_accounts_store::SecretBackedExternalCredentials::new(secrets)),
        Arc::new(fleet_provider_coolify::CoolifyHttpLifecycle),
        Arc::new(fleet_storage_sqlite::CoolifyObservationRepository::new(
            pool.clone(),
        )),
        Arc::new(fleet_storage_sqlite::AuditSink::new(pool.clone())),
    ))
}

/// Runs an approved Coolify lifecycle action as a durable operation.
#[derive(Debug)]
pub struct CoolifyLifecycleExecutor {
    lifecycle: Arc<CoolifyLifecycle>,
}

impl CoolifyLifecycleExecutor {
    /// Composes the executor over the lifecycle use cases.
    #[must_use]
    pub fn new(lifecycle: Arc<CoolifyLifecycle>) -> Self {
        Self { lifecycle }
    }
}

#[async_trait]
impl OperationExecutor for CoolifyLifecycleExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload = operation
            .payload_json
            .as_deref()
            .ok_or_else(|| "the Coolify operation has no payload".to_owned())?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("calling Coolify"))
            .await
            .map_err(|error| error.to_string())?;
        let outcome = self.lifecycle.execute(&operation.kind, payload).await?;
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

/// Routes the lifecycle kind to the lifecycle executor and everything else
/// onward.
#[derive(Debug)]
pub struct CoolifyLifecycleDispatch {
    fallback: Arc<dyn OperationExecutor>,
    lifecycle: Arc<dyn OperationExecutor>,
}

impl CoolifyLifecycleDispatch {
    /// Composes the dispatch from the fallback chain and the lifecycle
    /// executor.
    #[must_use]
    pub fn new(
        fallback: Arc<dyn OperationExecutor>,
        lifecycle: Arc<dyn OperationExecutor>,
    ) -> Self {
        Self {
            fallback,
            lifecycle,
        }
    }
}

#[async_trait]
impl OperationExecutor for CoolifyLifecycleDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == LIFECYCLE_KIND {
            self.lifecycle.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}
