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

// ---------------------------------------------------------------------
// Settings (FM-1034).
// ---------------------------------------------------------------------

use std::time::Duration;

use fleet_application::coolify::settings::{CoolifySettings, HeldValueStore, SETTINGS_KIND};
use fleet_core::SensitiveString;
use fleet_secrets::{SecretError, SecretValue};

/// The secret-record name prefix for held environment values. Only this
/// namespace resolves here, so a hold id can never reach an account token.
pub const HOLD_PREFIX: &str = "coolify-env-hold/";

/// Held environment values over the encrypted secret store: one record per
/// request, named `coolify-env-hold/<hold-id>`.
#[derive(Debug)]
pub struct SecretBackedHeldValues {
    secrets: Arc<SecretStore>,
}

impl SecretBackedHeldValues {
    /// Composes the store over the controller's secret store.
    #[must_use]
    pub fn new(secrets: Arc<SecretStore>) -> Self {
        Self { secrets }
    }

    fn name(hold_id: &str) -> String {
        format!("{HOLD_PREFIX}{hold_id}")
    }

    async fn record_id(&self, name: &str) -> Result<Option<String>, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|_| "the secret store is unreadable".to_owned())?
            .into_iter()
            .find(|record| record.name == name)
            .map(|record| record.id))
    }
}

#[async_trait]
impl HeldValueStore for SecretBackedHeldValues {
    async fn put(&self, hold_id: &str, document: &SensitiveString) -> Result<(), String> {
        let name = Self::name(hold_id);
        let value = || SecretValue::new(document.expose().as_bytes().to_vec());
        if let Some(id) = self.record_id(&name).await? {
            return self
                .secrets
                .update(&id, value())
                .await
                .map(|_| ())
                .map_err(|_| "a held value could not be stored".to_owned());
        }
        match self.secrets.create(&name, value()).await {
            Ok(_) => Ok(()),
            Err(SecretError::DuplicateName { .. }) => Err("the hold id is already used".to_owned()),
            Err(_) => Err("a held value could not be stored".to_owned()),
        }
    }

    async fn get(&self, hold_id: &str) -> Result<Option<SensitiveString>, String> {
        let Some(id) = self.record_id(&Self::name(hold_id)).await? else {
            return Ok(None);
        };
        let value = self
            .secrets
            .resolve(&id)
            .await
            .map_err(|_| "a held value is unreadable".to_owned())?;
        String::from_utf8(value.expose().to_vec())
            .map(|text| Some(SensitiveString::new(text)))
            .map_err(|_| "a held value is not UTF-8".to_owned())
    }

    async fn discard(&self, hold_id: &str) -> Result<(), String> {
        if let Some(id) = self.record_id(&Self::name(hold_id)).await? {
            self.secrets
                .delete(&id)
                .await
                .map_err(|_| "a held value could not be deleted".to_owned())?;
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<String>, String> {
        Ok(self
            .secrets
            .list()
            .await
            .map_err(|_| "the secret store is unreadable".to_owned())?
            .into_iter()
            .filter_map(|record| record.name.strip_prefix(HOLD_PREFIX).map(str::to_owned))
            .collect())
    }
}

/// Composes the settings use cases over the lifecycle use cases, the HTTP
/// settings client, the secret store, and the action request table.
#[must_use]
pub fn compose_coolify_settings(
    pool: &sqlx::SqlitePool,
    secrets: Arc<SecretStore>,
    lifecycle: Arc<CoolifyLifecycle>,
) -> Arc<CoolifySettings> {
    Arc::new(CoolifySettings::new(
        lifecycle,
        Arc::new(fleet_provider_coolify::CoolifyHttpSettings),
        Arc::new(SecretBackedHeldValues::new(secrets)),
        Arc::new(fleet_storage_sqlite::ActionRequestRepository::new(
            pool.clone(),
        )),
    ))
}

/// Runs an approved Coolify settings change as a durable operation.
#[derive(Debug)]
pub struct CoolifySettingsExecutor {
    settings: Arc<CoolifySettings>,
}

impl CoolifySettingsExecutor {
    /// Composes the executor over the settings use cases.
    #[must_use]
    pub fn new(settings: Arc<CoolifySettings>) -> Self {
        Self { settings }
    }
}

#[async_trait]
impl OperationExecutor for CoolifySettingsExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload = operation
            .payload_json
            .as_deref()
            .ok_or_else(|| "the Coolify operation has no payload".to_owned())?;
        operations
            .record_progress(&operation.id, Some(0), Some(1), Some("calling Coolify"))
            .await
            .map_err(|error| error.to_string())?;
        let outcome = match self.settings.execute(&operation.kind, payload).await {
            Ok(outcome) => outcome,
            // A change that stopped part way, or whose redeploy failed, is
            // recorded as a failed operation that still names what was
            // applied (names only), instead of losing it.
            Err(failure) => {
                let Some(partial) = failure.partial else {
                    return Err(failure.message);
                };
                let result = serde_json::to_string(&partial)
                    .map_err(|_| "the outcome could not be recorded".to_owned())?;
                let error = serde_json::json!({
                    "reason": "settings_partial",
                    "detail": fleet_core::scrub_failure_detail(&failure.message),
                })
                .to_string();
                return operations
                    .complete(&operation.id, "failed", Some(&result), Some(&error))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
            }
        };
        // The outcome names fields and keys, never a value.
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

/// Routes the settings kind to the settings executor and everything else
/// onward.
#[derive(Debug)]
pub struct CoolifySettingsDispatch {
    fallback: Arc<dyn OperationExecutor>,
    settings: Arc<dyn OperationExecutor>,
}

impl CoolifySettingsDispatch {
    /// Composes the dispatch from the fallback chain and the settings
    /// executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, settings: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, settings }
    }
}

#[async_trait]
impl OperationExecutor for CoolifySettingsDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == SETTINGS_KIND {
            self.settings.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}

/// How often held environment values with no live request are swept.
pub const HOLD_SWEEP_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// Removes held values whose request was denied, expired, or finished.
/// Returns when `shutdown` resolves.
pub async fn run_hold_sweeper(
    settings: Arc<CoolifySettings>,
    interval: Duration,
    shutdown: impl std::future::Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(interval) => {}
        }
        if let Err(error) = settings
            .sweep_held(fleet_core::SystemClock::now_unix_millis())
            .await
        {
            eprintln!("coolify held-value sweep failed: {error}");
        }
    }
}
