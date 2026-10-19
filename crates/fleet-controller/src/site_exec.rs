//! The site-template composition and executor (FM-1035).
//!
//! [`compose_site_templates`] wires the application's site-template use cases
//! to the HTTP clients (creation, lifecycle, settings: separate mutating
//! surfaces from read discovery) over the Coolify lifecycle use cases, which
//! own the account and credential access. [`SiteDispatch`] sends the
//! `coolify.site` operation kind to [`SiteExecutor`] and everything else down
//! the chain. The executor decides nothing: it hands the payload to
//! [`SiteTemplates::execute`] and records the outcome. A deployment that
//! stopped after creating the resource is recorded as a failed operation that
//! still carries the structured partial result (the uuid and every step).

use std::sync::Arc;

use async_trait::async_trait;
use fleet_application::coolify::lifecycle::CoolifyLifecycle;
use fleet_application::operation::{Operation, Operations};
use fleet_application::site_templates::{DeployProgress, SITE_KIND, SiteTemplates};
use fleet_application::worker::OperationExecutor;

/// Composes the site-template use cases over the store pool and the
/// lifecycle use cases.
#[must_use]
pub fn compose_site_templates(
    pool: &sqlx::SqlitePool,
    lifecycle: Arc<CoolifyLifecycle>,
) -> Arc<SiteTemplates> {
    Arc::new(SiteTemplates::new(
        lifecycle,
        Arc::new(fleet_provider_coolify::CoolifyHttpLifecycle),
        Arc::new(fleet_provider_coolify::CoolifyHttpSettings),
        Arc::new(fleet_provider_coolify::CoolifyHttpCreate),
        Arc::new(fleet_storage_sqlite::CoolifyObservationRepository::new(
            pool.clone(),
        )),
    ))
}

/// Notes what was created in the operation's progress, before the next
/// step, so the uuid survives a crash.
struct OperationProgress<'a> {
    operations: &'a Operations,
    id: &'a str,
}

#[async_trait]
impl DeployProgress for OperationProgress<'_> {
    async fn note(&self, step: &str, detail: &str) {
        let current = match step {
            "create" => 1,
            _ => 2,
        };
        let message = format!("{step}: {detail}");
        let _ = self
            .operations
            .record_progress(self.id, Some(current), Some(3), Some(&message))
            .await;
    }
}

/// Runs an approved site deployment as a durable operation.
#[derive(Debug)]
pub struct SiteExecutor {
    sites: Arc<SiteTemplates>,
}

impl SiteExecutor {
    /// Composes the executor over the site-template use cases.
    #[must_use]
    pub fn new(sites: Arc<SiteTemplates>) -> Self {
        Self { sites }
    }
}

#[async_trait]
impl OperationExecutor for SiteExecutor {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        let payload = operation
            .payload_json
            .as_deref()
            .ok_or_else(|| "the site deployment has no payload".to_owned())?;
        operations
            .record_progress(&operation.id, Some(0), Some(3), Some("calling Coolify"))
            .await
            .map_err(|error| error.to_string())?;
        let progress = OperationProgress {
            operations,
            id: &operation.id,
        };
        let outcome = match self
            .sites
            .execute(&operation.kind, payload, &progress)
            .await
        {
            Ok(outcome) => outcome,
            // A deployment that stopped after the resource existed is a
            // failed operation that still names what was created.
            Err(failure) => {
                let Some(partial) = failure.partial else {
                    return Err(failure.message);
                };
                let result = serde_json::to_string(&partial)
                    .map_err(|_| "the outcome could not be recorded".to_owned())?;
                let error = serde_json::json!({
                    "reason": "site_partial",
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
        let result = serde_json::to_string(&outcome)
            .map_err(|_| "the outcome could not be recorded".to_owned())?;
        operations
            .record_progress(&operation.id, Some(3), Some(3), Some("verified"))
            .await
            .map_err(|error| error.to_string())?;
        operations
            .complete(&operation.id, "succeeded", Some(&result), None)
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

/// Routes the site kind to the site executor and everything else onward.
#[derive(Debug)]
pub struct SiteDispatch {
    fallback: Arc<dyn OperationExecutor>,
    site: Arc<dyn OperationExecutor>,
}

impl SiteDispatch {
    /// Composes the dispatch from the fallback chain and the site executor.
    #[must_use]
    pub fn new(fallback: Arc<dyn OperationExecutor>, site: Arc<dyn OperationExecutor>) -> Self {
        Self { fallback, site }
    }
}

#[async_trait]
impl OperationExecutor for SiteDispatch {
    async fn execute(&self, operations: &Operations, operation: &Operation) -> Result<(), String> {
        if operation.kind == SITE_KIND {
            self.site.execute(operations, operation).await
        } else {
            self.fallback.execute(operations, operation).await
        }
    }
}
