//! Read-only Skills Manager observations and their authorization boundary.

#![warn(missing_docs)]

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::PortFailure;

/// How long a Skills Manager observation remains fresh.
pub const SKILLS_FRESHNESS_MS: i64 = 24 * 60 * 60 * 1000;
/// Maximum number of machine observations in one skills matrix page.
pub const MAX_SKILLS_MATRIX_PAGE: u32 = 200;

/// Availability of the supported Skills Manager contract on a machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillsAvailability {
    /// A supported CLI answered the read contract.
    Available,
    /// No CLI is installed.
    Absent,
    /// The CLI is present but its version or response is unsupported.
    Unsupported,
}

/// A safely normalized observation from one machine.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillsSnapshot {
    /// The observed machine.
    pub machine_id: String,
    /// Contract availability.
    pub availability: SkillsAvailability,
    /// Exact CLI version when available.
    pub cli_version: Option<String>,
    /// Safe library and topology data. The provider filters this before persistence.
    pub data: serde_json::Value,
    /// Whether the update check completed.
    pub update_check: String,
    /// Observation time in epoch milliseconds.
    pub observed_at: i64,
}

/// Skills observation persistence port.
#[async_trait]
pub trait SkillsPort: Send + Sync {
    /// Read one machine's latest observation.
    async fn get(&self, machine_id: &str) -> Result<Option<SkillsSnapshot>, PortFailure>;
    /// Read one ordered page of latest observations.
    async fn list(
        &self,
        after_machine_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<SkillsSnapshot>, PortFailure>;
    /// Persist a new observation, replacing only that machine's latest snapshot.
    async fn record(&self, snapshot: &SkillsSnapshot) -> Result<(), PortFailure>;
}

/// A Skills observation annotated with derived freshness.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillsView {
    /// The snapshot.
    #[serde(flatten)]
    pub snapshot: SkillsSnapshot,
    /// Whether the observation is older than the freshness window.
    pub stale: bool,
}

/// An authorized page of skills observations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkillsPage {
    /// Visible observations on this page.
    pub items: Vec<SkillsView>,
    /// Cursor for the next database page, if any.
    pub next_cursor: Option<String>,
    /// Requested page size.
    pub limit: u32,
}

/// Skills read use cases.
pub struct Skills {
    port: Arc<dyn SkillsPort>,
}

impl std::fmt::Debug for Skills {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Skills").finish_non_exhaustive()
    }
}

impl Skills {
    /// Compose from its persistence port.
    #[must_use]
    pub fn new(port: Arc<dyn SkillsPort>) -> Self {
        Self { port }
    }

    /// Read one machine's observation under `skills.read`.
    ///
    /// # Errors
    ///
    /// Returns a denial or persistence failure.
    pub async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        machine_id: &str,
        now: i64,
    ) -> Result<Option<SkillsView>, SkillsError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id: &principal.id,
                action: Permission::SkillsRead,
                resource: Some(machine_id),
            },
        )
        .map_err(SkillsError::Denied)?;
        self.port
            .get(machine_id)
            .await
            .map(|v| v.map(|snapshot| view(snapshot, now)))
            .map_err(|_| SkillsError::Backend)
    }

    /// Read the fleet matrix, authorizing each machine before returning its topology.
    ///
    /// # Errors
    ///
    /// Returns a persistence failure.
    pub async fn matrix(
        &self,
        authorizer: &dyn Authorizer,
        principal: &ActingPrincipal,
        now: i64,
        after_machine_id: Option<&str>,
        limit: u32,
    ) -> Result<SkillsPage, SkillsError> {
        let limit = limit.clamp(1, MAX_SKILLS_MATRIX_PAGE);
        let rows = self
            .port
            .list(after_machine_id, limit.saturating_add(1))
            .await
            .map_err(|_| SkillsError::Backend)?;
        let has_more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
        let next_cursor = has_more.then(|| {
            rows[usize::try_from(limit).unwrap_or(usize::MAX) - 1]
                .machine_id
                .clone()
        });
        let rows = rows
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX));
        let mut visible = Vec::new();
        for row in rows {
            if authorize(
                authorizer,
                AccessRequest {
                    principal_id: &principal.id,
                    action: Permission::SkillsRead,
                    resource: Some(&row.machine_id),
                },
            )
            .is_ok()
            {
                visible.push(view(row, now));
            }
        }
        Ok(SkillsPage {
            items: visible,
            next_cursor,
            limit,
        })
    }

    /// Persist a normalized observation produced by the trusted probe adapter.
    ///
    /// # Errors
    ///
    /// Returns a persistence failure.
    pub async fn record(&self, snapshot: &SkillsSnapshot) -> Result<(), SkillsError> {
        self.port
            .record(snapshot)
            .await
            .map_err(|_| SkillsError::Backend)
    }
}

fn view(snapshot: SkillsSnapshot, now: i64) -> SkillsView {
    SkillsView {
        stale: now.saturating_sub(snapshot.observed_at) > SKILLS_FRESHNESS_MS,
        snapshot,
    }
}

/// A skills read failure.
#[derive(Debug)]
pub enum SkillsError {
    /// The caller is not allowed to read this machine's skill topology.
    Denied(Decision),
    /// The snapshot backend failed.
    Backend,
}
