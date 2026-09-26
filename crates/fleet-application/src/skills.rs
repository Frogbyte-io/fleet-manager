//! Read-only Skills Manager observations and their authorization boundary.

#![warn(missing_docs)]

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, authorize};
use crate::operation::PortFailure;

/// One machine's desired Fleet-managed skills and their drift, suitable
/// for the skill matrix and an overview attention projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillMatrixRow {
    /// The stable Fleet machine identity.
    pub machine_id: String,
    /// Desired skill/agent pairs after scope composition.
    pub desired: Vec<(String, String)>,
    /// Desired catalog version/agent triples.
    pub catalog_skills: Vec<(String, String, String)>,
    /// Drift against the supplied normalized observation.
    pub differences: fleet_core::DifferenceSet,
}

/// Builds the skill matrix and attention data for one machine from Fleet
/// assignments and a normalized observation. `None` means the machine is
/// offline; stale observations remain unknown and unavailable CLIs remain
/// unsupported, so neither case can become an apply step.
///
/// # Errors
///
/// Returns an error for ambiguous identities or conflicting catalog pins.
pub fn skill_matrix_row(
    target: &crate::composition::MachineSkillTarget,
    assignments: &[crate::composition::SkillAssignment],
    observed: Option<&crate::observed::ObservedState>,
) -> Result<SkillMatrixRow, crate::composition::SkillAssignmentCompositionError> {
    let composed = crate::composition::compose_skill_assignments(target, assignments)?;
    let offline_observation;
    let observed = if let Some(observed) = observed {
        observed
    } else {
        offline_observation = crate::observed::ObservedState {
            skills_availability: Some(crate::observed::SkillsObservationAvailability::Offline),
            ..crate::observed::ObservedState::default()
        };
        &offline_observation
    };
    let desired = crate::observed::DesiredState {
        skills: composed.skills.clone(),
        catalog_skills: composed.catalog_skills.clone(),
        ..crate::observed::DesiredState::default()
    };
    Ok(SkillMatrixRow {
        machine_id: target.machine_id.clone(),
        desired: composed.skills,
        catalog_skills: composed.catalog_skills,
        differences: crate::observed::compare(&desired, observed),
    })
}

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
        let page_size = usize::try_from(limit).unwrap_or(usize::MAX);
        let fetch_limit = limit.saturating_add(1);
        let mut scan_cursor = after_machine_id.map(str::to_owned);
        let mut visible = Vec::new();
        let mut has_more = false;

        // Fill the public page with authorized rows. Advance an internal
        // scan cursor over denied rows, but expose only a cursor for the last
        // row returned to this caller.
        loop {
            let rows = self
                .port
                .list(scan_cursor.as_deref(), fetch_limit)
                .await
                .map_err(|_| SkillsError::Backend)?;
            let count = rows.len();
            if count == 0 {
                break;
            }
            for row in rows {
                if scan_cursor
                    .as_deref()
                    .is_some_and(|cursor| row.machine_id.as_str() <= cursor)
                {
                    return Err(SkillsError::Backend);
                }
                scan_cursor = Some(row.machine_id.clone());
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
                    if visible.len() == page_size {
                        has_more = true;
                        break;
                    }
                    visible.push(view(row, now));
                }
            }
            if has_more || count < usize::try_from(fetch_limit).unwrap_or(usize::MAX) {
                break;
            }
        }
        let next_cursor = has_more
            .then(|| visible.last().map(|row| row.snapshot.machine_id.clone()))
            .flatten();
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

#[cfg(test)]
mod assignment_projection_tests {
    use super::skill_matrix_row;
    use crate::composition::{
        MachineSkillTarget, ProvenanceRecord, SkillAssignment, SkillAssignmentScope,
    };
    use crate::observed::{ObservedState, SkillsObservationAvailability};

    fn assignment() -> SkillAssignment {
        SkillAssignment {
            skill_id: "global-help".into(),
            deploy_to: vec!["codex".into()],
            deny_agents: vec![],
            catalog_version: None,
            scope: SkillAssignmentScope::All,
            provenance: ProvenanceRecord {
                resource_id: "assignment-1".into(),
                resource_name: "global-help".into(),
                path: "/spec".into(),
            },
        }
    }

    fn target() -> MachineSkillTarget {
        MachineSkillTarget {
            machine_id: "machine-1".into(),
            groups: vec![],
            tags: vec![],
        }
    }

    #[test]
    fn matrix_projection_shows_drift_for_available_cli_and_keeps_offline_queued() {
        let fresh = ObservedState {
            skills_answered: Some(true),
            skills_availability: Some(SkillsObservationAvailability::Available),
            ..ObservedState::default()
        };
        let fresh_row = skill_matrix_row(&target(), &[assignment()], Some(&fresh)).unwrap();
        assert_eq!(
            fresh_row.differences.fields[0].state,
            fleet_core::DifferenceState::Missing
        );
        let offline_row = skill_matrix_row(&target(), &[assignment()], None).unwrap();
        assert_eq!(
            offline_row.differences.fields[0].state,
            fleet_core::DifferenceState::Unknown
        );
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
