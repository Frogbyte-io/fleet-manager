//! Server-side planning (FM-407, ADR 0013): the controller computes a
//! machine's plan from the active desired revision and the machine's
//! observed state, and a plan's identity is a digest of its content.
//!
//! Composition covers what desired state binds to machines today: skill
//! assignments (including the built-in default, ADR 0012), selected by
//! each assignment's scope against the machine's groups and tags. Tool
//! versions and checkouts need a machine-to-profile/project binding the
//! schema does not have yet, so they are not composed here.
//!
//! Two safety rules shape the result:
//!
//! - An observed skill that no `SkillPreset` names is not Fleet's to
//!   remove. It is reported as unactionable, never planned for undeploy;
//!   only skills Fleet Git manages can be undeployed by a plan.
//! - The plan id is the SHA-256 of the machine, the active revision, and
//!   the ordered actions. Applying by id recomputes the plan and refuses
//!   when the id no longer matches, so a reviewed plan runs only if it is
//!   still exactly what the controller would compute.
#![warn(missing_docs)]

use std::collections::BTreeSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authz::{AccessRequest, Authorizer, Decision, Permission, authorize};
use crate::composition::{
    BuiltinSkillAssignment, DEFAULT_BUILTIN_SKILL_AGENTS, MachineSkillTarget, ProvenanceRecord,
    SkillAssignment, SkillAssignmentScope, compose_skill_assignments, with_builtin_assignments,
};
use crate::machine::MachinePort;
use crate::observed::{DesiredState, compare};
use crate::observed_assembly::{ObservedAssemblyError, ObservedStateAssembler};
use crate::operation::{AuditPort, PortFailure};
use crate::planner::{Plan, plan};
use crate::skill_catalog::SkillCatalogPort;
use crate::source::{ActiveRevision, DesiredResourceRecord, SourcePort};
use fleet_core::{DifferenceSet, DifferenceState};

/// The resources are read in pages of this size.
const RESOURCE_PAGE: i64 = 500;
/// A revision with more skill presets than this is refused rather than
/// planned from a partial read.
const MAX_SKILL_PRESETS: usize = 5_000;

/// A plan the controller computed, with the identity that binds approvals
/// and apply to exactly this content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComputedPlan {
    /// The content digest identifying this plan.
    pub plan_id: String,
    /// The machine the plan is for.
    pub machine_id: String,
    /// The desired revision the plan was computed against.
    pub revision: ActiveRevision,
    /// The ordered actions and the differences the planner refused to act on.
    pub plan: Plan,
}

/// What drift computation found for one machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DriftOutcome {
    /// Drift was computed against the active revision. Only fields that
    /// differ are listed; a field absent from the list is in sync.
    Computed {
        /// The revision the machine was compared with.
        revision: ActiveRevision,
        /// The differences: actionable ones first (in plan order), then
        /// the `unknown` and `unsupported` ones the planner will not act on.
        differences: Vec<fleet_core::FieldDifference>,
    },
    /// No desired revision is active, so nothing can drift.
    NoRevision,
    /// Drift could not be computed for this machine.
    Unavailable {
        /// Why, caller-safe.
        detail: String,
    },
}

/// One machine's drift.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriftEntry {
    /// The machine.
    pub machine_id: String,
    /// The machine's current name.
    pub machine_name: String,
    /// What was found.
    pub outcome: DriftOutcome,
}

/// One page of fleet drift, newest machines first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DriftPage {
    /// The entries for machines the caller may read.
    pub entries: Vec<DriftEntry>,
    /// The cursor for the next page, when more machines follow.
    pub next_cursor: Option<String>,
}

/// Why a plan could not be computed or applied.
#[derive(Debug)]
pub enum PlanningError {
    /// The caller may not plan for this machine.
    Denied(Decision),
    /// The machine is not registered.
    UnknownMachine,
    /// No desired revision is active, so there is nothing to converge toward.
    NoActiveRevision,
    /// The active revision's resources are not held (activated before
    /// snapshots existed); fetch it again.
    ResourcesUnavailable,
    /// The recomputed plan differs from the one the caller reviewed.
    Stale {
        /// The id the caller asked to apply.
        requested: String,
        /// The id the controller computes now.
        current: String,
    },
    /// The desired resources could not be composed.
    Composition(String),
    /// A store failed.
    Backend {
        /// Which store.
        context: &'static str,
        /// The failure detail.
        detail: String,
    },
}

impl std::fmt::Display for PlanningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied(decision) => write!(f, "denied: {decision}"),
            Self::UnknownMachine => write!(f, "the machine is not registered"),
            Self::NoActiveRevision => write!(
                f,
                "no desired revision is active; fetch and activate one first"
            ),
            Self::ResourcesUnavailable => write!(
                f,
                "the active revision holds no resource snapshot; fetch it again"
            ),
            Self::Stale { requested, current } => write!(
                f,
                "the plan {requested} is stale; the controller now computes {current}. Plan again"
            ),
            Self::Composition(detail) => write!(f, "desired state could not be composed: {detail}"),
            Self::Backend { context, detail } => {
                write!(f, "planning failed reading {context}: {detail}")
            }
        }
    }
}

impl std::error::Error for PlanningError {}

/// The planning use cases.
#[derive(Clone)]
pub struct Planning {
    source: Arc<dyn SourcePort>,
    machines: Arc<dyn MachinePort>,
    assembler: ObservedStateAssembler,
    catalog: Arc<dyn SkillCatalogPort>,
    audit: Arc<dyn AuditPort>,
}

impl std::fmt::Debug for Planning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Planning").finish_non_exhaustive()
    }
}

impl Planning {
    /// Composes the use cases from the stores they read.
    #[must_use]
    pub fn new(
        source: Arc<dyn SourcePort>,
        machines: Arc<dyn MachinePort>,
        assembler: ObservedStateAssembler,
        catalog: Arc<dyn SkillCatalogPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            source,
            machines,
            assembler,
            catalog,
            audit,
        }
    }

    /// Computes and audits a plan for the machine.
    ///
    /// # Errors
    ///
    /// Fails on denial, an unknown machine, no active revision, or a
    /// failing store.
    pub async fn create_plan(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        machine_id: &str,
        now: i64,
    ) -> Result<ComputedPlan, PlanningError> {
        Self::authorize(authorizer, principal_id, machine_id)?;
        let computed = self.compute(machine_id, now).await?;
        let mut metadata = crate::audit::AuditMetadata::default();
        for (key, value) in [
            ("event", "apply_plan_created"),
            ("planId", computed.plan_id.as_str()),
            ("commitSha", computed.revision.commit_sha.as_str()),
        ] {
            metadata
                .insert(key, value)
                .map_err(|error| PlanningError::Backend {
                    context: "audit",
                    detail: error.to_string(),
                })?;
        }
        self.audit
            .record_intent(&crate::audit::AuditIntent {
                actor: principal_id.to_owned(),
                action: Permission::ApplyExecute.id().to_owned(),
                resource: Some(machine_id.to_owned()),
                decision: Decision::allow(),
                correlation_id: None,
                operation_id: None,
                metadata,
            })
            .await
            .map_err(|detail| PlanningError::Backend {
                context: "audit",
                detail,
            })?;
        Ok(computed)
    }

    /// Recomputes the plan and returns it only when it is still the plan
    /// the caller reviewed.
    ///
    /// # Errors
    ///
    /// Fails like [`create_plan`](Self::create_plan), and with
    /// [`PlanningError::Stale`] when the plan changed.
    pub async fn resolve_for_apply(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        machine_id: &str,
        plan_id: &str,
        now: i64,
    ) -> Result<ComputedPlan, PlanningError> {
        Self::authorize(authorizer, principal_id, machine_id)?;
        let computed = self.compute(machine_id, now).await?;
        if computed.plan_id == plan_id {
            Ok(computed)
        } else {
            Err(PlanningError::Stale {
                requested: plan_id.to_owned(),
                current: computed.plan_id,
            })
        }
    }

    /// One machine's drift against the active revision. Reading drift
    /// needs `skills.read` for the machine, as the Skills matrix does.
    ///
    /// # Errors
    ///
    /// Fails on denial or an unknown machine; every other failure is
    /// reported in the entry's outcome.
    pub async fn machine_drift(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        machine_id: &str,
        now: i64,
    ) -> Result<DriftEntry, PlanningError> {
        Self::authorize_read(authorizer, principal_id, machine_id)?;
        let machine = self.machines.get(machine_id).await.map_err(|failure| {
            if matches!(failure, PortFailure::NotFound { .. }) {
                PlanningError::UnknownMachine
            } else {
                PlanningError::Backend {
                    context: "machine",
                    detail: failure_detail(failure),
                }
            }
        })?;
        Ok(self.entry_for(&machine.id, &machine.name, now).await)
    }

    /// Drift across the machines the caller may read, one page at a time.
    /// A machine whose drift cannot be computed is reported as such and
    /// never fails the page.
    ///
    /// # Errors
    ///
    /// Fails when the machine list cannot be read.
    pub async fn drift_page(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        cursor: Option<&str>,
        limit: u32,
        now: i64,
    ) -> Result<DriftPage, PlanningError> {
        let mut machines = self
            .machines
            .list(
                &crate::machine::MachineFilter {
                    cursor: cursor.map(str::to_owned),
                    ..crate::machine::MachineFilter::default()
                },
                limit.saturating_add(1),
            )
            .await
            .map_err(|failure| PlanningError::Backend {
                context: "machines",
                detail: failure_detail(failure),
            })?;
        let more = machines.len() > limit as usize;
        machines.truncate(limit as usize);
        let next_cursor = more
            .then(|| machines.last().map(|machine| machine.id.clone()))
            .flatten();
        let mut entries = Vec::new();
        for machine in &machines {
            if Self::authorize_read(authorizer, principal_id, &machine.id).is_err() {
                continue;
            }
            entries.push(self.entry_for(&machine.id, &machine.name, now).await);
        }
        Ok(DriftPage {
            entries,
            next_cursor,
        })
    }

    async fn entry_for(&self, machine_id: &str, name: &str, now: i64) -> DriftEntry {
        let outcome = match self.compute(machine_id, now).await {
            Ok(computed) => DriftOutcome::Computed {
                revision: computed.revision,
                differences: computed
                    .plan
                    .actions
                    .into_iter()
                    .map(|action| action.difference)
                    .chain(computed.plan.unactionable)
                    .collect(),
            },
            Err(PlanningError::NoActiveRevision) => DriftOutcome::NoRevision,
            Err(PlanningError::Backend { context, .. }) => DriftOutcome::Unavailable {
                detail: format!(
                    "reading the {context} failed; the detail is in the controller log"
                ),
            },
            Err(other) => DriftOutcome::Unavailable {
                detail: other.to_string(),
            },
        };
        DriftEntry {
            machine_id: machine_id.to_owned(),
            machine_name: name.to_owned(),
            outcome,
        }
    }

    fn authorize_read(
        authorizer: &dyn Authorizer,
        principal_id: &str,
        machine_id: &str,
    ) -> Result<(), PlanningError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::SkillsRead,
                resource: Some(machine_id),
            },
        )
        .map(|_| ())
        .map_err(PlanningError::Denied)
    }

    fn authorize(
        authorizer: &dyn Authorizer,
        principal_id: &str,
        machine_id: &str,
    ) -> Result<(), PlanningError> {
        authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::ApplyExecute,
                resource: Some(machine_id),
            },
        )
        .map(|_| ())
        .map_err(PlanningError::Denied)
    }

    async fn compute(&self, machine_id: &str, now: i64) -> Result<ComputedPlan, PlanningError> {
        let backend = |context| move |detail: String| PlanningError::Backend { context, detail };
        let summary = self
            .source
            .active_summary()
            .await
            .map_err(backend("desired revision"))?
            .ok_or(PlanningError::NoActiveRevision)?;
        if !summary.snapshot_held {
            return Err(PlanningError::ResourcesUnavailable);
        }
        let machine = self.machines.get(machine_id).await.map_err(|failure| {
            if matches!(failure, PortFailure::NotFound { .. }) {
                PlanningError::UnknownMachine
            } else {
                PlanningError::Backend {
                    context: "machine",
                    detail: failure_detail(failure),
                }
            }
        })?;
        let presets = self.skill_presets().await?;
        let managed: BTreeSet<String> = presets.iter().map(|p| p.skill_id.clone()).collect();
        let builtins = self.builtins().await?;
        // Catalog entries a SkillPreset pins, plus the shipped built-in, are
        // the ones Fleet manages; other installed catalog versions are
        // reported, never removed.
        let managed_catalogs: BTreeSet<String> = presets
            .iter()
            .filter_map(|p| p.catalog_version.as_ref().map(|(id, _)| id.clone()))
            .chain(builtins.iter().map(|b| b.catalog_id.clone()))
            .collect();
        let assignments = with_builtin_assignments(&presets, &builtins);
        let composed = compose_skill_assignments(
            &MachineSkillTarget {
                machine_id: machine.id.clone(),
                groups: machine.groups.clone(),
                tags: machine.tags.clone(),
            },
            &assignments,
        )
        .map_err(|error| PlanningError::Composition(format!("{error:?}")))?;
        let desired = DesiredState {
            skills: composed.skills,
            catalog_skills: composed.catalog_skills,
            ..DesiredState::default()
        };
        let observed =
            self.assembler
                .assemble(machine_id, now)
                .await
                .map_err(|error| match error {
                    ObservedAssemblyError::UnknownMachine => PlanningError::UnknownMachine,
                    ObservedAssemblyError::Backend { context, detail } => {
                        PlanningError::Backend { context, detail }
                    }
                })?;
        let computed = split_unmanaged(compare(&desired, &observed), &managed, &managed_catalogs);
        let mut resolved = plan(&computed.0);
        resolved.unactionable.extend(computed.1);
        let revision = summary.revision;
        Ok(ComputedPlan {
            plan_id: plan_id(machine_id, &revision, &resolved),
            machine_id: machine_id.to_owned(),
            revision,
            plan: resolved,
        })
    }

    /// The active revision's skill presets as assignments.
    async fn skill_presets(&self) -> Result<Vec<SkillAssignment>, PlanningError> {
        let mut assignments = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let page = self
                .source
                .active_resources(Some("SkillPreset"), after.as_deref(), RESOURCE_PAGE)
                .await
                .map_err(|detail| PlanningError::Backend {
                    context: "desired resources",
                    detail,
                })?;
            let Some(last) = page.last() else {
                return Ok(assignments);
            };
            after = Some(last.id.clone());
            for record in &page {
                assignments.push(assignment_from(record)?);
            }
            if assignments.len() > MAX_SKILL_PRESETS {
                return Err(PlanningError::Composition(format!(
                    "the active revision has more than {MAX_SKILL_PRESETS} skill presets"
                )));
            }
        }
    }

    /// The built-in skills this release ships, pinned to their published
    /// version. A catalog without the built-in entry has none.
    async fn builtins(&self) -> Result<Vec<BuiltinSkillAssignment>, PlanningError> {
        let id = fleet_core::BUILTIN_FLEET_SKILL_CATALOG_ID;
        let entry = match self.catalog.get(id).await {
            Ok(entry) => entry,
            Err(detail) if detail.contains("not found") => return Ok(Vec::new()),
            Err(detail) => {
                return Err(PlanningError::Backend {
                    context: "skill catalog",
                    detail,
                });
            }
        };
        Ok(entry
            .published_from
            .map(|version| BuiltinSkillAssignment {
                skill_id: entry.content.name,
                catalog_id: id.to_owned(),
                catalog_version_id: version,
                deploy_to: DEFAULT_BUILTIN_SKILL_AGENTS
                    .iter()
                    .map(|agent| (*agent).to_owned())
                    .collect(),
            })
            .into_iter()
            .collect())
    }
}

fn failure_detail(failure: PortFailure) -> String {
    match failure {
        PortFailure::NotFound { what } => what,
        PortFailure::Conflict { detail } | PortFailure::Backend { detail } => detail,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PresetSpec {
    skill_id: String,
    #[serde(default)]
    catalog_id: Option<String>,
    #[serde(default)]
    catalog_version_id: Option<String>,
    #[serde(default = "all_scope")]
    scope: SkillAssignmentScope,
    #[serde(default)]
    deploy_to: Vec<String>,
    #[serde(default)]
    deny_agents: Vec<String>,
}

fn all_scope() -> SkillAssignmentScope {
    SkillAssignmentScope::All
}

fn assignment_from(record: &DesiredResourceRecord) -> Result<SkillAssignment, PlanningError> {
    let spec: PresetSpec = serde_json::from_value(record.spec.clone()).map_err(|error| {
        PlanningError::Composition(format!(
            "the SkillPreset {} is not readable: {error}",
            record.id
        ))
    })?;
    Ok(SkillAssignment {
        skill_id: spec.skill_id,
        deploy_to: spec.deploy_to,
        deny_agents: spec.deny_agents,
        catalog_version: spec.catalog_id.zip(spec.catalog_version_id),
        scope: spec.scope,
        provenance: ProvenanceRecord {
            resource_id: record.id.clone(),
            resource_name: record.name.clone(),
            path: "/spec".to_owned(),
        },
    })
}

/// Separates the observed-only skills Fleet does not manage: they stay in
/// the report as unactionable, and never reach the planner as an undeploy.
fn split_unmanaged(
    set: DifferenceSet,
    managed: &BTreeSet<String>,
    managed_catalogs: &BTreeSet<String>,
) -> (DifferenceSet, Vec<fleet_core::FieldDifference>) {
    let mut kept = DifferenceSet::new();
    let mut unmanaged = Vec::new();
    for difference in set.fields {
        let unmanaged_extra = difference.state == DifferenceState::Extra
            && (difference
                .identity
                .strip_prefix("skill:")
                .and_then(|rest| rest.split('/').next())
                .is_some_and(|skill_id| !managed.contains(skill_id))
                || difference
                    .identity
                    .strip_prefix("catalog-skill:")
                    .and_then(|rest| rest.split('/').next())
                    .is_some_and(|catalog_id| !managed_catalogs.contains(catalog_id)));
        if unmanaged_extra {
            let mut difference = difference;
            difference.state = DifferenceState::Unsupported;
            difference.reason = Some(
                "no SkillPreset in Fleet Git manages this skill; Fleet will not remove it"
                    .to_owned(),
            );
            unmanaged.push(difference);
        } else {
            kept.push(difference);
        }
    }
    unmanaged.sort_by(|a, b| a.identity.cmp(&b.identity));
    (kept, unmanaged)
}

/// The content digest that identifies a plan.
fn plan_id(machine_id: &str, revision: &ActiveRevision, plan: &Plan) -> String {
    let canonical = serde_json::json!({
        "machineId": machine_id,
        "commitSha": revision.commit_sha,
        "contentDigest": revision.content_digest,
        "actions": plan.actions,
    });
    format!("{:x}", Sha256::digest(canonical.to_string().as_bytes()))
}
