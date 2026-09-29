//! Fleet's own record of which pinned catalog skill version it installed
//! on a machine (FM-411).
//!
//! Skills Manager does not report a Fleet catalog version, and its private
//! files are not an interface, so the only trustworthy source is what Fleet
//! itself verified: a successful `skills.catalog-rollout` records the
//! (machine, catalog id, agent) it installed. A later skills probe keeps a
//! record only while the fresh inventory still shows the skill deployed to
//! that agent; a removed or undeployed skill invalidates it.
#![warn(missing_docs)]

use async_trait::async_trait;

use crate::operation::PortFailure;
use crate::skills::{SkillsAvailability, SkillsSnapshot};

/// One verified catalog installation on a machine for an agent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogInstall {
    /// The machine the version was installed on.
    pub machine_id: String,
    /// The catalog entry.
    pub catalog_id: String,
    /// The immutable catalog version installed (`<catalogId>@<sha256>`).
    pub version_id: String,
    /// The agent the skill was deployed to.
    pub agent: String,
    /// The skill's name in Skills Manager, used to check it is still present.
    pub skill_name: String,
    /// When Fleet verified the installation (epoch milliseconds).
    pub installed_at: i64,
}

/// Persistence of verified catalog installations.
#[async_trait]
pub trait CatalogInstallPort: Send + Sync {
    /// Records installations, replacing any earlier record for the same
    /// (machine, catalog id, agent).
    async fn record_installs(&self, installs: &[CatalogInstall]) -> Result<(), PortFailure>;
    /// A machine's recorded installations.
    async fn list_installs(&self, machine_id: &str) -> Result<Vec<CatalogInstall>, PortFailure>;
    /// Removes a record, unless a newer installation replaced it after
    /// `installed_at_or_before`.
    async fn remove_install(
        &self,
        machine_id: &str,
        catalog_id: &str,
        agent: &str,
        installed_at_or_before: i64,
    ) -> Result<(), PortFailure>;
}

/// Whether a record still holds against a snapshot.
///
/// - A snapshot taken before the installation cannot contradict it.
/// - An `unsupported` CLI cannot answer, so the record is neither confirmed
///   nor contradicted here (the assembler leaves the observation unanswered).
/// - An `absent` CLI has no skills, so every earlier record is invalid.
/// - An `available` inventory must list the skill deployed to the agent.
#[must_use]
pub fn install_holds(install: &CatalogInstall, snapshot: &SkillsSnapshot) -> bool {
    if snapshot.observed_at < install.installed_at {
        return true;
    }
    match snapshot.availability {
        SkillsAvailability::Unsupported => true,
        SkillsAvailability::Absent => false,
        SkillsAvailability::Available => snapshot
            .data
            .get("skills")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|skill| {
                skill.get("id").and_then(serde_json::Value::as_str)
                    == Some(install.skill_name.as_str())
            })
            .flat_map(|skill| {
                skill
                    .get("deployedTo")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .any(|agent| agent.as_str() == Some(install.agent.as_str())),
    }
}

/// Drops the records a fresh snapshot invalidates, for its machine.
///
/// # Errors
///
/// Fails when the store cannot be read or written.
pub async fn prune_installs(
    port: &dyn CatalogInstallPort,
    snapshot: &SkillsSnapshot,
) -> Result<(), PortFailure> {
    for install in port.list_installs(&snapshot.machine_id).await? {
        if !install_holds(&install, snapshot) {
            port.remove_install(
                &install.machine_id,
                &install.catalog_id,
                &install.agent,
                snapshot.observed_at,
            )
            .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CatalogInstall, install_holds};
    use crate::skills::{SkillsAvailability, SkillsSnapshot};

    fn install(at: i64) -> CatalogInstall {
        CatalogInstall {
            machine_id: "m".into(),
            catalog_id: "c".into(),
            version_id: "c@1".into(),
            agent: "codex".into(),
            skill_name: "fleet".into(),
            installed_at: at,
        }
    }

    fn snapshot(
        availability: SkillsAvailability,
        at: i64,
        skills: &serde_json::Value,
    ) -> SkillsSnapshot {
        SkillsSnapshot {
            machine_id: "m".into(),
            availability,
            cli_version: None,
            data: serde_json::json!({ "skills": skills }),
            update_check: "complete".into(),
            observed_at: at,
        }
    }

    #[test]
    fn an_install_holds_only_while_the_skill_is_deployed_to_the_agent() {
        let deployed = serde_json::json!([{"id": "fleet", "deployedTo": ["codex"]}]);
        let other_agent = serde_json::json!([{"id": "fleet", "deployedTo": ["claude_code"]}]);
        let removed = serde_json::json!([{"id": "db", "deployedTo": ["codex"]}]);
        let available = SkillsAvailability::Available;
        assert!(install_holds(
            &install(10),
            &snapshot(available.clone(), 20, &deployed)
        ));
        assert!(!install_holds(
            &install(10),
            &snapshot(available.clone(), 20, &other_agent)
        ));
        assert!(!install_holds(
            &install(10),
            &snapshot(available, 20, &removed)
        ));
        assert!(!install_holds(
            &install(10),
            &snapshot(SkillsAvailability::Absent, 20, &serde_json::json!([]))
        ));
        assert!(install_holds(
            &install(10),
            &snapshot(SkillsAvailability::Unsupported, 20, &serde_json::json!([]))
        ));
    }

    #[test]
    fn a_snapshot_older_than_the_install_cannot_invalidate_it() {
        let empty = serde_json::json!([]);
        assert!(install_holds(
            &install(30),
            &snapshot(SkillsAvailability::Available, 20, &empty)
        ));
    }
}
