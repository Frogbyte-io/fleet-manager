//! Server-side planning (FM-407, ADR 0013) over the real stores: the plan
//! is computed from the active revision and the machine's observations,
//! its id is a content digest, and applying by id refuses a stale plan.

use std::sync::Arc;

use fleet_application::authz::{AccessRequest, Authorizer, Decision, ReasonId};
use fleet_application::catalog_installs::{CatalogInstall, CatalogInstallPort as _};
use fleet_application::machine::{MachinePort as _, NewEndpoint, RegisterMachine};
use fleet_application::observed_assembly::ObservedStateAssembler;
use fleet_application::planning::{Planning, PlanningError};
use fleet_application::skills::{SkillsAvailability, SkillsPort as _, SkillsSnapshot};
use fleet_application::source::{ActiveRevision, DesiredResourceRecord, SourcePort as _};
use fleet_core::{DifferenceState, EndpointKind};
use fleet_storage_sqlite::{
    AuditSink, MachineRepository, ProjectRepository, SkillCatalogRepository, SkillsRepository,
    SourceRepository, Store,
};

const NOW: i64 = 5_000_000_000;

#[derive(Debug)]
struct Deny;
impl Authorizer for Deny {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    store: Store,
    planning: Planning,
    machine_id: String,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("fleet.db")).await.unwrap();
    let pool = store.pool().clone();
    let machines = MachineRepository::new(pool.clone());
    let machine = machines
        .register(&RegisterMachine {
            name: "box".to_owned(),
            description: String::new(),
            endpoints: vec![NewEndpoint {
                kind: EndpointKind::Ssh,
                reference: "ops@box.lan:22".to_owned(),
            }],
            tags: vec!["dev".to_owned()],
            groups: vec!["lab".to_owned()],
        })
        .await
        .unwrap();
    let assembler = ObservedStateAssembler::new(
        Arc::new(MachineRepository::new(pool.clone())),
        Arc::new(SkillsRepository::new(pool.clone())),
        Arc::new(ProjectRepository::new(pool.clone())),
    )
    .with_catalog_installs(Arc::new(SkillsRepository::new(pool.clone())));
    let planning = Planning::new(
        Arc::new(SourceRepository::new(pool.clone())),
        Arc::new(machines),
        assembler,
        Arc::new(SkillCatalogRepository::new(pool.clone())),
        Arc::new(AuditSink::new(pool)),
    );
    Harness {
        _dir: dir,
        store,
        planning,
        machine_id: machine.id,
    }
}

fn preset(
    id: &str,
    skill: &str,
    scope: serde_json::Value,
    deploy_to: &[&str],
) -> DesiredResourceRecord {
    DesiredResourceRecord {
        kind: "SkillPreset".to_owned(),
        id: id.to_owned(),
        name: id.to_owned(),
        spec: serde_json::json!({"skillId": skill, "scope": scope, "deployTo": deploy_to, "denyAgents": []}),
    }
}

impl Harness {
    async fn activate(&self, sha: &str, resources: &[DesiredResourceRecord]) {
        let source = SourceRepository::new(self.store.pool().clone());
        let revision = ActiveRevision {
            commit_sha: sha.to_owned(),
            content_digest: format!("digest-{sha}"),
        };
        source
            .record_valid_revision(&revision, resources)
            .await
            .unwrap();
        source.activate_serialized(&revision).await.unwrap();
    }

    async fn observe_skills(&self, deployed: &[(&str, &[&str])]) {
        let skills: Vec<_> = deployed
            .iter()
            .map(|(id, agents)| serde_json::json!({"id": id, "deployedTo": agents}))
            .collect();
        SkillsRepository::new(self.store.pool().clone())
            .record(&SkillsSnapshot {
                machine_id: self.machine_id.clone(),
                availability: SkillsAvailability::Available,
                cli_version: None,
                data: serde_json::json!({ "skills": skills }),
                update_check: "complete".to_owned(),
                observed_at: NOW - 1000,
            })
            .await
            .unwrap();
    }

    async fn plan(&self) -> fleet_application::planning::ComputedPlan {
        self.planning
            .create_plan(
                &fleet_auth::LanAllowAllAuthorizer,
                fleet_auth::LAN_PRINCIPAL_ID,
                &self.machine_id,
                NOW,
            )
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn no_active_revision_means_no_plan() {
    let harness = harness().await;
    let error = harness
        .planning
        .create_plan(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            &harness.machine_id,
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, PlanningError::NoActiveRevision), "{error}");
}

#[tokio::test]
async fn a_matching_preset_plans_a_deploy_and_others_do_not() {
    let harness = harness().await;
    harness
        .activate(
            "aaa",
            &[
                preset(
                    "p-all",
                    "db",
                    serde_json::json!({"type": "all"}),
                    &["codex"],
                ),
                preset(
                    "p-group",
                    "lab-only",
                    serde_json::json!({"type": "group", "value": "lab"}),
                    &["claude_code"],
                ),
                preset(
                    "p-other",
                    "elsewhere",
                    serde_json::json!({"type": "group", "value": "prod"}),
                    &["codex"],
                ),
                preset(
                    "p-mine",
                    "mine",
                    serde_json::json!({"type": "machine", "value": "not-this-machine"}),
                    &["codex"],
                ),
            ],
        )
        .await;
    harness.observe_skills(&[]).await;
    let computed = harness.plan().await;
    let identities: Vec<_> = computed
        .plan
        .actions
        .iter()
        .map(|a| (a.kind.as_str(), a.difference.identity.as_str()))
        .collect();
    assert_eq!(
        identities,
        [
            ("skills.deploy", "skill:db/codex"),
            ("skills.deploy", "skill:lab-only/claude_code"),
        ]
    );
    assert_eq!(computed.revision.commit_sha, "aaa");
    // Deterministic: the same inputs yield the same identity.
    assert_eq!(harness.plan().await.plan_id, computed.plan_id);
}

#[tokio::test]
async fn only_skills_fleet_git_manages_can_be_undeployed() {
    let harness = harness().await;
    harness
        .activate(
            "aaa",
            &[
                // Managed, but scoped to another group: deployed here is drift.
                preset(
                    "p-old",
                    "old",
                    serde_json::json!({"type": "group", "value": "prod"}),
                    &["codex"],
                ),
            ],
        )
        .await;
    harness
        .observe_skills(&[("old", &["codex"]), ("hand-installed", &["codex"])])
        .await;
    let computed = harness.plan().await;
    let undeploys: Vec<_> = computed
        .plan
        .actions
        .iter()
        .filter(|a| a.kind == "skills.undeploy")
        .map(|a| a.difference.identity.as_str())
        .collect();
    assert_eq!(undeploys, ["skill:old/codex"]);
    let hand = computed
        .plan
        .unactionable
        .iter()
        .find(|d| d.identity == "skill:hand-installed/codex")
        .expect("the unmanaged skill is reported");
    assert_eq!(hand.state, DifferenceState::Unsupported);
    assert!(hand.reason.as_deref().unwrap().contains("will not remove"));
}

fn catalog_diffs(
    computed: &fleet_application::planning::ComputedPlan,
) -> Vec<(String, DifferenceState)> {
    computed
        .plan
        .actions
        .iter()
        .map(|a| &a.difference)
        .chain(computed.plan.unactionable.iter())
        .filter(|d| d.identity.starts_with("catalog-skill:"))
        .map(|d| (d.identity.clone(), d.state))
        .collect()
}

impl Harness {
    async fn builtin_version(&self) -> String {
        use fleet_application::skill_catalog::SkillCatalogPort as _;
        SkillCatalogRepository::new(self.store.pool().clone())
            .get(fleet_core::BUILTIN_FLEET_SKILL_CATALOG_ID)
            .await
            .unwrap()
            .published_from
            .expect("the built-in is published")
    }

    async fn record_install(&self, version: &str, agent: &str, skill: &str, at: i64) {
        SkillsRepository::new(self.store.pool().clone())
            .record_installs(&[CatalogInstall {
                machine_id: self.machine_id.clone(),
                catalog_id: fleet_core::BUILTIN_FLEET_SKILL_CATALOG_ID.to_owned(),
                version_id: version.to_owned(),
                agent: agent.to_owned(),
                skill_name: skill.to_owned(),
                installed_at: at,
            }])
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn the_builtin_skill_deploys_through_a_reviewed_plan_and_converges() {
    let harness = harness().await;
    fleet_controller::builtin_skills::seed_builtin_skills(harness.store.pool(), NOW)
        .await
        .unwrap();
    harness.activate("aaa", &[]).await;
    harness.observe_skills(&[]).await;

    // Nothing installed: the pinned version is missing and planned.
    let computed = harness.plan().await;
    let rollouts: Vec<_> = computed
        .plan
        .actions
        .iter()
        .filter(|a| a.kind == "skills.catalog-rollout")
        .collect();
    assert_eq!(rollouts.len(), 2, "claude_code and codex: {computed:?}");
    let version = harness.builtin_version().await;
    assert!(rollouts.iter().all(|a| {
        a.difference.state == DifferenceState::Missing
            && a.difference.desired.as_deref() == Some(version.as_str())
    }));

    // An older Fleet install is changed, still planned as a rollout.
    harness.observe_skills(&[("fleet", &["codex"])]).await;
    harness
        .record_install("builtin-fleet@old", "codex", "fleet", NOW - 2000)
        .await;
    let changed = catalog_diffs(&harness.plan().await);
    assert!(changed.contains(&(
        "catalog-skill:builtin-fleet/codex".to_owned(),
        DifferenceState::Changed
    )));
    assert!(changed.contains(&(
        "catalog-skill:builtin-fleet/claude_code".to_owned(),
        DifferenceState::Missing
    )));

    // The pinned version installed everywhere: no drift, nothing planned.
    harness
        .observe_skills(&[("fleet", &["codex", "claude_code"])])
        .await;
    harness
        .record_install(&version, "codex", "fleet", NOW - 2000)
        .await;
    harness
        .record_install(&version, "claude_code", "fleet", NOW - 2000)
        .await;
    let synced = harness.plan().await;
    assert!(catalog_diffs(&synced).is_empty(), "{synced:?}");
    assert!(synced.plan.actions.is_empty(), "{synced:?}");

    // The skill removed from the machine invalidates the record: planned again.
    harness.observe_skills(&[]).await;
    let removed = catalog_diffs(&harness.plan().await);
    assert_eq!(removed.len(), 2);
    assert!(
        removed
            .iter()
            .all(|(_, state)| *state == DifferenceState::Missing)
    );

    // An unreadable machine (stale snapshot) never counts as in sync.
    SkillsRepository::new(harness.store.pool().clone())
        .record(&SkillsSnapshot {
            machine_id: harness.machine_id.clone(),
            availability: SkillsAvailability::Available,
            cli_version: None,
            data: serde_json::json!({"skills": [{"id": "fleet", "deployedTo": ["codex", "claude_code"]}]}),
            update_check: "complete".to_owned(),
            observed_at: NOW - 30 * 60 * 60 * 1000,
        })
        .await
        .unwrap();
    let stale = catalog_diffs(&harness.plan().await);
    assert!(
        stale
            .iter()
            .all(|(_, state)| *state == DifferenceState::Unknown)
    );
    assert_eq!(stale.len(), 2);

    // Git taking the skill over with an empty deployTo removes the default.
    harness
        .activate(
            "bbb",
            &[preset(
                "p-fleet",
                "fleet",
                serde_json::json!({"type": "all"}),
                &[],
            )],
        )
        .await;
    assert!(catalog_diffs(&harness.plan().await).is_empty());
}

#[tokio::test]
async fn an_installed_catalog_version_fleet_does_not_manage_is_reported_never_removed() {
    let harness = harness().await;
    harness.activate("aaa", &[]).await;
    harness.observe_skills(&[("other", &["codex"])]).await;
    SkillsRepository::new(harness.store.pool().clone())
        .record_installs(&[CatalogInstall {
            machine_id: harness.machine_id.clone(),
            catalog_id: "catalog-x".to_owned(),
            version_id: "catalog-x@1".to_owned(),
            agent: "codex".to_owned(),
            skill_name: "other".to_owned(),
            installed_at: NOW - 2000,
        }])
        .await
        .unwrap();
    let computed = harness.plan().await;
    assert!(computed.plan.actions.is_empty(), "{computed:?}");
    let reported = catalog_diffs(&computed);
    assert_eq!(
        reported,
        [(
            "catalog-skill:catalog-x/codex".to_owned(),
            DifferenceState::Unsupported
        )]
    );
}

#[tokio::test]
async fn applying_by_id_refuses_a_plan_that_went_stale() {
    let harness = harness().await;
    harness
        .activate(
            "aaa",
            &[preset(
                "p-all",
                "db",
                serde_json::json!({"type": "all"}),
                &["codex"],
            )],
        )
        .await;
    harness.observe_skills(&[]).await;
    let reviewed = harness.plan().await;
    let auth = fleet_auth::LanAllowAllAuthorizer;

    let same = harness
        .planning
        .resolve_for_apply(
            &auth,
            fleet_auth::LAN_PRINCIPAL_ID,
            &harness.machine_id,
            &reviewed.plan_id,
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(same, reviewed);

    // An observation changes what would be done.
    harness.observe_skills(&[("db", &["codex"])]).await;
    let error = harness
        .planning
        .resolve_for_apply(
            &auth,
            fleet_auth::LAN_PRINCIPAL_ID,
            &harness.machine_id,
            &reviewed.plan_id,
            NOW,
        )
        .await
        .unwrap_err();
    let PlanningError::Stale { requested, current } = error else {
        panic!("expected a stale plan");
    };
    assert_eq!(requested, reviewed.plan_id);
    assert_ne!(current, requested);

    // A new revision also invalidates a reviewed plan.
    harness.observe_skills(&[]).await;
    harness
        .activate(
            "bbb",
            &[preset(
                "p-all",
                "db",
                serde_json::json!({"type": "all"}),
                &["codex"],
            )],
        )
        .await;
    assert!(matches!(
        harness
            .planning
            .resolve_for_apply(
                &auth,
                fleet_auth::LAN_PRINCIPAL_ID,
                &harness.machine_id,
                &reviewed.plan_id,
                NOW
            )
            .await,
        Err(PlanningError::Stale { .. })
    ));
    // A forged id never matches.
    assert!(matches!(
        harness
            .planning
            .resolve_for_apply(
                &auth,
                fleet_auth::LAN_PRINCIPAL_ID,
                &harness.machine_id,
                "forged",
                NOW
            )
            .await,
        Err(PlanningError::Stale { .. })
    ));
}

#[tokio::test]
async fn planning_is_authorized_and_audited() {
    let harness = harness().await;
    harness
        .activate(
            "aaa",
            &[preset(
                "p-all",
                "db",
                serde_json::json!({"type": "all"}),
                &["codex"],
            )],
        )
        .await;
    let audits = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM audit_events WHERE action = 'apply.execute'",
        )
        .fetch_one(harness.store.pool())
        .await
        .unwrap()
    };
    let denied = harness
        .planning
        .create_plan(
            &Deny,
            fleet_auth::LAN_PRINCIPAL_ID,
            &harness.machine_id,
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(denied, PlanningError::Denied(_)));
    assert_eq!(audits().await, 0, "a denied request records no plan");
    let computed = harness.plan().await;
    assert_eq!(audits().await, 1);
    let metadata: String =
        sqlx::query_scalar("SELECT metadata_json FROM audit_events WHERE action = 'apply.execute'")
            .fetch_one(harness.store.pool())
            .await
            .unwrap();
    assert!(metadata.contains(&computed.plan_id), "{metadata}");
    let unknown = harness
        .planning
        .create_plan(
            &fleet_auth::LanAllowAllAuthorizer,
            fleet_auth::LAN_PRINCIPAL_ID,
            "no-such-machine",
            NOW,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(unknown, PlanningError::UnknownMachine),
        "{unknown}"
    );
}
