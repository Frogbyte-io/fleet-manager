//! The project use cases over fakes: normalization as identity, conflicts
//! refused, denials touching nothing, and checkout facts as observations.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::operation::{AuditPort, PortFailure};
use fleet_application::project::{
    NewProject, ProjectFilter, ProjectPort, ProjectUseCaseError, Projects,
};
use fleet_core::{CheckoutFact, NormalizedRemote, Project};

const NOW: i64 = 1_800_000_000_000;

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

#[derive(Debug, Default)]
struct AllowAll;

impl Authorizer for AllowAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

#[derive(Debug, Default)]
struct DenyAll;

impl Authorizer for DenyAll {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

/// The source over recorded projects; a switch makes it fail like the real
/// backend would.
#[derive(Debug, Default)]
struct FakeProjects {
    projects: Mutex<Vec<Project>>,
    checkouts: Mutex<Vec<CheckoutFact>>,
    keys: Mutex<Vec<(String, String)>>,
}

#[async_trait]
impl ProjectPort for FakeProjects {
    async fn create(&self, project: &NewProject) -> Result<Project, PortFailure> {
        if let Some(key) = &project.idempotency_key {
            self.keys
                .lock()
                .unwrap()
                .push((key.clone(), project.remote.clone()));
        }
        let created = Project {
            id: format!("project-{}", self.projects.lock().unwrap().len() + 1),
            remote: project.remote.clone(),
            name: project.name.clone(),
            description: project.description.clone(),
            created_at: NOW,
            updated_at: NOW,
        };
        self.projects.lock().unwrap().push(created.clone());
        Ok(created)
    }

    async fn get(&self, id: &str) -> Result<Project, PortFailure> {
        self.projects
            .lock()
            .unwrap()
            .iter()
            .find(|project| project.id == id)
            .cloned()
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("project {id:?}"),
            })
    }

    async fn list(&self, filter: &ProjectFilter, limit: u32) -> Result<Vec<Project>, PortFailure> {
        // Newest first, per the port contract.
        let mut projects: Vec<Project> = self
            .projects
            .lock()
            .unwrap()
            .iter()
            .filter(|project| {
                filter
                    .remote_prefix
                    .as_ref()
                    .is_none_or(|prefix| project.remote.starts_with(prefix))
                    && filter.name_substring.as_ref().is_none_or(|needle| {
                        project.name.to_lowercase().contains(&needle.to_lowercase())
                    })
            })
            .cloned()
            .collect();
        projects.sort_by_key(|project| std::cmp::Reverse(project.created_at));
        Ok(projects.into_iter().take(limit as usize).collect())
    }

    async fn update(
        &self,
        id: &str,
        name: &str,
        description: &str,
    ) -> Result<Project, PortFailure> {
        let mut projects = self.projects.lock().unwrap();
        let slot = projects
            .iter_mut()
            .find(|project| project.id == id)
            .ok_or_else(|| PortFailure::NotFound {
                what: format!("project {id:?}"),
            })?;
        name.clone_into(&mut slot.name);
        description.clone_into(&mut slot.description);
        Ok(slot.clone())
    }

    async fn delete(&self, id: &str) -> Result<(), PortFailure> {
        let mut projects = self.projects.lock().unwrap();
        let before = projects.len();
        projects.retain(|project| project.id != id);
        if projects.len() == before {
            return Err(PortFailure::NotFound {
                what: format!("project {id:?}"),
            });
        }
        self.checkouts
            .lock()
            .unwrap()
            .retain(|fact| fact.project_id != id);
        Ok(())
    }

    async fn record_checkout(&self, fact: &CheckoutFact) -> Result<(), PortFailure> {
        if !self
            .projects
            .lock()
            .unwrap()
            .iter()
            .any(|project| project.id == fact.project_id)
        {
            return Err(PortFailure::NotFound {
                what: format!("project {:?}", fact.project_id),
            });
        }
        self.checkouts.lock().unwrap().push(fact.clone());
        Ok(())
    }

    async fn find_by_idempotency_key(&self, key: &str) -> Result<Option<Project>, PortFailure> {
        let keys = self.keys.lock().unwrap();
        let remote = keys
            .iter()
            .find(|(stored, _)| stored == key)
            .map(|(_, remote)| remote.clone());
        drop(keys);
        match remote {
            Some(remote) => self
                .projects
                .lock()
                .unwrap()
                .iter()
                .find(|project| project.remote == remote)
                .cloned()
                .map(Some)
                .map_or_else(
                    || {
                        Err(PortFailure::NotFound {
                            what: "keyed project".to_owned(),
                        })
                    },
                    Ok,
                ),
            None => Ok(None),
        }
    }

    async fn find_by_remote(&self, remote: &str) -> Result<Option<Project>, PortFailure> {
        Ok(self
            .projects
            .lock()
            .unwrap()
            .iter()
            .find(|project| project.remote == remote)
            .cloned())
    }

    async fn checkouts(&self, project_id: &str) -> Result<Vec<CheckoutFact>, PortFailure> {
        Ok(self
            .checkouts
            .lock()
            .unwrap()
            .iter()
            .filter(|fact| fact.project_id == project_id)
            .cloned()
            .collect())
    }
}

#[derive(Debug, Default)]
struct FakeAudit {
    events: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.events.lock().unwrap().push(intent.clone());
        Ok(())
    }

    async fn record_outcome(&self, _: &str, _: AuditOutcome) -> Result<(), String> {
        Ok(())
    }
}

struct Fixture {
    projects_port: Arc<FakeProjects>,
    audit: Arc<FakeAudit>,
    projects: Projects,
}

fn compose() -> Fixture {
    let projects_port = Arc::new(FakeProjects::default());
    let audit = Arc::new(FakeAudit::default());
    let projects = Projects::new(projects_port.clone(), audit.clone());
    Fixture {
        projects_port,
        audit,
        projects,
    }
}

#[tokio::test]
async fn registration_normalizes_the_remote_and_stores_the_normalized_form() {
    let fixture = compose();
    let project = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "https://github.com/Frogbyte-io/fleet-manager.git".to_owned(),
                name: "fleet-manager".to_owned(),
                description: String::new(),
                idempotency_key: None,
            },
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        project.remote, "github.com/Frogbyte-io/fleet-manager",
        "the normalized form is the stored identity"
    );
}

#[tokio::test]
async fn the_same_repository_under_a_different_spelling_is_a_conflict() {
    let fixture = compose();
    fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "git@github.com:Frogbyte-io/fleet-manager.git".to_owned(),
                name: "fleet-manager".to_owned(),
                description: String::new(),
                idempotency_key: None,
            },
            None,
        )
        .await
        .unwrap();

    let conflict = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "https://github.com/Frogbyte-io/fleet-manager.git".to_owned(),
                name: "the-same-repo".to_owned(),
                description: String::new(),
                idempotency_key: None,
            },
            None,
        )
        .await
        .unwrap_err();
    match conflict {
        ProjectUseCaseError::Conflict { detail } => {
            assert!(
                detail.contains("github.com/Frogbyte-io/fleet-manager"),
                "the conflict names the normalized form: {detail}"
            );
        }
        other => panic!("expected a conflict, got {other:?}"),
    }
    assert_eq!(
        fixture.projects_port.projects.lock().unwrap().len(),
        1,
        "the conflicting registration created nothing"
    );
}

#[tokio::test]
async fn credential_bearing_remotes_are_refused_not_stored() {
    let fixture = compose();
    let refused = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "https://user:password@github.com/Frogbyte-io/secret.git".to_owned(),
                name: "secret".to_owned(),
                description: String::new(),
                idempotency_key: None,
            },
            None,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ProjectUseCaseError::Invalid { .. }),
        "{refused:?}"
    );
    assert!(
        fixture.audit.events.lock().unwrap().is_empty(),
        "a refused registration audits nothing"
    );
}

#[tokio::test]
async fn the_read_model_carries_the_observed_checkouts_newest_first() {
    let fixture = compose();
    let project = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "github.com/Frogbyte-io/fleet-manager".to_owned(),
                name: "fleet-manager".to_owned(),
                description: String::new(),
                idempotency_key: None,
            },
            None,
        )
        .await
        .unwrap();

    let older = CheckoutFact {
        project_id: project.id.clone(),
        machine_id: "machine-a".to_owned(),
        root: "/home/dev/code/fleet-manager".to_owned(),
        branch: Some("main".to_owned()),
        dirty: Some(false),
        source: "agentless/1".to_owned(),
        observed_at: NOW - 1_000,
    };
    let newer = CheckoutFact {
        project_id: project.id.clone(),
        machine_id: "machine-b".to_owned(),
        root: "/srv/work/fleet-manager".to_owned(),
        branch: Some("feature/x".to_owned()),
        dirty: Some(true),
        source: "agentless/1".to_owned(),
        observed_at: NOW,
    };
    for fact in [&older, &newer] {
        fixture
            .projects
            .record_checkout(&AllowAll, &principal(), fact.clone())
            .await
            .unwrap();
    }

    let view = fixture
        .projects
        .get(&AllowAll, &principal(), &project.id)
        .await
        .unwrap();
    assert_eq!(view.checkouts.len(), 2);
    assert_eq!(
        view.checkouts[0].machine_id, "machine-b",
        "newest observation first"
    );
}

#[tokio::test]
async fn deleting_a_project_removes_its_checkouts_but_touches_nothing_else() {
    let fixture = compose();
    let project = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "github.com/Frogbyte-io/fleet-manager".to_owned(),
                name: "fleet-manager".to_owned(),
                description: String::new(),
                idempotency_key: None,
            },
            None,
        )
        .await
        .unwrap();
    fixture
        .projects
        .record_checkout(
            &AllowAll,
            &principal(),
            CheckoutFact {
                project_id: project.id.clone(),
                machine_id: "machine-a".to_owned(),
                root: "/home/dev/code/fleet-manager".to_owned(),
                branch: Some("main".to_owned()),
                dirty: Some(false),
                source: "agentless/1".to_owned(),
                observed_at: NOW,
            },
        )
        .await
        .unwrap();

    fixture
        .projects
        .delete(&AllowAll, &principal(), &project.id)
        .await
        .unwrap();
    assert!(fixture.projects_port.projects.lock().unwrap().is_empty());
    assert!(fixture.projects_port.checkouts.lock().unwrap().is_empty());
    assert_eq!(
        fixture.audit.events.lock().unwrap().len(),
        2,
        "create + delete audited"
    );
}

#[tokio::test]
async fn denied_callers_are_refused_without_touching_anything() {
    let fixture = compose();
    let deny = DenyAll;
    assert!(matches!(
        fixture
            .projects
            .register(
                &deny,
                &principal(),
                NewProject {
                    remote: "github.com/a/b".to_owned(),
                    name: "x".to_owned(),
                    description: String::new(),
                    idempotency_key: None,
                },
                None,
            )
            .await,
        Err(ProjectUseCaseError::Denied(_))
    ));
    assert!(matches!(
        fixture
            .projects
            .list(&deny, &principal(), &ProjectFilter::default(), 10)
            .await,
        Err(ProjectUseCaseError::Denied(_))
    ));
    assert!(matches!(
        fixture
            .projects
            .delete(&deny, &principal(), "project-1")
            .await,
        Err(ProjectUseCaseError::Denied(_))
    ));
    assert!(fixture.projects_port.projects.lock().unwrap().is_empty());
    assert!(fixture.audit.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_malformed_registration_is_refused_before_any_write() {
    let fixture = compose();
    let cases = [
        NewProject {
            remote: "https://".to_owned(),
            name: "x".to_owned(),
            description: String::new(),
            idempotency_key: None,
        },
        NewProject {
            remote: "github.com/a/b".to_owned(),
            name: String::new(),
            description: String::new(),
            idempotency_key: None,
        },
        NewProject {
            remote: "github.com/a/b".to_owned(),
            name: "x".to_owned(),
            description: "d".repeat(600),
            idempotency_key: None,
        },
    ];
    for new in cases {
        let refused = fixture
            .projects
            .register(&AllowAll, &principal(), new, None)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, ProjectUseCaseError::Invalid { .. }),
            "{refused:?}"
        );
    }
    assert!(fixture.projects_port.projects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_list_narrows_by_remote_prefix_and_name_substring() {
    let fixture = compose();
    for (remote, name) in [
        ("github.com/Frogbyte-io/fleet-manager", "fleet-manager"),
        ("github.com/Frogbyte-io/other", "other"),
        ("gitlab.com/someone/thing", "thing"),
    ] {
        fixture
            .projects
            .register(
                &AllowAll,
                &principal(),
                NewProject {
                    remote: remote.to_owned(),
                    name: name.to_owned(),
                    description: String::new(),
                    idempotency_key: None,
                },
                None,
            )
            .await
            .unwrap();
    }

    let github = fixture
        .projects
        .list(
            &AllowAll,
            &principal(),
            &ProjectFilter {
                remote_prefix: Some("github.com/".to_owned()),
                name_substring: None,
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(github.len(), 2, "only the github projects match");

    let named = fixture
        .projects
        .list(
            &AllowAll,
            &principal(),
            &ProjectFilter {
                remote_prefix: None,
                name_substring: Some("MANAGER".to_owned()),
            },
            50,
        )
        .await
        .unwrap();
    assert_eq!(named.len(), 1, "the name filter is case-insensitive");
    assert_eq!(named[0].name, "fleet-manager");
}

#[tokio::test]
async fn an_idempotent_replay_returns_the_original_project() {
    let fixture = compose();
    let key = "anonymous-lan-admin:create-1";
    let first = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "github.com/Frogbyte-io/fleet-manager".to_owned(),
                name: "fleet-manager".to_owned(),
                description: String::new(),
                idempotency_key: Some(key.to_owned()),
            },
            Some(key.to_owned()),
        )
        .await
        .unwrap();

    // A replay with the same caller-scoped key returns the original project
    // instead of a conflict.
    let replay = fixture
        .projects
        .register(
            &AllowAll,
            &principal(),
            NewProject {
                remote: "git@github.com:Frogbyte-io/fleet-manager.git".to_owned(),
                name: "a-different-name".to_owned(),
                description: String::new(),
                idempotency_key: Some(key.to_owned()),
            },
            Some(key.to_owned()),
        )
        .await
        .unwrap();
    assert_eq!(replay.id, first.id);
    assert_eq!(replay.name, first.name);
    assert_eq!(
        fixture.projects_port.projects.lock().unwrap().len(),
        1,
        "the replay created nothing"
    );
}

#[test]
fn the_normalized_remote_type_is_the_identity_anchor() {
    let a = NormalizedRemote::parse("git@github.com:Frogbyte-io/fleet-manager.git").unwrap();
    let b = NormalizedRemote::parse("https://github.com/Frogbyte-io/fleet-manager").unwrap();
    assert_eq!(a, b, "spellings fold to one identity");
}
