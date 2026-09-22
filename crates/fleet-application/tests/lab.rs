//! The Lab use cases over fakes: pin validation, versioning with
//! provenance, and the provisioning record lifecycle.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplatePort, LabUseCaseError, NewLabTemplate, NewProvision,
    ProvisionPort,
};
use fleet_application::operation::AuditPort;
use fleet_core::{LabTemplateContent, RecipeVersion};

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

fn content(name: &str, image_version_id: &str) -> LabTemplateContent {
    LabTemplateContent {
        name: name.to_owned(),
        description: "the lab base".to_owned(),
        image_version_id: image_version_id.to_owned(),
        cores: 2,
        memory_mib: 2048,
        disk_gib: 20,
        bootstrap_project_id: None,
        readiness_probe: fleet_core::ReadinessProbe::GuestAgent,
        readiness_command: None,
        readiness_deadline_seconds: 300,
        ttl_seconds: 3_600,
        cleanup: fleet_core::CleanupStrategy::Destroy,
    }
}

#[derive(Debug, Default)]
struct FakeTemplates {
    templates: Mutex<Vec<fleet_application::lab::LabTemplate>>,
    versions: Mutex<Vec<fleet_application::lab::LabTemplateVersion>>,
}

#[async_trait]
impl LabTemplatePort for FakeTemplates {
    async fn create(
        &self,
        template: &NewLabTemplate,
        now: i64,
    ) -> Result<fleet_application::lab::LabTemplate, String> {
        let mut templates = self.templates.lock().unwrap();
        if templates
            .iter()
            .any(|existing| existing.content.name == template.content.name)
        {
            return Err(format!(
                "the template name {:?} is already taken",
                template.content.name
            ));
        }
        let stored = fleet_application::lab::LabTemplate {
            id: format!("tpl-{}", templates.len() + 1),
            content: template.content.clone(),
            published_from: None,
            created_at: now,
            updated_at: now,
        };
        templates.push(stored.clone());
        Ok(stored)
    }

    async fn get(&self, id: &str) -> Result<fleet_application::lab::LabTemplate, String> {
        self.templates
            .lock()
            .unwrap()
            .iter()
            .find(|template| template.id == id)
            .cloned()
            .ok_or_else(|| format!("template {id} not found"))
    }

    async fn list(&self) -> Result<Vec<fleet_application::lab::LabTemplate>, String> {
        Ok(self.templates.lock().unwrap().clone())
    }

    async fn update(
        &self,
        id: &str,
        content: &LabTemplateContent,
        now: i64,
    ) -> Result<fleet_application::lab::LabTemplate, String> {
        let mut templates = self.templates.lock().unwrap();
        let template = templates
            .iter_mut()
            .find(|template| template.id == id)
            .ok_or_else(|| format!("template {id} not found"))?;
        template.content = content.clone();
        template.updated_at = now;
        Ok(template.clone())
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let mut templates = self.templates.lock().unwrap();
        let before = templates.len();
        templates.retain(|template| template.id != id);
        if templates.len() == before {
            return Err(format!("template {id} not found"));
        }
        Ok(())
    }

    async fn publish(
        &self,
        _template_id: &str,
        version: &fleet_application::lab::LabTemplateVersion,
    ) -> Result<fleet_application::lab::LabTemplateVersion, String> {
        let mut versions = self.versions.lock().unwrap();
        versions.push(version.clone());
        Ok(version.clone())
    }

    async fn get_version(
        &self,
        id: &str,
    ) -> Result<fleet_application::lab::LabTemplateVersion, String> {
        self.versions
            .lock()
            .unwrap()
            .iter()
            .find(|version| version.id == id)
            .cloned()
            .ok_or_else(|| format!("version {id} not found"))
    }
}

#[derive(Debug, Default)]
struct FakeProvisions {
    records: Mutex<Vec<fleet_application::lab::ProvisionRecord>>,
}

#[async_trait]
impl ProvisionPort for FakeProvisions {
    async fn create(
        &self,
        new: &NewProvision,
        now: i64,
    ) -> Result<fleet_application::lab::ProvisionRecord, String> {
        let mut records = self.records.lock().unwrap();
        let record = fleet_application::lab::ProvisionRecord {
            id: format!("prv-{}", records.len() + 1),
            template_version_id: new.template_version_id.clone(),
            state: fleet_core::GuestState::Provisioning,
            node: None,
            vmid: None,
            clone_upid: None,
            guest_ipv4: None,
            ready_at: None,
            created_at: now,
            updated_at: now,
        };
        records.push(record.clone());
        Ok(record)
    }

    async fn get(&self, id: &str) -> Result<fleet_application::lab::ProvisionRecord, String> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|record| record.id == id)
            .cloned()
            .ok_or_else(|| format!("provision {id} not found"))
    }

    async fn update(&self, record: &fleet_application::lab::ProvisionRecord) -> Result<(), String> {
        let mut records = self.records.lock().unwrap();
        let stored = records
            .iter_mut()
            .find(|stored| stored.id == record.id)
            .ok_or_else(|| format!("provision {} not found", record.id))?;
        *stored = record.clone();
        Ok(())
    }

    async fn list(&self) -> Result<Vec<fleet_application::lab::ProvisionRecord>, String> {
        Ok(self.records.lock().unwrap().clone())
    }
}

/// The pin validator over a canned set of promoted versions.
#[derive(Debug, Default)]
struct FakePins {
    promoted: Mutex<Vec<String>>,
}

impl FakePins {
    /// The canned digest the fake reports for promoted versions.
    const DIGEST: &'static str = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabca";
}

impl FakePins {
    fn with_promoted(version_id: &str) -> Arc<Self> {
        Arc::new(Self {
            promoted: Mutex::new(vec![version_id.to_owned()]),
        })
    }
}

#[async_trait]
impl ImagePinValidator for FakePins {
    async fn promoted_version(&self, version_id: &str) -> Result<Option<RecipeVersion>, String> {
        Ok(self
            .promoted
            .lock()
            .unwrap()
            .iter()
            .any(|id| id == version_id)
            .then(|| RecipeVersion {
                id: version_id.to_owned(),
                recipe_id: "rcp-1".to_owned(),
                name: "ubuntu-base".to_owned(),
                description: String::new(),
                content_digest: Self::DIGEST.to_owned(),
                content: "{}".to_owned(),
                source: fleet_core::RecipeSource::Iso,
                node: "pve".to_owned(),
                storage_pool: "local-lvm".to_owned(),
                published_at: NOW,
                promoted_at: Some(NOW),
                promoted_by: Some("tester".to_owned()),
            }))
    }
}

#[derive(Debug, Default)]
struct FakeAudit {
    intents: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl AuditPort for FakeAudit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.intents.lock().unwrap().push(intent.clone());
        Ok(())
    }

    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

fn service(pins: Arc<dyn ImagePinValidator>) -> (Lab, Arc<FakeTemplates>, Arc<FakeAudit>) {
    let templates = Arc::new(FakeTemplates::default());
    let audit = Arc::new(FakeAudit::default());
    (
        Lab::new(
            templates.clone(),
            Arc::new(FakeProvisions::default()),
            pins,
            audit.clone(),
        ),
        templates,
        audit,
    )
}

fn service_with_pins(pins: Arc<FakePins>) -> (Lab, Arc<FakeTemplates>, Arc<FakeAudit>) {
    let templates = Arc::new(FakeTemplates::default());
    let audit = Arc::new(FakeAudit::default());
    (
        Lab::new(
            templates.clone(),
            Arc::new(FakeProvisions::default()),
            pins,
            audit.clone(),
        ),
        templates,
        audit,
    )
}

#[tokio::test]
async fn templates_walk_create_publish_with_provenance() {
    let (lab, _templates, audit) = service(FakePins::with_promoted("rcp-1@abc"));

    // An unpromoted pin is refused at create.
    let error = lab
        .create_template(
            &AllowAll,
            &principal(),
            NewLabTemplate {
                content: content("ubuntu-lab", "rcp-1@NOT-promoted"),
            },
            NOW,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, LabUseCaseError::PinRefused { .. }),
        "{error}"
    );

    // A promoted pin is accepted.
    let template = lab
        .create_template(
            &AllowAll,
            &principal(),
            NewLabTemplate {
                content: content("ubuntu-lab", "rcp-1@abc"),
            },
            NOW,
        )
        .await
        .unwrap();

    // Publish: the version carries the image digest and the publisher.
    let version = lab
        .publish_template(&AllowAll, &principal(), &template.id, NOW + 1)
        .await
        .unwrap();
    assert_eq!(version.image_digest, FakePins::DIGEST);
    assert_eq!(version.published_by, "anonymous-lan-admin");

    // The pin is re-validated at both update and publish: an unpromoted
    // image refuses at either boundary.
    let error = lab
        .update_template(
            &AllowAll,
            &principal(),
            &template.id,
            content("ubuntu-lab", "rcp-1@GONE"),
            NOW + 2,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, LabUseCaseError::PinRefused { .. }),
        "{error}"
    );

    // The flow is audited.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| intent
            .metadata
            .entries()
            .any(|(k, v)| k == "event" && v == "lab_template_publishing")),
        "{intents:?}"
    );
}

#[tokio::test]
async fn provisioning_starts_with_a_record_in_provisioning_state() {
    let (lab, _templates, _audit) = service(FakePins::with_promoted("rcp-1@abc"));
    let template = lab
        .create_template(
            &AllowAll,
            &principal(),
            NewLabTemplate {
                content: content("ubuntu-lab", "rcp-1@abc"),
            },
            NOW,
        )
        .await
        .unwrap();
    let version = lab
        .publish_template(&AllowAll, &principal(), &template.id, NOW + 1)
        .await
        .unwrap();

    let record = lab
        .start_provision(&AllowAll, &principal(), &version.id, NOW + 2)
        .await
        .unwrap();
    assert_eq!(record.state, fleet_core::GuestState::Provisioning);
    assert_eq!(record.template_version_id, version.id);

    // The record is readable and listed.
    let fetched = lab
        .get_provision(&AllowAll, &principal(), &record.id)
        .await
        .unwrap();
    assert_eq!(fetched.id, record.id);
    let listed = lab.list_provisions(&AllowAll, &principal()).await.unwrap();
    assert_eq!(listed.len(), 1);
}

#[tokio::test]
async fn provisioning_refuses_an_unpromoted_pin_at_start() {
    let pins = FakePins::with_promoted("rcp-1@abc");
    let (lab, _templates, _audit) = service_with_pins(pins.clone());
    let template = lab
        .create_template(
            &AllowAll,
            &principal(),
            NewLabTemplate {
                content: content("ubuntu-lab", "rcp-1@abc"),
            },
            NOW,
        )
        .await
        .unwrap();
    let version = lab
        .publish_template(&AllowAll, &principal(), &template.id, NOW + 1)
        .await
        .unwrap();

    // The image is demoted after publish: provisioning refuses.
    pins.promoted.lock().unwrap().clear();
    let error = lab
        .start_provision(&AllowAll, &principal(), &version.id, NOW + 2)
        .await
        .unwrap_err();
    assert!(
        matches!(error, LabUseCaseError::PinRefused { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn a_denied_caller_never_reaches_the_ports() {
    let (lab, templates, _audit) = service(FakePins::with_promoted("rcp-1@abc"));
    let error = lab
        .list_templates(&DenyAll, &principal())
        .await
        .unwrap_err();
    assert!(matches!(error, LabUseCaseError::Denied(_)));
    let error = lab
        .create_template(
            &DenyAll,
            &principal(),
            NewLabTemplate {
                content: content("ubuntu-lab", "rcp-1@abc"),
            },
            NOW,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, LabUseCaseError::Denied(_)));
    assert!(
        templates.templates.lock().unwrap().is_empty(),
        "the ports were reached despite the denial"
    );
}
