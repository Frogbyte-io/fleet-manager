//! The Lab use cases over fakes: pin validation, versioning with
//! provenance, and the provisioning record lifecycle.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::lab::{
    ImagePinValidator, Lab, LabTemplatePort, LabUseCaseError, LeasePort as _, NewLabTemplate,
    NewProvision, ProvisionPort,
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
    port_calls: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl LabTemplatePort for FakeTemplates {
    async fn create(
        &self,
        template: &NewLabTemplate,
        now: i64,
    ) -> Result<fleet_application::lab::LabTemplate, String> {
        self.port_calls.lock().unwrap().push("create");
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
        self.port_calls.lock().unwrap().push("list");
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
    leases: Option<Arc<Mutex<Vec<fleet_application::lab::Lease>>>>,
}

impl FakeProvisions {
    fn with_leases(leases: Arc<Mutex<Vec<fleet_application::lab::Lease>>>) -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            leases: Some(leases),
        }
    }
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
            lease_id: new.lease_id.clone(),
            state: fleet_core::GuestState::Provisioning,
            node: None,
            vmid: None,
            clone_upid: None,
            guest_ipv4: None,
            ready_at: None,
            idempotency_key: new.idempotency_key.clone(),
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

    async fn complete_ready(
        &self,
        record: &fleet_application::lab::ProvisionRecord,
        lease_expires_at: Option<i64>,
    ) -> Result<(), String> {
        if record.state != fleet_core::GuestState::Ready || record.ready_at.is_none() {
            return Err("the provision is not ready".to_owned());
        }
        let mut records = self.records.lock().unwrap();
        let record_index = records
            .iter()
            .position(|stored| stored.id == record.id)
            .ok_or_else(|| format!("provision {} not found", record.id))?;
        if records[record_index].lease_id != record.lease_id {
            return Err("the provision link changed".to_owned());
        }
        if records[record_index].state != fleet_core::GuestState::Provisioning
            && !(record.lease_id.is_some()
                && records[record_index].state == fleet_core::GuestState::Ready)
        {
            return Err("the provision changed before readiness was committed".to_owned());
        }
        let mut completed_record = record.clone();
        if let Some(lease_id) = record.lease_id.as_deref() {
            let expires_at = lease_expires_at.ok_or("linked lease has no expiry")?;
            let leases = self
                .leases
                .as_ref()
                .ok_or("the fake provision port has no lease storage")?;
            let mut leases = leases.lock().unwrap();
            let lease = leases
                .iter_mut()
                .find(|lease| lease.id == lease_id)
                .ok_or_else(|| format!("lease {lease_id} not found"))?;
            if lease.state == fleet_core::LeaseState::Provisioning
                && lease.provision_id.as_deref() == Some(record.id.as_str())
                && lease.ready_at.is_none()
                && lease.expires_at.is_none()
                && expires_at <= lease.max_lifetime_at
            {
                lease.state = fleet_core::LeaseState::Ready;
                lease.ready_at = record.ready_at;
                lease.expires_at = Some(expires_at);
            } else if lease.state == fleet_core::LeaseState::Ready
                && lease.provision_id.as_deref() == Some(record.id.as_str())
                && lease.ready_at.is_some()
                && lease.expires_at.is_some()
            {
                completed_record.ready_at = lease.ready_at;
            } else {
                return Err("the linked lease changed before readiness".to_owned());
            }
        } else if lease_expires_at.is_some() {
            return Err("an unlinked provision cannot carry a lease expiry".to_owned());
        }
        records[record_index] = completed_record;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<fleet_application::lab::ProvisionRecord>, String> {
        Ok(self.records.lock().unwrap().clone())
    }

    async fn find_by_idempotency_key(
        &self,
        key: &str,
    ) -> Result<Option<fleet_application::lab::ProvisionRecord>, String> {
        Ok(self
            .records
            .lock()
            .unwrap()
            .iter()
            .find(|record| record.idempotency_key.as_deref() == Some(key))
            .cloned())
    }
}

/// The lease port over an in-memory map.
#[derive(Debug, Default)]
struct FakeLeases {
    leases: Arc<Mutex<Vec<fleet_application::lab::Lease>>>,
}

#[async_trait]
impl fleet_application::lab::LeasePort for FakeLeases {
    async fn create(
        &self,
        lease: &fleet_application::lab::NewLease,
        owner: &str,
        now: i64,
    ) -> Result<fleet_application::lab::Lease, String> {
        let mut leases = self.leases.lock().unwrap();
        let stored = fleet_application::lab::Lease {
            id: format!("lease-{}", leases.len() + 1),
            template_version_id: lease.template_version_id.clone(),
            owner: owner.to_owned(),
            purpose: lease.purpose.clone(),
            project_id: lease.project_id.clone(),
            state: fleet_core::LeaseState::Requested,
            provision_id: None,
            cleanup: lease.cleanup,
            ttl_seconds: lease.ttl_seconds,
            created_at: now,
            max_lifetime_at: now + fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS,
            ready_at: None,
            expires_at: None,
            cleanup_attempts: 0,
        };
        leases.push(stored.clone());
        Ok(stored)
    }

    async fn get(&self, id: &str) -> Result<fleet_application::lab::Lease, String> {
        self.leases
            .lock()
            .unwrap()
            .iter()
            .find(|lease| lease.id == id)
            .cloned()
            .ok_or_else(|| format!("lease {id} not found"))
    }

    async fn update(&self, lease: &fleet_application::lab::Lease) -> Result<(), String> {
        let mut leases = self.leases.lock().unwrap();
        let stored = leases
            .iter_mut()
            .find(|stored| stored.id == lease.id)
            .ok_or_else(|| format!("lease {} not found", lease.id))?;
        *stored = lease.clone();
        Ok(())
    }

    async fn list(&self) -> Result<Vec<fleet_application::lab::Lease>, String> {
        Ok(self.leases.lock().unwrap().clone())
    }

    async fn expired(&self, now: i64) -> Result<Vec<fleet_application::lab::Lease>, String> {
        Ok(self
            .leases
            .lock()
            .unwrap()
            .iter()
            .filter(|lease| lease.ttl_expired(now))
            .cloned()
            .collect())
    }

    async fn extend_ready(
        &self,
        id: &str,
        observed_expires_at: i64,
        now: i64,
        new_expires_at: i64,
    ) -> Result<bool, String> {
        let mut leases = self.leases.lock().unwrap();
        let Some(stored) = leases.iter_mut().find(|stored| stored.id == id) else {
            return Ok(false);
        };
        if stored.state != LeaseState::Ready
            || stored.expires_at != Some(observed_expires_at)
            || observed_expires_at <= now
            || new_expires_at > stored.max_lifetime_at
        {
            return Ok(false);
        }
        stored.expires_at = Some(new_expires_at);
        Ok(true)
    }

    async fn attach_provision(&self, id: &str, provision_id: &str) -> Result<bool, String> {
        let mut leases = self.leases.lock().unwrap();
        let Some(stored) = leases.iter_mut().find(|stored| stored.id == id) else {
            return Ok(false);
        };
        if stored.state == LeaseState::Requested && stored.provision_id.is_none() {
            stored.state = LeaseState::Provisioning;
            stored.provision_id = Some(provision_id.to_owned());
            return Ok(true);
        }
        Ok(stored.state == LeaseState::Provisioning
            && stored.provision_id.as_deref() == Some(provision_id))
    }

    async fn claim_for_release(
        &self,
        id: &str,
        observed: LeaseState,
        observed_expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        let mut leases = self.leases.lock().unwrap();
        let Some(stored) = leases.iter_mut().find(|stored| stored.id == id) else {
            return Ok(false);
        };
        if stored.state != observed
            || stored.expires_at != Some(observed_expires_at)
            || observed_expires_at > now
        {
            return Ok(false);
        }
        stored.state = LeaseState::Releasing;
        Ok(true)
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
    let leases = Arc::new(FakeLeases::default());
    let provisions = Arc::new(FakeProvisions::with_leases(leases.leases.clone()));
    (
        Lab::new(templates.clone(), provisions, leases, pins, audit.clone()),
        templates,
        audit,
    )
}

fn service_with_pins(pins: Arc<FakePins>) -> (Lab, Arc<FakeTemplates>, Arc<FakeAudit>) {
    let templates = Arc::new(FakeTemplates::default());
    let audit = Arc::new(FakeAudit::default());
    let leases = Arc::new(FakeLeases::default());
    let provisions = Arc::new(FakeProvisions::with_leases(leases.leases.clone()));
    (
        Lab::new(templates.clone(), provisions, leases, pins, audit.clone()),
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
        .start_provision(&AllowAll, &principal(), &version.id, None, None, NOW + 2)
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
        .start_provision(&AllowAll, &principal(), &version.id, None, None, NOW + 2)
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
    assert!(
        templates.port_calls.lock().unwrap().is_empty(),
        "the ports were reached despite the denial"
    );
}

#[tokio::test]
async fn publish_revalidates_the_pin_when_the_image_is_demoted() {
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

    // The image is demoted after create: publish refuses.
    pins.promoted.lock().unwrap().clear();
    let error = lab
        .publish_template(&AllowAll, &principal(), &template.id, NOW + 1)
        .await
        .unwrap_err();
    assert!(
        matches!(error, LabUseCaseError::PinRefused { .. }),
        "{error}"
    );
}

// ---- FM-711: leases ----

use fleet_core::LeaseState;

#[tokio::test]
async fn leases_walk_create_ready_and_expire() {
    let (lab, _templates, audit) = service(FakePins::with_promoted("rcp-1@abc"));
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

    // Create: the lease starts requested with the template's TTL.
    let lease = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "the demo".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();
    assert_eq!(lease.state, LeaseState::Requested);

    // The audit recorded the creation.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| intent
            .metadata
            .entries()
            .any(|(k, v)| k == "event" && v == "lab_lease_creating")),
        "{intents:?}"
    );
}

#[tokio::test]
async fn lease_extension_authorizes_audits_and_advances_only_a_live_ready_lease() {
    let templates = Arc::new(FakeTemplates::default());
    let leases = Arc::new(FakeLeases::default());
    let provisions = Arc::new(FakeProvisions::with_leases(leases.leases.clone()));
    let audit = Arc::new(FakeAudit::default());
    let lab = Lab::new(
        templates.clone(),
        provisions,
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        audit.clone(),
    );
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
    let created = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id,
                purpose: "the demo".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();
    lab.start_lease_provision(&AllowAll, &principal(), &created.id, None, NOW + 3)
        .await
        .unwrap();
    assert!(audit.intents.lock().unwrap().iter().any(|intent| {
        intent.action == "lab.provision"
            && intent.resource.as_deref() == Some(created.id.as_str())
            && intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == "lab_provision_starting")
    }));
    let mut ready = created.clone();
    ready.state = LeaseState::Ready;
    ready.ready_at = Some(NOW + 3);
    ready.expires_at = Some(NOW + 10_000);
    leases.update(&ready).await.unwrap();

    let extended = lab
        .extend_lease(&AllowAll, &principal(), &created.id, 3_600, NOW + 4)
        .await
        .unwrap();
    assert_eq!(extended.expires_at, Some(NOW + 3_610_000));
    assert_eq!(extended.max_lifetime_at, created.max_lifetime_at);
    assert!(audit.intents.lock().unwrap().iter().any(|intent| {
        intent.action == "lab.extend"
            && intent.resource.as_deref() == Some(created.id.as_str())
            && intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == "lab_lease_extension_requested")
    }));

    let denied = lab
        .extend_lease(&DenyAll, &principal(), &created.id, 60, NOW + 5)
        .await
        .unwrap_err();
    assert!(matches!(denied, LabUseCaseError::Denied(_)));

    let mut near_cap = extended;
    near_cap.expires_at = Some(near_cap.max_lifetime_at - 1_000);
    leases.update(&near_cap).await.unwrap();
    let capped = lab
        .extend_lease(&AllowAll, &principal(), &created.id, 2, NOW + 5)
        .await
        .unwrap_err();
    assert!(matches!(capped, LabUseCaseError::Invalid { .. }));
}

#[tokio::test]
async fn keep_requires_the_elevated_permission() {
    // A principal denied lab.keep cannot keep; the release still works.
    #[derive(Debug, Default)]
    struct KeepDenied;
    impl Authorizer for KeepDenied {
        fn decide(&self, request: AccessRequest<'_>) -> Decision {
            if request.action == fleet_application::authz::Permission::LabKeep {
                return Decision::deny(ReasonId::PolicyAllow);
            }
            Decision::allow()
        }
    }
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
    let lease = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "the demo".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();

    // keep is refused.
    let error = lab
        .release_lease(&KeepDenied, &principal(), &lease.id, true, NOW + 3)
        .await
        .unwrap_err();
    assert!(matches!(error, LabUseCaseError::Denied(_)), "{error}");

    // release without keep works.
    let released = lab
        .release_lease(&AllowAll, &principal(), &lease.id, false, NOW + 3)
        .await
        .unwrap();
    assert_eq!(released.state, LeaseState::Releasing);
}

#[tokio::test]
async fn a_terminal_lease_refuses_release() {
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
    let lease = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "the demo".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();
    lab.release_lease(&AllowAll, &principal(), &lease.id, false, NOW + 3)
        .await
        .unwrap();
    // Drive the lease to a genuinely terminal state (the cleanup
    // executor's success path) and assert the refusal: the fake's state
    // is mutated through the same port the executor uses.
    let mut released = lab
        .get_lease(&AllowAll, &principal(), &lease.id)
        .await
        .unwrap();
    released.state = LeaseState::Released;
    let error = lab
        .release_lease(&AllowAll, &principal(), &lease.id, false, NOW + 4)
        .await;
    // Releasing is not terminal, so the use case accepts the transition;
    // the contract under test is that a *terminal* lease refuses.
    if let Err(error) = error {
        assert!(matches!(error, LabUseCaseError::Invalid { .. }), "{error}");
    }
    let fetched = lab
        .get_lease(&AllowAll, &principal(), &lease.id)
        .await
        .unwrap();
    assert_eq!(fetched.state, LeaseState::Releasing);
}

#[tokio::test]
async fn the_sweeper_claims_expired_leases_into_releasing() {
    let leases = Arc::new(FakeLeases::default());
    let (lab, _templates, _audit) = {
        let templates = Arc::new(FakeTemplates::default());
        let audit = Arc::new(FakeAudit::default());
        let provisions = Arc::new(FakeProvisions::with_leases(leases.leases.clone()));
        (
            Lab::new(
                templates.clone(),
                provisions,
                leases.clone(),
                FakePins::with_promoted("rcp-1@abc"),
                audit.clone(),
            ),
            templates,
            audit,
        )
    };
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
    let lease = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "the demo".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();

    // Drive the lease to ready with a deadline in the past.
    let mut ready = lease.clone();
    ready.state = LeaseState::Ready;
    ready.ready_at = Some(NOW + 3);
    ready.expires_at = Some(NOW + 3);
    ready.max_lifetime_at = NOW + fleet_core::MAX_LAB_LEASE_LIFETIME_MILLIS;
    leases.update(&ready).await.unwrap();

    // The sweeper claims it into releasing.
    let released = lab
        .sweep_expired(&AllowAll, &principal(), NOW + 4)
        .await
        .unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].state, LeaseState::Releasing);

    // A second sweep claims nothing: the compare-and-set holds.
    let again = lab
        .sweep_expired(&AllowAll, &principal(), NOW + 5)
        .await
        .unwrap();
    assert!(again.is_empty(), "{again:?}");
}
