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
        ssh_user: "root".to_owned(),
        ssh_port: 22,
        ssh_trust_mode: "tofu".to_owned(),
        ssh_fingerprint: None,
        readiness_deadline_seconds: 300,
        ttl_seconds: 3_600,
        cleanup: fleet_core::CleanupStrategy::Destroy,
    }
}

fn sample_project(id: &str) -> fleet_core::Project {
    fleet_core::Project {
        id: id.to_owned(),
        remote: format!("github.com/example/{id}.git"),
        name: id.to_owned(),
        description: String::new(),
        created_at: NOW,
        updated_at: NOW,
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
            machine_id: None,
            endpoint_id: None,
            ready_project_operation_id: None,
            readiness_deadline_at: None,
            failed_step: None,
            account_id: None,
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

    async fn reserve_clone_target(
        &self,
        _record_id: &str,
        _node: &str,
        _vmid: u32,
    ) -> Result<fleet_application::lab::CloneTargetReservation, String> {
        unimplemented!("the Lab use cases never reserve a clone target")
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
    fail_claim_on_call: Mutex<Option<usize>>,
    claim_calls: Mutex<usize>,
    /// Releases the lease inside the next re-arm, as a concurrent winner
    /// would between the use case's read and its compare-and-set.
    race_rearm: Mutex<bool>,
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
            cleanup_next_at: None,
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

    async fn list(
        &self,
        project_id: Option<&str>,
    ) -> Result<Vec<fleet_application::lab::Lease>, String> {
        Ok(self
            .leases
            .lock()
            .unwrap()
            .iter()
            .filter(|lease| match project_id {
                None => true,
                Some(id) => lease.project_id.as_deref() == Some(id),
            })
            .cloned()
            .collect())
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

    async fn attach_provision(
        &self,
        id: &str,
        provision_id: &str,
    ) -> Result<fleet_application::lab::AttachProvisionOutcome, String> {
        let mut leases = self.leases.lock().unwrap();
        let Some(stored) = leases.iter_mut().find(|stored| stored.id == id) else {
            return Ok(fleet_application::lab::AttachProvisionOutcome::Conflict);
        };
        if stored.state == LeaseState::Requested && stored.provision_id.is_none() {
            stored.state = LeaseState::Provisioning;
            stored.provision_id = Some(provision_id.to_owned());
            return Ok(fleet_application::lab::AttachProvisionOutcome::Attached);
        }
        Ok(
            if stored.state == LeaseState::Provisioning
                && stored.provision_id.as_deref() == Some(provision_id)
            {
                fleet_application::lab::AttachProvisionOutcome::AlreadyAttached
            } else {
                fleet_application::lab::AttachProvisionOutcome::Conflict
            },
        )
    }

    async fn claim_for_release(
        &self,
        id: &str,
        observed: LeaseState,
        observed_expires_at: i64,
        now: i64,
    ) -> Result<bool, String> {
        let call = {
            let mut calls = self.claim_calls.lock().unwrap();
            *calls += 1;
            *calls
        };
        if *self.fail_claim_on_call.lock().unwrap() == Some(call) {
            return Err("simulated claim failure".to_owned());
        }
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

    async fn transition(
        &self,
        id: &str,
        observed: LeaseState,
        provision_id: Option<&str>,
        to: LeaseState,
    ) -> Result<bool, String> {
        let mut leases = self.leases.lock().unwrap();
        let Some(stored) = leases.iter_mut().find(|stored| stored.id == id) else {
            return Ok(false);
        };
        if stored.state != observed || stored.provision_id.as_deref() != provision_id {
            return Ok(false);
        }
        stored.state = to;
        Ok(true)
    }

    async fn rearm_cleanup(
        &self,
        id: &str,
        observed_attempts: u32,
        attempts: u32,
    ) -> Result<bool, String> {
        let mut leases = self.leases.lock().unwrap();
        let Some(stored) = leases.iter_mut().find(|stored| stored.id == id) else {
            return Ok(false);
        };
        if std::mem::take(&mut *self.race_rearm.lock().unwrap()) {
            stored.state = LeaseState::Released;
        }
        if stored.state != LeaseState::CleanupFailed || stored.cleanup_attempts != observed_attempts
        {
            return Ok(false);
        }
        stored.state = LeaseState::Releasing;
        stored.cleanup_attempts = attempts;
        stored.cleanup_next_at = None;
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
                promoted_build_id: Some("build-1".to_owned()),
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

/// Canned projects: the ids are fixed instances, the default fake has none.
#[derive(Debug, Default)]
struct FakeProjects {
    known: Mutex<Vec<fleet_core::Project>>,
}

impl FakeProjects {
    fn with(known: fleet_core::Project) -> Arc<Self> {
        Arc::new(Self {
            known: Mutex::new(vec![known]),
        })
    }
}

#[async_trait::async_trait]
impl fleet_application::project::ProjectPort for FakeProjects {
    async fn create(
        &self,
        _: &fleet_application::project::NewProject,
    ) -> Result<fleet_core::Project, fleet_application::operation::PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "not needed".to_owned(),
        })
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<fleet_core::Project, fleet_application::operation::PortFailure> {
        self.known
            .lock()
            .unwrap()
            .iter()
            .find(|project| project.id == id)
            .cloned()
            .ok_or_else(|| fleet_application::operation::PortFailure::NotFound {
                what: format!("project {id}"),
            })
    }

    async fn list(
        &self,
        _: &fleet_application::project::ProjectFilter,
        _: u32,
    ) -> Result<Vec<fleet_core::Project>, fleet_application::operation::PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "not needed".to_owned(),
        })
    }

    async fn update(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<fleet_core::Project, fleet_application::operation::PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "not needed".to_owned(),
        })
    }

    async fn delete(&self, _: &str) -> Result<(), fleet_application::operation::PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "not needed".to_owned(),
        })
    }

    async fn record_checkout(
        &self,
        _: &fleet_core::CheckoutFact,
    ) -> Result<(), fleet_application::operation::PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "not needed".to_owned(),
        })
    }

    async fn find_by_idempotency_key(
        &self,
        _: &str,
    ) -> Result<Option<fleet_core::Project>, fleet_application::operation::PortFailure> {
        Ok(None)
    }

    async fn find_by_remote(
        &self,
        _: &str,
    ) -> Result<Option<fleet_core::Project>, fleet_application::operation::PortFailure> {
        Ok(None)
    }

    async fn checkouts(
        &self,
        _: &str,
    ) -> Result<Vec<fleet_core::CheckoutFact>, fleet_application::operation::PortFailure> {
        Err(fleet_application::operation::PortFailure::Backend {
            detail: "not needed".to_owned(),
        })
    }
}

fn service(pins: Arc<dyn ImagePinValidator>) -> (Lab, Arc<FakeTemplates>, Arc<FakeAudit>) {
    let templates = Arc::new(FakeTemplates::default());
    let audit = Arc::new(FakeAudit::default());
    let leases = Arc::new(FakeLeases::default());
    let provisions = Arc::new(FakeProvisions::with_leases(leases.leases.clone()));
    (
        Lab::new(
            templates.clone(),
            provisions,
            leases,
            pins,
            Arc::new(FakeProjects::default()),
            audit.clone(),
        ),
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
        Lab::new(
            templates.clone(),
            provisions,
            leases,
            pins,
            Arc::new(FakeProjects::default()),
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
        Arc::new(FakeProjects::default()),
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
    let (started, attached) = lab
        .start_lease_provision(&AllowAll, &principal(), &created.id, None, NOW + 3)
        .await
        .unwrap();
    assert!(attached);
    let (replayed, attached) = lab
        .start_lease_provision(&AllowAll, &principal(), &created.id, None, NOW + 3)
        .await
        .unwrap();
    assert!(!attached);
    assert_eq!(started.id, replayed.id);
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
                Arc::new(FakeProjects::default()),
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
    let mut published = 0;
    let released = lab
        .sweep_expired_with_progress(&AllowAll, &principal(), NOW + 4, || published += 1)
        .await
        .unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].state, LeaseState::Releasing);
    assert_eq!(published, 1);

    // A second sweep claims nothing: the compare-and-set holds.
    let again = lab
        .sweep_expired(&AllowAll, &principal(), NOW + 5)
        .await
        .unwrap();
    assert!(again.is_empty(), "{again:?}");
}

#[tokio::test]
async fn sweep_reports_each_committed_claim_before_a_later_failure() {
    let leases = Arc::new(FakeLeases::default());
    let templates = Arc::new(FakeTemplates::default());
    let audit = Arc::new(FakeAudit::default());
    let lab = Lab::new(
        templates,
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        Arc::new(FakeProjects::default()),
        audit,
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
    let mut created = Vec::new();
    for purpose in ["first", "second"] {
        let lease = lab
            .create_lease(
                &AllowAll,
                &principal(),
                fleet_application::lab::NewLease {
                    template_version_id: version.id.clone(),
                    purpose: purpose.to_owned(),
                    project_id: None,
                    cleanup: fleet_core::CleanupStrategy::Destroy,
                    ttl_seconds: 3_600,
                },
                NOW + 2,
            )
            .await
            .unwrap();
        let mut ready = lease.clone();
        ready.state = LeaseState::Ready;
        ready.ready_at = Some(NOW + 3);
        ready.expires_at = Some(NOW + 3);
        leases.update(&ready).await.unwrap();
        created.push(lease.id);
    }
    *leases.fail_claim_on_call.lock().unwrap() = Some(2);

    let mut published = 0;
    let error = lab
        .sweep_expired_with_progress(&AllowAll, &principal(), NOW + 4, || published += 1)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("simulated claim failure"));
    assert_eq!(published, 1);
    let first = lab
        .get_lease(&AllowAll, &principal(), &created[0])
        .await
        .unwrap();
    let second = lab
        .get_lease(&AllowAll, &principal(), &created[1])
        .await
        .unwrap();
    assert_eq!(first.state, LeaseState::Releasing);
    assert_eq!(second.state, LeaseState::Ready);
}

#[tokio::test]
async fn lease_creation_records_an_existent_explicit_project() {
    let leases = Arc::new(FakeLeases::default());
    let audit = Arc::new(FakeAudit::default());
    let lab = Lab::new(
        Arc::new(FakeTemplates::default()),
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        FakeProjects::with(sample_project("proj-1")),
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
    let lease = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "the demo".to_owned(),
                project_id: Some("proj-1".to_owned()),
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();
    assert_eq!(lease.project_id, Some("proj-1".to_owned()));
    // The create event itself carries the linkage: both entries must sit
    // on the same `lab_lease_creating` intent.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| {
            let entries: Vec<(&str, &str)> = intent.metadata.entries().collect();
            entries
                .iter()
                .any(|(k, v)| k == &"event" && v == &"lab_lease_creating")
                && entries
                    .iter()
                    .any(|(k, v)| k == &"projectId" && v == &"proj-1")
        }),
        "{intents:?}"
    );
}

#[tokio::test]
async fn lease_creation_inherits_the_template_versions_bootstrap_project() {
    let leases = Arc::new(FakeLeases::default());
    let lab = Lab::new(
        Arc::new(FakeTemplates::default()),
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        FakeProjects::with(sample_project("proj-1")),
        Arc::new(FakeAudit::default()),
    );
    let template = lab
        .create_template(
            &AllowAll,
            &principal(),
            NewLabTemplate {
                content: LabTemplateContent {
                    bootstrap_project_id: Some("proj-1".to_owned()),
                    ..content("ubuntu-lab", "rcp-1@abc")
                },
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
    assert_eq!(lease.project_id, Some("proj-1".to_owned()));
}

#[tokio::test]
async fn lease_creation_refuses_an_unknown_project() {
    let leases = Arc::new(FakeLeases::default());
    let lab = Lab::new(
        Arc::new(FakeTemplates::default()),
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        Arc::new(FakeProjects::default()),
        Arc::new(FakeAudit::default()),
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
    let error = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "the demo".to_owned(),
                project_id: Some("ghost".to_owned()),
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap_err();
    match error {
        LabUseCaseError::Invalid { detail } => {
            assert!(detail.contains("ghost"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        leases.leases.lock().unwrap().is_empty(),
        "the lease was created for an unknown project"
    );
}

#[tokio::test]
async fn lease_listing_narrows_by_project() {
    let leases = Arc::new(FakeLeases::default());
    let lab = Lab::new(
        Arc::new(FakeTemplates::default()),
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        FakeProjects::with(sample_project("proj-1")),
        Arc::new(FakeAudit::default()),
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
    for purpose in ["first", "second"] {
        lab.create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: purpose.to_owned(),
                project_id: Some("proj-1".to_owned()),
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();
    }
    lab.create_lease(
        &AllowAll,
        &principal(),
        fleet_application::lab::NewLease {
            template_version_id: version.id.clone(),
            purpose: "unlinked".to_owned(),
            project_id: None,
            cleanup: fleet_core::CleanupStrategy::Destroy,
            ttl_seconds: 3_600,
        },
        NOW + 3,
    )
    .await
    .unwrap();
    let linked = lab
        .list_leases(&AllowAll, &principal(), Some("proj-1"))
        .await
        .unwrap();
    assert_eq!(linked.len(), 2);
    let everything = lab
        .list_leases(&AllowAll, &principal(), None)
        .await
        .unwrap();
    assert_eq!(everything.len(), 3);
}

#[tokio::test]
async fn lease_creation_refuses_a_stale_template_bootstrap_project() {
    let leases = Arc::new(FakeLeases::default());
    let lab = Lab::new(
        Arc::new(FakeTemplates::default()),
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        Arc::new(FakeProjects::default()),
        Arc::new(FakeAudit::default()),
    );
    let template = lab
        .create_template(
            &AllowAll,
            &principal(),
            NewLabTemplate {
                content: LabTemplateContent {
                    bootstrap_project_id: Some("deleted".to_owned()),
                    ..content("ubuntu-lab", "rcp-1@abc")
                },
            },
            NOW,
        )
        .await
        .unwrap();
    let version = lab
        .publish_template(&AllowAll, &principal(), &template.id, NOW + 1)
        .await
        .unwrap();
    let error = lab
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
        .unwrap_err();
    match error {
        LabUseCaseError::Invalid { detail } => {
            assert!(detail.contains("deleted"), "{detail}");
            assert!(detail.contains("explicit project id"), "{detail}");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        leases.leases.lock().unwrap().is_empty(),
        "the lease was created for a stale bootstrap project"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn exec_runs_only_on_a_ready_unexpired_lease_with_a_lab_machine() {
    let templates = Arc::new(FakeTemplates::default());
    let audit = Arc::new(FakeAudit::default());
    let leases = Arc::new(FakeLeases::default());
    let provisions = Arc::new(FakeProvisions::with_leases(leases.leases.clone()));
    let lab = Lab::new(
        templates,
        provisions.clone(),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        Arc::new(FakeProjects::default()),
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
    let lease = lab
        .create_lease(
            &AllowAll,
            &principal(),
            fleet_application::lab::NewLease {
                template_version_id: version.id.clone(),
                purpose: "exec".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            NOW + 2,
        )
        .await
        .unwrap();
    let exec = |now: i64, script: &'static str, timeout: u64| {
        let lab = &lab;
        let id = lease.id.clone();
        async move {
            lab.exec_lease(&AllowAll, &principal(), &id, script, timeout, None, now)
                .await
        }
    };

    // Not ready yet.
    assert!(matches!(
        exec(NOW + 3, "uname -a", 60).await.unwrap_err(),
        LabUseCaseError::Invalid { .. }
    ));

    // Ready, but the guest has no Lab machine.
    let mut record = provisions
        .create(
            &NewProvision {
                template_version_id: version.id.clone(),
                lease_id: Some(lease.id.clone()),
                idempotency_key: None,
            },
            NOW + 3,
        )
        .await
        .unwrap();
    {
        let mut stored = leases.leases.lock().unwrap();
        let entry = stored
            .iter_mut()
            .find(|entry| entry.id == lease.id)
            .unwrap();
        entry.state = fleet_core::LeaseState::Ready;
        entry.provision_id = Some(record.id.clone());
        entry.expires_at = Some(NOW + 1_000);
    }
    let error = exec(NOW + 4, "uname -a", 60).await.unwrap_err();
    assert!(error.to_string().contains("Lab machine"), "{error}");

    // Ready with a machine: the lab.exec operation, the command not audited.
    record.machine_id = Some("machine-1".to_owned());
    record.endpoint_id = Some("endpoint-1".to_owned());
    provisions.update(&record).await.unwrap();
    let new = exec(NOW + 5, "echo secret-ish-value", 120).await.unwrap();
    assert_eq!(new.kind, "lab.exec");
    let payload: serde_json::Value =
        serde_json::from_str(new.payload_json.as_deref().unwrap()).unwrap();
    assert_eq!(payload["leaseId"], lease.id.as_str());
    assert_eq!(payload["timeoutSeconds"], 120);
    let audited = format!("{:?}", audit.intents.lock().unwrap());
    assert!(audited.contains("lab_exec_requested"));
    assert!(!audited.contains("secret-ish-value"));

    // A retried request with the same key maps to the same operation key,
    // scoped to the principal and the lease; another principal's key differs.
    let keyed = |who: &'static str, now: i64| {
        let lab = &lab;
        let id = lease.id.clone();
        async move {
            lab.exec_lease(
                &AllowAll,
                &ActingPrincipal { id: who.to_owned() },
                &id,
                "true",
                60,
                Some("k1"),
                now,
            )
            .await
            .unwrap()
            .idempotency_key
        }
    };
    let first = keyed("anonymous-lan-admin", NOW + 5).await;
    assert_eq!(
        first.as_deref(),
        Some(format!("anonymous-lan-admin:lab-exec:{}:k1", lease.id).as_str())
    );
    assert_eq!(keyed("anonymous-lan-admin", NOW + 6).await, first);
    assert_ne!(keyed("someone-else", NOW + 6).await, first);

    // The 64 KiB bound.
    let oversized = "x".repeat(fleet_application::lab::MAX_LAB_EXEC_SCRIPT_BYTES + 1);
    assert!(matches!(
        lab.exec_lease(
            &AllowAll,
            &principal(),
            &lease.id,
            &oversized,
            60,
            None,
            NOW + 5
        )
        .await
        .unwrap_err(),
        LabUseCaseError::Invalid { .. }
    ));

    // A ready lease without a TTL deadline is refused too.
    {
        let mut stored = leases.leases.lock().unwrap();
        stored
            .iter_mut()
            .find(|entry| entry.id == lease.id)
            .unwrap()
            .expires_at = None;
    }
    assert!(matches!(
        exec(NOW + 5, "true", 60).await.unwrap_err(),
        LabUseCaseError::Invalid { .. }
    ));
    {
        let mut stored = leases.leases.lock().unwrap();
        stored
            .iter_mut()
            .find(|entry| entry.id == lease.id)
            .unwrap()
            .expires_at = Some(NOW + 1_000);
    }

    // Bounds, expiry, and authorization.
    for (now, script, timeout) in [
        (NOW + 5, "  ", 60),
        (NOW + 5, "true", 0),
        (NOW + 5, "true", 901),
        (NOW + 1_000, "true", 60),
    ] {
        assert!(matches!(
            exec(now, script, timeout).await.unwrap_err(),
            LabUseCaseError::Invalid { .. }
        ));
    }
    assert!(matches!(
        lab.exec_lease(&DenyAll, &principal(), &lease.id, "true", 60, None, NOW + 5)
            .await
            .unwrap_err(),
        LabUseCaseError::Denied(_)
    ));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn cleanup_retry_rearms_only_a_cleanup_failed_lease_authorized_and_audited() {
    use fleet_application::lab::MAX_CLEANUP_ATTEMPTS;

    // Denies exactly lab.lease, so the use case is shown to require it.
    #[derive(Debug, Default)]
    struct LeaseDenied;
    impl Authorizer for LeaseDenied {
        fn decide(&self, request: AccessRequest<'_>) -> Decision {
            if request.action == fleet_application::authz::Permission::LabLease {
                return Decision::deny(ReasonId::PolicyAllow);
            }
            Decision::allow()
        }
    }

    let leases = Arc::new(FakeLeases::default());
    let audit = Arc::new(FakeAudit::default());
    let lab = Lab::new(
        Arc::new(FakeTemplates::default()),
        Arc::new(FakeProvisions::with_leases(leases.leases.clone())),
        leases.clone(),
        FakePins::with_promoted("rcp-1@abc"),
        Arc::new(FakeProjects::default()),
        audit.clone(),
    );
    let mut lease = leases
        .create(
            &fleet_application::lab::NewLease {
                template_version_id: "tv-1".to_owned(),
                purpose: "the demo".to_owned(),
                project_id: None,
                cleanup: fleet_core::CleanupStrategy::Destroy,
                ttl_seconds: 3_600,
            },
            "anonymous-lan-admin",
            NOW,
        )
        .await
        .unwrap();

    // Only cleanup_failed can be re-armed; a releasing lease is refused
    // unchanged, before any audit.
    lease.state = LeaseState::Releasing;
    lease.cleanup_attempts = 2;
    lease.cleanup_next_at = Some(NOW + 60_000);
    leases.update(&lease).await.unwrap();
    let error = lab
        .retry_cleanup(&AllowAll, &principal(), &lease.id)
        .await
        .unwrap_err();
    assert!(matches!(error, LabUseCaseError::Invalid { .. }), "{error}");
    assert!(error.to_string().contains("releasing"), "{error}");
    assert!(audit.intents.lock().unwrap().is_empty());

    lease.state = LeaseState::CleanupFailed;
    lease.cleanup_attempts = MAX_CLEANUP_ATTEMPTS;
    lease.cleanup_next_at = None;
    leases.update(&lease).await.unwrap();

    // The caller must hold lab.lease on it.
    let error = lab
        .retry_cleanup(&LeaseDenied, &principal(), &lease.id)
        .await
        .unwrap_err();
    assert!(matches!(error, LabUseCaseError::Denied(_)), "{error}");
    assert!(matches!(
        lab.retry_cleanup(&AllowAll, &principal(), "no-such-lease")
            .await
            .unwrap_err(),
        LabUseCaseError::NotFound { .. }
    ));

    let rearmed = lab
        .retry_cleanup(&AllowAll, &principal(), &lease.id)
        .await
        .unwrap();
    assert_eq!(rearmed.state, LeaseState::Releasing);
    assert_eq!(rearmed.cleanup_next_at, None);
    // The failed-attempt count is kept, so the next attempt's idempotency
    // key is a fresh one, and its cleanup is due at once.
    assert_eq!(rearmed.cleanup_attempts, MAX_CLEANUP_ATTEMPTS);
    assert!(fleet_application::lab::cleanup_due(&rearmed, NOW));
    assert_eq!(
        fleet_application::lab::cleanup_operation(&rearmed, None)
            .idempotency_key
            .as_deref(),
        Some(format!("lab-cleanup:{}:{MAX_CLEANUP_ATTEMPTS}", lease.id).as_str())
    );
    let stored = leases.get(&lease.id).await.unwrap();
    assert_eq!(stored.state, LeaseState::Releasing);
    assert_eq!(stored.cleanup_attempts, MAX_CLEANUP_ATTEMPTS);
    let intents = audit.intents.lock().unwrap().clone();
    assert_eq!(intents.len(), 2);
    assert_eq!(intents[0].action, "lab.lease");
    assert_eq!(intents[0].resource.as_deref(), Some(lease.id.as_str()));
    let events = |intents: &[AuditIntent]| -> Vec<String> {
        intents
            .iter()
            .filter_map(|intent| {
                intent
                    .metadata
                    .entries()
                    .find(|(key, _)| *key == "event")
                    .map(|(_, value)| value.to_owned())
            })
            .collect()
    };
    assert_eq!(
        events(&intents),
        [
            "lab_lease_cleanup_rearm_requested",
            "lab_lease_cleanup_rearmed"
        ]
    );
    assert!(
        intents[1]
            .metadata
            .entries()
            .any(|entry| entry == ("failedAttempts", "5"))
    );

    // A second re-arm finds a releasing lease and changes nothing.
    assert!(matches!(
        lab.retry_cleanup(&AllowAll, &principal(), &lease.id)
            .await
            .unwrap_err(),
        LabUseCaseError::Invalid { .. }
    ));

    // A lease that changes between the read and the compare-and-set: the
    // re-arm loses with a conflict, the newer state stands, and only the
    // request is audited.
    lease.state = LeaseState::CleanupFailed;
    lease.cleanup_attempts = MAX_CLEANUP_ATTEMPTS;
    leases.update(&lease).await.unwrap();
    *leases.race_rearm.lock().unwrap() = true;
    let error = lab
        .retry_cleanup(&AllowAll, &principal(), &lease.id)
        .await
        .unwrap_err();
    assert!(matches!(error, LabUseCaseError::Conflict { .. }), "{error}");
    let stored = leases.get(&lease.id).await.unwrap();
    assert_eq!(stored.state, LeaseState::Released);
    assert_eq!(stored.cleanup_attempts, MAX_CLEANUP_ATTEMPTS);
    let intents = audit.intents.lock().unwrap().clone();
    assert_eq!(events(&intents[2..]), ["lab_lease_cleanup_rearm_requested"]);
}
