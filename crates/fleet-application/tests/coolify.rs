//! FM-1030: Coolify discovery over in-memory ports: central authorization,
//! audit without credential material, and stale-aware folding of runs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::coolify::{
    ClassFailure, ClassResult, CoolifyDatabase, CoolifyDiscovery, CoolifyObservationPort,
    CoolifyServer, CoolifySnapshot, CoolifySource, FailureKind, RawCoolifyDiscovery,
};
use fleet_application::external_accounts::{
    ExternalAccount, ExternalAccountError, ExternalAccountPort, ExternalCredentialStore,
    NewExternalAccount, StoredProbe,
};
use fleet_application::operation::AuditPort;
use fleet_application::proxmox::CredentialStoreError;
use fleet_core::{ExternalProviderKind, SensitiveString};

const TOKEN: &str = "tok-super-secret-value-123456";

fn principal() -> ActingPrincipal {
    ActingPrincipal {
        id: "anonymous-lan-admin".to_owned(),
    }
}

#[derive(Debug)]
struct Deny(Vec<Permission>);

impl Authorizer for Deny {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if self.0.contains(&request.action) {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

#[derive(Debug)]
struct Accounts(Vec<ExternalAccount>);

#[async_trait]
impl ExternalAccountPort for Accounts {
    async fn create(&self, _: &NewExternalAccount) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn get(&self, id: &str) -> Result<ExternalAccount, String> {
        self.0
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| format!("account {id} not found"))
    }
    async fn list(&self) -> Result<Vec<ExternalAccount>, String> {
        Ok(self.0.clone())
    }
    async fn update(
        &self,
        _: &str,
        _: &NewExternalAccount,
        _: bool,
    ) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn record_probe(
        &self,
        _: &str,
        _: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String> {
        Err("unsupported".to_owned())
    }
    async fn delete(&self, _: &str) -> Result<(), String> {
        Err("unsupported".to_owned())
    }
}

#[derive(Debug, Default)]
struct Credentials(HashMap<String, String>);

#[async_trait]
impl ExternalCredentialStore for Credentials {
    async fn load(&self, id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(self.0.get(id).cloned())
    }
    async fn store(&self, _: &str, _: &str) -> Result<(), CredentialStoreError> {
        Ok(())
    }
    async fn clear(&self, _: &str) -> Result<(), CredentialStoreError> {
        Ok(())
    }
}

/// Answers the queued runs in order and records the token it was handed.
#[derive(Debug, Default)]
struct Source {
    runs: Mutex<Vec<RawCoolifyDiscovery>>,
    tokens: Mutex<Vec<String>>,
    urls: Mutex<Vec<String>>,
}

#[async_trait]
impl CoolifySource for Source {
    async fn discover(&self, base_url: &str, token: &SensitiveString) -> RawCoolifyDiscovery {
        self.tokens.lock().unwrap().push(token.expose().to_owned());
        self.urls.lock().unwrap().push(base_url.to_owned());
        self.runs.lock().unwrap().remove(0)
    }
}

#[derive(Debug, Default)]
struct Observations(Mutex<HashMap<String, (CoolifySnapshot, i64)>>);

#[async_trait]
impl CoolifyObservationPort for Observations {
    async fn load(&self, id: &str) -> Result<Option<(CoolifySnapshot, i64)>, String> {
        Ok(self.0.lock().unwrap().get(id).cloned())
    }
    async fn save(&self, id: &str, snapshot: &CoolifySnapshot, at: i64) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .insert(id.to_owned(), (snapshot.clone(), at));
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Audit(Mutex<Vec<AuditIntent>>);

#[async_trait]
impl AuditPort for Audit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.0.lock().unwrap().push(intent.clone());
        Ok(())
    }
    async fn record_outcome(&self, _: &str, _: AuditOutcome) -> Result<(), String> {
        Ok(())
    }
}

fn account(id: &str, kind: ExternalProviderKind) -> ExternalAccount {
    ExternalAccount {
        id: id.to_owned(),
        kind,
        label: format!("label-{id}"),
        base_url: "https://coolify.example.test".to_owned(),
        scope_id: None,
        notes: String::new(),
        last_probe: None,
        created_at: 1,
        updated_at: 1,
    }
}

fn server(uuid: &str) -> CoolifyServer {
    CoolifyServer {
        uuid: uuid.to_owned(),
        name: uuid.to_owned(),
        ..CoolifyServer::default()
    }
}

fn all_ok() -> RawCoolifyDiscovery {
    RawCoolifyDiscovery {
        version: Some("4.4.6".to_owned()),
        servers: ClassResult::Complete(vec![server("s1")]),
        projects: ClassResult::Complete(vec![]),
        applications: ClassResult::Complete(vec![]),
        services: ClassResult::Complete(vec![]),
        databases: ClassResult::Complete(vec![CoolifyDatabase {
            uuid: "d1".to_owned(),
            ..CoolifyDatabase::default()
        }]),
        deployments: ClassResult::Complete(vec![]),
    }
}

fn servers_refused() -> RawCoolifyDiscovery {
    let mut run = all_ok();
    run.servers = ClassResult::Failed(ClassFailure {
        kind: FailureKind::Unauthorized,
        detail: "the token was refused (HTTP 401)".to_owned(),
    });
    run.version = None;
    run
}

struct Rig {
    service: CoolifyDiscovery,
    source: Arc<Source>,
    observations: Arc<Observations>,
    audit: Arc<Audit>,
}

fn rig(runs: Vec<RawCoolifyDiscovery>, with_secret: bool) -> Rig {
    let source = Arc::new(Source {
        runs: Mutex::new(runs),
        ..Source::default()
    });
    let observations = Arc::new(Observations::default());
    let audit = Arc::new(Audit::default());
    let mut credentials = Credentials::default();
    if with_secret {
        credentials.0.insert("c1".to_owned(), TOKEN.to_owned());
        credentials.0.insert("cf1".to_owned(), TOKEN.to_owned());
    }
    Rig {
        service: CoolifyDiscovery::new(
            Arc::new(Accounts(vec![
                account("c1", ExternalProviderKind::Coolify),
                account("cf1", ExternalProviderKind::Cloudflare),
            ])),
            Arc::new(credentials),
            source.clone(),
            observations.clone(),
            audit.clone(),
        ),
        source,
        observations,
        audit,
    }
}

fn events(audit: &Audit) -> Vec<String> {
    audit
        .0
        .lock()
        .unwrap()
        .iter()
        .map(|intent| {
            intent
                .metadata
                .entries()
                .find(|(k, _)| *k == "event")
                .map(|(_, v)| v.to_owned())
                .unwrap_or_default()
        })
        .collect()
}

#[tokio::test]
async fn discovery_resolves_the_token_just_in_time_records_and_audits_without_it() {
    let rig = rig(vec![all_ok()], true);
    let observation = rig
        .service
        .discover(&Deny(vec![]), &principal(), "c1")
        .await
        .expect("discovery");
    assert_eq!(rig.source.tokens.lock().unwrap().as_slice(), [TOKEN]);
    assert_eq!(
        rig.source.urls.lock().unwrap().as_slice(),
        ["https://coolify.example.test"]
    );
    assert_eq!(observation.snapshot.version.as_deref(), Some("4.4.6"));
    assert_eq!(observation.snapshot.servers.items.len(), 1);
    assert!(rig.observations.0.lock().unwrap().contains_key("c1"));
    assert_eq!(
        events(&rig.audit),
        ["coolify_discovering", "coolify_discovered"]
    );
    let rendered = format!("{:?}", rig.audit.0.lock().unwrap());
    assert!(!rendered.contains(TOKEN), "the token reached the audit log");
}

#[tokio::test]
async fn a_failed_class_keeps_the_previous_items_marked_stale() {
    let rig = rig(vec![all_ok(), servers_refused()], true);
    rig.service
        .discover(&Deny(vec![]), &principal(), "c1")
        .await
        .expect("first");
    let second = rig
        .service
        .discover(&Deny(vec![]), &principal(), "c1")
        .await
        .expect("an unauthorized class is a result, not an error");
    let servers = &second.snapshot.servers;
    assert_eq!(servers.items.len(), 1, "the previous servers are kept");
    assert_eq!(
        servers.failure.as_ref().map(|f| f.kind),
        Some(FailureKind::Unauthorized)
    );
    assert!(servers.is_stale(second.evaluated_at));
    assert!(servers.observed_at.is_some());
    // The other classes refreshed, and the version survives a failed /version.
    assert!(!second.snapshot.databases.is_stale(second.evaluated_at));
    assert_eq!(second.snapshot.version.as_deref(), Some("4.4.6"));
    let audit = format!("{:?}", rig.audit.0.lock().unwrap());
    assert!(audit.contains("servers=1:stale:unauthorized"), "{audit}");
}

#[tokio::test]
async fn reading_needs_a_discovery_and_the_read_permission() {
    let rig = rig(vec![all_ok()], true);
    assert!(matches!(
        rig.service
            .observation(&Deny(vec![]), &principal(), "c1")
            .await,
        Err(ExternalAccountError::NotFound { .. })
    ));
    rig.service
        .discover(&Deny(vec![]), &principal(), "c1")
        .await
        .expect("discovery");
    let read = rig
        .service
        .observation(&Deny(vec![]), &principal(), "c1")
        .await
        .expect("read");
    assert_eq!(read.snapshot.databases.items.len(), 1);
    assert!(matches!(
        rig.service
            .observation(
                &Deny(vec![Permission::ExternalAccountRead]),
                &principal(),
                "c1"
            )
            .await,
        Err(ExternalAccountError::Denied(_))
    ));
}

#[tokio::test]
async fn running_discovery_is_authorized_centrally_before_any_credential_or_network_use() {
    let rig = rig(vec![all_ok()], true);
    let result = rig
        .service
        .discover(
            &Deny(vec![Permission::ExternalAccountConfig]),
            &principal(),
            "c1",
        )
        .await;
    assert!(matches!(result, Err(ExternalAccountError::Denied(_))));
    // Read permission alone does not run discovery either.
    assert!(rig.source.tokens.lock().unwrap().is_empty());
    assert!(events(&rig.audit).is_empty());
    assert!(rig.observations.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn only_coolify_accounts_with_a_stored_token_can_be_discovered() {
    let rig = rig(vec![all_ok()], true);
    assert!(matches!(
        rig.service
            .discover(&Deny(vec![]), &principal(), "cf1")
            .await,
        Err(ExternalAccountError::Invalid { .. })
    ));
    assert!(matches!(
        rig.service
            .discover(&Deny(vec![]), &principal(), "missing")
            .await,
        Err(ExternalAccountError::NotFound { .. })
    ));
    let no_secret = self::rig(vec![all_ok()], false);
    assert!(matches!(
        no_secret
            .service
            .discover(&Deny(vec![]), &principal(), "c1")
            .await,
        Err(ExternalAccountError::NoSecret { .. })
    ));
    assert!(no_secret.source.tokens.lock().unwrap().is_empty());
    assert!(events(&no_secret.audit).is_empty());
}
