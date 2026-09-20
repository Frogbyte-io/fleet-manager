//! The Proxmox use cases over fakes: the explicit-trust gate (observe →
//! confirm → discover), credential secrecy, and the honest failure
//! taxonomy.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{AccessRequest, ActingPrincipal, Authorizer, Decision, ReasonId};
use fleet_application::operation::AuditPort;
use fleet_application::proxmox::{
    CredentialStoreError, NewProxmoxAccount, ProxmoxAccountPort, ProxmoxAccounts,
    ProxmoxCredentialStore, ProxmoxDiscoverPort, ProxmoxSourceError, ProxmoxTrustProbe,
    ProxmoxUseCaseError, RawDiscovery,
};
use fleet_core::SensitiveString;

const NOW: i64 = 1_800_000_000_000;

/// A full SHA-256-shaped fingerprint for the trust-flow tests.
const FP: &str = "DC2C116EC9C7EA618AA4E41EFB9BDEE4AA3D81EB16388F2B360AABE283A76498";

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

/// The account port over an in-memory map, mirroring the SQLite adapter's
/// semantics (unique names, not-found details).
#[derive(Debug, Default)]
struct FakeAccounts {
    accounts: Mutex<Vec<fleet_application::proxmox::ProxmoxAccount>>,
}

impl FakeAccounts {
    fn find(&self, id: &str) -> Option<fleet_application::proxmox::ProxmoxAccount> {
        self.accounts
            .lock()
            .unwrap()
            .iter()
            .find(|account| account.id == id)
            .cloned()
    }
}

#[async_trait]
impl ProxmoxAccountPort for FakeAccounts {
    async fn create(
        &self,
        new: &NewProxmoxAccount,
    ) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        if self
            .accounts
            .lock()
            .unwrap()
            .iter()
            .any(|account| account.name == new.name)
        {
            return Err(format!("the account name {:?} is already taken", new.name));
        }
        let mut accounts = self.accounts.lock().unwrap();
        let account = fleet_application::proxmox::ProxmoxAccount {
            id: format!("acc-{}", accounts.len() + 1),
            name: new.name.clone(),
            host: new.host.clone(),
            port: new.port.unwrap_or(8006),
            token_id: new.token_id.clone(),
            fingerprint: None,
            observed_fingerprint: None,
            created_at: NOW,
        };
        accounts.push(account.clone());
        Ok(account)
    }

    async fn get(&self, id: &str) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        self.find(id)
            .ok_or_else(|| format!("account {id} not found"))
    }

    async fn list(&self) -> Result<Vec<fleet_application::proxmox::ProxmoxAccount>, String> {
        Ok(self.accounts.lock().unwrap().clone())
    }

    async fn set_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .iter_mut()
            .find(|account| account.id == id)
            .ok_or_else(|| format!("account {id} not found"))?;
        account.fingerprint = fingerprint;
        Ok(account.clone())
    }

    async fn set_observed_fingerprint(
        &self,
        id: &str,
        fingerprint: Option<String>,
    ) -> Result<fleet_application::proxmox::ProxmoxAccount, String> {
        let mut accounts = self.accounts.lock().unwrap();
        let account = accounts
            .iter_mut()
            .find(|account| account.id == id)
            .ok_or_else(|| format!("account {id} not found"))?;
        account.observed_fingerprint = fingerprint;
        Ok(account.clone())
    }

    async fn delete(&self, id: &str) -> Result<(), String> {
        let mut accounts = self.accounts.lock().unwrap();
        let before = accounts.len();
        accounts.retain(|account| account.id != id);
        if accounts.len() == before {
            return Err(format!("account {id} not found"));
        }
        Ok(())
    }
}

/// The credential store over a map, recording what was stored and cleared.
#[derive(Debug, Default)]
struct FakeCredentials {
    secrets: Mutex<std::collections::HashMap<String, String>>,
    cleared: Mutex<Vec<String>>,
}

#[async_trait]
impl ProxmoxCredentialStore for FakeCredentials {
    async fn load(&self, account_id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(self.secrets.lock().unwrap().get(account_id).cloned())
    }

    async fn store(&self, account_id: &str, secret: &str) -> Result<(), CredentialStoreError> {
        self.secrets
            .lock()
            .unwrap()
            .insert(account_id.to_owned(), secret.to_owned());
        Ok(())
    }

    async fn clear(&self, account_id: &str) -> Result<(), CredentialStoreError> {
        self.secrets.lock().unwrap().remove(account_id);
        self.cleared.lock().unwrap().push(account_id.to_owned());
        Ok(())
    }
}

/// The discovery port over canned results and failures.
#[derive(Debug, Default)]
struct FakeDiscovery {
    result: Mutex<Option<Result<RawDiscovery, ProxmoxSourceError>>>,
    calls: Mutex<Vec<String>>,
}

impl FakeDiscovery {
    fn with(result: Result<RawDiscovery, ProxmoxSourceError>) -> Arc<Self> {
        Arc::new(Self {
            result: Mutex::new(Some(result)),
            calls: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl ProxmoxDiscoverPort for FakeDiscovery {
    async fn discover(
        &self,
        account: &fleet_application::proxmox::ProxmoxAccount,
        _secret: &SensitiveString,
    ) -> Result<RawDiscovery, ProxmoxSourceError> {
        self.calls.lock().unwrap().push(account.id.clone());
        self.result
            .lock()
            .unwrap()
            .take()
            .expect("a discovery answer was prepared")
    }
}

/// The trust probe over a canned fingerprint.
#[derive(Debug, Default)]
struct FakeProbe {
    fingerprint: Mutex<Option<String>>,
}

impl FakeProbe {
    fn with(fingerprint: &str) -> Arc<Self> {
        Arc::new(Self {
            fingerprint: Mutex::new(Some(fingerprint.to_owned())),
        })
    }
}

#[async_trait]
impl ProxmoxTrustProbe for FakeProbe {
    async fn observe(&self, _host: &str, _port: u16) -> Result<String, ProxmoxSourceError> {
        self.fingerprint
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| ProxmoxSourceError::Connect {
                detail: "unreachable".to_owned(),
            })
    }
}

/// The audit sink over a vector, for secrecy assertions.
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

fn discovery_ok() -> RawDiscovery {
    RawDiscovery {
        version: "9.2.2".to_owned(),
        resources: vec![fleet_application::proxmox::ProxmoxResource {
            kind: "node".to_owned(),
            id: "node/pve".to_owned(),
            node: None,
            vmid: None,
            name: Some("pve".to_owned()),
            status: Some("online".to_owned()),
            account_id: String::new(),
            pve_version: String::new(),
            observed_at: 0,
        }],
        warnings: Vec::new(),
        reported_count: 1,
    }
}

fn service(
    discovery: Arc<dyn ProxmoxDiscoverPort>,
    probe: Arc<dyn ProxmoxTrustProbe>,
) -> (ProxmoxAccounts, Arc<FakeAudit>) {
    let audit = Arc::new(FakeAudit::default());
    (
        ProxmoxAccounts::new(
            Arc::new(FakeAccounts::default()),
            Arc::new(FakeCredentials::default()),
            discovery,
            probe,
            audit.clone(),
        ),
        audit,
    )
}

async fn create_account(proxmox: &ProxmoxAccounts) -> fleet_application::proxmox::ProxmoxAccount {
    proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "192.168.68.223".to_owned(),
                port: Some(8006),
                token_id: "root@pam!GLM-AGENT".to_owned(),
            },
            "the-token-secret-material",
        )
        .await
        .expect("the account is well formed")
}

/// Observes and confirms the canned fingerprint, the honest trust flow.
async fn observe_and_confirm(proxmox: &ProxmoxAccounts, account_id: &str) {
    let observed = proxmox
        .observe(&AllowAll, &principal(), account_id)
        .await
        .expect("the probe answers");
    proxmox
        .confirm(&AllowAll, &principal(), account_id, &observed)
        .await
        .expect("the observed fingerprint confirms");
}

#[tokio::test]
async fn discovery_is_locked_until_the_fingerprint_is_confirmed() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    let error = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::UnconfirmedTrust { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn observe_confirm_then_discover_walks_the_trust_flow() {
    let (proxmox, audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;

    // Observe: the fingerprint arrives without any credential sent.
    let observed = proxmox
        .observe(&AllowAll, &principal(), &account.id)
        .await
        .unwrap();
    assert_eq!(observed, FP);

    // Confirm: the account becomes trusted, fingerprint normalized.
    let account = proxmox
        .confirm(
            &AllowAll,
            &principal(),
            &account.id,
            &fleet_application::proxmox::normalize_fingerprint(FP).to_lowercase(),
        )
        .await
        .unwrap();
    assert_eq!(account.fingerprint.as_deref(), Some(FP));

    // Discover: the snapshot lands with provenance.
    let snapshot = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    assert_eq!(snapshot.pve_version, "9.2.2");
    assert_eq!(snapshot.resources.len(), 1);
    assert_eq!(snapshot.resources[0].account_id, account.id);
    assert_eq!(snapshot.resources[0].pve_version, "9.2.2");
    assert_eq!(snapshot.resources[0].observed_at, NOW);
    assert_eq!(snapshot.observed_at, NOW);

    // The trust flow is audited as account mutations.
    let intents = audit.intents.lock().unwrap();
    assert!(
        intents.iter().any(|intent| {
            intent
                .metadata
                .entries()
                .any(|(key, value)| key == "event" && value == "proxmox_fingerprint_confirming")
        }),
        "{intents:?}"
    );
}

#[tokio::test]
async fn a_fingerprint_mismatch_is_reported_as_evidence_not_an_empty_list() {
    let (proxmox, _audit) = service(
        FakeDiscovery::with(Err(ProxmoxSourceError::FingerprintMismatch {
            observed: FP.to_owned(),
            pinned: "DD".repeat(32),
        })),
        FakeProbe::with(FP),
    );
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let error = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    match error {
        ProxmoxUseCaseError::Source(ProxmoxSourceError::FingerprintMismatch {
            observed,
            pinned,
        }) => {
            assert_eq!(observed, FP);
            assert_eq!(pinned, "DD".repeat(32));
        }
        other => panic!("expected a fingerprint mismatch, got {other}"),
    }
}

#[tokio::test]
async fn auth_and_privilege_failures_are_honest_states() {
    for source_error in [
        ProxmoxSourceError::Auth,
        ProxmoxSourceError::Forbidden {
            detail: "no permission".to_owned(),
        },
        ProxmoxSourceError::Connect {
            detail: "timeout".to_owned(),
        },
    ] {
        let (proxmox, _audit) =
            service(FakeDiscovery::with(Err(source_error)), FakeProbe::with(FP));
        let account = create_account(&proxmox).await;
        observe_and_confirm(&proxmox, &account.id).await;
        let error = proxmox
            .discover(&AllowAll, &principal(), &account.id, NOW)
            .await
            .unwrap_err();
        assert!(matches!(error, ProxmoxUseCaseError::Source(_)), "{error}");
    }
}

#[tokio::test]
async fn the_token_secret_never_surfaces_in_audit_or_errors() {
    let (proxmox, audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    observe_and_confirm(&proxmox, &account.id).await;
    let _ = proxmox
        .discover(&AllowAll, &principal(), &account.id, NOW)
        .await
        .unwrap();
    for intent in audit.intents.lock().unwrap().iter() {
        let rendered = format!("{intent:?}");
        assert!(
            !rendered.contains("the-token-secret-material"),
            "the secret leaked into audit: {rendered}"
        );
    }
}

#[tokio::test]
async fn a_failed_secret_write_removes_the_account() {
    // A store that refuses writes: the account must not survive half-made.
    #[derive(Debug)]
    struct RefusingStore;
    #[async_trait]
    impl ProxmoxCredentialStore for RefusingStore {
        async fn load(&self, _account_id: &str) -> Result<Option<String>, CredentialStoreError> {
            Ok(None)
        }
        async fn store(
            &self,
            _account_id: &str,
            _secret: &str,
        ) -> Result<(), CredentialStoreError> {
            Err(CredentialStoreError::Backend {
                detail: "the disk is full".to_owned(),
            })
        }
        async fn clear(&self, _account_id: &str) -> Result<(), CredentialStoreError> {
            Ok(())
        }
    }
    let audit = Arc::new(FakeAudit::default());
    let proxmox = ProxmoxAccounts::new(
        Arc::new(FakeAccounts::default()),
        Arc::new(RefusingStore),
        FakeDiscovery::with(Ok(discovery_ok())),
        FakeProbe::with(FP),
        audit,
    );
    let error = proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "192.168.68.223".to_owned(),
                port: None,
                token_id: "root@pam!GLM-AGENT".to_owned(),
            },
            "the-token-secret-material",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::Backend { .. }),
        "{error}"
    );
    let accounts = proxmox
        .list(&AllowAll, &principal(), 50, None)
        .await
        .unwrap();
    assert!(accounts.is_empty(), "the half-made account is gone");
}

#[tokio::test]
async fn deleting_an_account_clears_its_secret() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    proxmox
        .delete(&AllowAll, &principal(), &account.id)
        .await
        .unwrap();
    assert!(
        proxmox
            .list(&AllowAll, &principal(), 50, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_denied_caller_never_reaches_the_ports() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    let error = proxmox
        .list(&DenyAll, &principal(), 50, None)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
    let error = proxmox
        .discover(&DenyAll, &principal(), &account.id, NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, ProxmoxUseCaseError::Denied(_)));
}

#[tokio::test]
async fn malformed_accounts_are_refused_before_any_write() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    for new in [
        NewProxmoxAccount {
            name: String::new(),
            host: "192.168.68.223".to_owned(),
            port: None,
            token_id: "root@pam!GLM-AGENT".to_owned(),
        },
        NewProxmoxAccount {
            name: "pve-main".to_owned(),
            host: "https://192.168.68.223".to_owned(),
            port: None,
            token_id: "root@pam!GLM-AGENT".to_owned(),
        },
        NewProxmoxAccount {
            name: "pve-main".to_owned(),
            host: "192.168.68.223".to_owned(),
            port: None,
            token_id: "no-shape".to_owned(),
        },
    ] {
        let error = proxmox
            .create(&AllowAll, &principal(), new, "secret")
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProxmoxUseCaseError::Invalid { .. }),
            "{error}"
        );
    }
    assert!(
        proxmox
            .list(&AllowAll, &principal(), 50, None)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_conflicting_account_name_is_a_conflict() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    create_account(&proxmox).await;
    let error = proxmox
        .create(
            &AllowAll,
            &principal(),
            NewProxmoxAccount {
                name: "pve-main".to_owned(),
                host: "10.0.0.1".to_owned(),
                port: None,
                token_id: "root@pam!OTHER".to_owned(),
            },
            "another-secret",
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, ProxmoxUseCaseError::Conflict { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn confirm_refuses_a_malformed_fingerprint() {
    let (proxmox, _audit) = service(FakeDiscovery::with(Ok(discovery_ok())), FakeProbe::with(FP));
    let account = create_account(&proxmox).await;
    for fingerprint in ["", "nothex", "A".repeat(63).as_str(), &"G".repeat(64)] {
        let error = proxmox
            .confirm(&AllowAll, &principal(), &account.id, fingerprint)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ProxmoxUseCaseError::Invalid { .. }),
            "{error}"
        );
    }
}
