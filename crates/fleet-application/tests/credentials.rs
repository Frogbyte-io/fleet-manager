//! The delegated credential use cases (ADR 0011) over in-memory ports: the
//! token is stored only as a hash and never audited, issuing is bounded and
//! authorized, and a presented token is authenticated against the store on
//! every call.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, Authorizer, Decision, ReasonId, delegated_principal_id,
};
use fleet_application::credentials::{
    AuthenticationFailure, CredentialCrypto, CredentialError, CredentialStatus, CredentialStore,
    Credentials, DelegatedCredential, GrantBook, IssueCredential, MAX_TTL_SECONDS,
    StoredCredential,
};
use fleet_application::operation::AuditPort;

const ADMIN: &str = "anonymous-lan-admin";
const NOW: i64 = 1_000_000_000;

#[derive(Debug, Default)]
struct Store {
    rows: Mutex<Vec<(DelegatedCredential, String)>>,
}

#[async_trait]
impl CredentialStore for Store {
    async fn insert(&self, credential: &DelegatedCredential, hash: &str) -> Result<(), String> {
        self.rows
            .lock()
            .unwrap()
            .push((credential.clone(), hash.to_owned()));
        Ok(())
    }
    async fn list(&self) -> Result<Vec<DelegatedCredential>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|(c, _)| c.clone())
            .collect())
    }
    async fn get(&self, id: &str) -> Result<Option<DelegatedCredential>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|(c, _)| c.id == id)
            .map(|(c, _)| c.clone()))
    }
    async fn find_by_hash(&self, hash: &str) -> Result<Option<StoredCredential>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|(_, stored)| stored == hash)
            .map(|(credential, token_hash)| StoredCredential {
                credential: credential.clone(),
                token_hash: token_hash.clone(),
            }))
    }
    async fn revoke(
        &self,
        id: &str,
        by: &str,
        now: i64,
    ) -> Result<Option<DelegatedCredential>, String> {
        let mut rows = self.rows.lock().unwrap();
        Ok(rows.iter_mut().find(|(c, _)| c.id == id).map(|(c, _)| {
            c.revoked_at.get_or_insert(now);
            c.revoked_by.get_or_insert_with(|| by.to_owned());
            c.clone()
        }))
    }
}

#[derive(Debug, Default)]
struct Audit {
    intents: Mutex<Vec<AuditIntent>>,
    refuse: Mutex<bool>,
}

#[async_trait]
impl AuditPort for Audit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        if *self.refuse.lock().unwrap() {
            return Err("the ledger is full".to_owned());
        }
        self.intents.lock().unwrap().push(intent.clone());
        Ok(())
    }
    async fn record_outcome(&self, _id: &str, _outcome: AuditOutcome) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Crypto {
    counter: Mutex<u32>,
}

impl CredentialCrypto for Crypto {
    fn generate_token(&self) -> String {
        let mut counter = self.counter.lock().unwrap();
        *counter += 1;
        format!("fake-token-{counter}")
    }
    fn hash_token(&self, token: &str) -> String {
        format!("hash-of-{token}")
    }
    fn hashes_equal(&self, left: &str, right: &str) -> bool {
        left == right
    }
}

#[derive(Debug)]
struct AdminsOnly;

impl Authorizer for AdminsOnly {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.principal_id == ADMIN {
            Decision::allow()
        } else {
            Decision::deny(ReasonId::ActionNotDelegated)
        }
    }
}

struct Fixture {
    credentials: Credentials,
    store: Arc<Store>,
    audit: Arc<Audit>,
    grants: Arc<GrantBook>,
}

fn fixture() -> Fixture {
    let store = Arc::new(Store::default());
    let audit = Arc::new(Audit::default());
    let grants = Arc::new(GrantBook::new());
    Fixture {
        credentials: Credentials::new(
            store.clone(),
            audit.clone(),
            Arc::new(Crypto::default()),
            grants.clone(),
        ),
        store,
        audit,
        grants,
    }
}

fn request() -> IssueCredential {
    IssueCredential {
        owner: "release-qa".to_owned(),
        ttl_seconds: 3600,
        templates: vec!["tpl-1".to_owned()],
        versions: vec!["ver-2".to_owned()],
        label: "ci".to_owned(),
    }
}

#[tokio::test]
async fn issuing_stores_only_the_hash_and_audits_without_the_token() {
    let fixture = fixture();
    let issued = fixture
        .credentials
        .issue(&AdminsOnly, ADMIN, request(), NOW)
        .await
        .unwrap();
    assert_eq!(issued.token, "fake-token-1");
    assert_eq!(issued.credential.owner, "release-qa");
    assert_eq!(issued.credential.expires_at, NOW + 3_600_000);
    assert_eq!(issued.credential.issued_by, ADMIN);
    let rows = fixture.store.rows.lock().unwrap();
    assert_eq!(rows[0].1, "hash-of-fake-token-1");
    drop(rows);
    let intents = fixture.audit.intents.lock().unwrap();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].action, "credential.issue");
    assert_eq!(
        intents[0].resource.as_deref(),
        Some(issued.credential.id.as_str())
    );
    let recorded = format!("{:?}", intents[0]);
    assert!(!recorded.contains("fake-token-1"), "{recorded}");
    assert!(!recorded.contains("hash-of"), "{recorded}");
    // Debug output of the issued credential never shows the token either.
    assert!(!format!("{issued:?}").contains("fake-token-1"));
}

#[tokio::test]
async fn issue_list_and_revoke_are_authorized_for_administrators_only() {
    let fixture = fixture();
    let delegated = delegated_principal_id("release-qa", "c1");
    assert!(matches!(
        fixture
            .credentials
            .issue(&AdminsOnly, &delegated, request(), NOW)
            .await,
        Err(CredentialError::Denied(_))
    ));
    assert!(matches!(
        fixture.credentials.list(&AdminsOnly, &delegated).await,
        Err(CredentialError::Denied(_))
    ));
    assert!(matches!(
        fixture
            .credentials
            .revoke(&AdminsOnly, &delegated, "c1", NOW)
            .await,
        Err(CredentialError::Denied(_))
    ));
    assert!(fixture.store.rows.lock().unwrap().is_empty());
    assert!(fixture.audit.intents.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issuing_is_bounded_and_validated() {
    let fixture = fixture();
    let bad: Vec<IssueCredential> = vec![
        IssueCredential {
            owner: String::new(),
            ..request()
        },
        IssueCredential {
            owner: "Release QA".to_owned(),
            ..request()
        },
        IssueCredential {
            owner: "a:b".to_owned(),
            ..request()
        },
        IssueCredential {
            owner: "x".repeat(64),
            ..request()
        },
        IssueCredential {
            ttl_seconds: 0,
            ..request()
        },
        IssueCredential {
            ttl_seconds: 59,
            ..request()
        },
        IssueCredential {
            ttl_seconds: MAX_TTL_SECONDS + 1,
            ..request()
        },
        IssueCredential {
            templates: vec![],
            versions: vec![],
            ..request()
        },
        IssueCredential {
            templates: vec!["a b".to_owned()],
            ..request()
        },
        IssueCredential {
            templates: vec![String::new()],
            ..request()
        },
        IssueCredential {
            versions: vec!["v".repeat(129)],
            ..request()
        },
        IssueCredential {
            templates: (0..33).map(|n| format!("t{n}")).collect(),
            ..request()
        },
        IssueCredential {
            label: "x\ny".to_owned(),
            ..request()
        },
        IssueCredential {
            label: "x".repeat(129),
            ..request()
        },
    ];
    for request in bad {
        let shown = format!("{request:?}");
        assert!(
            matches!(
                fixture
                    .credentials
                    .issue(&AdminsOnly, ADMIN, request, NOW)
                    .await,
                Err(CredentialError::Invalid { .. })
            ),
            "{shown} must be refused"
        );
    }
    assert!(fixture.store.rows.lock().unwrap().is_empty());
    // The longest lifetime is accepted.
    let issued = fixture
        .credentials
        .issue(
            &AdminsOnly,
            ADMIN,
            IssueCredential {
                ttl_seconds: MAX_TTL_SECONDS,
                ..request()
            },
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(issued.credential.expires_at, NOW + 86_400_000);
}

#[tokio::test]
async fn the_ledger_refusing_the_intent_issues_nothing() {
    let fixture = fixture();
    *fixture.audit.refuse.lock().unwrap() = true;
    assert!(matches!(
        fixture
            .credentials
            .issue(&AdminsOnly, ADMIN, request(), NOW)
            .await,
        Err(CredentialError::Backend { .. })
    ));
    assert!(fixture.store.rows.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_token_authenticates_until_it_expires_or_is_revoked() {
    let fixture = fixture();
    let issued = fixture
        .credentials
        .issue(&AdminsOnly, ADMIN, request(), NOW)
        .await
        .unwrap();
    let principal = issued.credential.principal_id();
    assert_eq!(
        principal,
        delegated_principal_id("release-qa", &issued.credential.id)
    );

    let authenticated = fixture
        .credentials
        .authenticate(&issued.token, "GET", "/api/v1/lab/leases", NOW + 1)
        .await
        .unwrap();
    assert_eq!(authenticated.principal_id, principal);
    let grant = fixture
        .grants
        .get(&principal)
        .expect("the grant is registered");
    assert!(grant.allows_version("tpl-1", "any"));
    assert!(grant.allows_version("other", "ver-2"));
    assert!(!grant.allows_version("other", "ver-3"));

    // Every use is audited under the credential principal, route only.
    let intents = fixture.audit.intents.lock().unwrap().clone();
    let used = intents.last().unwrap();
    assert_eq!(used.action, "credential.use");
    assert_eq!(used.actor, principal);
    assert!(used.decision.allowed);
    let recorded = format!("{used:?}");
    assert!(recorded.contains("/api/v1/lab/leases"));
    assert!(!recorded.contains(&issued.token));

    // Unknown and tampered tokens identify no one: nothing is audited.
    let before = fixture.audit.intents.lock().unwrap().len();
    for token in ["fake-token-9", "", "fake-token-1 "] {
        assert!(matches!(
            fixture
                .credentials
                .authenticate(token, "GET", "/", NOW)
                .await,
            Err(AuthenticationFailure::Unknown)
        ));
    }
    assert_eq!(fixture.audit.intents.lock().unwrap().len(), before);

    // Expiry applies to the next call, at the exact expiry instant.
    let expired = fixture
        .credentials
        .authenticate(&issued.token, "GET", "/x", issued.credential.expires_at)
        .await;
    assert!(matches!(
        expired,
        Err(AuthenticationFailure::Inactive(CredentialStatus::Expired))
    ));
    assert!(fixture.grants.get(&principal).is_none());
    let denied = fixture
        .audit
        .intents
        .lock()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert!(!denied.decision.allowed);
    assert_eq!(denied.decision.reason, ReasonId::CredentialInactive);
    assert_eq!(denied.actor, principal);

    // Revocation applies to the next call, and wins over expiry.
    fixture
        .credentials
        .authenticate(&issued.token, "GET", "/x", NOW + 2)
        .await
        .unwrap();
    let revoked = fixture
        .credentials
        .revoke(&AdminsOnly, ADMIN, &issued.credential.id, NOW + 3)
        .await
        .unwrap();
    assert_eq!(revoked.status(NOW + 4), CredentialStatus::Revoked);
    assert!(fixture.grants.get(&principal).is_none());
    assert!(matches!(
        fixture
            .credentials
            .authenticate(&issued.token, "GET", "/x", NOW + 4)
            .await,
        Err(AuthenticationFailure::Inactive(CredentialStatus::Revoked))
    ));
    // Revoking again keeps the first revocation.
    let again = fixture
        .credentials
        .revoke(&AdminsOnly, ADMIN, &issued.credential.id, NOW + 99)
        .await
        .unwrap();
    assert_eq!(again.revoked_at, Some(NOW + 3));
    assert!(matches!(
        fixture
            .credentials
            .revoke(&AdminsOnly, ADMIN, "missing", NOW)
            .await,
        Err(CredentialError::NotFound { .. })
    ));
}

#[tokio::test]
async fn an_unauditable_use_is_a_refused_use() {
    let fixture = fixture();
    let issued = fixture
        .credentials
        .issue(&AdminsOnly, ADMIN, request(), NOW)
        .await
        .unwrap();
    *fixture.audit.refuse.lock().unwrap() = true;
    assert!(matches!(
        fixture
            .credentials
            .authenticate(&issued.token, "GET", "/x", NOW + 1)
            .await,
        Err(AuthenticationFailure::Backend(_))
    ));
}

#[tokio::test]
async fn listing_shows_metadata_without_any_token_or_hash() {
    let fixture = fixture();
    let issued = fixture
        .credentials
        .issue(&AdminsOnly, ADMIN, request(), NOW)
        .await
        .unwrap();
    let listed = fixture.credentials.list(&AdminsOnly, ADMIN).await.unwrap();
    assert_eq!(listed.len(), 1);
    let shown = format!("{listed:?}");
    assert!(!shown.contains(&issued.token) && !shown.contains("hash-of"));
    assert_eq!(listed[0].status(NOW), CredentialStatus::Active);
}
