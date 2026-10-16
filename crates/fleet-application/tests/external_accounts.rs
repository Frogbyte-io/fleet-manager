//! FM-1001: external account use cases over in-memory ports: central
//! authorization, audit, and the write-only token.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::audit::{AuditIntent, AuditOutcome};
use fleet_application::authz::{
    AccessRequest, ActingPrincipal, Authorizer, Decision, Permission, ReasonId,
};
use fleet_application::external_accounts::{
    CreateExternalAccount, ExternalAccount, ExternalAccountError, ExternalAccountPort,
    ExternalAccounts, ExternalCredentialStore, ExternalProbePort, NewExternalAccount, StoredProbe,
    UpdateExternalAccount,
};
use fleet_application::operation::AuditPort;
use fleet_application::proxmox::CredentialStoreError;
use fleet_core::{ExternalProviderKind, ProbeReport, ProbeStatus, SensitiveString};

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

#[derive(Debug, Default)]
struct Accounts(Mutex<Vec<ExternalAccount>>);

#[async_trait]
impl ExternalAccountPort for Accounts {
    async fn create(&self, new: &NewExternalAccount) -> Result<ExternalAccount, String> {
        let mut all = self.0.lock().unwrap();
        if all
            .iter()
            .any(|a| a.kind == new.kind && a.label == new.label)
        {
            return Err("the label is already taken".to_owned());
        }
        let account = ExternalAccount {
            id: format!("acc-{}", all.len() + 1),
            kind: new.kind,
            label: new.label.clone(),
            base_url: new.base_url.clone(),
            scope_id: new.scope_id.clone(),
            notes: new.notes.clone(),
            last_probe: None,
            created_at: 1,
            updated_at: 1,
        };
        all.insert(0, account.clone());
        Ok(account)
    }
    async fn get(&self, id: &str) -> Result<ExternalAccount, String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| format!("account {id} not found"))
    }
    async fn list(&self) -> Result<Vec<ExternalAccount>, String> {
        Ok(self.0.lock().unwrap().clone())
    }
    async fn update(
        &self,
        id: &str,
        new: &NewExternalAccount,
        clear_probe: bool,
    ) -> Result<ExternalAccount, String> {
        let mut all = self.0.lock().unwrap();
        let account = all
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("account {id} not found"))?;
        account.label.clone_from(&new.label);
        account.base_url.clone_from(&new.base_url);
        account.scope_id.clone_from(&new.scope_id);
        account.notes.clone_from(&new.notes);
        if clear_probe {
            account.last_probe = None;
        }
        Ok(account.clone())
    }
    async fn record_probe(
        &self,
        id: &str,
        probe: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String> {
        let mut all = self.0.lock().unwrap();
        let account = all
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("account {id} not found"))?;
        account.last_probe = probe.cloned();
        Ok(account.clone())
    }
    async fn delete(&self, id: &str) -> Result<(), String> {
        let mut all = self.0.lock().unwrap();
        let before = all.len();
        all.retain(|a| a.id != id);
        if all.len() == before {
            return Err(format!("account {id} not found"));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Credentials(Mutex<HashMap<String, String>>);

#[async_trait]
impl ExternalCredentialStore for Credentials {
    async fn load(&self, id: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(self.0.lock().unwrap().get(id).cloned())
    }
    async fn store(&self, id: &str, secret: &str) -> Result<(), CredentialStoreError> {
        self.0
            .lock()
            .unwrap()
            .insert(id.to_owned(), secret.to_owned());
        Ok(())
    }
    async fn clear(&self, id: &str) -> Result<(), CredentialStoreError> {
        self.0.lock().unwrap().remove(id);
        Ok(())
    }
}

/// Answers a canned status and records the token it was handed.
#[derive(Debug)]
struct Prober {
    status: ProbeStatus,
    seen: Mutex<Vec<String>>,
}

#[async_trait]
impl ExternalProbePort for Prober {
    async fn probe(
        &self,
        _kind: ExternalProviderKind,
        _base_url: &str,
        _scope_id: Option<&str>,
        token: &SensitiveString,
    ) -> ProbeReport {
        self.seen.lock().unwrap().push(token.expose().to_owned());
        ProbeReport::simple(self.status, "canned")
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
    async fn record_outcome(&self, _id: &str, _outcome: AuditOutcome) -> Result<(), String> {
        Ok(())
    }
}

struct Rig {
    service: ExternalAccounts,
    credentials: Arc<Credentials>,
    prober: Arc<Prober>,
    audit: Arc<Audit>,
}

fn rig(status: ProbeStatus) -> Rig {
    let credentials = Arc::new(Credentials::default());
    let prober = Arc::new(Prober {
        status,
        seen: Mutex::default(),
    });
    let audit = Arc::new(Audit::default());
    Rig {
        service: ExternalAccounts::new(
            Arc::new(Accounts::default()),
            credentials.clone(),
            prober.clone(),
            audit.clone(),
        ),
        credentials,
        prober,
        audit,
    }
}

fn coolify(label: &str) -> CreateExternalAccount {
    CreateExternalAccount {
        kind: ExternalProviderKind::Coolify,
        label: label.to_owned(),
        base_url: Some("https://coolify.example.test/".to_owned()),
        scope_id: None,
        notes: None,
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
async fn create_stores_the_token_apart_and_audits_without_it() {
    let rig = rig(ProbeStatus::Ok);
    let account = rig
        .service
        .create(&Deny(vec![]), &principal(), coolify("prod"), TOKEN)
        .await
        .expect("create");
    assert_eq!(account.base_url, "https://coolify.example.test");
    assert_eq!(
        rig.credentials.load(&account.id).await.unwrap().as_deref(),
        Some(TOKEN)
    );
    // The record itself carries no token anywhere.
    assert!(!format!("{account:?}{}", serde_json::to_string(&account).unwrap()).contains(TOKEN));
    assert_eq!(
        events(&rig.audit),
        ["external_account_creating", "external_account_created"]
    );
    let audited = format!("{:?}", rig.audit.0.lock().unwrap());
    assert!(!audited.contains(TOKEN));
    assert!(
        rig.audit
            .0
            .lock()
            .unwrap()
            .iter()
            .all(|i| i.action == "external_account.config")
    );
}

#[tokio::test]
async fn several_accounts_per_kind_but_labels_are_unique_within_a_kind() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    rig.service
        .create(&allow, &principal(), coolify("a"), TOKEN)
        .await
        .unwrap();
    rig.service
        .create(&allow, &principal(), coolify("b"), TOKEN)
        .await
        .unwrap();
    let error = rig
        .service
        .create(&allow, &principal(), coolify("a"), TOKEN)
        .await
        .unwrap_err();
    assert!(matches!(error, ExternalAccountError::Conflict { .. }));
    let cloudflare = CreateExternalAccount {
        kind: ExternalProviderKind::Cloudflare,
        label: "a".to_owned(),
        base_url: None,
        scope_id: Some("0123abcd".to_owned()),
        notes: Some("dns".to_owned()),
    };
    let account = rig
        .service
        .create(&allow, &principal(), cloudflare, TOKEN)
        .await
        .expect("same label under another kind");
    assert_eq!(account.base_url, "https://api.cloudflare.com/client/v4");
}

#[tokio::test]
async fn invalid_requests_are_refused_before_any_audit_or_secret_write() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    for bad in [
        CreateExternalAccount {
            base_url: None,
            ..coolify("x")
        },
        CreateExternalAccount {
            base_url: Some("https://u:p@host".to_owned()),
            ..coolify("x")
        },
        CreateExternalAccount {
            scope_id: Some("abc".to_owned()),
            ..coolify("x")
        },
        coolify(""),
    ] {
        let error = rig
            .service
            .create(&allow, &principal(), bad, TOKEN)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ExternalAccountError::Invalid { .. }),
            "{error}"
        );
    }
    let error = rig
        .service
        .create(&allow, &principal(), coolify("x"), "")
        .await
        .unwrap_err();
    assert!(matches!(error, ExternalAccountError::Invalid { .. }));
    assert!(rig.audit.0.lock().unwrap().is_empty());
    assert!(rig.credentials.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn every_endpoint_is_authorized_centrally() {
    let rig = rig(ProbeStatus::Ok);
    let account = rig
        .service
        .create(&Deny(vec![]), &principal(), coolify("prod"), TOKEN)
        .await
        .unwrap();
    rig.audit.0.lock().unwrap().clear();
    let no_config = Deny(vec![Permission::ExternalAccountConfig]);
    let no_read = Deny(vec![Permission::ExternalAccountRead]);
    let denied = |error: ExternalAccountError| matches!(error, ExternalAccountError::Denied(_));
    assert!(denied(
        rig.service
            .create(&no_config, &principal(), coolify("z"), TOKEN)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        rig.service
            .update(
                &no_config,
                &principal(),
                &account.id,
                UpdateExternalAccount::default(),
                None
            )
            .await
            .unwrap_err()
    ));
    assert!(denied(
        rig.service
            .probe(&no_config, &principal(), &account.id)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        rig.service
            .delete(&no_config, &principal(), &account.id)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        rig.service
            .list(&no_read, &principal(), None, 10, None)
            .await
            .unwrap_err()
    ));
    assert!(denied(
        rig.service
            .get(&no_read, &principal(), &account.id)
            .await
            .unwrap_err()
    ));
    // Nothing happened: no audit event, no probe, the token is intact.
    assert!(rig.audit.0.lock().unwrap().is_empty());
    assert!(rig.prober.seen.lock().unwrap().is_empty());
    assert!(rig.credentials.load(&account.id).await.unwrap().is_some());
}

#[tokio::test]
async fn probe_records_the_classified_result_and_audits_the_status_only() {
    for status in [
        ProbeStatus::Ok,
        ProbeStatus::Unreachable,
        ProbeStatus::Unauthorized,
        ProbeStatus::InsufficientPermission,
    ] {
        let rig = rig(status);
        let allow = Deny(vec![]);
        let account = rig
            .service
            .create(&allow, &principal(), coolify("prod"), TOKEN)
            .await
            .unwrap();
        let probed = rig
            .service
            .probe(&allow, &principal(), &account.id)
            .await
            .unwrap();
        assert_eq!(probed.last_probe.unwrap().report.status, status);
        assert_eq!(rig.prober.seen.lock().unwrap().as_slice(), [TOKEN]);
        let audit = rig.audit.0.lock().unwrap();
        let probed_event = audit.last().unwrap();
        assert!(
            probed_event
                .metadata
                .entries()
                .any(|entry| entry == ("status", status.id()))
        );
        assert!(!format!("{audit:?}").contains(TOKEN));
    }
}

#[tokio::test]
async fn update_replaces_the_token_and_clears_a_stale_probe() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    let account = rig
        .service
        .create(&allow, &principal(), coolify("prod"), TOKEN)
        .await
        .unwrap();
    rig.service
        .probe(&allow, &principal(), &account.id)
        .await
        .unwrap();
    // Notes only: the probe still applies.
    let kept = rig
        .service
        .update(
            &allow,
            &principal(),
            &account.id,
            UpdateExternalAccount {
                notes: Some("hello".to_owned()),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    assert!(kept.last_probe.is_some());
    let rotated = rig
        .service
        .update(
            &allow,
            &principal(),
            &account.id,
            UpdateExternalAccount::default(),
            Some("brand-new-token-9876"),
        )
        .await
        .unwrap();
    assert!(rotated.last_probe.is_none());
    assert_eq!(
        rig.credentials.load(&account.id).await.unwrap().as_deref(),
        Some("brand-new-token-9876")
    );
    let audited = format!("{:?}", rig.audit.0.lock().unwrap());
    assert!(!audited.contains("brand-new-token"));
    assert!(audited.contains("replaced"));
}

#[tokio::test]
async fn delete_removes_the_account_and_its_token() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    let account = rig
        .service
        .create(&allow, &principal(), coolify("prod"), TOKEN)
        .await
        .unwrap();
    rig.service
        .delete(&allow, &principal(), &account.id)
        .await
        .unwrap();
    assert!(rig.credentials.load(&account.id).await.unwrap().is_none());
    assert!(matches!(
        rig.service.get(&allow, &principal(), &account.id).await,
        Err(ExternalAccountError::NotFound { .. })
    ));
    let names = events(&rig.audit);
    assert_eq!(
        &names[names.len() - 2..],
        ["external_account_deleting", "external_account_deleted"]
    );
}

#[tokio::test]
async fn moving_to_another_origin_needs_a_new_token_in_the_same_request() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    let account = rig
        .service
        .create(&allow, &principal(), coolify("prod"), TOKEN)
        .await
        .unwrap();
    let to = |url: &str| UpdateExternalAccount {
        base_url: Some(url.to_owned()),
        ..Default::default()
    };
    for url in [
        "https://other.example.test",
        "http://coolify.example.test",
        "https://coolify.example.test:8443",
    ] {
        let error = rig
            .service
            .update(&allow, &principal(), &account.id, to(url), None)
            .await
            .unwrap_err();
        assert!(
            matches!(error, ExternalAccountError::Invalid { .. }),
            "{url}"
        );
    }
    // Nothing changed, and nothing was audited as an update.
    assert_eq!(
        rig.credentials.load(&account.id).await.unwrap().as_deref(),
        Some(TOKEN)
    );
    assert!(!events(&rig.audit).contains(&"external_account_updating".to_owned()));
    // A path-only change keeps the origin; a new token authorizes a move.
    rig.service
        .update(
            &allow,
            &principal(),
            &account.id,
            to("https://coolify.example.test/sub"),
            None,
        )
        .await
        .expect("same origin");
    let moved = rig
        .service
        .update(
            &allow,
            &principal(),
            &account.id,
            to("https://other.example.test"),
            Some("a-new-token-for-the-new-host"),
        )
        .await
        .expect("new origin with a new token");
    assert_eq!(moved.base_url, "https://other.example.test");
}

#[tokio::test]
async fn cloudflare_requires_https_except_on_loopback() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    let cloudflare = |url: &str| CreateExternalAccount {
        kind: ExternalProviderKind::Cloudflare,
        label: "dns".to_owned(),
        base_url: Some(url.to_owned()),
        scope_id: None,
        notes: None,
    };
    let error = rig
        .service
        .create(
            &allow,
            &principal(),
            cloudflare("http://api.example.test"),
            TOKEN,
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("https"), "{error}");
    rig.service
        .create(
            &allow,
            &principal(),
            cloudflare("http://127.0.0.1:9"),
            TOKEN,
        )
        .await
        .expect("loopback stub");
}

#[tokio::test]
async fn a_label_or_note_the_scrubber_would_change_is_refused() {
    let rig = rig(ProbeStatus::Ok);
    let allow = Deny(vec![]);
    let error = rig
        .service
        .create(
            &allow,
            &principal(),
            coolify("Authorization: Bearer abcdefghijklmnop"),
            TOKEN,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ExternalAccountError::Invalid { .. }));
    let with_notes = CreateExternalAccount {
        notes: Some("see https://user:hunter2@example.test/x".to_owned()),
        ..coolify("ok")
    };
    let error = rig
        .service
        .create(&allow, &principal(), with_notes, TOKEN)
        .await
        .unwrap_err();
    assert!(matches!(error, ExternalAccountError::Invalid { .. }));
    assert!(rig.audit.0.lock().unwrap().is_empty());
}

/// A credential store whose writes can be made to fail.
#[derive(Debug, Default)]
struct FlakyCredentials {
    inner: Credentials,
    fail: Mutex<bool>,
}

#[async_trait]
impl ExternalCredentialStore for FlakyCredentials {
    async fn load(&self, id: &str) -> Result<Option<String>, CredentialStoreError> {
        self.inner.load(id).await
    }
    async fn store(&self, id: &str, secret: &str) -> Result<(), CredentialStoreError> {
        if *self.fail.lock().unwrap() {
            return Err(CredentialStoreError::Backend {
                detail: "store down".to_owned(),
            });
        }
        self.inner.store(id, secret).await
    }
    async fn clear(&self, id: &str) -> Result<(), CredentialStoreError> {
        self.inner.clear(id).await
    }
}

#[tokio::test]
async fn a_failed_token_replacement_leaves_the_old_token_and_no_stale_probe() {
    let credentials = Arc::new(FlakyCredentials::default());
    let service = ExternalAccounts::new(
        Arc::new(Accounts::default()),
        credentials.clone(),
        Arc::new(Prober {
            status: ProbeStatus::Ok,
            seen: Mutex::default(),
        }),
        Arc::new(Audit::default()),
    );
    let allow = Deny(vec![]);
    let account = service
        .create(&allow, &principal(), coolify("prod"), TOKEN)
        .await
        .unwrap();
    service
        .probe(&allow, &principal(), &account.id)
        .await
        .unwrap();
    *credentials.fail.lock().unwrap() = true;
    let error = service
        .update(
            &allow,
            &principal(),
            &account.id,
            UpdateExternalAccount::default(),
            Some("replacement-token-123456"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ExternalAccountError::Credentials(_)));
    assert_eq!(
        credentials.load(&account.id).await.unwrap().as_deref(),
        Some(TOKEN),
        "the old token stays"
    );
    let after = service
        .get(&allow, &principal(), &account.id)
        .await
        .unwrap();
    assert!(
        after.last_probe.is_none(),
        "no probe outlives a credential change attempt"
    );
}
