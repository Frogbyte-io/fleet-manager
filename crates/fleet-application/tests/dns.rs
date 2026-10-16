//! FM-1042: DNS authorization, and the apply routine against a scripted
//! gateway (create races, verification, failure classes).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use fleet_application::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use fleet_application::dns::{
    ChangeParameters, Dns, DnsCredentials, DnsError, DnsFailure, DnsFailureClass, DnsGateway,
    DnsObservation, DnsObservationPort, DnsRecord, DnsZone, Plan, PlanOp, plan_delete, plan_upsert,
};
use fleet_application::external_accounts::{
    ExternalAccount, ExternalAccountPort, ExternalCredentialStore, NewExternalAccount, StoredProbe,
};
use fleet_application::proxmox::CredentialStoreError;
use fleet_core::ExternalProviderKind;

#[derive(Debug)]
struct Deny;
impl Authorizer for Deny {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::deny(ReasonId::UnknownPrincipal)
    }
}

/// Allows everything except one permission.
#[derive(Debug)]
struct Without(Permission);
impl Authorizer for Without {
    fn decide(&self, request: AccessRequest<'_>) -> Decision {
        if request.action == self.0 {
            Decision::deny(ReasonId::UnknownPrincipal)
        } else {
            Decision::allow()
        }
    }
}

fn account() -> ExternalAccount {
    ExternalAccount {
        id: "acc1".to_owned(),
        kind: ExternalProviderKind::Cloudflare,
        label: "dns".to_owned(),
        base_url: "https://api.cloudflare.com/client/v4".to_owned(),
        scope_id: None,
        notes: String::new(),
        last_probe: None,
        created_at: 0,
        updated_at: 0,
    }
}

#[derive(Debug)]
struct Accounts;
#[async_trait]
impl ExternalAccountPort for Accounts {
    async fn create(&self, _: &NewExternalAccount) -> Result<ExternalAccount, String> {
        unreachable!()
    }
    async fn get(&self, id: &str) -> Result<ExternalAccount, String> {
        if id == "acc1" {
            Ok(account())
        } else {
            Err("not found".to_owned())
        }
    }
    async fn list(&self) -> Result<Vec<ExternalAccount>, String> {
        Ok(vec![account()])
    }
    async fn update(
        &self,
        _: &str,
        _: &NewExternalAccount,
        _: bool,
    ) -> Result<ExternalAccount, String> {
        unreachable!()
    }
    async fn record_probe(
        &self,
        _: &str,
        _: Option<&StoredProbe>,
    ) -> Result<ExternalAccount, String> {
        unreachable!()
    }
    async fn delete(&self, _: &str) -> Result<(), String> {
        unreachable!()
    }
}

#[derive(Debug)]
struct Credentials;
#[async_trait]
impl ExternalCredentialStore for Credentials {
    async fn load(&self, _: &str) -> Result<Option<String>, CredentialStoreError> {
        Ok(Some("the-token".to_owned()))
    }
    async fn store(&self, _: &str, _: &str) -> Result<(), CredentialStoreError> {
        unreachable!()
    }
    async fn clear(&self, _: &str) -> Result<(), CredentialStoreError> {
        unreachable!()
    }
}

#[derive(Debug)]
struct Observations;
#[async_trait]
impl DnsObservationPort for Observations {
    async fn replace(&self, _: &DnsObservation, _: Option<&str>) -> Result<(), String> {
        Ok(())
    }
    async fn for_name(&self, _: &str) -> Result<Vec<DnsObservation>, String> {
        Ok(Vec::new())
    }
}

/// A gateway scripted per call: record lists are answered from a queue, and
/// every write is logged. An empty queue answers the last list again.
#[derive(Debug, Default)]
struct Script {
    lists: Mutex<Vec<Vec<DnsRecord>>>,
    create: Mutex<Option<DnsFailure>>,
    delete: Mutex<Option<DnsFailure>>,
    writes: Mutex<Vec<String>>,
    reads: Mutex<usize>,
    zone_calls: Mutex<usize>,
    zone_id: Mutex<Option<String>>,
}

#[async_trait]
impl DnsGateway for Script {
    async fn list_zones(
        &self,
        _: &DnsCredentials,
        _: Option<&str>,
    ) -> Result<Vec<DnsZone>, DnsFailure> {
        *self.zone_calls.lock().unwrap() += 1;
        Ok(vec![DnsZone {
            id: self
                .zone_id
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| "zone1".to_owned()),
            name: "example.com".to_owned(),
            status: "active".to_owned(),
        }])
    }
    async fn list_records(
        &self,
        _: &DnsCredentials,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<Vec<DnsRecord>, DnsFailure> {
        *self.reads.lock().unwrap() += 1;
        let mut lists = self.lists.lock().unwrap();
        if lists.len() > 1 {
            Ok(lists.remove(0))
        } else {
            Ok(lists.first().cloned().unwrap_or_default())
        }
    }
    async fn create_record(
        &self,
        _: &DnsCredentials,
        _: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, DnsFailure> {
        self.writes
            .lock()
            .unwrap()
            .push(format!("create {}", record.content));
        match self.create.lock().unwrap().clone() {
            Some(failure) => Err(failure),
            None => Ok(record.clone()),
        }
    }
    async fn update_record(
        &self,
        _: &DnsCredentials,
        _: &str,
        id: &str,
        record: &DnsRecord,
    ) -> Result<DnsRecord, DnsFailure> {
        self.writes
            .lock()
            .unwrap()
            .push(format!("update {id} {}", record.content));
        Ok(record.clone())
    }
    async fn delete_record(&self, _: &DnsCredentials, _: &str, id: &str) -> Result<(), DnsFailure> {
        self.writes.lock().unwrap().push(format!("delete {id}"));
        match self.delete.lock().unwrap().clone() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }
}

fn dns(script: &Arc<Script>) -> Dns {
    Dns::new(
        Arc::new(Accounts),
        Arc::new(Credentials),
        script.clone(),
        Arc::new(Observations),
    )
}

fn record(id: &str, content: &str, ttl: u32) -> DnsRecord {
    DnsRecord {
        id: Some(id.to_owned()),
        record_type: "A".to_owned(),
        name: "www.example.com".to_owned(),
        content: content.to_owned(),
        ttl,
        proxied: false,
        priority: None,
    }
}

fn create_payload(content: &str) -> String {
    let desired = DnsRecord {
        id: None,
        ..record("x", content, 300)
    };
    payload(content, plan_upsert(&[], &desired, None).unwrap())
}

fn payload(content: &str, preview: Plan) -> String {
    serde_json::to_string(&ChangeParameters {
        account_id: "acc1".to_owned(),
        zone_id: "zone1".to_owned(),
        zone_name: "example.com".to_owned(),
        name: "www.example.com".to_owned(),
        record_type: "A".to_owned(),
        content: content.to_owned(),
        ttl: Some(300),
        proxied: Some(false),
        priority: None,
        replaces: None,
        preview,
    })
    .unwrap()
}

#[tokio::test]
async fn reads_and_changes_need_dns_read_and_never_reach_the_provider_without_it() {
    let script = Arc::new(Script::default());
    let dns = dns(&script);
    assert!(matches!(
        dns.zones(&Deny, "p", None).await,
        Err(DnsError::Denied(_))
    ));
    assert!(matches!(
        dns.records(
            &Without(Permission::DnsRead),
            "p",
            "www.example.com",
            None,
            None,
            0
        )
        .await,
        Err(DnsError::Denied(_))
    ));
    // Nothing was read from the provider.
    assert_eq!(*script.reads.lock().unwrap(), 0);
    assert_eq!(*script.zone_calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn a_create_that_loses_a_race_to_an_identical_record_is_still_a_success() {
    let script = Arc::new(Script::default());
    // Before: nothing. The create is refused as a duplicate; the re-read
    // shows the record, so the change is in place. Then verification reads.
    *script.lists.lock().unwrap() = vec![Vec::new(), vec![record("r1", "203.0.113.9", 300)]];
    *script.create.lock().unwrap() = Some(DnsFailure::new(
        DnsFailureClass::Conflict,
        "An identical record already exists.",
    ));
    let outcome = dns(&script)
        .execute("dns.record.upsert", &create_payload("203.0.113.9"))
        .await
        .expect("an identical record is the goal");
    assert_eq!(outcome.outcome, "created");
    assert!(outcome.verified);
}

#[tokio::test]
async fn a_conflict_that_is_not_the_wanted_record_fails_with_its_class() {
    let script = Arc::new(Script::default());
    *script.lists.lock().unwrap() = vec![Vec::new()];
    *script.create.lock().unwrap() = Some(DnsFailure::new(
        DnsFailureClass::Conflict,
        "A CNAME record with that host already exists.",
    ));
    let error = dns(&script)
        .execute("dns.record.upsert", &create_payload("203.0.113.9"))
        .await
        .expect_err("a real conflict");
    assert!(error.starts_with("conflict:"), "{error}");
}

#[tokio::test]
async fn a_write_that_does_not_stick_fails_verification() {
    let script = Arc::new(Script::default());
    // The provider accepts the create but the re-read shows nothing.
    *script.lists.lock().unwrap() = vec![Vec::new()];
    let error = dns(&script)
        .execute("dns.record.upsert", &create_payload("203.0.113.9"))
        .await
        .expect_err("not verified");
    assert!(error.contains("verification failed"), "{error}");
}

#[tokio::test]
async fn a_delete_that_does_not_stick_fails_verification_and_a_gone_record_is_a_success() {
    let before = record("r1", "203.0.113.9", 300);
    let plan = plan_delete(
        std::slice::from_ref(&before),
        "A",
        "www.example.com",
        "203.0.113.9",
        None,
    );
    assert_eq!(plan.operation, PlanOp::Delete);
    let script = Arc::new(Script::default());
    *script.lists.lock().unwrap() = vec![vec![before.clone()]];
    let error = dns(&script)
        .execute(
            "dns.record.delete",
            &delete_payload("203.0.113.9", plan.clone()),
        )
        .await
        .expect_err("still present");
    assert!(error.contains("still present"), "{error}");
    assert_eq!(script.writes.lock().unwrap().as_slice(), ["delete r1"]);

    // The record vanishes between the read and the delete: the goal.
    let script = Arc::new(Script::default());
    *script.lists.lock().unwrap() = vec![vec![before], Vec::new()];
    *script.delete.lock().unwrap() = Some(DnsFailure::new(
        DnsFailureClass::NotFound,
        "Record does not exist.",
    ));
    let outcome = dns(&script)
        .execute("dns.record.delete", &delete_payload("203.0.113.9", plan))
        .await
        .expect("gone is the goal");
    assert_eq!(outcome.outcome, "deleted");
}

fn delete_payload(content: &str, preview: Plan) -> String {
    let mut params: ChangeParameters = serde_json::from_str(&payload(content, preview)).unwrap();
    params.ttl = None;
    params.proxied = None;
    serde_json::to_string(&params).unwrap()
}

#[tokio::test]
async fn a_malformed_or_foreign_payload_is_refused_before_any_provider_call() {
    let script = Arc::new(Script::default());
    let dns = dns(&script);
    assert!(dns.execute("noop", "{}").await.is_err());
    assert!(dns.execute("dns.record.upsert", "{}").await.is_err());
    // A preview that does not match the parameters never executes.
    let mut params: ChangeParameters =
        serde_json::from_str(&create_payload("203.0.113.9")).unwrap();
    params.content = "203.0.113.10".to_owned();
    let error = dns
        .execute(
            "dns.record.upsert",
            &serde_json::to_string(&params).unwrap(),
        )
        .await
        .expect_err("a forged preview");
    assert!(error.contains("preview"), "{error}");
    assert_eq!(*script.reads.lock().unwrap(), 0);
    assert!(script.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_zone_id_that_is_not_the_named_zone_changes_nothing() {
    let script = Arc::new(Script::default());
    *script.zone_id.lock().unwrap() = Some("another-zone".to_owned());
    let error = dns(&script)
        .execute("dns.record.upsert", &create_payload("203.0.113.9"))
        .await
        .expect_err("a forged zone id");
    assert!(error.contains("zone id"), "{error}");
    assert_eq!(*script.reads.lock().unwrap(), 0);
    assert!(script.writes.lock().unwrap().is_empty());
}
