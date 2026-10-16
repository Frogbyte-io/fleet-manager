use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};

use super::diff::{assess, date_part, days_from_date, dns_host_matches, registrars_match};
use super::*;
use crate::audit::AuditIntent;
use crate::authz::{AccessRequest, Authorizer, Decision, Permission, ReasonId};
use crate::operation::AuditPort;

const NOW: i64 = 1_792_000_000_000; // 2026-10-14

fn today() -> i64 {
    diff::days_from_millis(NOW)
}

fn observation(
    registrar: Option<&str>,
    expires: Option<&str>,
    ns: &[&str],
) -> DomainObservation {
    DomainObservation {
        observed_at: NOW,
        rdap: RdapObservation {
            status: RdapStatus::Ok,
            server: Some("https://rdap.example/".to_owned()),
            registrar: registrar.map(str::to_owned),
            expires: expires.map(str::to_owned),
            statuses: vec![],
            nameservers: vec![],
            detail: None,
        },
        dns: DnsObservation {
            status: DnsStatus::Ok,
            apex: DnsRecords {
                ns: ns.iter().map(|n| (*n).to_owned()).collect(),
                ..DnsRecords::default()
            },
            www: DnsRecords::default(),
            detail: None,
        },
    }
}

fn diff_of<'a>(assessment: &'a Assessment, field: &str) -> &'a FieldDiff {
    assessment.diffs.iter().find(|d| d.field == field).unwrap()
}

fn codes(assessment: &Assessment) -> Vec<WarningCode> {
    assessment.warnings.iter().map(|w| w.code).collect()
}

#[test]
fn dates_convert_to_day_numbers() {
    assert_eq!(days_from_date("1970-01-01"), Some(0));
    assert_eq!(days_from_date("2000-03-01"), Some(11_017));
    assert_eq!(days_from_date("2027-08-13T04:00:00Z"), days_from_date("2027-08-13"));
    assert_eq!(days_from_date("2027-13-01"), None);
    assert_eq!(days_from_date("soon"), None);
    assert_eq!(date_part("2027-08-13T04:00:00Z").as_deref(), Some("2027-08-13"));
    assert_eq!(today(), days_from_date("2026-10-14").unwrap());
}

#[test]
fn registrar_names_match_across_legal_suffixes_and_punctuation() {
    assert!(registrars_match("GoDaddy", "GoDaddy.com, LLC"));
    assert!(registrars_match("Webhuset", "Webhuset AS"));
    assert!(registrars_match("Sikt", "SIKT - KUNNSKAPSSEKTORENS TJENESTELEVERANDØR"));
    assert!(!registrars_match("Porkbun", "Namecheap, Inc."));
    assert!(!registrars_match("Hostinger", "Webhuset AS"));
}

#[test]
fn dns_hosts_match_by_name_or_known_alias() {
    let ns = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
    assert!(dns_host_matches("Cloudflare", &ns(&["elliott.ns.cloudflare.com"])));
    assert!(dns_host_matches("Hostinger", &ns(&["ns1.dns-parking.com"])));
    assert!(dns_host_matches("GoDaddy", &ns(&["ns01.domaincontrol.com"])));
    assert!(!dns_host_matches("Cloudflare", &ns(&["ns1.dns-parking.com"])));
    assert!(!dns_host_matches("", &ns(&["ns1.dns-parking.com"])));
}

#[test]
fn agreeing_fields_are_in_sync_and_make_no_noise() {
    let fields = json!({
        "fqdn": "example.com", "registrar": "GoDaddy", "expires": "2027-08-13",
        "nameservers": ["B.NS.example.net.", "a.ns.example.net"], "dnsHost": "example",
    });
    let seen = observation(
        Some("GoDaddy.com, LLC"),
        Some("2027-08-13T04:00:00Z"),
        &["a.ns.example.net", "b.ns.example.net"],
    );
    let result = assess(&fields, Some(&seen), today(), 30);
    for field in ["registrar", "expires", "nameservers", "dnsHost"] {
        assert_eq!(diff_of(&result, field).state, FieldState::InSync, "{field}");
    }
    assert!(result.warnings.is_empty());
    assert!(result.suggestion.is_empty());
}

#[test]
fn a_changed_registrar_warns_and_is_suggested() {
    let fields = json!({"fqdn": "example.com", "registrar": "Porkbun"});
    let seen = observation(Some("Namecheap, Inc."), None, &[]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(diff_of(&result, "registrar").state, FieldState::Changed);
    assert_eq!(codes(&result), [WarningCode::RegistrarMismatch]);
    assert_eq!(result.suggestion[0].field, "registrar");
    assert_eq!(result.suggestion[0].value, json!("Namecheap, Inc."));
}

#[test]
fn a_field_the_entry_lacks_is_changed_and_suggested_without_a_warning() {
    let fields = json!({"fqdn": "example.com"});
    let seen = observation(Some("Webhuset AS"), Some("2028-01-01"), &["ns1.example.net"]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(diff_of(&result, "registrar").state, FieldState::Changed);
    assert_eq!(diff_of(&result, "expires").state, FieldState::Changed);
    assert_eq!(diff_of(&result, "nameservers").state, FieldState::Changed);
    assert!(result.warnings.is_empty());
    let suggested: Vec<_> = result.suggestion.iter().map(|s| s.field).collect();
    assert_eq!(suggested, ["registrar", "expires", "nameservers"]);
}

#[test]
fn nothing_to_compare_is_unknown() {
    let fields = json!({"fqdn": "example.com", "registrar": "Porkbun"});
    // No observation at all.
    let none = assess(&fields, None, today(), 30);
    assert!(none.diffs.iter().all(|d| d.state == FieldState::Unknown));
    assert!(none.suggestion.is_empty());
    // An observation that found nothing (no RDAP for the TLD).
    let mut blank = observation(None, None, &[]);
    blank.rdap = RdapObservation::empty(RdapStatus::Unavailable, "no RDAP for .no");
    let result = assess(&fields, Some(&blank), today(), 30);
    assert_eq!(diff_of(&result, "registrar").state, FieldState::Unknown);
    assert!(result.warnings.is_empty());
}

#[test]
fn nameservers_that_differ_from_the_recorded_set_warn() {
    let fields = json!({"fqdn": "example.com", "nameservers": ["ns1.old.net", "ns2.old.net"]});
    let seen = observation(None, None, &["ns1.new.net", "ns2.new.net"]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(diff_of(&result, "nameservers").state, FieldState::Changed);
    assert_eq!(codes(&result), [WarningCode::NameserversMismatch]);
    assert_eq!(
        result.suggestion[0].value,
        json!(["ns1.new.net", "ns2.new.net"])
    );
}

#[test]
fn registry_nameservers_stand_in_when_dns_did_not_answer() {
    let fields = json!({"fqdn": "example.com", "nameservers": ["ns1.a.net"]});
    let mut seen = observation(None, None, &[]);
    seen.rdap.nameservers = vec!["ns1.a.net".to_owned()];
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(diff_of(&result, "nameservers").state, FieldState::InSync);
}

#[test]
fn nameservers_that_do_not_match_dns_host_warn() {
    let fields = json!({"fqdn": "example.com", "dnsHost": "Cloudflare"});
    let seen = observation(None, None, &["ns1.dns-parking.com"]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(diff_of(&result, "dnsHost").state, FieldState::Changed);
    assert_eq!(codes(&result), [WarningCode::DnsHostMismatch]);
    // A provider's name cannot be derived from its servers.
    assert!(result.suggestion.iter().all(|s| s.field != "dnsHost"));
}

#[test]
fn expiry_inside_the_window_warns_and_urgent_expiry_is_an_error() {
    let soon = json!({"fqdn": "example.com", "expires": "2026-11-03"}); // 20 days
    let result = assess(&soon, None, today(), 30);
    assert_eq!(codes(&result), [WarningCode::Expiring]);
    assert_eq!(result.warnings[0].severity, Severity::Warn);

    let urgent = json!({"fqdn": "example.com", "expires": "2026-10-18"}); // 4 days
    assert_eq!(assess(&urgent, None, today(), 30).warnings[0].severity, Severity::Err);

    let lapsed = json!({"fqdn": "example.com", "expires": "2026-10-01"});
    let result = assess(&lapsed, None, today(), 30);
    assert_eq!(result.warnings[0].severity, Severity::Err);
    assert!(result.warnings[0].message.contains("expired 13 days ago"));

    let far = json!({"fqdn": "example.com", "expires": "2027-10-01"});
    assert!(assess(&far, None, today(), 30).warnings.is_empty());
    // The window is configurable.
    assert_eq!(codes(&assess(&far, None, today(), 400)), [WarningCode::Expiring]);
}

#[test]
fn auto_renew_off_while_expiring_is_its_own_warning() {
    let fields = json!({"fqdn": "example.com", "expires": "2026-11-03", "autoRenew": false});
    let result = assess(&fields, None, today(), 30);
    assert_eq!(codes(&result), [WarningCode::AutoRenewOffExpiring]);
    let renewing = json!({"fqdn": "example.com", "expires": "2026-11-03", "autoRenew": true});
    assert_eq!(codes(&assess(&renewing, None, today(), 30)), [WarningCode::Expiring]);
    // Auto-renew off but nowhere near expiry is not a warning.
    let distant = json!({"fqdn": "example.com", "expires": "2028-11-03", "autoRenew": false});
    assert!(assess(&distant, None, today(), 30).warnings.is_empty());
}

#[test]
fn the_registrys_expiry_wins_over_a_stale_recorded_one() {
    // Renewed at the registrar: the entry still says it is about to lapse.
    let fields = json!({"fqdn": "example.com", "expires": "2026-11-03"});
    let seen = observation(None, Some("2027-11-03T00:00:00Z"), &[]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(codes(&result), [WarningCode::ExpiryChanged]);
    assert_eq!(result.suggestion[0].value, json!("2027-11-03"));
}

#[test]
fn warnings_are_ordered_most_serious_first() {
    let fields = json!({"fqdn": "example.com", "registrar": "Porkbun",
        "expires": "2026-10-16", "autoRenew": false});
    let seen = observation(Some("Namecheap"), None, &[]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(
        codes(&result),
        [WarningCode::AutoRenewOffExpiring, WarningCode::RegistrarMismatch]
    );
}

// ---- service ----

#[derive(Debug, Default)]
struct Directory {
    entries: Vec<DomainEntry>,
}

#[async_trait]
impl DomainDirectory for Directory {
    async fn get(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        key: &str,
    ) -> Result<DomainEntry, ProjectUseCaseError> {
        crate::authz::authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::RegistryRead,
                resource: None,
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        self.entries
            .iter()
            .find(|entry| entry.key.eq_ignore_ascii_case(key))
            .cloned()
            .ok_or(ProjectUseCaseError::NotFound {
                what: "registry entry".to_owned(),
            })
    }

    async fn list(
        &self,
        authorizer: &dyn Authorizer,
        principal_id: &str,
        after: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DomainEntry>, ProjectUseCaseError> {
        crate::authz::authorize(
            authorizer,
            AccessRequest {
                principal_id,
                action: Permission::RegistryRead,
                resource: None,
            },
        )
        .map_err(ProjectUseCaseError::Denied)?;
        Ok(self
            .entries
            .iter()
            .filter(|entry| after.is_none_or(|after| entry.key.as_str() > after))
            .take(usize::try_from(limit).unwrap())
            .cloned()
            .collect())
    }
}

#[derive(Debug, Default)]
struct RdapStub {
    /// fqdn -> (server, answer); a missing fqdn has no RDAP.
    answers: Mutex<HashMap<String, (String, Result<RdapAnswer, RdapFailure>)>>,
    queries: Mutex<Vec<(std::time::Instant, String)>>,
}

impl RdapStub {
    fn with(self, fqdn: &str, server: &str, answer: Result<RdapAnswer, RdapFailure>) -> Self {
        self.answers
            .lock()
            .unwrap()
            .insert(fqdn.to_owned(), (server.to_owned(), answer));
        self
    }
}

#[async_trait]
impl RdapPort for RdapStub {
    async fn server_for(&self, fqdn: &str) -> Result<Option<String>, String> {
        Ok(self
            .answers
            .lock()
            .unwrap()
            .get(fqdn)
            .map(|(server, _)| server.clone()))
    }

    async fn lookup(&self, server: &str, fqdn: &str) -> Result<RdapAnswer, RdapFailure> {
        self.queries
            .lock()
            .unwrap()
            .push((std::time::Instant::now(), server.to_owned()));
        self.answers.lock().unwrap().get(fqdn).unwrap().1.clone()
    }
}

#[derive(Debug, Default)]
struct DnsStub {
    zones: HashMap<(String, u8), Vec<String>>,
    missing: Vec<String>,
}

fn kind_id(kind: DnsKind) -> u8 {
    match kind {
        DnsKind::Ns => 0,
        DnsKind::A => 1,
        DnsKind::Aaaa => 2,
        DnsKind::Cname => 3,
    }
}

impl DnsStub {
    fn with(mut self, name: &str, kind: DnsKind, values: &[&str]) -> Self {
        self.zones.insert(
            (name.to_owned(), kind_id(kind)),
            values.iter().map(|v| (*v).to_owned()).collect(),
        );
        self
    }
}

#[async_trait]
impl DnsPort for DnsStub {
    async fn resolve(&self, name: &str, kind: DnsKind) -> Result<Vec<String>, DnsFailure> {
        if self.missing.iter().any(|m| m == name) {
            return Err(DnsFailure::NameDoesNotExist);
        }
        Ok(self
            .zones
            .get(&(name.to_owned(), kind_id(kind)))
            .cloned()
            .unwrap_or_default())
    }
}

#[derive(Debug, Default)]
struct Store {
    rows: Mutex<HashMap<String, DomainObservation>>,
}

#[async_trait]
impl ObservationStore for Store {
    async fn save(&self, key: &str, observation: &DomainObservation) -> Result<(), String> {
        self.rows
            .lock()
            .unwrap()
            .insert(key.to_owned(), observation.clone());
        Ok(())
    }
    async fn get(&self, key: &str) -> Result<Option<DomainObservation>, String> {
        Ok(self.rows.lock().unwrap().get(key).cloned())
    }
    async fn list(&self) -> Result<Vec<(String, DomainObservation)>, String> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect())
    }
    async fn retain(&self, keep: &[String]) -> Result<(), String> {
        self.rows.lock().unwrap().retain(|key, _| keep.contains(key));
        Ok(())
    }
}

#[derive(Debug, Default)]
struct Audit {
    intents: Mutex<Vec<AuditIntent>>,
}

#[async_trait]
impl AuditPort for Audit {
    async fn record_intent(&self, intent: &AuditIntent) -> Result<(), String> {
        self.intents.lock().unwrap().push(intent.clone());
        Ok(())
    }
    async fn record_outcome(
        &self,
        _operation_id: &str,
        _outcome: crate::audit::AuditOutcome,
    ) -> Result<(), String> {
        Ok(())
    }
}

#[derive(Debug)]
struct Allow;
impl Authorizer for Allow {
    fn decide(&self, _request: AccessRequest<'_>) -> Decision {
        Decision::allow()
    }
}

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

struct Rig {
    enricher: DomainEnricher,
    rdap: Arc<RdapStub>,
    store: Arc<Store>,
    audit: Arc<Audit>,
}

fn entry(key: &str, fields: Value) -> DomainEntry {
    DomainEntry {
        key: key.to_owned(),
        fields,
    }
}

fn rig(entries: Vec<DomainEntry>, rdap: RdapStub, dns: DnsStub, gap: Duration) -> Rig {
    let rdap = Arc::new(rdap);
    let store = Arc::new(Store::default());
    let audit = Arc::new(Audit::default());
    let settings = EnrichSettings {
        rdap_gap: gap,
        ..EnrichSettings::default()
    };
    let enricher = DomainEnricher::new(
        Arc::new(Directory { entries }),
        rdap.clone(),
        Arc::new(dns),
        store.clone(),
        audit.clone(),
        settings,
    )
    .with_clock(Arc::new(|| NOW));
    Rig {
        enricher,
        rdap,
        store,
        audit,
    }
}

fn com_answer() -> RdapAnswer {
    RdapAnswer {
        registrar: Some("Porkbun LLC".to_owned()),
        expires: Some("2027-08-13T04:00:00Z".to_owned()),
        statuses: vec!["client transfer prohibited".to_owned()],
        nameservers: vec!["a.ns.cloudflare.com".to_owned()],
    }
}

#[tokio::test]
async fn refresh_records_rdap_and_dns_and_audits_before_looking_up() {
    let rdap = RdapStub::default().with("example.com", "https://rdap.verisign.com/", Ok(com_answer()));
    let dns = DnsStub::default()
        .with("example.com", DnsKind::Ns, &["a.ns.cloudflare.com"])
        .with("example.com", DnsKind::A, &["93.184.216.34"])
        .with("www.example.com", DnsKind::Cname, &["example.com"]);
    let rig = rig(
        vec![entry("example.com", json!({"fqdn": "example.com", "registrar": "Porkbun"}))],
        rdap,
        dns,
        Duration::ZERO,
    );
    let view = rig
        .enricher
        .refresh(&Allow, "alice", Some("corr-1"), "example.com")
        .await
        .unwrap();
    let observed = view.observation.unwrap();
    assert_eq!(observed.rdap.status, RdapStatus::Ok);
    assert_eq!(observed.rdap.expires.as_deref(), Some("2027-08-13"));
    assert_eq!(observed.dns.apex.ns, ["a.ns.cloudflare.com"]);
    assert_eq!(observed.dns.apex.a, ["93.184.216.34"]);
    assert_eq!(observed.dns.www.cname, ["example.com"]);
    assert_eq!(observed.dns.status, DnsStatus::Ok);
    // Stored, and the registrar agrees after normalization.
    assert!(rig.store.get("example.com").await.unwrap().is_some());
    assert_eq!(
        diff_of(&view.assessment, "registrar").state,
        FieldState::InSync
    );
    let intents = rig.audit.intents.lock().unwrap();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].action, "registry.observe");
    assert_eq!(intents[0].resource.as_deref(), Some("domain/example.com"));
    assert_eq!(intents[0].actor, "alice");
    assert_eq!(intents[0].correlation_id.as_deref(), Some("corr-1"));
}

#[tokio::test]
async fn a_tld_without_rdap_reports_unavailable_not_an_error() {
    let rig = rig(
        vec![entry("example.de", json!({"fqdn": "example.de"}))],
        RdapStub::default(),
        DnsStub::default().with("example.de", DnsKind::Ns, &["ns1.example.net"]),
        Duration::ZERO,
    );
    let view = rig
        .enricher
        .refresh(&Allow, "alice", None, "example.de")
        .await
        .unwrap();
    let observed = view.observation.unwrap();
    assert_eq!(observed.rdap.status, RdapStatus::Unavailable);
    assert!(observed.rdap.detail.unwrap().contains(".de"));
    // DNS still answered.
    assert_eq!(observed.dns.apex.ns, ["ns1.example.net"]);
    assert!(rig.rdap.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rdap_failures_and_unregistered_names_are_recorded_as_observations() {
    let rdap = RdapStub::default()
        .with("gone.com", "https://rdap.verisign.com/", Err(RdapFailure::NotFound))
        .with(
            "busy.com",
            "https://rdap.verisign.com/",
            Err(RdapFailure::Failed("the RDAP server answered HTTP 429".to_owned())),
        );
    let dns = DnsStub {
        missing: vec!["gone.com".to_owned()],
        ..DnsStub::default()
    };
    let rig = rig(
        vec![
            entry("busy.com", json!({"fqdn": "busy.com"})),
            entry("gone.com", json!({"fqdn": "gone.com"})),
        ],
        rdap,
        dns,
        Duration::ZERO,
    );
    let gone = rig.enricher.refresh(&Allow, "a", None, "gone.com").await.unwrap();
    let gone = gone.observation.unwrap();
    assert_eq!(gone.rdap.status, RdapStatus::NotFound);
    assert_eq!(gone.dns.status, DnsStatus::NotFound);
    let busy = rig.enricher.refresh(&Allow, "a", None, "busy.com").await.unwrap();
    let busy = busy.observation.unwrap();
    assert_eq!(busy.rdap.status, RdapStatus::Error);
    assert!(busy.rdap.detail.unwrap().contains("429"));
}

#[tokio::test]
async fn a_missing_www_does_not_make_the_name_not_found() {
    let dns = DnsStub {
        missing: vec!["www.example.com".to_owned()],
        ..DnsStub::default().with("example.com", DnsKind::A, &["192.0.2.1"])
    };
    let rig = rig(
        vec![entry("example.com", json!({"fqdn": "example.com"}))],
        RdapStub::default(),
        dns,
        Duration::ZERO,
    );
    let view = rig.enricher.refresh(&Allow, "a", None, "example.com").await.unwrap();
    assert_eq!(view.observation.unwrap().dns.status, DnsStatus::Ok);
}

#[tokio::test]
async fn refresh_without_the_observe_permission_does_nothing() {
    let rdap = RdapStub::default().with("example.com", "https://rdap.verisign.com/", Ok(com_answer()));
    let rig = rig(
        vec![entry("example.com", json!({"fqdn": "example.com"}))],
        rdap,
        DnsStub::default(),
        Duration::ZERO,
    );
    let error = rig
        .enricher
        .refresh(&Without(Permission::RegistryObserve), "bob", None, "example.com")
        .await
        .unwrap_err();
    assert!(matches!(error, ProjectUseCaseError::Denied(_)));
    assert!(rig.audit.intents.lock().unwrap().is_empty());
    assert!(rig.rdap.queries.lock().unwrap().is_empty());
    assert!(rig.store.rows.lock().unwrap().is_empty());
    // Reading is a different permission and still works.
    assert!(rig
        .enricher
        .get(&Without(Permission::RegistryObserve), "bob", "example.com")
        .await
        .is_ok());
    let blind = rig
        .enricher
        .get(&Without(Permission::RegistryRead), "bob", "example.com")
        .await
        .unwrap_err();
    assert!(matches!(blind, ProjectUseCaseError::Denied(_)));
}

#[tokio::test]
async fn refresh_of_an_unknown_entry_is_not_found() {
    let rig = rig(vec![], RdapStub::default(), DnsStub::default(), Duration::ZERO);
    let error = rig.enricher.refresh(&Allow, "a", None, "nope.com").await.unwrap_err();
    assert!(matches!(error, ProjectUseCaseError::NotFound { .. }));
}

#[tokio::test]
async fn queries_to_one_rdap_server_are_spaced_by_the_gap() {
    let server = "https://rdap.verisign.com/";
    let rdap = RdapStub::default()
        .with("a.com", server, Ok(com_answer()))
        .with("b.com", server, Ok(com_answer()))
        .with("c.org", "https://rdap.pir.org/", Ok(com_answer()));
    let rig = rig(
        vec![
            entry("a.com", json!({"fqdn": "a.com"})),
            entry("b.com", json!({"fqdn": "b.com"})),
            entry("c.org", json!({"fqdn": "c.org"})),
        ],
        rdap,
        DnsStub::default(),
        Duration::from_millis(120),
    );
    let report = rig.enricher.sweep(&Allow, "system", None).await.unwrap();
    assert_eq!(report.observed, 3);
    let queries = rig.rdap.queries.lock().unwrap();
    let verisign: Vec<_> = queries.iter().filter(|(_, s)| s == server).collect();
    assert_eq!(verisign.len(), 2);
    let gap = verisign[1].0.duration_since(verisign[0].0);
    assert!(gap >= Duration::from_millis(100), "gap was {gap:?}");
}

#[tokio::test]
async fn an_on_demand_lookup_refuses_to_queue_behind_a_long_backlog() {
    let server = "https://rdap.verisign.com/";
    let rdap = RdapStub::default()
        .with("a.com", server, Ok(com_answer()))
        .with("b.com", server, Ok(com_answer()));
    let rig = rig(
        vec![
            entry("a.com", json!({"fqdn": "a.com"})),
            entry("b.com", json!({"fqdn": "b.com"})),
        ],
        rdap,
        DnsStub::default(),
        Duration::from_secs(40),
    );
    // The first lookup takes the free slot; the next would wait 40 s.
    rig.enricher.refresh(&Allow, "a", None, "a.com").await.unwrap();
    let error = rig.enricher.refresh(&Allow, "a", None, "b.com").await.unwrap_err();
    assert!(matches!(
        error,
        ProjectUseCaseError::Backend { context: "registry_observe_rate_limited", .. }
    ));
    assert_eq!(rig.rdap.queries.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn sweep_skips_fresh_observations_audits_once_and_prunes_removed_entries() {
    let server = "https://rdap.verisign.com/";
    let rdap = RdapStub::default()
        .with("new.com", server, Ok(com_answer()))
        .with("fresh.com", server, Ok(com_answer()))
        .with("stale.com", server, Ok(com_answer()));
    let rig = rig(
        vec![
            entry("fresh.com", json!({"fqdn": "fresh.com"})),
            entry("new.com", json!({"fqdn": "new.com"})),
            entry("stale.com", json!({"fqdn": "stale.com"})),
        ],
        rdap,
        DnsStub::default(),
        Duration::ZERO,
    );
    let day = 86_400_000;
    let at = |age: i64| DomainObservation {
        observed_at: NOW - age,
        ..observation(None, None, &[])
    };
    rig.store.save("fresh.com", &at(1_000)).await.unwrap();
    rig.store.save("stale.com", &at(2 * day)).await.unwrap();
    rig.store.save("removed.com", &at(1_000)).await.unwrap();

    let report = rig
        .enricher
        .sweep(&Allow, "system", Some(Duration::from_secs(86_400)))
        .await
        .unwrap();
    assert_eq!(
        report,
        SweepReport {
            observed: 2,
            fresh: 1,
            failed: 0
        }
    );
    let queried = rig.rdap.queries.lock().unwrap().len();
    assert_eq!(queried, 2);
    let rows = rig.store.rows.lock().unwrap();
    assert!(rows.contains_key("new.com") && rows.contains_key("fresh.com"));
    assert!(!rows.contains_key("removed.com"));
    let intents = rig.audit.intents.lock().unwrap();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].resource, None);
    assert_eq!(intents[0].actor, "system");
}

#[tokio::test]
async fn sweep_is_refused_without_the_observe_permission() {
    let rig = rig(
        vec![entry("a.com", json!({"fqdn": "a.com"}))],
        RdapStub::default(),
        DnsStub::default(),
        Duration::ZERO,
    );
    let error = rig
        .enricher
        .sweep(&Without(Permission::RegistryObserve), "system", None)
        .await
        .unwrap_err();
    assert!(matches!(error, ProjectUseCaseError::Denied(_)));
    assert!(rig.audit.intents.lock().unwrap().is_empty());
}

#[tokio::test]
async fn list_marks_domains_needing_attention_even_before_their_first_lookup() {
    let rig = rig(
        vec![
            entry("a.com", json!({"fqdn": "a.com", "expires": "2027-01-01"})),
            entry("b.com", json!({"fqdn": "b.com", "expires": "2026-10-20", "autoRenew": false})),
            entry("c.com", json!({"fqdn": "c.com", "registrar": "Porkbun"})),
        ],
        RdapStub::default(),
        DnsStub::default(),
        Duration::ZERO,
    );
    rig.store
        .save("c.com", &observation(Some("Namecheap"), None, &[]))
        .await
        .unwrap();
    let all = rig.enricher.list(&Allow, "a", false, None, 10).await.unwrap();
    assert_eq!(all.len(), 3);
    let attention = rig.enricher.list(&Allow, "a", true, None, 10).await.unwrap();
    let keys: Vec<_> = attention.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys, ["b.com", "c.com"]);
    // Paging: after the first, limit one.
    let page = rig.enricher.list(&Allow, "a", true, Some("b.com"), 1).await.unwrap();
    assert_eq!(page[0].key, "c.com");
}

#[test]
fn settings_parse_the_environment_values() {
    let defaults = EnrichSettings::from_env_values(None, Some("")).unwrap();
    assert_eq!(defaults.interval, Duration::from_secs(DEFAULT_INTERVAL_SECONDS));
    assert_eq!(defaults.expiry_window_days, DEFAULT_WINDOW_DAYS);
    let tuned = EnrichSettings::from_env_values(Some("3600"), Some("60")).unwrap();
    assert_eq!(tuned.interval, Duration::from_secs(3600));
    assert_eq!(tuned.expiry_window_days, 60);
    let off = EnrichSettings::from_env_values(Some("0"), None).unwrap();
    assert!(off.interval.is_zero());
}

#[test]
fn malformed_settings_are_refused_by_name() {
    for (interval, window, needle) in [
        (Some("often"), None, INTERVAL_VAR),
        (Some("30"), None, INTERVAL_VAR),
        (None, Some("0"), WINDOW_VAR),
        (None, Some("9999"), WINDOW_VAR),
        (None, Some("soon"), WINDOW_VAR),
    ] {
        let error = EnrichSettings::from_env_values(interval, window).unwrap_err();
        assert!(error.contains(needle), "{error}");
    }
}
