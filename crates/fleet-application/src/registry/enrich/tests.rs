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

fn observation(registrar: Option<&str>, expires: Option<&str>, ns: &[&str]) -> DomainObservation {
    DomainObservation {
        observed_at: NOW,
        last_error: None,
        stale_since: None,
        failures: 0,
        rdap: RdapObservation {
            status: RdapStatus::Ok,
            source: RegistrationSource::Rdap,
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
    assert_eq!(
        days_from_date("2027-08-13T04:00:00Z"),
        days_from_date("2027-08-13")
    );
    assert_eq!(days_from_date("2027-13-01"), None);
    assert_eq!(days_from_date("soon"), None);
    assert_eq!(
        date_part("2027-08-13T04:00:00Z").as_deref(),
        Some("2027-08-13")
    );
    assert_eq!(today(), days_from_date("2026-10-14").unwrap());
}

#[test]
fn registrar_names_match_across_legal_suffixes_and_punctuation() {
    assert!(registrars_match("GoDaddy", "GoDaddy.com, LLC"));
    assert!(registrars_match("Webhuset", "Webhuset AS"));
    assert!(registrars_match(
        "Sikt",
        "SIKT - KUNNSKAPSSEKTORENS TJENESTELEVERANDØR"
    ));
    assert!(!registrars_match("Porkbun", "Namecheap, Inc."));
    assert!(!registrars_match("Hostinger", "Webhuset AS"));
}

fn ns(names: &[&str]) -> Vec<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

#[test]
fn dns_hosts_match_whole_labels_by_name_or_known_alias() {
    assert_eq!(
        dns_host_matches("Cloudflare", &ns(&["elliott.ns.cloudflare.com"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("Cloudflare DNS", &ns(&["elliott.ns.cloudflare.com"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("Hostinger", &ns(&["ns1.dns-parking.com"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("GoDaddy", &ns(&["ns01.domaincontrol.com"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("Domeneshop", &ns(&["ns.hyp.net", "ns2.hyp.net"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("AWS", &ns(&["ns-123.awsdns-45.com"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("Route 53", &ns(&["ns-9.awsdns-01.org"])),
        Some(true)
    );
    assert_eq!(
        dns_host_matches("Cloudflare", &ns(&["ns1.dns-parking.com"])),
        Some(false)
    );
}

#[test]
fn dns_host_words_never_match_inside_a_label() {
    // "aws" is three letters: only the alias applies, and only to awsdns.
    assert_eq!(
        dns_host_matches(
            "aws",
            &ns(&["ns1.laws.example.net", "ns2.jaws.example.net"])
        ),
        Some(false)
    );
    // A word is not matched as a substring of a longer label.
    assert_eq!(
        dns_host_matches("Cloudflare", &ns(&["ns1.notcloudflare.example.net"])),
        Some(false)
    );
    assert_eq!(
        dns_host_matches("Hosting Provider", &ns(&["ns1.example.net"])),
        None
    );
}

#[test]
fn generic_dns_host_values_are_unknown() {
    for value in [
        "registrar",
        "Same as registrar",
        "same as registrar",
        "n/a",
        "",
        "-",
    ] {
        assert_eq!(
            dns_host_matches(value, &ns(&["ns1.example.net"])),
            None,
            "{value:?}"
        );
    }
    let fields = json!({"fqdn": "example.com", "dnsHost": "same as registrar"});
    let seen = observation(None, None, &["ns1.example.net"]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(diff_of(&result, "dnsHost").state, FieldState::Unknown);
    assert!(result.warnings.is_empty());
}

#[test]
fn registrar_aliases_cover_rebrands() {
    assert!(registrars_match("Route 53", "Amazon Registrar, Inc."));
    assert!(registrars_match(
        "Google Domains",
        "Squarespace Domains LLC"
    ));
    assert!(!registrars_match("Google Domains", "Namecheap, Inc."));
    assert!(!registrars_match("Route 53", "Squarespace Domains LLC"));
    // A mismatch the aliases do not excuse is still a warning.
    let fields = json!({"fqdn": "example.com", "registrar": "Porkbun"});
    let seen = observation(Some("Squarespace Domains LLC"), None, &[]);
    let result = assess(&fields, Some(&seen), today(), 30);
    assert_eq!(result.warnings[0].severity, Severity::Warn);
}

#[test]
fn impossible_dates_are_not_dates() {
    assert_eq!(days_from_date("2027-02-29"), None);
    assert_eq!(days_from_date("2027-04-31"), None);
    assert_eq!(days_from_date("2027-00-10"), None);
    assert_eq!(days_from_date("2027-06-00"), None);
    assert!(
        days_from_date("2028-02-29").is_some(),
        "2028 is a leap year"
    );
    assert_eq!(days_from_date("2100-02-29"), None, "2100 is not");
    assert!(days_from_date("2000-02-29").is_some(), "2000 is");
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
    let seen = observation(
        Some("Webhuset AS"),
        Some("2028-01-01"),
        &["ns1.example.net"],
    );
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
    assert_eq!(result.warnings[0].severity, Severity::Info);
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
    assert_eq!(
        assess(&urgent, None, today(), 30).warnings[0].severity,
        Severity::Err
    );

    let lapsed = json!({"fqdn": "example.com", "expires": "2026-10-01"});
    let result = assess(&lapsed, None, today(), 30);
    assert_eq!(result.warnings[0].severity, Severity::Err);
    assert!(result.warnings[0].message.contains("expired 13 days ago"));

    let far = json!({"fqdn": "example.com", "expires": "2027-10-01"});
    assert!(assess(&far, None, today(), 30).warnings.is_empty());
    // The window is configurable.
    assert_eq!(
        codes(&assess(&far, None, today(), 400)),
        [WarningCode::Expiring]
    );
}

#[test]
fn auto_renew_off_while_expiring_is_its_own_warning() {
    let fields = json!({"fqdn": "example.com", "expires": "2026-11-03", "autoRenew": false});
    let result = assess(&fields, None, today(), 30);
    assert_eq!(codes(&result), [WarningCode::AutoRenewOffExpiring]);
    let renewing = json!({"fqdn": "example.com", "expires": "2026-11-03", "autoRenew": true});
    assert_eq!(
        codes(&assess(&renewing, None, today(), 30)),
        [WarningCode::Expiring]
    );
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
        [
            WarningCode::AutoRenewOffExpiring,
            WarningCode::RegistrarMismatch
        ]
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

type StubAnswer = (String, Result<RdapAnswer, RdapFailure>);

#[derive(Debug, Default)]
struct RdapStub {
    /// fqdn -> (server, answer); a missing fqdn has no RDAP.
    answers: Mutex<HashMap<String, StubAnswer>>,
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
        self.rows
            .lock()
            .unwrap()
            .retain(|key, _| keep.contains(key));
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
    let rdap = RdapStub::default().with(
        "example.com",
        "https://rdap.verisign.com/",
        Ok(com_answer()),
    );
    let dns = DnsStub::default()
        .with("example.com", DnsKind::Ns, &["a.ns.cloudflare.com"])
        .with("example.com", DnsKind::A, &["93.184.216.34"])
        .with("www.example.com", DnsKind::Cname, &["example.com"]);
    let rig = rig(
        vec![entry(
            "example.com",
            json!({"fqdn": "example.com", "registrar": "Porkbun"}),
        )],
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
        .with(
            "gone.com",
            "https://rdap.verisign.com/",
            Err(RdapFailure::NotFound),
        )
        .with(
            "busy.com",
            "https://rdap.verisign.com/",
            Err(RdapFailure::Failed(
                "the RDAP server answered HTTP 429".to_owned(),
            )),
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
    let gone = rig
        .enricher
        .refresh(&Allow, "a", None, "gone.com")
        .await
        .unwrap();
    let gone = gone.observation.unwrap();
    assert_eq!(gone.rdap.status, RdapStatus::NotFound);
    assert_eq!(gone.dns.status, DnsStatus::NotFound);
    let busy = rig
        .enricher
        .refresh(&Allow, "a", None, "busy.com")
        .await
        .unwrap();
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
    let view = rig
        .enricher
        .refresh(&Allow, "a", None, "example.com")
        .await
        .unwrap();
    assert_eq!(view.observation.unwrap().dns.status, DnsStatus::Ok);
}

#[tokio::test]
async fn refresh_without_the_observe_permission_does_nothing() {
    let rdap = RdapStub::default().with(
        "example.com",
        "https://rdap.verisign.com/",
        Ok(com_answer()),
    );
    let rig = rig(
        vec![entry("example.com", json!({"fqdn": "example.com"}))],
        rdap,
        DnsStub::default(),
        Duration::ZERO,
    );
    let error = rig
        .enricher
        .refresh(
            &Without(Permission::RegistryObserve),
            "bob",
            None,
            "example.com",
        )
        .await
        .unwrap_err();
    assert!(matches!(error, ProjectUseCaseError::Denied(_)));
    assert!(rig.audit.intents.lock().unwrap().is_empty());
    assert!(rig.rdap.queries.lock().unwrap().is_empty());
    assert!(rig.store.rows.lock().unwrap().is_empty());
    // Reading is a different permission and still works.
    assert!(
        rig.enricher
            .get(&Without(Permission::RegistryObserve), "bob", "example.com")
            .await
            .is_ok()
    );
    let blind = rig
        .enricher
        .get(&Without(Permission::RegistryRead), "bob", "example.com")
        .await
        .unwrap_err();
    assert!(matches!(blind, ProjectUseCaseError::Denied(_)));
}

#[tokio::test]
async fn refresh_of_an_unknown_entry_is_not_found() {
    let rig = rig(
        vec![],
        RdapStub::default(),
        DnsStub::default(),
        Duration::ZERO,
    );
    let error = rig
        .enricher
        .refresh(&Allow, "a", None, "nope.com")
        .await
        .unwrap_err();
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
    rig.enricher
        .refresh(&Allow, "a", None, "a.com")
        .await
        .unwrap();
    let error = rig
        .enricher
        .refresh(&Allow, "a", None, "b.com")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ProjectUseCaseError::Backend {
            context: "registry_observe_rate_limited",
            ..
        }
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
        .sweep(&Allow, "system", Some(Duration::from_hours(24)))
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
    assert_eq!(intents[0].actor, crate::skill_catalog::CONTROLLER_ACTOR);
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
            entry(
                "b.com",
                json!({"fqdn": "b.com", "expires": "2026-10-20", "autoRenew": false}),
            ),
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
    let all = rig
        .enricher
        .list(&Allow, "a", false, None, 10)
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    let attention = rig
        .enricher
        .list(&Allow, "a", true, None, 10)
        .await
        .unwrap();
    let keys: Vec<_> = attention.iter().map(|v| v.key.as_str()).collect();
    assert_eq!(keys, ["b.com", "c.com"]);
    // Paging: after the first, limit one.
    let page = rig
        .enricher
        .list(&Allow, "a", true, Some("b.com"), 1)
        .await
        .unwrap();
    assert_eq!(page[0].key, "c.com");
}

#[test]
fn settings_parse_the_environment_values() {
    let defaults = EnrichSettings::from_env_values(None, Some("")).unwrap();
    assert_eq!(
        defaults.interval,
        Duration::from_secs(DEFAULT_INTERVAL_SECONDS)
    );
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

// ---- failures, staleness, health ----

fn failed_rdap() -> Result<RdapAnswer, RdapFailure> {
    Err(RdapFailure::Failed(
        "the server could not be reached".to_owned(),
    ))
}

#[tokio::test]
async fn a_failed_lookup_keeps_the_last_good_data_and_marks_it_stale() {
    let server = "https://rdap.verisign.com/";
    let rig = rig(
        vec![entry(
            "example.com",
            json!({"fqdn": "example.com", "registrar": "Porkbun"}),
        )],
        RdapStub::default().with("example.com", server, Ok(com_answer())),
        DnsStub::default().with("example.com", DnsKind::Ns, &["a.ns.cloudflare.com"]),
        Duration::ZERO,
    );
    let good = rig
        .enricher
        .refresh(&Allow, "a", None, "example.com")
        .await
        .unwrap();
    assert!(good.observation.as_ref().unwrap().is_settled());

    // The next attempt fails: the earlier registrar and expiry survive.
    rig.rdap
        .answers
        .lock()
        .unwrap()
        .insert("example.com".to_owned(), (server.to_owned(), failed_rdap()));
    let view = rig
        .enricher
        .refresh(&Allow, "a", None, "example.com")
        .await
        .unwrap();
    let kept = view.observation.unwrap();
    assert_eq!(kept.rdap.status, RdapStatus::Ok);
    assert_eq!(kept.rdap.registrar.as_deref(), Some("Porkbun LLC"));
    assert_eq!(kept.rdap.expires.as_deref(), Some("2027-08-13"));
    assert_eq!(kept.stale_since, Some(NOW));
    assert_eq!(kept.failures, 1);
    assert!(
        kept.last_error
            .as_deref()
            .unwrap()
            .contains("could not be reached")
    );
    assert!(!kept.is_settled());
    assert!(codes(&view.assessment).contains(&WarningCode::StaleObservation));
    // And what was stored is the merged observation.
    assert_eq!(rig.store.get("example.com").await.unwrap().unwrap(), kept);

    // Recovery clears the marks.
    rig.rdap.answers.lock().unwrap().insert(
        "example.com".to_owned(),
        (server.to_owned(), Ok(com_answer())),
    );
    let healed = rig
        .enricher
        .refresh(&Allow, "a", None, "example.com")
        .await
        .unwrap();
    let healed = healed.observation.unwrap();
    assert!(healed.is_settled() && healed.last_error.is_none());
}

#[tokio::test]
async fn a_failure_with_nothing_good_to_keep_is_recorded_as_the_failure() {
    let rig = rig(
        vec![entry("example.com", json!({"fqdn": "example.com"}))],
        RdapStub::default().with("example.com", "https://rdap.verisign.com/", failed_rdap()),
        DnsStub::default(),
        Duration::ZERO,
    );
    let view = rig
        .enricher
        .refresh(&Allow, "a", None, "example.com")
        .await
        .unwrap();
    let observed = view.observation.unwrap();
    assert_eq!(observed.rdap.status, RdapStatus::Error);
    assert_eq!(observed.stale_since, None);
    assert_eq!(observed.failures, 1);
}

#[tokio::test]
async fn an_unsettled_observation_is_not_fresh_for_the_sweep() {
    let server = "https://rdap.verisign.com/";
    let rig = rig(
        vec![entry("example.com", json!({"fqdn": "example.com"}))],
        RdapStub::default().with("example.com", server, failed_rdap()),
        DnsStub::default(),
        Duration::ZERO,
    );
    // A just-recorded failure (age ~0) is retried by the next sweep...
    let mut failed = observation(None, None, &[]);
    failed.rdap = RdapObservation::empty(RdapStatus::Error, "down");
    failed.failures = 1;
    rig.store.save("example.com", &failed).await.unwrap();
    let report = rig
        .enricher
        .sweep(&Allow, "system", Some(Duration::from_hours(24)))
        .await
        .unwrap();
    assert_eq!((report.observed, report.fresh), (1, 0));
    // ...while a settled one of the same age is skipped.
    rig.store
        .save("example.com", &observation(None, None, &[]))
        .await
        .unwrap();
    let report = rig
        .enricher
        .sweep(&Allow, "system", Some(Duration::from_hours(24)))
        .await
        .unwrap();
    assert_eq!((report.observed, report.fresh), (0, 1));
}

#[test]
fn health_warnings_cover_not_found_persistent_failure_and_age() {
    let fields = json!({"fqdn": "example.com"});
    let context = |now: i64, stale: Option<i64>| diff::AssessContext {
        today: diff::days_from_millis(now),
        window_days: 30,
        now_millis: now,
        stale_after_millis: stale,
    };
    let mut gone = observation(None, None, &[]);
    gone.rdap = RdapObservation::empty(RdapStatus::NotFound, "unregistered");
    let result = diff::assess_with(&fields, Some(&gone), &context(NOW, None));
    assert_eq!(codes(&result), [WarningCode::RdapNotFound]);
    assert_eq!(result.warnings[0].severity, Severity::Warn);

    let mut failing = observation(None, None, &[]);
    failing.failures = 3;
    failing.last_error = Some("down".to_owned());
    let result = diff::assess_with(&fields, Some(&failing), &context(NOW, None));
    assert_eq!(codes(&result), [WarningCode::LookupFailing]);
    failing.failures = 2;
    assert!(
        diff::assess_with(&fields, Some(&failing), &context(NOW, None))
            .warnings
            .is_empty()
    );

    // Older than twice the interval is stale; within it is not; off is never.
    let day = 86_400_000;
    let old = observation(None, None, &[]);
    let later = NOW + 3 * day;
    let result = diff::assess_with(&fields, Some(&old), &context(later, Some(2 * day)));
    assert_eq!(codes(&result), [WarningCode::StaleObservation]);
    assert_eq!(result.warnings[0].severity, Severity::Info);
    assert!(
        diff::assess_with(&fields, Some(&old), &context(NOW + day, Some(2 * day)))
            .warnings
            .is_empty()
    );
    assert!(
        diff::assess_with(&fields, Some(&old), &context(later, None))
            .warnings
            .is_empty()
    );
}

#[tokio::test]
async fn sweep_forgets_nothing_when_the_directory_is_empty_and_audits_as_the_controller() {
    let rig = rig(
        vec![],
        RdapStub::default(),
        DnsStub::default(),
        Duration::ZERO,
    );
    rig.store
        .save("kept.com", &observation(None, None, &[]))
        .await
        .unwrap();
    rig.enricher.sweep(&Allow, "system", None).await.unwrap();
    assert!(rig.store.get("kept.com").await.unwrap().is_some());

    let rig = rig_with_one_domain();
    rig.enricher
        .sweep(&Allow, "anonymous-lan-admin", None)
        .await
        .unwrap();
    let intents = rig.audit.intents.lock().unwrap();
    assert_eq!(intents[0].actor, crate::skill_catalog::CONTROLLER_ACTOR);
    let facts: std::collections::BTreeMap<_, _> = intents[0].metadata.entries().collect();
    assert_eq!(facts["authorizedAs"], "anonymous-lan-admin");
    assert_eq!(facts["trigger"], "scheduled");
}

fn rig_with_one_domain() -> Rig {
    rig(
        vec![entry("a.com", json!({"fqdn": "a.com"}))],
        RdapStub::default().with("a.com", "https://rdap.verisign.com/", Ok(com_answer())),
        DnsStub::default(),
        Duration::ZERO,
    )
}

type WhoisStubAnswer = (Option<String>, Result<WhoisAnswer, WhoisFailure>);

#[derive(Debug, Default)]
struct WhoisStub {
    /// fqdn -> (server, answer); a server of `None` means no WHOIS.
    answers: Mutex<HashMap<String, WhoisStubAnswer>>,
    queries: Mutex<Vec<(std::time::Instant, String)>>,
    /// Whether the IANA referral needs a network query (and a slot).
    uncached_referrals: bool,
}

impl WhoisStub {
    fn uncached(mut self) -> Self {
        self.uncached_referrals = true;
        self
    }

    fn with(
        self,
        fqdn: &str,
        server: Option<&str>,
        answer: Result<WhoisAnswer, WhoisFailure>,
    ) -> Self {
        self.answers
            .lock()
            .unwrap()
            .insert(fqdn.to_owned(), (server.map(str::to_owned), answer));
        self
    }
}

#[async_trait]
impl WhoisPort for WhoisStub {
    fn referral_is_cached(&self, _fqdn: &str) -> bool {
        !self.uncached_referrals
    }

    async fn server_for(&self, fqdn: &str) -> Result<Option<String>, String> {
        Ok(self
            .answers
            .lock()
            .unwrap()
            .get(fqdn)
            .and_then(|(server, _)| server.clone()))
    }

    async fn lookup(&self, server: &str, fqdn: &str) -> Result<WhoisAnswer, WhoisFailure> {
        self.queries
            .lock()
            .unwrap()
            .push((std::time::Instant::now(), server.to_owned()));
        self.answers.lock().unwrap().get(fqdn).unwrap().1.clone()
    }
}

fn io_answer() -> WhoisAnswer {
    WhoisAnswer {
        registrar: Some("Example Registrar, Inc.".to_owned()),
        expires: Some("2027-05-01T09:08:07Z".to_owned()),
    }
}

fn whois_rig(domains: &[&str], whois: WhoisStub, gap: Duration) -> (Rig, Arc<WhoisStub>) {
    let entries = domains
        .iter()
        .map(|d| entry(d, json!({"fqdn": d, "registrar": "Example Registrar"})))
        .collect();
    let rdap = Arc::new(RdapStub::default());
    let store = Arc::new(Store::default());
    let audit = Arc::new(Audit::default());
    let whois = Arc::new(whois);
    let enricher = DomainEnricher::new(
        Arc::new(Directory { entries }),
        rdap.clone(),
        Arc::new(DnsStub::default()),
        store.clone(),
        audit.clone(),
        EnrichSettings {
            rdap_gap: gap,
            ..EnrichSettings::default()
        },
    )
    .with_whois(whois.clone())
    .with_clock(Arc::new(|| NOW));
    let rig = Rig {
        enricher,
        rdap,
        store,
        audit,
    };
    (rig, whois)
}

async fn observe_one(rig: &Rig, fqdn: &str) -> DomainObservation {
    rig.enricher
        .refresh(&Allow, "alice", None, fqdn)
        .await
        .unwrap()
        .observation
        .unwrap()
}

#[tokio::test]
async fn a_tld_without_rdap_falls_back_to_whois_and_reports_its_source() {
    let whois = WhoisStub::default().with("example.io", Some("whois.nic.io"), Ok(io_answer()));
    let (rig, _) = whois_rig(&["example.io"], whois, Duration::ZERO);
    let observed = observe_one(&rig, "example.io").await;
    assert_eq!(observed.rdap.status, RdapStatus::Ok);
    assert_eq!(observed.rdap.source, RegistrationSource::Whois);
    assert_eq!(observed.rdap.server.as_deref(), Some("whois.nic.io"));
    assert_eq!(
        observed.rdap.registrar.as_deref(),
        Some("Example Registrar, Inc.")
    );
    assert_eq!(observed.rdap.expires.as_deref(), Some("2027-05-01"));
    assert!(rig.rdap.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn whois_data_goes_through_the_same_diff_and_warnings() {
    let whois = WhoisStub::default().with(
        "example.io",
        Some("whois.nic.io"),
        Ok(WhoisAnswer {
            registrar: Some("Other Registrar".to_owned()),
            expires: Some("2026-10-20".to_owned()),
        }),
    );
    let (rig, _) = whois_rig(&["example.io"], whois, Duration::ZERO);
    let view = rig
        .enricher
        .refresh(&Allow, "alice", None, "example.io")
        .await
        .unwrap();
    let found = codes(&view.assessment);
    assert!(found.contains(&WarningCode::RegistrarMismatch), "{found:?}");
    assert!(found.contains(&WarningCode::Expiring), "{found:?}");
}

#[tokio::test]
async fn a_whois_answer_without_an_expiry_still_reports_the_registrar() {
    let whois = WhoisStub::default().with(
        "example.gg",
        Some("whois.gg"),
        Ok(WhoisAnswer {
            registrar: Some("Example Registrar Ltd".to_owned()),
            expires: None,
        }),
    );
    let (rig, _) = whois_rig(&["example.gg"], whois, Duration::ZERO);
    let observed = observe_one(&rig, "example.gg").await;
    assert_eq!(observed.rdap.status, RdapStatus::Ok);
    assert_eq!(observed.rdap.expires, None);
}

#[tokio::test]
async fn a_tld_with_neither_rdap_nor_whois_is_unavailable() {
    let whois = WhoisStub::default().with("example.zz", None, Ok(io_answer()));
    let (rig, whois) = whois_rig(&["example.zz"], whois, Duration::ZERO);
    let observed = observe_one(&rig, "example.zz").await;
    assert_eq!(observed.rdap.status, RdapStatus::Unavailable);
    assert!(observed.rdap.detail.unwrap().contains(".zz"));
    assert!(whois.queries.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_unreadable_whois_answer_is_unavailable_and_a_transport_failure_is_an_error() {
    let whois = WhoisStub::default()
        .with(
            "odd.io",
            Some("whois.nic.io"),
            Err(WhoisFailure::Unreadable),
        )
        .with(
            "down.io",
            Some("whois.nic.io"),
            Err(WhoisFailure::Failed(
                "the WHOIS server could not be reached".to_owned(),
            )),
        )
        .with("gone.io", Some("whois.nic.io"), Err(WhoisFailure::NotFound));
    let (rig, _) = whois_rig(&["odd.io", "down.io", "gone.io"], whois, Duration::ZERO);
    assert_eq!(
        observe_one(&rig, "odd.io").await.rdap.status,
        RdapStatus::Unavailable
    );
    assert_eq!(
        observe_one(&rig, "down.io").await.rdap.status,
        RdapStatus::Error
    );
    assert_eq!(
        observe_one(&rig, "gone.io").await.rdap.status,
        RdapStatus::NotFound
    );
}

#[tokio::test]
async fn whois_queries_to_one_server_are_spaced_and_on_demand_waits_are_refused() {
    let whois = WhoisStub::default()
        .with("a.io", Some("whois.nic.io"), Ok(io_answer()))
        .with("b.io", Some("whois.nic.io"), Ok(io_answer()));
    let (rig, whois) = whois_rig(&["a.io", "b.io"], whois, Duration::from_millis(120));
    let report = rig.enricher.sweep(&Allow, "system", None).await.unwrap();
    assert_eq!(report.observed, 2);
    {
        let queries = whois.queries.lock().unwrap();
        assert_eq!(queries.len(), 2);
        let gap = queries[1].0.duration_since(queries[0].0);
        assert!(gap >= Duration::from_millis(100), "gap was {gap:?}");
    }

    let whois = WhoisStub::default()
        .with("a.io", Some("whois.nic.io"), Ok(io_answer()))
        .with("b.io", Some("whois.nic.io"), Ok(io_answer()));
    let (rig, whois) = whois_rig(&["a.io", "b.io"], whois, Duration::from_secs(40));
    observe_one(&rig, "a.io").await;
    let error = rig
        .enricher
        .refresh(&Allow, "a", None, "b.io")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ProjectUseCaseError::Backend {
            context: "registry_observe_rate_limited",
            ..
        }
    ));
    assert_eq!(whois.queries.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_uncached_iana_referral_takes_a_slot_on_the_shared_limiter() {
    let whois = WhoisStub::default()
        .uncached()
        .with("a.io", Some("whois.nic.io"), Ok(io_answer()))
        .with("b.gg", Some("whois.gg"), Ok(io_answer()));
    let (rig, whois) = whois_rig(&["a.io", "b.gg"], whois, Duration::from_secs(40));
    observe_one(&rig, "a.io").await;
    // A different registry, but the same IANA slot, which is 40 s away.
    let error = rig
        .enricher
        .refresh(&Allow, "a", None, "b.gg")
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ProjectUseCaseError::Backend {
            context: "registry_observe_rate_limited",
            ..
        }
    ));
    assert_eq!(whois.queries.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_throttled_whois_server_is_an_error_with_an_honest_detail() {
    let whois = WhoisStub::default().with(
        "a.io",
        Some("whois.nic.io"),
        Err(WhoisFailure::Failed(
            "the WHOIS server is rate limiting queries; try again later".to_owned(),
        )),
    );
    let (rig, _) = whois_rig(&["a.io"], whois, Duration::ZERO);
    let observed = observe_one(&rig, "a.io").await;
    assert_eq!(observed.rdap.status, RdapStatus::Error);
    assert!(observed.rdap.detail.unwrap().contains("rate limiting"));
}
